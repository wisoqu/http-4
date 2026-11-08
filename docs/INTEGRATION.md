# Полное руководство по архитектуре и интеграции `http4`

Этот документ объясняет **человеческим языком**, как именно работает каждый узел `http4` внутри и как встроить его в реальный продакшен-проект за 1–5 минут без переписывания кода.

---

## Часть 1. Как это работает внутри (на пальцах)

Когда запрос попадает в `http4` (неважно — по бинарному протоколу `h4` поверх TLS 1.3 или по обычному HTTP/1.1 / HTTP/2 через гейтвей/адаптер), он проходит **конвейер из 6 ступеней от самых дешёвых проверок к самым дорогим**:

1. **Защита структуры и 0-RTT (`~100 нс`, `src/headers.js`, `src/server.js`)**  
   Отсекаются CRLF/NUL-инъекции в заголовках, попытки обхода путей (`/../`, `%2e`), дубли псевдозаголовков и небезопасные повторённые 0-RTT мутации (`425 Too Early`).
2. **Проверка и офлайн-сужение прав (`~2–13 мкс`, `src/identity.js` + `native/h4_core.c`)**  
   Корневой токен один раз подписан `Ed25519` (результат кэшируется в памяти). Дальше любой агент может сам дописать к токену сужающее звено `HMAC-SHA256-128` в C11 — сузить путь (`/v1` → `/v1/docs`), права (`READ|WRITE` → `READ`) или время жизни, не обращаясь к серверу авторизации. Попытка расширить права отбивается мгновенно.
3. **Умный лимитер + `h4-pass` + C11 Proof-of-Effort (`~0.1–3.5 мкс`, `src/limits.js`, `src/privacy-pass.js`)**  
   - В спокойном режиме честный клиент присылает подписанную квитанцию своего расхода (`h4-rl`), а сервер тратит всего 1 C11 HMAC (`~3.5 мкс`).  
   - При перегрузке или флуде сервер **не банит весь офисный/облачный IP**, а включает цену входа (`EFFORT_REQUIRED`): легитимный клиент либо отдаёт одноразовый крипто-пропуск `h4-pass` (0% нагрузки на телефон/ноутбук), либо решает крипто-задачку (`SHA-256` или 4 KB `MemHard`), которую сервер проверяет за **`380 нс`**.
4. **Экономический потолок и дедлайн (`~200 нс`, кадры `INTENT` и `COST`)**  
   Если клиент указал `h4-cost-ceiling: 5`, а маршрут стоит `40` условных единиц — сервер отказывает **до запуска тяжёлой логики/модели** (`402 / COST_REFUSED`).
5. **Склейка дублей и кэш по тенантам (`~1 мкс`, `src/cache.js`)**  
   Если 50 агентов в одну миллисекунду прислали одинаковый `GET` или `POST` с одинаковым `h4-dedup` ключом, `H4Cache.coalesce` выполняет бэкенд **ровно 1 раз** и раздаёт ответ всем 50 ожидающим. При этом кэш жёстко изолирован по криптографическому `tenant`, чтобы данные клиентов никогда не пересеклись.
6. **Выполнение маршрута / живой стриминг с `F.CANCEL` (`src/server.js`)**  
   При потоковой выдаче токенов (`SUB` или `Accept: text/event-stream`), как только клиент вызывает `AbortController.abort()`, по проводу улетает кадр `F.CANCEL`, сервер мгновенно обрывает генерацию и **возвращает неизрасходованный бюджет** на баланс клиента.

---

## Часть 2. Четыре сценария интеграции

### Сценарий 1: У вас бэкенд на Python (FastAPI / Django / vLLM / LiteLLM), Go или Rust
Вам **вообще не нужно писать код на JS**. Поставьте `http4` рядом как входной sidecar-прокси:

```bash
# 1. Сгенерируйте ключи (опционально, если нужны capability-токены):
npx http4 keygen

# 2. Запустите прокси перед вашим FastAPI на порту 8000:
npx http4 proxy \
  --upstream http://127.0.0.1:8000 \
  --port 8080 \
  --budget 200 \
  --ttl-ms 5000 \
  --poe-mode memhard
```

Что сразу получает ваш Python/Go сервис на `:8000`:
- Схлопывание штормов одинаковых запросов (`h4-dedup: <ключ>`).
- Проверенные заголовки `x-h4-verified-subject`, `x-h4-verified-tenant`, `x-h4-verified-scope` (подделать их снаружи невозможно — прокси вычищает входные заголовки).
- Защиту от L7 DDoS на C11 до того, как запрос дойдёт до Python/воркеров.

---

### Сценарий 2: У вас существующий сервер на Express / Fastify / Node `http`
Добавьте `h4Shield` **одной строкой** перед вашими роутами:

```js
import express from 'express';
import { h4Shield } from 'http4/adapters';

const app = express();

// Не читает и не ломает body stream — express.json() и multer работают штатно!
app.use(h4Shield({
  budget: 200,
  windowMs: 10_000,
  poeMode: 'sha256', // или 'memhard' против GPU-ботов
}));

app.use(express.json());

app.post('/v1/infer', async (req, res) => {
  res.json({ ok: true, caller: req.h4.subject, remaining: req.h4.budgetRemaining });
});

app.listen(3000);
```

---

### Сценарий 3: Cloudflare Workers / Next.js App Router / Bun / Deno / Hono
Оберните ваш стандартный `Request -> Response` обработчик в `withH4`:

```js
// app/api/agent/route.js (Next.js App Router)
import { withH4 } from 'http4/adapters';

const handler = withH4(async (request) => {
  return Response.json({ answer: 'computed once even under 100x retry storm' });
}, {
  budget: 150,
  defaultTtlMs: 3_000,
});

export const GET = handler;
export const POST = handler;
```

---

### Сценарий 4: Нативный H4-сервер + мультиагентный SDK с динамическими роутами (`:param`)

```js
import crypto from 'node:crypto';
import { H4Server, KeyRegistry, mintRoot, CAPS, createH4Fetch, AgentSession } from 'http4';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const registry = new KeyRegistry().add(1, publicKey);

const server = new H4Server({
  registry,
  requireCap: true,
  routes: {
    'GET /v1/projects/:projectId/docs': ({ params, identity }) => ({
      status: 200,
      body: { projectId: params.projectId, tenant: identity.tenant },
      cost: 2,
    }),
  },
});

const h4Fetch = createH4Fetch({ server });
const rootToken = mintRoot({
  keyId: 1,
  privateKey,
  caps: CAPS.READ | CAPS.WRITE | CAPS.DELEGATE,
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
  scope: '/v1/projects',
  tenant: 'org-42',
});

const leadAgent = new AgentSession({ token: rootToken, h4Fetch, budget: 100 });
// Суб-агент получает доступ ТОЛЬКО на чтение ТОЛЬКО проекта alpha!
const subAgent = leadAgent.delegate({ caps: CAPS.READ, scope: '/v1/projects/alpha', budget: 10 });

const ok = await subAgent.fetch('h4://local/v1/projects/alpha/docs');   // 200 OK
const nope = await subAgent.fetch('h4://local/v1/projects/beta/docs');  // 403 Forbidden (до вызова роута!)
```
