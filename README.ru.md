# HTTP/4 (`http4` v0.2.0) — Русская документация

> **[🇬🇧 English README](README.md)** · **[Пошаговый гайд по интеграции](docs/INTEGRATION.md)** · **[Спецификация протокола](spec/http4.md)** · **[Модель кибербезопасности](SECURITY.md)**

[![CI & Sanitizers](https://github.com/wisoqu/http-4/actions/workflows/ci.yml/badge.svg)](https://github.com/wisoqu/http-4/actions/workflows/ci.yml)

Агент-нативный, экономически осознанный и устойчивый к L7-атакам слой поверх HTTP/QUIC — с **нативным C11 Node-API ускорителем**, **нулевыми внешними зависимостями** и **интеграцией за 1 команду или 1 строчку кода** в любые существующие проекты (Python/FastAPI, Go, Express, Next.js, Cloudflare Workers, Bun).

---

## Зачем переходить на `http4` (какую боль он закрывает прямо сейчас)

Классический HTTP создавался под человека в браузере. В эпоху ИИ-агентов и дорогих LLM-вызовов сломались три вещи:
1. **Штормы ретраев сжигают деньги на GPU:** 50 агентов одновременно ретраят один промпт — ваш FastAPI / OpenAI-прокси делает 50 одинаковых вызовов модели вместо одного. `http4` склеивает их на лету (**singleflight coalescing**: 50 запросов → **1 вычисление**).
2. **Суб-агенты ломают авторизацию:** главный агент порождает узких подагентов. Раздавать им мастер-ключ опасно, а ходить на OAuth-сервер на каждый чих — медленно. В `http4` агент **сам за 2 микросекунды офлайн** выпускает суженный Macaroon-токен (например, *только чтение `/v1/docs` на 60 секунд*), расширить права которого математически невозможно.
3. **Обычный rate-limit по IP банит честных пользователей за общим NAT/облаком:** в нашей симуляции за общим CGNAT обычный лимитер режет **88%** честных запросов. `http4` поднимает выживаемость честных агентов с **12% до 100%**, срезая атакующих до **2.3%** через клиентские крипто-квитанции, одноразовые пропуска `h4-pass` (0% нагрузки на батарею) и C11 Proof-of-Effort.

---

## 4 способа встроить в свой проект за 1 минуту

Установка (Node.js ≥ 20, автоматически собирает C11 аддон при наличии `gcc`/`clang`, иначе прозрачно работает на чистом JS):

```bash
npm install github:wisoqu/http-4
```

### Способ 1. Без единой строчки кода (Python FastAPI, vLLM, Ollama, Go, Rust, PHP)
Запустите `http4` как легковесный прокси перед вашим сервером:

```bash
npx http4 proxy --upstream http://127.0.0.1:8000 --port 8080 --budget 200 --ttl-ms 5000
```
Готово: ваш сервер на `:8000` мгновенно защищён от дублирующихся ретраев (`h4-dedup`), L7-флуда и подделки прав.

### Способ 2. 1 строчка для Express / Fastify / Node.js
Не ломает `express.json()`, `multer` или GraphQL — поток тела запроса остаётся нетронутым:

```js
import express from 'express';
import { h4Shield } from 'http4/adapters';

const app = express();
app.use(h4Shield({ budget: 200, windowMs: 10_000 })); // <- вся защита в 1 строку!
app.use(express.json());
app.post('/v1/chat', (req, res) => res.json({ caller: req.h4.subject, ok: true }));
app.listen(3000);
```

### Способ 3. 1 строчка для Next.js App Router / Cloudflare Workers / Bun / Hono

```js
import { withH4 } from 'http4/adapters';

export default {
  fetch: withH4(async (req) => Response.json({ ok: true }), {
    budget: 200,
    defaultTtlMs: 5_000,
  }),
};
```

### Способ 4. Клиентский SDK для мультиагентных систем (`fetch` + стриминг + `F.CANCEL`)

```js
import { createH4Fetch, AgentSession, CAPS } from 'http4';

const h4Fetch = createH4Fetch({ maxEffortBits: 20 });
const orchestrator = new AgentSession({ token: rootGrant, h4Fetch, budget: 100 });

// Офлайн-делегация узкому суб-агенту за ~2 µs:
const reader = orchestrator.delegate({ caps: CAPS.READ, scope: '/v1/docs', budget: 20 });
const res = await reader.fetch('https://api.example.com/v1/docs/spec');

// Стриминг с мгновенной остановкой генерации на сервере (`F.CANCEL`) и возвратом бюджета:
const ac = new AbortController();
for await (const chunk of orchestrator.stream('h4://api.example.com:8443/v1/llm/stream', { signal: ac.signal })) {
  if (enough) ac.abort();
}
```

Подробный разбор архитектуры простыми словами — в **[docs/INTEGRATION.md](docs/INTEGRATION.md)**.

---

## Проверка и команды

```bash
npx http4 doctor                         # самодиагностика и замер C11 хешрейта
npm test                                 # 62 инварианта спеки + 17 киберсекьюрити/фазз тестов
npm run test:san                         # C11 AddressSanitizer + UndefinedBehaviorSanitizer
node examples/reverse-proxy-sidecar.js   # демо: 50 параллельных ретраев -> 1 вызов бэкенда
node examples/agent-mesh.js              # демо: офлайн-делегация суб-агентам + F.CANCEL стриминг
```

## Лицензия

Код — MIT (`LICENSE`), спецификация — CC BY 4.0 (`LICENSE-spec`).
