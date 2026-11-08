# HTTP/4 (`v0.2.0`) — Reference Implementation, C11 Engine & SDK

> Агент-нативный, экономически осознанный и устойчивый к L7-атакам протокол поколения HTTP/4.  
> Спецификация: **[spec/http4.md](spec/http4.md)** · Модель безопасности: **[SECURITY.md](SECURITY.md)**

HTTP/4 меняет три фундаментальные вещи по сравнению с HTTP/1.1–3:
1. **Намерение и цена на проводе** (`INTENT`, `COST`, `RESULT`): запрос объявляет потолок стоимости, дедлайн и идемпотентность; ответ возвращает фактическую цену и ошибку предсказания (`cost_asym`).
2. **Офлайн-делегация прав (Macaroon Capabilities)**: один Ed25519 на корневой грант (кэшируется) + цепочка сужающих `HMAC-SHA256-128` звеньев за микросекунды без походов в auth-сервер.
3. **Кооперативная и асимметричная защита от перегрузки**: клиент сам ведёт бюджет по подписанным квитанциям (`h4-rl`), использует одноразовые крипто-пропуска без сжигания батареи (`h4-pass`), либо платит вычислительным Proof-of-Effort (`SHA-256` или кэш-тяжёлый 4 KB `MemHard`), ускоренным нативным **C11 Node-API движком**.

---

## Быстрый старт (0 внешних npm-зависимостей, Node.js ≥ 20)

```bash
npm run build:native   # сборка C11 N-API ускорителя (автоматически с pure-JS fallback)
npm test               # 62 инварианта спеки + 15 киберсекьюрити red-team & fuzz тестов
npm run test:san       # прогон C11 ядра под AddressSanitizer + UndefinedBehaviorSanitizer
npm run example        # live multi-agent mesh: делегация + стриминг + F.CANCEL
npm run scenario       # 7 сценариев поверх реального TLS 1.3 (ALPN h4)
npm run bench          # честные бенчмарки на текущем железе
npm run attack         # симуляция L7 DDoS (20,000 запросов за общим CGNAT)
```

---

## Интеграция за 5 минут

### 1. Клиентский SDK (`fetch`-совместимый + 1-строчная делегация суб-агентам)

```js
import { createH4Fetch, AgentSession, CAPS } from 'http4';

const h4Fetch = createH4Fetch({
  maxEffortBits: 20, // защита клиента от злонамеренно сложного PoE
});

const orchestrator = new AgentSession({ token: rootGrant, h4Fetch, budget: 100 });

// Офлайн-делегация за ~2 µs без обращения к серверу авторизации:
const researcher = orchestrator.delegate({
  caps: CAPS.READ,
  scope: '/v1/docs',
  budget: 25,
  delegable: false,
});

const res = await researcher.fetch('h4://api.example.com:8443/v1/docs/spec');
console.log(await res.json(), 'cost=', res.h4.result.costActual);

// Живой стриминг токенов с мгновенной отменой генерации на сервере (`F.CANCEL`):
const ac = new AbortController();
for await (const chunk of orchestrator.stream('h4://api.example.com:8443/v1/llm/stream', { signal: ac.signal })) {
  process.stdout.write(chunk);
  if (doneReading) ac.abort(); // останавливает LLM на сервере и возвращает неизрасходованный бюджет
}
```

### 2. Универсальные адаптеры (Cloudflare Workers / Bun / Next.js / Hono / Express)

```js
import { H4Server, toWebHandler, toNodeMiddleware } from 'http4';

const h4 = new H4Server({
  routes: {
    'GET /v1/items': async () => ({ status: 200, body: { items: [1, 2, 3] }, cost: 1, ttlMs: 5000 }),
    'SUB /v1/stream': async function* ({ signal }) {
      for (let i = 0; i < 10 && !signal?.aborted; i++) yield { token: i };
    },
  },
});

// Edge / WinterCG (Cloudflare Workers, Bun, Deno, Next.js App Router):
export default { fetch: toWebHandler(h4) };

// Node.js / Express / Connect / Fastify middleware:
// app.use(toNodeMiddleware(h4, { altSvc: 'h4=":8443"; ma=86400' }));
```

---

## Архитектура репозитория

| Файл | Назначение |
|---|---|
| `native/h4_core.c`, `native/h4_napi.c` | Нативное C11 / Node-API v8 ядро (`SHA-256 PoE`, 4 KB `MemHard`, `HMAC`, цепочки capability, сканер кадров) |
| `native/test_san.c` | Автономный C11 тест + 100,000 итераций фаззинга под `ASan + UBSan` |
| `src/native.js` | Автоматический загрузчик C11 аддона с прозрачным pure-JS fallback (`H4_PURE_JS=1`) |
| `src/varint.js`, `src/headers.js`, `src/frames.js` | QUIC-varint (62 бита + zigzag), статический словарь заголовков с защитой от CRLF/NUL, 14 типов кадров |
| `src/identity.js` | Macaroon capability-токены с доменным разделением, офлайн-сужением и O(1) отзывом (`revokeGrant`) |
| `src/limits.js`, `src/privacy-pass.js` | Кооперативные квитанции, одноразовые пропуска `h4-pass` (0% CPU клиента), `SHA-256` и `MemHard` PoE |
| `src/cache.js`, `src/server.js`, `src/client.js` | Tenant-изолированный LRU, singleflight coalescing, 0-RTT защита (`425`), `handleStream` + возврат бюджета |
| `src/wire.js` | Мультиплексированный TLS 1.3 транспорт (`ALPN h4`, защита от ALPACA, Slowloris и Rapid-Reset, `F.CANCEL`) |
| `src/gateway.js`, `src/h3-compat.js` | HTTP/1.1 & HTTP/2 ↔ H4 edge-гейтвей (включая SSE) + RFC 9114 GREASE-safe HTTP/3 extension кадры (`0x42..0x4d`) |
| `src/sdk.js`, `src/adapters.js`, `types/index.d.ts` | Web `fetch` SDK (`Alt-Svc` авто-апгрейд), `AgentSession`, адаптеры для Web/Node фреймворков и полные TypeScript типы |
| `SECURITY.md`, `test/security-audit.js` | Формальная модель угроз, вынесенные инфраструктурные границы и red-team / differential-fuzz набор |

---

## Ключевые измеренные показатели (2 vCPU Xeon · Node v22 · C11 N-API)

Все цифры воспроизводятся локально командой `npm run bench`:

| Показатель | Результат |
|---|---|
| Простой `GET` / агентский вызов на проводе | **12 B** (6.0× меньше HTTP/1.1) / **48 B** (4.2× меньше HTTP/1.1) |
| Парсинг полного бинарного запроса (79 B) | **667 ns** (`1.50 M ops/s`) |
| Обслужить запрос (sync cache path) | **17.6 µs** (`56,900 req/s` на 1 ядро) |
| Отклонить атакующий запрос | **7.3 µs** (`2.4×` дешевле обслуживания) |
| Скорость решения PoE (`C11 N-API` vs `Pure JS`) | **2.99 M hashes/s** vs `0.49 M hashes/s` (**6.1× быстрее**) |
| Проверка PoE защитником (`SHA-256` / `4 KB MemHard`) | **380 ns** (`2.63 M/s`) / **2.94 µs** (`340 k/s`) — O(1) при любой сложности |
| L7 DDoS за общим CGNAT (`20,000` запросов) | Честные агенты: **12.0% → 100.0%**, атакующие: **12.0% → 2.3%** |

---

## Лицензия

Код — MIT (`LICENSE`), спецификация — CC BY 4.0 (`LICENSE-spec`). SPDX: `CC-BY-4.0 OR MIT`.
