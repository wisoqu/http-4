# Как участвовать / Contributing

Правило одно: **каждое утверждение в спеке должно быть либо доказано тестом,
либо измерено бенчмарком.**

## Что считается хорошим патчем

- Новый инвариант в `test/run.js` или `test/security-audit.js` с номером раздела спеки.
  Приложите вывод, где тест **падает** на старом коде (зелёный тест, который
  никогда не падал, — это баг, а не покрытие).
- Измерение в `bench/bench.js` с указанием CPU, ОС и версии Node.js.
- Изменения в C11 ядре (`native/`) обязаны компилироваться без единого предупреждения
  (`-Wall -Wextra -Werror`) и проходить `AddressSanitizer + UndefinedBehaviorSanitizer`
  и дифференциальный фаззинг `C11 ↔ JS`.

## Перед отправкой PR

```bash
npm run build:native
npm run test:san
npm test
npm run test:purejs
npm run bench -- quick
npm run scenario
```
