# Sentinel: план исполнения для кодинг-агентов

Дата: 2026-09-06. Основание: [SPEC.md](SPEC.md).
Repo: https://github.com/Ferrum-Sidereum/sentinel
Baseline: `c0796140ca4cfa22381319153b337b028e625e83`.

## Как работать

Не реализовывать весь SPEC одним PR. Один агент-интегратор владеет контрактами, схемой БД и merge order. Рабочие агенты делают небольшие вертикальные PR в отдельных ветках; security reviewer проверяет ключи, миграции и все пути выдачи независимо от автора.

Требования SPEC являются целевым поведением, а не доказательством работоспособности текущего кода. Перед стартом каждого PR сверить HEAD и прочитать актуальные затрагиваемые файлы. Не загружать реальные токены, пользовательский vault или CA в тесты и отчёты.

Порядок: baseline -> безопасный core -> общие policy/scanner -> gateway hardening -> permissions/runtime -> UX/integrations -> distribution. P2-фичи не оправдывают пропуск P0.

## Этап 0. Baseline и контракты

### T00: воспроизводимость и карта системы [P0]

Владелец: интегратор + QA. Зависимости: нет.

- Сверить исследованный commit с HEAD; прочитать llm, audit, scrubber, placeholder, frontend и workflows.
- Проверить pinned Go/Wails/dependencies; записать build/test results и platform limitations в `docs/baseline.md`.
- Прогнать доступные проверки SPEC; blocker не обходить слепым понижением go directive.
- Зафиксировать команды, safe GUI DTO, placeholder formats и существующие тесты.
- Добавить test-only temp data dir и injectable credential backend.

Выход: baseline report, минимальный test harness, список реальных блокеров. Gate: другой агент может воспроизвести результат; нет выдуманных PASS.

### T01: contracts-first [P0]

Владелец: интегратор. После T00.

- Зафиксировать common service, ошибки, secret metadata, policy decision, schema revisions и migration plan.
- Согласовать CAS/version updates, key identity и cross-process locking.
- Определить публичные DTO CLI/GUI, сохранив safe boundaries.
- Оставить shared CLI dispatch points одному владельцу.

Выход: `docs/architecture.md`, skeleton interfaces/tests без mock-success production paths. Gate: ревью API и migration state machine.

## Этап 1. Безопасный core

### T02: key lifecycle [P0]

Владелец: Core agent. После T01. Область: keyring, service, CLI/GUI storage adapters.

Реализовать LoadExisting/CreateNew, error taxonomy, запрет нового plaintext fallback и idempotent init. Переиспользовать хорошие GUI checks, не ослаблять их.

Gate: A01-A02, crash-safe fresh initialization; существующий ключ не заменяется из-за lookup error. Независимое security review.

### T03: vault schema + явная legacy migration [P0]

Владелец: Core agent. После T02.

Реализовать schema version, preview/apply migration, name conflicts, consistent backup, transaction/CAS, timestamps/expiry/disabled, rekey recovery journal без значений. Тестировать WAL и concurrent CLI/GUI.

Gate: A03-A05. Dry-run не меняет файлы; injected crashes не уничтожают recovery path; cleanup старого passphrase отдельный.

### T04: CLI/GUI общий service и safe input [P0]

Владелец: Interface agent. После T03.

Перевести CLI и GUI на общий service, canonical naming и bindings. Сохранить `created_at` при rotate. Добавить hidden TTY input, `--from-env`, `--from-file`, `--stdin` и testable command runner. Не добавлять GUI plaintext-read/export bridge.

Gate: A05 и malformed flags/empty/oversize/concurrent-update tests. DTO только metadata.

## Этап 2. Правила и безопасное сканирование

### T05: policy engine и policy test [P0]

Владелец: Policy agent. Зависимости: T01, затем T04 для integration.

Реализовать Parse/Validate/Evaluate, policy version migration, immutable reload и capability matrix. Добавить dry-run fixtures с dummy metadata. Unsupported security fields не игнорировать.

Gate: A09-A10, race tests policy reload; без network/decrypt в policy test.

### T06: scanner/CI [P1, unsafe output fix P0]

Владелец: Scanner agent. Зависимости: T01, integration после T04.

Реализовать safe output, exit codes, vault required/off, custom pattern parity, UTF-8 coordinates, bounded traversal и ignore rules. JSON сначала, SARIF/action после stable contract. Не переписывать детекторы без необходимости.

Gate: A11-A13, canary и large-input tests. Clean report не возникает после пропущенной decrypt/I/O error.

## Этап 3. Gateway hardening

### T07: egress enforcement [P0]

Владелец: Gateway agent. После T04-T05.

Typed injection locations, HTTPS-only injection, exact authority/port, URL/body deny, path/method/header rules, transport без proxy loop, корректный CONNECT/response processing, bounded I/O и timeouts.

Gate: A06-A10. Local TLS fixtures доказывают отсутствие canary на forbidden upstream. Отдельное ревью protocol parsing, normalization и redirects.

### T08: MCP correctness и sanitization [P0]

Владелец: MCP agent. После T04-T05; параллельно T07 при раздельных файлах.

Strict mode/reference errors, IDs/notifications, single writer, framing limits, safe stderr/structured content, process lifecycle. Общие policy/expiry invariants для llm и HTTP adapters.

Gate: A14-A16, canary boundary tests, fuzz parser. Не называть простое скрытие stderr полноценной sanitization.

## Этап 4. Управление сессиями и разрешениями

### T09: runtime supervisor + doctor/status [P1]

Владелец: Runtime agent. После T04; integration с T07-T08.

Bound ephemeral ports, private runtime registry, health identity, lifecycle, read-only diagnostics и structured status. Проверить current serve/run/llm-serve до изменения поведения.

Gate: A21-A22. Concurrent processes живут параллельно, stale PID не false-green. Doctor не создаёт ключи и CA.

### T10: approval broker и grants [P1]

Владелец: Permissions agent. После T05, T07-T09.

Protected local IPC, identity/session model, single-use/15m grants, TTL/revoke/version invalidation, headless deny и typed CLI commands. Egress attribution не строится на agent-name header.

Gate: A17-A20. Competitive single-use test; inject честно сообщает, что уже выданный секрет нельзя отозвать. Reviewer проверяет IPC ACL и TOCTOU.

### T11: structured audit + follow [P1]

Владелец: Observability agent. Схема после T01; integration после T07-T10.

Расширить существующий logger/cmdAudit: event schema, durable event перед выдачей, cross-process serialization, filters/follow/retention, redacted destination. Audit failure не разрешает выдачу.

Gate: A24 и canary absence. Journal не смешивает строки, follow переживает rotation.

## Этап 5. UX и клиентские подключения

### T12: config generator [P1]

Владелец: Integrations agent. После T09-T10.

Templates/diff/write по реальным схемам Claude/Cursor/VS Code. Тестировать invalid JSON, unknown fields, collisions, absolute paths, Windows escaping, backup/recovery. Не скачивать MCP packages.

Gate: A23, dummy local MCP round-trip каждого заявленного клиента либо явно отмеченный unsupported.

### T13: desktop flow [P1]

Владелец: UX agent. После T04, T06, T09-T12.

Onboarding, host/header/expiry forms, honest runtime state, approval modal, policy test results и activity filters. Typed bindings, write-only secret value, policy revision protection.

Gate: A05, A13, A19, A22-A25. Keyboard-only smoke-test, no false-green, no reveal endpoint.

## Этап 6. Поставка и необязательные улучшения

### T14: regression/security gate + docs [P0 для релиза]

Владелец: QA + независимый reviewer. После T02-T13.

Прогнать A01-A25, Go tests/vet/race, frontend checks, GUI native tests, fuzz smoke-tests. Синхронизировать README EN/RU, recovery, capability matrix и exit codes. Diff проверяется на secrets и незаявленные permissions.

Gate: PASS/FAIL/BLOCKED report с командами и окружением. Любой P0 fail блокирует релиз.

### T15: binaries и packaging [P2]

Владелец: Release agent. После T14.

Артефакты для фактически проверенных платформ, checksums/SBOM/provenance, signing при наличии полномочий, затем brew/scoop. Установка на чистом окружении, doctor и dummy flow.

### T16: дополнительные UX/observability [P2]

Владелец: UX/Observability agents. После T13-T14.

Tray на поддержанных платформах, hash-chain + verify с честными ограничениями, metadata last-use и фильтры. Не включать plaintext history, permanent grants, cloud sync или auto-provider rotation без amendment.

## Параллельность и merge order

```text
T00 -> T01 -> T02 -> T03 -> T04
         |                  |
         +-> T05 -----------+-> T07 ----+
         +-> T06            +-> T08 ----+-> T09 -> T10
                                                   |
                                      T11 <--------+
                                      T12 <--------+
                        T06 + T11 + T12 -> T13 -> T14 -> T15/T16
```

Диаграмма упрощённая: текстовые зависимости имеют приоритет. T05/T06 могут писать unit tests параллельно core, но integration merge после T04. T09 завершается после T07/T08. Audit schema проектируется рано, enforcement закрывается до релиза.

Единственный интегратор изменяет shared contracts/schema и конфликтующие CLI dispatch points. Не разрешать нескольким агентам создавать несовместимые migration numbers, DTO или Policy structs. Каждый PR ребейзится на согласованную основу, без force-push общей ветки.

## Универсальное задание рабочему агенту

```text
Работай в Ferrum-Sidereum/sentinel. Прочитай SPEC.md и PLAN.md.
Твоя задача: <T-ID>. Реализуй только её и необходимые regression tests.

1. Сверь HEAD, прочитай затрагиваемый код, tests и contracts.
2. Проверь prerequisites. Если контракт/dependency не готов, обозначь BLOCKED;
   не реализуй фиктивный success.
3. До кода выпиши S/A IDs, файлы, риски и тест-план.
4. Используй temp data dir, fake keychain и dummy credentials. Не обращайся
   к пользовательским vault/keychain/CA и реальным аккаунтам.
5. Сначала regression test, затем минимальное изменение. Не ослабляй проверки
   ради passing build и не снижай toolchain без подтверждённой причины.
6. Не добавляй cloud telemetry, secret logging, reveal/export endpoints,
   глобальный CA trust, broad grants или destructive auto-migration.
7. Запусти проверки. Незапущенные пометь BLOCKED с причиной.
8. Обнови docs. Подготовь отдельный PR, не публикуй релиз.

Финальный отчёт: T-ID и S/A IDs; изменения и совместимость; точные команды
и PASS/FAIL/BLOCKED; migration/rollback impact; остаточные риски и review items.
```

## Задание агенту-интегратору

Пройди T00/T01 первым. Затем назначай готовые задачи по зависимостям и веди `docs/implementation-status.md` со статусами pending/in_progress/review/blocked/done и ссылками на PR. Не помечай done до прохождения gates. Перед merge проверяй отсутствие пересекающихся schema/contracts изменений. Публикация, удаление recovery material и изменение внешних аккаунтов требуют отдельного решения владельца.
