# Бриф stage-17-audit (WP-17 — Tamper-evident audit + live tail)

## Контекст
Читай первым: `SPEC.md` §WP-17, затем `internal/audit/` целиком (Logger, Log, Open, формат записей), `cmd/sentinel/` — audit-команда, `internal/policy/` (поле `policy.audit.retention`). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s17`.

## Задача (все Acceptance criteria WP-17)
- Каждая запись: `seq`, `ts` (RFC3339 UTC), `prev_hash`, `hash = sha256(canonical(record без hash) || prev_hash)`. Genesis record с нулевым `prev_hash`.
- `sentinel audit verify`: идёт по цепочке, репортит первый разрыв с sequence number.
- `sentinel audit tail -f`: стрим новых записей; `--since 1h`, `--type approval_denied`, `--secret NAME`, `--json`.
- Rotation по `policy.audit.retention` + size-based второй триггер. Rotation НЕ рвёт chain: `prev_hash` carry в header нового файла.
- Fsync policy: durable write для security-relevant (`approval_*`, `secret_*`), buffered для остальных.
- Audit payloads — только фиксированный набор typed fields, не arbitrary `any`: попытка залогировать value matching stored secret — rejected/redacted by construction (тест).
- Существующие вызовы `l.Log("", "event", map[string]any{...})` по репо — сигнатуру `Log` НЕ менять (расширение только внутри пакета + формат записи).
- Тесты: verify pass на сгенерированном логе, fail на byte-flipped с именем записи; rotation continuity across files; `tail -f` видит запись другого процесса за 200ms; retention prunes by age+size; value-like payload rejected/redacted.

## Границы
МОЖНО: `internal/audit/` (+ тесты), `cmd/sentinel/` audit-файлы (`audit*.go`: verify/tail флаги — существующую команду расширять, не переписывать), ОДНА register-строка если нужна новая субкоманда (предпочтительно субфлаги `audit verify|tail` внутри существующей команды).
НЕЛЬЗЯ: остальные `cmd/sentinel/`, `internal/policy/` (только чтение retention), `internal/vault/`, `internal/scrubber/`, `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/audit/... ./cmd/sentinel/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-17-audit`. Финальный отчёт: файлы, риски.
