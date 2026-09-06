# Бриф stage-09-ports (WP-09 — Port management and `status`)

## Контекст
Читай первым: `SPEC.md` §WP-09, затем `cmd/sentinel/` — файлы serve/mcp/llm-serve команд, `cmd/sentinel/cli.go` (dispatch, register, dataDir, globals), `internal/audit/`. Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s09`.

## Задача (все Acceptance criteria WP-09)
- Дефолтные порты разные и задокументированы: egress `18449`, MCP HTTP `18450`, LLM gateway `18451`. Все переопределяются флагом `--port` и env (`SENTINEL_EGRESS_PORT`, `SENTINEL_MCP_PORT`, `SENTINEL_LLM_PORT` — имена выбери, задокументируй в help).
- `--port 0` выбирает свободный порт и печатает выбранный адрес.
- При bind failure: какой порт, какой процесс там ожидается, suggest `--port`.
- `~/.sentinel/run/<service>.json` (`{pid, addr, service, started_at, version}`) на старте; удалять при чистом shutdown; stale-файлы детектить по pid и чистить.
- Новый `sentinel status`: какие gateways up, адреса, vault path, key source (keychain/passphrase), policy mtime, secret count, expired count. Значений НЕ печатать. Поддержать `--json` (инфраструктура `emitJSON` уже есть в cli.go).
- Graceful shutdown SIGINT/SIGTERM: stop listeners, flush audit, zero keys. Заменить голый `select {}` в `cmdMCPServe`.
- Зарегистрировать `status` в dispatch-таблице `cmd/sentinel/main.go` (аддитивно: одна строка `command{...}` + новый файл `status.go`; существующие регистрации НЕ трогать).
- Удалить из README note про `mcp serve`/`llm-serve` port-collision (только эту note).
- Тесты: два gateway одновременно с дефолтами не коллайдят; `--port 0` печатает parseable адрес принимающий соединение; stale run file с мёртвым pid чистится; SIGTERM ⇒ exit 0, run file удалён, audit заканчивается полной JSON-строкой.

## Границы
МОЖНО: новый `internal/runtime/` (+ тесты), `cmd/sentinel/serve*.go`, `cmd/sentinel/mcp*.go`, `cmd/sentinel/llm*.go`, новый `cmd/sentinel/status.go`, ОДНА строка register в `main.go`, README (только port-collision note).
НЕЛЬЗЯ: `internal/vault/`, `internal/keyring/`, `internal/mcp/`, `internal/scrubber/`, `internal/audit/`, `cmd/sentinel/main.go` (кроме register-строки), `cmd/sentinel/cli.go`, `cmd/sentinel/scan*`, `cmd/sentinel-gui/`, `.github/`, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/runtime/... ./cmd/sentinel/...` зелёные, старые тесты не ломать; `go vet` по тронутым пакетам. Коммит в `stage-09-ports`. Финальный отчёт: файлы, риски.
