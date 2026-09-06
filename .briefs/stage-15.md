# Бриф stage-15-client (WP-15 — Client config generator)

## Контекст
Читай первым: `SPEC.md` §WP-15, затем `cmd/sentinel/cli.go` (dispatch/register/exit codes), `examples/` (текущие `claude_desktop_config.json`, `cursor_mcp.json`). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s15`.

## Задача (все Acceptance criteria WP-15)
- `sentinel client add claude|cursor|vscode|windsurf --name NAME --profile P -- <cmd...>`: находит config клиента по OS, вставляет `mcpServers` entry с абсолютным путём к running `sentinel` binary, корректный escaping, placeholder env mapping.
- `--dry-run` печатает JSON. `--print-only` никогда не трогает файлы. Перед записью — backup оригинала рядом.
- `sentinel client ls`: detected clients + Sentinel-managed entries в каждом.
- Перегенерировать `examples/claude_desktop_config.json` и `examples/cursor_mcp.json` из того же кода (не дрейфуют).
- Тесты: per client per OS с fake home; exact JSON; Windows paths escape + round-trip `json.Unmarshal`; существующие чужие `mcpServers` entries preserved; re-run idempotent (no dup); committed `examples/*.json` == generator output (drift test).
- Регистрация: команды `client` (одна register-строка + сабдиспатч внутри `client.go` на add/ls, как у `mcp` команды если она так устроена — посмотри `cmdMCP` как образец стиля).

## Границы
МОЖНО: новый `cmd/sentinel/client.go` + `client_test.go`, ОДНА register-строка в `main.go`, `examples/*.json` (регенерация).
НЕЛЬЗЯ: всё остальное `cmd/sentinel/`, `internal/...`, `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./cmd/sentinel/...` зелёные; `go vet ./cmd/sentinel/`. Коммит в `stage-15-client`. Финальный отчёт: файлы, риски.
