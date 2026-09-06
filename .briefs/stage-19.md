# Бриф stage-19-mcp (WP-19 — MCP protocol conformance)

## Контекст
Читай первым: `SPEC.md` §WP-19 (~656-678), затем `internal/mcp/` целиком (framing, scrubbing ключей, inbound checks, stderr чайлда, exit codes, EOF/pipe handling). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s19`.

## Задача (все Acceptance criteria WP-19)
- Framing: детектить framing пира ОДИН раз, отвечать В ТОМ ЖЕ framing. `Content-Length` полностью, `io.ReadFull` ошибки honoured, max frame size enforced, malformed headers rejected (не fall through в line mode).
- Scrub по JSON **shape**, не hardcoded key list: walk всех string leaves, configurable skip list для полей где redaction ломает протокол (`jsonrpc`, `id`, `method`, `uri`, schema fields). Skip list задокументировать.
- Inbound checks расширить на `resources/read`, `prompts/get`, `completion/complete`. Репортить ВСЕ findings, не только первый.
- Child `stderr`: захватывать, прогонять через тот же scrub pipeline, потом forward. Никогда raw.
- Прокидывать exit code чайлда; при крэше — JSON-RPC error клиенту перед выходом.
- EOF/broken pipe в обе стороны без deadlock; context для детерминированного shutdown.
- Никакого unbounded buffering: cap + error.
- Тесты: Content-Length клиент ⇒ Content-Length ответы; truncated body ⇒ named error без hang/partial forward; секрет в поле `output` (вне старого key list) scrubbed; секрет в child stderr scrubbed до терминала; child exit 7 ⇒ sentinel exit 7; child killed mid-request ⇒ JSON-RPC error с правильным id; 10 MiB frame ⇒ rejected; fuzz target для `readFrame` (запуск в CI 30s — добавить в workflow ТОЛЬКО fuzz-строчку аддитивно, весь workflow не переписывать).

## Границы
МОЖНО: `internal/mcp/` (+ тесты), `.github/workflows/ci.yml` — ТОЛЬКО добавить fuzz-шаг (аддитивно, одна строчка-секция).
НЕЛЬЗЯ: `internal/scrubber/` (только вызовы существующего API; если нужен новый API scrubber'а — НЕ добавлять, реализуй обход внутри mcp), `internal/vault/`, `internal/egress/`, `cmd/...`, README, `SPEC.md`. Публичные сигнатуры `internal/mcp`, используемые `cmd/sentinel` (`cmdMCPServe` и др.), НЕ менять. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/mcp/... ./internal/...` зелёные (старые тесты не ломать); `go vet` по `internal/mcp/`; `go test -fuzz=FuzzReadFrame -fuzztime=10s ./internal/mcp/` локально 10s проходит. Коммит в `stage-19-mcp`. Финальный отчёт: файлы, риски.
