# Бриф stage-11-bindmode (WP-11 — Bind enforcement in inject mode)

## Контекст
Читай первым: `SPEC.md` §WP-11, затем `internal/mcp/` (inject path + интеграция с broker из WP-10: `internal/broker/` Request/Decision), `internal/policy/` (секция hosts/bindings), `internal/vault/` (Secret.Hosts). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s11`.

## Задача (все Acceptance criteria WP-11)
- Секрет с `hosts: [api.github.com]` инжектится в child ТОЛЬКО если child declared to talk to that host. Источник declaration по порядку: `--dest` флаг `mcp run`, profile's `hosts` в policy, иначе **deny**.
- `mode: broker` — третий MCP mode: placeholder остаётся в child env, child резолвит через loopback endpoint с broker per call. Лучше чем `inject`; documented default once works, `inject` за explicit flag.
- Каждая инъекция — audit `(secret, child argv0, declared dests)`.
- Тесты: host-bound secret без declared dest ⇒ refused named error; matching declared dest ⇒ allowed; wildcard `*` требует `--allow-unbound` + warns; `mode: broker` end-to-end против stub MCP server в `testdata`; `_ = mode` и подобные discard statements gone из `internal/mcp/gateway.go`.
- Сигнатуры broker API НЕ менять; `cmd/sentinel/mcp*.go` — только новые флаги (`--dest`, `--allow-unbound`, `--mode`).

## Границы
МОЖНО: `internal/mcp/` (+ тесты, + testdata), `cmd/sentinel/mcp*.go` (только флаги), `internal/policy/` (только чтение hosts/profile — struct НЕ менять).
НЕЛЬЗЯ: `internal/broker/`, `internal/vault/`, `internal/egress/`, `internal/audit/`, `cmd/sentinel/main.go`, `cmd/sentinel/cli.go`, `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/mcp/... ./internal/broker/... ./cmd/sentinel/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-11-bindmode`. Финальный отчёт: файлы, риски.
