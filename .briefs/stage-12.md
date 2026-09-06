# Бриф stage-12-profiles (WP-12 — Profiles, for real)

## Контекст
Читай первым: `SPEC.md` §WP-12 (yaml-схема profiles выше), затем `internal/policy/` (текущая Policy struct, entity `mcp:deny:<tool>` hack — найти через grep), `internal/mcp/` (где entity keys consulted + `writeErr` с `null` id). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s12`.

## Задача (все Acceptance criteria WP-12)
- First-class schema (обратно совместимо, entity hack остаётся как deprecated с warning):
```yaml
profiles:
  dev: {secrets: [...], hosts: [...], deny_tools: [...], allow_tools: [], scrub_to_llm: ..., approvals: ask}
  ci: {secrets: [], approvals: deny}
```
- `--profile NAME` выбирает; unknown ⇒ exit 2. Без профиля — built-in `default` (denies nothing, auto-approves nothing).
- `allow_tools` non-empty = allowlist mode: всё остальное denied.
- Blocking покрывает `tools/call`, `resources/read`, `prompts/get`.
- Тесты: tool denied в profile `a` allowed в profile `b` (same policy file); allowlist denies unlisted; unknown profile ⇒ exit 2; `mcp:deny:*` больше не consulted + migration warning если найдены; denials — well-formed JSON-RPC error с **request's own id**, не `null`.
- Флаги только в `cmd/sentinel/mcp*.go` (`--profile`).

## Границы
МОЖНО: `internal/policy/` (только `profiles:` секция struct+parse+тесты), `internal/mcp/` (profile enforcement + writeErr id fix + тесты), `cmd/sentinel/mcp*.go` (только `--profile` флаг).
НЕЛЬЗЯ: `internal/broker/`, `internal/vault/`, `internal/egress/`, `internal/audit/`, `cmd/sentinel/main.go`, `cmd/sentinel/cli.go`, `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/mcp/... ./internal/policy/... ./internal/broker/... ./cmd/sentinel/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-12-profiles`. Финальный отчёт: файлы, риски.
