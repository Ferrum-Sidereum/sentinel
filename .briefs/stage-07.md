# Бриф stage-07-core (WP-07 — Unify CLI and GUI on one core)

## Контекст
Читай первым: `SPEC.md` §WP-07, затем `cmd/sentinel/cli.go` + `main.go` (dispatch/register, `openStore`, `cmdAdd` с `--bind/--header/--kind/--expires`), `cmd/sentinel-gui/storage.go` (`loadMasterKey`), `internal/keyring/` (`Load`/`Create`), `internal/vault/` (Store API: Put/Get/List/Delete/Rotate/Rollback/Touch), `internal/policy/` (yaml.Node comment-preserving write). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s07`.

## Задача (все Acceptance criteria WP-07)
- Новый `internal/core`: ЕДИНСТВЕННЫЙ API для open/init/add/list/get/rotate/remove/scan/policy-write. `cmd/sentinel` и `cmd/sentinel-gui` — тонкие адаптеры поверх него.
- Удалить `loadMasterKey` из `cmd/sentinel-gui/storage.go`; GUI зовёт `keyring.Load`/`Create`.
- Единая canonical name normalisation (`lower`, `-`/space ⇒ `_`, validate `^[a-z0-9_]{1,64}$`) — используют CLI, GUI, `env import`. Invalid names — ясная ошибка, НЕ silent rewrite.
- GUI secret creation получает те же required binding metadata что CLI (`hosts`, опционально `paths`/`methods`/`inject_hdr`). GUI-созданный секрет обязан резолвиться proxy.
- Policy writing: comment-preserving `yaml.Node` подход расширить на ВЕСЬ `Policy` struct, не три поля. Round-trip тест: unknown top-level key от future version переживает edit.
- CLI-адаптация: переведи `cmd/sentinel` команды на `core` (аддитивно, поведение и флаги НЕ менять, exit codes НЕ менять). GUI должен собираться (`go vet ./cmd/sentinel-gui/`; полный GUI build невозможен без frontend/dist — предсуществующая проблема, достаточно `go vet` + `go test`).
- Тесты: secret через `core` API GUI-адаптера резолвится egress proxy для bound host; normalisation идентична во всех трёх точках (table-driven, shared fixture); policy edit сохраняет comments+unrelated keys incl. nested `hosts:` и unknown key; `rg -n "sentinel-master"` — одно определение; README bullets "Desktop and CLI are not yet interchangeable" + "use the CLI throughout" удалены (только эти строки).
- ВАЖНО: `internal/core` — новый пакет, коллизий с другими агентами нет. `cmd/sentinel-gui/` правишь ТОЛЬКО ты (storage.go + адаптер). `cmd/sentinel/*.go` — только замена внутренностей вызовов на core, сигнатуры `cmdXxx(args) int` и register НЕ трогать.

## Границы
МОЖНО: новый `internal/core/` (+ тесты), `cmd/sentinel-gui/*.go` (кроме frontend/), `cmd/sentinel/*.go` (только внутренности → core), оба README (только указанные строки).
НЕЛЬЗЯ: `internal/vault/`, `internal/keyring/`, `internal/policy/` (только вызовы; Node-writer для whole-struct — внутри core, не в policy), `internal/mcp/`, `internal/egress/`, `internal/audit/`, `internal/scrubber/`, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/core/... ./cmd/sentinel/...` зелёные; `go vet ./cmd/sentinel-gui/` чисто; старые тесты не ломать. Коммит в `stage-07-core`. Финальный отчёт: файлы, риски.
