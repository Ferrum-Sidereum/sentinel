# Бриф stage-14-doctor (WP-14 — `doctor`)

## Контекст
Читай первым: `SPEC.md` §WP-14, затем `cmd/sentinel/cli.go` (dispatch/register/`command` struct/exit codes/`emitJSON`), `cmd/sentinel/main.go` (только register-блок, его НЕ трогать кроме одной строки), README Troubleshooting table. Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s14`.

## Задача (все Acceptance criteria WP-14)
- Новый `cmd/sentinel/doctor.go`, команда `sentinel doctor`. Каждый check: `ok`/`warn`/`fail` + one-line explanation + copy-pasteable fix.
- Checks: binary на `PATH`; data dir exists + permissions; keychain reachable; key source и match vault (verifier probe); vault opens + record count; policy parses + unknown keys; CA present/not expired/platform trust; дефолтные порты free или owned нашими run files (WP-09 run files может ещё не быть — если `~/.sentinel/run/*.json` отсутствует, репортить `warn` "runtime status unavailable", НЕ `fail`); Go toolchain version если source tree present; MCP client configs на диске + absolute paths exist; clock skew.
- Каждая строка README Troubleshooting table ⇒ named check. Маппинг assert'ить в тесте таблицей shared с docs (таблица в коде + тест).
- Каждый check: passing + failing fixture в тестах.
- `--json` output; exit 0 когда нет `fail`, 1 иначе.
- Без vault — говорит что делать (`sentinel init`), не erroring.
- Регистрация: ОДНА строка `command{"doctor", ...}` в register-блоке `main.go`, больше ничего в `main.go` не трогать.

## Границы
МОЖНО: новый `cmd/sentinel/doctor.go` + `doctor_test.go`, ОДНА register-строка в `main.go`.
НЕЛЬЗЯ: всё остальное `cmd/sentinel/`, `internal/...` (только вызовы существующих API), `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./cmd/sentinel/...` зелёные; `go vet ./cmd/sentinel/`. Коммит в `stage-14-doctor`. Финальный отчёт: файлы, риски.
