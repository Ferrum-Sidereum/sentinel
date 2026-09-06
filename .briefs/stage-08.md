# Бриф stage-08-cli (WP-08 — Honest CLI surface)

## Контекст
Читай первым: `SPEC.md` §WP-08 (~364-382), затем `cmd/sentinel/main.go` целиком (текущий hand-rolled switch + ручные arg-циклы). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s08`.

## Задача (все Acceptance criteria WP-08)
- Заменить hand-rolled `switch` + ручные arg-циклы на per-command `flag.FlagSet`.
- `sentinel help`, `sentinel <cmd> --help`, голый вызов — перечисляют ВСЕ команды с one-line описаниями.
- `sentinel version`: version, commit, build date, Go version через `-ldflags`.
- Глобальные флаги: `--data-dir` (перекрывает `~/.sentinel`, также `SENTINEL_DATA_DIR`), `--json`, `--quiet`, `--no-color`.
- Exit codes: `0` ok, `1` runtime error, `2` usage error, `3` policy violation/blocked, `4` locked/approval denied. Привести существующие команды к этой схеме.
- `--json` на `ls`, `scan`, `audit`, `status`, `doctor` (команд `status`/`doctor` может ещё не быть — сделай флаг инфраструктурно + на существующих; отсутствующие команды НЕ создавай, только не мешай им).
- НЕ менять поведение команд (scan/show-values логика WP-03, openStore/keyring WP-01 — не трогать внутренности, только вызовы).
- Тесты: каждая команда dispatch-таблицы есть в `help` (тест итерирует таблицу — новая команда без help роняет CI); unknown flag ⇒ exit 2 с именем флага; `--bind` последним без значения ⇒ exit 2 без паники; `--data-dir` полностью изолирует state (тест без `$HOME`); `--json` парсится, shape стабилен и задокументирован (комментарий в коде).

## Границы
МОЖНО: `cmd/sentinel/` целиком (+ тесты). `internal/` НЕ трогать вообще (только вызовы существующих API).
НЕЛЬЗЯ: `internal/...`, `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. Новые команды НЕ добавлять (только help/version/флаги/коды). НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./cmd/sentinel/... ./internal/...` зелёные; `go vet` по `cmd/sentinel/`. Коммит в `stage-08-cli`. Финальный отчёт: файлы, риски.
