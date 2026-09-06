# Бриф stage-18-policy (WP-18 — `policy test`)

## Контекст
Читай первым: `SPEC.md` §WP-18, затем `internal/policy/` целиком (Policy struct, Load, yaml.Node comment-preserving write), `cmd/sentinel/` — policy-команда если есть (иначе cli.go register-стиль). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s18`.

## Задача (все Acceptance criteria WP-18)
- `sentinel policy lint`: schema validation, unknown keys, unreachable rules, invalid regexes в `custom_patterns`, contradictory approval rules. Exit 2 на ошибке.
- `sentinel policy test --dest llm|untrusted|host:<h> --tool <name> [file]`: dry run по семплу; какие entity rules fired, resulting mode, transformed output с redacted values.
- `sentinel policy explain <field>`: какие gateways реально читают поле — ГЕНЕРИРУЕТСЯ из code annotations, не hand-maintained. Добавить механизм аннотаций (напр. struct tags или registry) + тест: новое policy поле без wiring роняет тест.
- `sentinel policy diff <a> <b>`: behavioural diff двух policy files over fixture corpus.
- Заменить README "do not assume every gateway enforces every policy field..." caveat указателем на `policy explain` (только это предложение).
- Сабкоманды — внутри одной `policy` команды (сабдиспатч как у `mcp`), ОДНА register-строка в `main.go` если `policy` ещё не зарегистрирован; если зарегистрирован — вообще не трогать `main.go`.
- Тесты: invalid regex в `custom_patterns` ловит lint, не runtime; `policy test` на fixture репортит точное fired rule; `explain` generated (новое поле без wiring = fail); README caveat заменён.

## Границы
МОЖНО: `internal/policy/` (+ тесты, + annotations механизм), `cmd/sentinel/policy*.go` (новые/существующие policy-файлы), ОДНА register-строка в `main.go` при необходимости, README (только caveat-предложение).
НЕЛЬЗЯ: остальное `cmd/sentinel/`, `internal/egress/`, `internal/llm/`, `internal/mcp/`, `internal/vault/`, `cmd/sentinel-gui/`, `.github/`, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/policy/... ./cmd/sentinel/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-18-policy`. Финальный отчёт: файлы, риски.
