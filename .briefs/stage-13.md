# Бриф stage-13-cigate (WP-13 — `scan` as a CI gate)

## Контекст
Читай первым: `SPEC.md` §WP-13, затем `cmd/sentinel/` — scan-команда и `cli.go` (dispatch, exit codes `ExitOK=0/Runtime=1/Usage=2/...`, `emitJSON`), `internal/scrubber/` (публичный API `ScanWithMatcher`, `Finding`). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s13`.

## Задача (все Acceptance criteria WP-13)
- Exit codes scan: `0` clean, `3` findings на/выше threshold, `1` operational error. Стабильный контракт, задокументировать в help команды.
- `--min-confidence`, `--fail-on TYPE,TYPE`, `--format text|json|sarif`.
- SARIF output (GitHub code scanning рендерит inline). SARIF 2.1.0, БЕЗ secret values внутри.
- `--redact` (default в non-TTY) + fingerprints WP-03 (уже есть — не ломать).
- Рекурсивный скан директории с `.gitignore` + новый `.sentinelignore` (тот же синтаксис; path/pattern правила задокументировать в help).
- `sentinel scan --staged` для pre-commit hook (git index, не worktree); hook положить в `scripts/`.
- Composite GitHub Action `action.yml` в корне репо (`uses: Ferrum-Sidereum/sentinel@v0`).
- Существующие флаги scan (`--show-values`, `--json`, file args) НЕ ломать; `--json` и `--format json` — синонимы/совместимы.
- Тесты: clean fixture ⇒ 0; dirty ⇒ 3; `--fail-on CREDIT_CARD` игнорирует EMAIL-only (0); SARIF валидируется против SARIF 2.1.0 schema и не содержит значений; `.sentinelignore` исключает path, `--no-ignore` включает; `--staged` читает git index.
- Self-hosting НЕ делать (CI правит оркестратор).

## Границы
МОЖНО: `cmd/sentinel/scan*.go` (существующие scan-файлы), новый `cmd/sentinel/scan_gate_test.go`, `action.yml` (новый), `scripts/` (только hook), `internal/scrubber/` — ТОЛЬКО если нужен новый query-API (предпочтительно обойтись существующим `ScanWithMatcher`).
НЕЛЬЗЯ: `cmd/sentinel/main.go` (register-строки НЕ добавлять — scan уже зарегистрирован), `cmd/sentinel/cli.go`, `internal/vault/`, `internal/keyring/`, `internal/mcp/`, `cmd/sentinel-gui/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./cmd/sentinel/... ./internal/scrubber/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-13-cigate`. Финальный отчёт: файлы, риски.
