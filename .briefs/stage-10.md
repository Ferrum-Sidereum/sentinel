# Бриф stage-10-broker (WP-10 — Approval broker)

## Контекст
Читай первым: `SPEC.md` §WP-10 (строки ~402-467: Request/Decision/Broker interface, три реализации, policy additions, rules), затем `internal/mcp/` (inject path — где сейчас отдаются credentials без gate), `internal/policy/` (структура Policy — куда добавить `approvals:`), `internal/audit/` (Log сигнатура — НЕ менять), `internal/vault/` (decrypt-for-injection path). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s10`.

## Задача (все Acceptance criteria WP-10)
- Новый `internal/broker`: `Request{Secret, Consumer ("mcp:<profile>:<child argv0>"|"egress:<host>"|"gui"|"cli"), Dest, Reason, Requested}`, `Decision{Allow, TTL (0=single use), Scope ("once"|"session"|"until"), Rule}`, `Broker interface { Ask(context.Context, Request) (Decision, error) }`.
- Три реализации: **Policy** (из `policy.yaml`, default для CI/headless), **Interactive** (prompt на controlling terminal: `agent "filesystem-mcp" requests snt://github_token for api.github.com — [o]nce / [s]ession / [1]5m / [d]eny?`), **Auto** (allow-all, только с `--yes-i-know` + warning, default НИКОГДА).
- Policy additions (расширить `internal/policy` struct + парсинг, обратно совместимо):
```yaml
approvals:
  default: ask
  rules: [{secret, consumer, dest, decision, ttl}]
  grant_cache: 15m
  max_uses_per_minute: 30
```
- Grants in memory, key `(secret, consumer, dest)`, expire, НИКОГДА на диск.
- Каждое decision — audit event (request fields + decision + rule), НИКОГДА value.
- Fail closed: no broker/no TTY/`default: ask` ⇒ deny + exit code 4.
- Denial НЕ убивает child: placeholder unresolved, сервер падает сам; log it.
- `mcp run --mode inject` идёт через broker (точка интеграции — минимальная, поведение без политик = как раньше через Policy-broker с default ask? Нет: сохрани текущее поведение за `approvals.default: allow` в дефолтной политике ИЛИ за env-флагом — выбери и задокументируй; старые тесты mcp НЕ должны упасть).
- Broker — ЕДИНСТВЕННЫЙ caller decrypt-for-injection path (enforce тестом: grep package graph или unexported constructor).
- README quickstart step 5 переписать вокруг approvals; "Use it only for trusted servers" ⇒ "approval required by default" (только эти строки).
- Тесты SPEC: `default: deny` ⇒ child env keeps `snt://` literal + `approval_denied` + exit 4 via `--strict`; allow rule ⇒ resolved + rule name + TTL; TTL expiry ⇒ re-ask; glob `secret`/`consumer`, `prod_*` deny beats later allow (first match wins, documented); rate limit ⇒ `approval_rate_limited`; interactive broker со scripted pty (accept+deny).

## Границы
МОЖНО: новый `internal/broker/` (+ тесты), `internal/policy/` (только `approvals:` секция struct+parse+тесты), `internal/mcp/` (только injectточка → broker), `cmd/sentinel/mcp*.go` (только `--strict`/`--yes-i-know` флаги), оба README (только указанные строки).
НЕЛЬЗЯ: `internal/vault/` (кроме вызовов), `internal/egress/`, `internal/audit/`, `internal/scrubber/`, `cmd/sentinel/main.go` (register НЕ трогать), `cmd/sentinel/cli.go`, `cmd/sentinel-gui/`, `.github/`, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./internal/broker/... ./internal/mcp/... ./internal/policy/... ./cmd/sentinel/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-10-broker`. Финальный отчёт: файлы, риски.
