# STAGE-04 — WP-04 Scoped decryption, no plaintext snapshot (§SPEC P0)

## Читать первым
- `C:/Users/Flusion/Downloads/SPEC.md` §2 (I1, I4, I5), §3.1 D6, §P0 WP-04 полностью.
- Ключевые файлы: `internal/vault/vault.go` (ValuesSnapshot), `internal/mcp/gateway.go`, `internal/scrubber/`, `internal/egress/`.

## Задача
- Удалить `ValuesSnapshot`. Новый `Matcher` интерфейс (`FindAll(text string) []Match{Name, Start, End}`)
  поверх расшифрованных `[]byte` с агрессивным zeroing; только имена+офсеты наружу; инвалидация кэша на write.
- Однопроходный substring-поиск (Aho-Corasick или эквивалент, in-repo, без новых зависимостей).
- Адаптировать `internal/mcp/gateway.go` и потребителей в scrubber/egress на новый API.
- Обновить README при необходимости + статус WP-04 в SPEC status table. Все acceptance WP-04,
  включая бенчмарк (200 secrets × 1 MiB < 50ms, число в PR-описании/отчёте).

## Границы
- МОЖНО: `internal/vault/`, `internal/scrubber/`, `internal/mcp/`, `internal/egress/`, README, SPEC status table, тесты.
- НЕЛЬЗЯ: keyring, cmd/sentinel CLI-поверхность (кроме минимальных адаптаций вызовов), policy, go.mod, workflows, GUI.
- Не выходить из worktree. Push НЕ делать. Коммит в ветку `stage-04-matcher`.

## Приёмка
```powershell
cd C:\Users\Flusion\sentinel-s04
go build ./...; go test ./...; go vet ./...; gofmt -l .
```
`internal/mcp/gateway_test.go` адаптирован и зелёный. Финальный отчёт.
