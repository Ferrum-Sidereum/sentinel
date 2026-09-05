# STAGE-03 — WP-03 Never echo, never print (§SPEC P0)

## Читать первым
- `C:/Users/Flusion/Downloads/SPEC.md` §2 (I1, I5), §3.1 D4/D5, §P0 WP-03 полностью.
- Ключевые файлы: `cmd/sentinel/main.go` (cmdAdd, cmdRotate, cmdScan).

## Задача
- Новый пакет `internal/termsecret`: `Read(prompt string) ([]byte, error)` — `golang.org/x/term.ReadPassword`
  на TTY, raw read на pipe, trim ровно одного trailing `\n`, без другого whitespace. Возврат `[]byte`, callers zero.
- `add`/`rotate` через него + флаги `--from-env NAME`, `--from-file PATH`, `--stdin`.
- `scan`: никогда не печатать value — только `type`, `detector`, `confidence`, `line:col`, fingerprint
  (sha256 первые 8 hex). `--show-values` только на интерактивном TTY + warning в stderr первым.
- GUI reveal: подтверждение + audit (минимально, без редизайна GUI).
- Обновить README + статус WP-03 в SPEC status table. Все пункты acceptance WP-03.

## Границы
- МОЖНО: `internal/termsecret/` (новый), `cmd/sentinel/` (add/rotate/scan), GUI reveal-минимум, `README.md`, `README.ru.md`, SPEC status table, тесты.
- НЕЛЬЗЯ: keyring API/семантика (WP-01), passphrase-файлы (WP-02), vault schema, policy, mcp, egress, go.mod, workflows.
- Аддитивно в общие файлы. Не выходить из worktree. Push НЕ делать. Коммит в ветку `stage-03-termsecret`.

## Приёмка
```powershell
cd C:\Users\Flusion\sentinel-s03
go build ./...; go test ./...; go vet ./...; gofmt -l .
```
Старые тесты зелёные. Финальный отчёт.
