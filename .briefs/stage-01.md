# STAGE-01 — WP-01 Master key safety (§SPEC P0)

## Читать первым
- `C:/Users/Flusion/Downloads/SPEC.md` §2 (инварианты), §3.1 D1, §P0 WP-01 полностью.
- Ключевые файлы: `internal/keyring/keyring.go`, `cmd/sentinel/main.go` (cmdInit).

## Задача
Разделить `LoadOrCreate` на `Load() ([]byte, error)` (никогда не создаёт) и
`Create(dir string) ([]byte, error)` (возвращает `ErrVaultExists`, если есть `vault.db`
или legacy passphrase-файл). Ошибки `ErrNotFound` / `ErrUnavailable` / `ErrVaultExists`.
Все команды кроме `init` — через `Load`; `init` — `Load`, и только на `ErrNotFound` — `Create`.
На `ErrUnavailable` — ненулевой exit с текстом remediation, без фолбэков.
Удалить `bin2hex`/`hex2bin`, использовать `encoding/hex`.
Добавить `credentialStore` seam для тестов (реальный keychain не трогать).
Обновить README security notes (убрать warning про создание нового ключа) + статус WP-01 в SPEC status table.
Критерии приёмки WP-01 — все пункты чеклистом.

## Границы
- МОЖНО: `internal/keyring/`, `cmd/sentinel/main.go` (только init/load-пути), `README.md`, `README.ru.md`, SPEC status table, тесты.
- НЕЛЬЗЯ: `~/.sentinel/passphrase` логика (это WP-02), schema vault, policy, mcp, egress, go.mod, workflows.
- Не выходить из своего worktree. Push НЕ делать. Коммит в свою ветку `stage-01-keyring`.

## Приёмка
```powershell
cd C:\Users\Flusion\sentinel-s01
go build ./...; go test ./...; go vet ./...; gofmt -l .
```
Старые тесты остаются зелёными. Финальный отчёт: что сделано, diff stat, результаты команд.
