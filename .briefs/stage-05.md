# STAGE-05 — WP-05 Toolchain and CI baseline (§SPEC P0)

## Читать первым
- `C:/Users/Flusion/Downloads/SPEC.md` §P0 WP-05 полностью, §3.2 D22.
- Ключевые файлы: `go.mod`, `.github/workflows/` (существующие: desktop-ux.yml, readme-quickstarts.yml — не ломать).

## Задача
- `go.mod`: explicit `toolchain` directive + минимальная версия Go в README.
- Новый `.github/workflows/ci.yml`: matrix ubuntu/windows/macos; `build`, `vet`, `test -race` (только CLI-пакеты,
  без Wails native deps), `gofmt -l`, frontend `typecheck`. `staticcheck` + `govulncheck` (non-blocking, annotate).
- gofmt-починить ТОЛЬКО `cmd/sentinel-gui/storage.go` и `internal/policy/policy.go` (и другие — только если реально грязные).
- Статус WP-05 в SPEC status table. Все acceptance WP-05. Branch protection — описать в финальном отчёте.

## Границы
- МОЖНО: `go.mod`, `.github/workflows/ci.yml`, gofmt-правки грязных файлов, `README.md`, SPEC status table.
- НЕЛЬЗЯ: любой Go-код кроме gofmt-правок, vault/keyring/policy/mcp/egress/CLI-логика, frontend-код.
- Не выходить из worktree. Push НЕ делать. Коммит в ветку `stage-05-ci`.

## Приёмка
```powershell
cd C:\Users\Flusion\sentinel-s05
go build ./...; go test ./...; go vet ./...; gofmt -l .
```
Финальный отчёт.
