# Бриф stage-16-release (WP-16 — Release binaries)

## Контекст
Читай первым: `SPEC.md` §WP-16 (~594-610), затем `.github/workflows/` (что уже есть после WP-05), `cmd/sentinel/` (команда `version` — как она сейчас получает версию), `go.mod` (модуль, Go-версия). Работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s16`.

## Задача (все Acceptance criteria WP-16)
- `.goreleaser.yaml`: tag-triggered сборка CLI для darwin/linux/windows × amd64/arm64.
- `.github/workflows/release.yml`: релиз по тегу — goreleaser, checksums, cosign keyless signing артефактов и checksums, SBOM на артефакт.
- Homebrew tap и Scoop manifest для CLI (формула/манифест в репо или отдельный tap-репо — выбери простое: файлы в `packaging/` + документация; главное — воспроизводимость).
- `sentinel version` показывает release tag (прокинуть через `-ldflags`, задокументировать какие флаги выставляет CI).
- Docs: install-секция в обоих README, НЕ требующая Go toolchain, заменяет "not a promise of downloadable release binaries".
- Desktop-сборки явно out of scope — сказать в release notes template.
- Проверяемость без реального тега: `goreleaser build --snapshot` должен проходить локально (если goreleaser нет в PATH — опиши в отчёте, workflow всё равно должен быть корректным по YAML; валидируй YAML парсингом через python/go).

## Границы
МОЖНО: `.github/workflows/release.yml` (новый), `.goreleaser.yaml` (новый), `packaging/` (новый), оба README (только install-секция), `cmd/sentinel/` — ТОЛЬКО `version` (аддитивно, прокинуть ldflags-переменные).
НЕЛЬЗЯ: `internal/...`, остальное `cmd/sentinel/`, `cmd/sentinel-gui/`, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать, тег НЕ создавать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/`; `go test ./cmd/sentinel/...` зелёные; YAML-файлы парсятся; `goreleaser build --snapshot` если доступен. Коммит в `stage-16-release`. Финальный отчёт: файлы, что проверено, что только ревью YAML.
