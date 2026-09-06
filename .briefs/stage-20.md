# Бриф stage-20-gui (WP-20 — GUI: activity, onboarding, tray)

## Контекст
Читай первым: `SPEC.md` §WP-20, затем `cmd/sentinel-gui/` целиком (`app.go`, `app_test.go` стиль, `storage.go` после WP-07), `internal/audit/` (tail API из WP-17), `internal/metrics/` (counts resolutions/denials/redactions), `internal/core/` (API из WP-07), `internal/broker/` (interactive broker interface из WP-10). Работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s20`.

## Задача (все Acceptance criteria WP-20)
- **Activity view:** live audit feed (who asked which secret, when, allowed/denied), filterable, на WP-17 tail. Surface `internal/metrics` counts.
- **Approval surface:** desktop app = interactive broker (native prompt: once / 15m / session / deny). Реальная проработка, это signature interaction.
- **Onboarding wizard:** keychain check ⇒ init ⇒ add first secret ⇒ client config (WP-15 код) ⇒ live test call. Каждый шаг показывает эквивалентную CLI-команду. Idempotent, safe re-run.
- **Tray:** status dot per gateway, quick pause всего egress, recent-denials badge.
- **Secret list:** last used, use count, expiry, bound hosts, masked value + confirmed audited reveal (reveal backend уже есть после WP-03 — только UI).
- Ограничение среды: `frontend/dist` отсутствует в репо, полного `wails build` нет. Делай: Go-side handlers + `app_test.go`-style unit tests + frontend файлы (JS/Svelte — посмотри что уже в `frontend/`, пиши в том же стеке). Acceptance "Frontend typecheck and build pass" — выполни если toolchain доступен (`npm`/`node` в frontend/), иначе задокументируй в отчёте что проверено/что нет.
- Тесты: approval prompt round-trip decision → broker; timeout ⇒ deny; reveal emits audit + refused when locked; NO secret value crosses Wails bridge без just-confirmed reveal (тест); wizard idempotent.
- Wails bridge: новые bound methods только для activity/approve/wizard/tray; secret-read методов НЕ добавлять.

## Границы
МОЖНО: `cmd/sentinel-gui/` целиком (Go + frontend/).
НЕЛЬЗЯ: `internal/...` (только вызовы core/broker/audit/metrics API — сигнатуры НЕ менять), `cmd/sentinel/`, `.github/`, README, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go vet ./cmd/sentinel-gui/` чисто; `go test ./cmd/sentinel-gui/...` зелёные (если пакета тестов не было — создай `app_test.go`-style); frontend typecheck/build если toolchain есть. Коммит в `stage-20-gui`. Финальный отчёт: файлы, что проверено, риски.
