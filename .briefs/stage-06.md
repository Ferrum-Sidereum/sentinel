# Бриф stage-06-vaultv2 (WP-06 — Vault schema v2)

## Контекст
Читай первым: `SPEC.md` §WP-06 (~296-339), затем `internal/vault/` целиком (текущая схема v1, `Put`, `rotate`, helpers join/split для meta). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s06`.

## Задача (все Acceptance criteria WP-06)
Схема:
```sql
CREATE TABLE secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL, nonce BLOB NOT NULL, kind TEXT NOT NULL, meta TEXT NOT NULL, version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT, last_used_at TEXT, use_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE secret_versions (name TEXT NOT NULL, version INTEGER NOT NULL, value BLOB NOT NULL, nonce BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (name, version));
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
```
- `meta` — JSON (hosts, paths, methods, inject_hdr, labels). Удалить join/split-хелперы с запятой.
- `Put`: `created_at` сохраняется при конфликте, `updated_at` обновляется.
- `rotate` пишет предыдущее значение в `secret_versions`, хранить последние N (default 3, configurable). `sentinel rollback <name>` восстанавливает предыдущую версию (CLI-команда тоже твоя, минимальная).
- `expires_at`: `add --expires 30d`; просроченные refused для injection с ясной ошибкой, `ls` метит их.
- `Touch(name)`: обновляет `last_used_at`/`use_count` при каждом успешном resolution.
- `PRAGMA journal_mode=WAL`, `foreign_keys=ON`, busy timeout.
- Миграция v1→v2 автоматически, в транзакции, после копии `vault.db` → `vault.db.v1.bak`.
- Сохранить публичный API, используемый `cmd/sentinel`, `cmd/sentinel-gui`, `internal/scrubber` (`NewMatcher`, `ValuesSnapshot`-семантика где есть): сигнатуры НЕ менять, только внутренности. `NewMatcher` обязан работать на v2.
- Тесты: fixture v1 `vault.db` (helper строит в тесте, значения известны) ⇒ миграция, все секреты расшифровываются теми же байтами; host со запятой round-trip; `Put` дважды ⇒ `created_at` стабилен, `updated_at` растёт; rotate×5 keep=3 ⇒ ровно 3 версии; rollback ⇒ точные предыдущие байты; expired refused resolver'ом + метка в `ls`; два процесса пишут конкурентно без `SQLITE_BUSY`.

## Границы
МОЖНО: `internal/vault/` (+ тесты), минимальные правки `cmd/sentinel/` ТОЛЬКО для `rollback`/`--expires` (аддитивно, сигнатуры не менять).
НЕЛЬЗЯ: `internal/keyring/`, `internal/scrubber/`, `internal/mcp/`, `internal/egress/`, `cmd/sentinel-gui/`, `.github/`, README (кроме строки про rollback/expires при необходимости), `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./...` кроме известного `cmd/sentinel-gui` (frontend/dist отсутствует — предсуществующая проблема); `go test ./internal/vault/... ./internal/scrubber/... ./cmd/sentinel/...` зелёные; `go vet` по тронутым пакетам. Коммит в `stage-06-vaultv2`. Финальный отчёт: файлы, риски.
