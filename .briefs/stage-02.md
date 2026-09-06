# Бриф stage-02-passphrase (WP-02 — Kill the plaintext passphrase)

## Контекст
Читай первым: `SPEC.md` §WP-02 (строки ~191-226), затем `internal/keyring/keyring.go` (API `Load`, `ErrUnavailable`, `Remediation` — уже в main после WP-01), `cmd/sentinel/main.go` (`openStore`, `cmdInit`), `internal/termsecret/` (чтение без эха после WP-03). Go-проект, работаешь ТОЛЬКО внутри `C:/Users/Flusion/sentinel-s02`.

## Задача (все Acceptance criteria WP-02)
- Удалить чтение/запись `~/.sentinel/passphrase` (`rg` не должен находить запись passphrase-байтов в файлы, кроме SPEC/README).
- Новый `~/.sentinel/key.json` (mode `0600`), секретов внутри НЕТ: `{version:1, kdf:"argon2id", salt: base64 32 случайных байт, time:3, memory_kib:262144, parallelism:4, verifier: base64 AES-GCM seal литерала "sentinel-kdf-v1" под derived key}`. Параметры читаются из файла (повышаемые позже).
- Passphrase читается каждый раз с TTY без эха (через `internal/termsecret`), подтверждение дважды при создании, НИКОГДА не персистится.
- `verifier`: неверная passphrase ⇒ именованная ошибка "wrong passphrase", vault не открывается (fail closed).
- Весь путь за флагом `sentinel init --passphrase`; без флага отсутствующий keychain = hard error.
- Текст промпта честно: passphrase не хранится, потеря = потеря vault.
- `sentinel migrate-key`: существующий `~/.sentinel/passphrase` ⇒ re-derive с fresh salt, re-encrypt vault, удалить старый файл только после успешного verified read. Fixture-тест (I9).
- Документировать в обоих README, заменить текущий "Plaintext fallback" warning.
- Тесты: одинаковые passphrase на двух инсталлах ⇒ разные ключи (разные соли); неверная ⇒ verifier mismatch; `key.json` mode `0600` (на Windows — вызов ACL-narrowing helper).

## Границы
МОЖНО: `internal/keyring/`, `cmd/sentinel/main.go` (+ новый файл passphrase.go/cmd при желании), тесты рядом, оба README (только секция про passphrase).
НЕЛЬЗЯ: `internal/vault/`, `internal/scrubber/`, `internal/mcp/`, остальное `cmd/sentinel/` (другие команды), `cmd/sentinel-gui/`, `.github/`, `SPEC.md`. НЕ выходи из worktree. Push НЕ делать.

## Приёмка
`go build ./internal/... ./cmd/sentinel/` чисто; `go test ./internal/... ./cmd/sentinel/...` — всё зелёное (старые тесты не ломать); `go vet` по тронутым пакетам. Коммит в свою ветку `stage-02-passphrase`. Финальный отчёт: что сделано, файлы, риски.
