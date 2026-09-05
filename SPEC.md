# Sentinel Engineering Spec

**Audience:** autonomous coding agents and human reviewers working on this repository.
**Status of this document:** normative. If code and this spec disagree, the spec wins or the spec gets amended in the same PR.
**Baseline commit reviewed for this spec:** `c079614` (main).

This document is the single source of truth for *what* to build next and *what "done" means*. It is written so that each work package (WP) can be handed to a separate agent with little extra context.

---

## 0. How agents must use this document

1. Pick exactly **one** WP. Do not bundle WPs into a single PR unless the WP explicitly says it depends on another and is trivially small.
2. Read the **Invariants** (§2). They are non-negotiable and apply to every PR.
3. Implement, then satisfy every line of that WP's **Acceptance criteria**. Acceptance criteria are checklists, not suggestions.
4. Every PR must include tests. "Manually verified" is not accepted.
5. Every PR must update user-facing docs it invalidates: `README.md`, `README.ru.md`, and this file's status table.
6. If a WP turns out to be wrong, mistaken, or impossible: stop, open an issue describing the conflict, and propose a spec amendment. Do not silently redesign.
7. Do not add new third-party dependencies without stating the reason in the PR description. Prefer the standard library.

### Definition of done (applies to all WPs)

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .            # must print nothing
```

Plus, for WPs touching the desktop shell:

```bash
cd cmd/sentinel-gui/frontend && npm ci && npm run typecheck && npm run build
```

---

## 1. Product thesis

> Give agents references, not your keys.

Sentinel's value is **not** "a place to keep secrets". It is **the moment of decision**: an AI agent needs a credential, and a human (or an explicit policy) decides whether it gets one, for which host, and for how long. Everything in the roadmap below is prioritised by how directly it serves that sentence.

Consequence for prioritisation: a broken master-key path or an unattended secret injection destroys the thesis. Cosmetic features do not compensate. **P0 before anything else.**

---

## 2. Invariants

These hold for all code in this repository.

- **I1. Never print a secret value.** Not to stdout, not to stderr, not to logs, not to audit records, not in error strings. Print names, references (`snt://name`), types, and confidence scores instead.
- **I2. Never generate a new master key when vault data already exists.** A failed keychain read is an error to surface, never a reason to re-key.
- **I3. Plaintext key material never touches disk** except behind an explicit, separately named opt-in flag that says so in its own name.
- **I4. A secret leaves the vault only for a named, logged purpose.** Every decrypt path emits an audit event describing consumer, destination host or tool, and outcome.
- **I5. Plaintext lives in memory as `[]byte`, is zeroed after use, and is never held in a long-lived `map[string]string`.**
- **I6. Listeners bind to loopback by default.** A non-loopback bind requires an explicit flag and prints a warning.
- **I7. Fail closed.** On policy load error, decrypt error, or unknown mode, refuse the operation. Do not degrade to pass-through.
- **I8. Documentation must not overstate.** No claim of "secure", "audited", or "production-ready" enters the docs. Describe mechanisms and their limits.
- **I9. No breaking change to `~/.sentinel` layout without a migration** that runs automatically and is covered by a test using a fixture from the previous format.

---

## 3. Verified current state

Read before proposing anything. Each item below was confirmed against source at the baseline commit.

### 3.1 Critical defects

| ID | Location | Problem |
|:--|:--|:--|
| D1 | `internal/keyring/keyring.go` `LoadOrCreate` | On any keychain read miss it generates a fresh random 32-byte key and writes it to the keychain. An existing `vault.db` then becomes permanently undecryptable. Violates I2. |
| D2 | `internal/keyring/keyring.go` `deriveFallback` | Argon2id with a **fixed global salt** (`sha256("sentinel-salt")`) and low cost (`t=1, m=64MiB, p=4`). Enables precomputation across all installs. |
| D3 | `cmd/sentinel/main.go` `cmdInit` | Writes the passphrase to `~/.sentinel/passphrase` in **plaintext**, while telling the user it is "stored hashed via argon2id". The message is false. Violates I3 and I8. |
| D4 | `cmd/sentinel/main.go` `cmdAdd`, `cmdRotate` | Secret value read via `bufio.Reader` from a TTY: **echoes to the terminal** and lands in scrollback. |
| D5 | `cmd/sentinel/main.go` `cmdScan` | Prints `f.Value`, i.e. the matched secret itself, with `%q`. Violates I1. |
| D6 | `internal/vault/vault.go` `ValuesSnapshot` | Decrypts **every** secret into a `map[string]string`. In `internal/mcp/gateway.go` the result is held for the whole session. Strings are immutable; they cannot be zeroed. Violates I5. |
| D7 | `internal/mcp/gateway.go` `runInner` | `inject` mode resolves references with **no approval, no host binding check, no rate limit, no audit of the resolution**. The core promise of the product is unguarded here. Violates I4. |
| D8 | `internal/mcp/gateway.go` `runInner` | Child `stderr` is wired straight to `os.Stderr`, unscrubbed. A server that logs its own config leaks injected secrets. |

### 3.2 Correctness and robustness defects

| ID | Location | Problem |
|:--|:--|:--|
| D9 | `internal/vault/vault.go` `join`/`split` | Comma-joined list columns with no escaping. A value containing `,` silently corrupts hosts/paths/methods/headers. |
| D10 | `internal/vault/vault.go` `Put` | `ON CONFLICT DO UPDATE` overwrites `created_at` with now. There is no `updated_at`, no `expires_at`, no `last_used_at`, and no version history. |
| D11 | `internal/mcp/gateway.go` `runInner` | `--profile` is parsed then discarded (`_ = profile`); the deny set is built from every `mcp:deny:*` entity key regardless of profile. Feature is a stub that looks implemented. |
| D12 | `internal/mcp/gateway.go` `readFrame` | Mixes newline framing and `Content-Length` framing, ignores the `io.ReadFull` error, and **always writes newline-delimited output** even when the peer used `Content-Length`. Protocol mismatch with conformant clients. |
| D13 | `internal/mcp/gateway.go` `scrubVal` | Only inspects keys `text`, `content`, `description`. Any other field passes unscrubbed. |
| D14 | `internal/mcp/gateway.go` `checkCall` | Only inspects `tools/call`; returns on the first finding, so a multi-placeholder payload reports one. `resources/read` and prompt paths are unchecked. |
| D15 | `internal/mcp/gateway.go` `runInner` | `c.Wait()` error is discarded; the child's exit code is not propagated. `sentinel` exits 0 when the wrapped server crashed. |
| D16 | `cmd/sentinel/main.go` `usage` | Prints `init\|add\|ls\|rm\|env\|scan` while `serve`, `run`, `trust-ca`, `llm-serve`, `mcp`, `audit`, `rotate` all exist and are undiscoverable. |
| D17 | `cmd/sentinel/serve.go`, `cmd/sentinel/mcp.go` | Ports hardcoded: `18449` for egress, `18450` for **both** `mcp serve` and `llm-serve`. Concurrent use collides. |
| D18 | `cmd/sentinel/extra.go` `cmdAudit` | Reads the whole log into memory to show the tail; no `-f` follow; documented as `audit tail` but the `tail` word is ignored. |
| D19 | `cmd/sentinel-gui/storage.go` vs `internal/keyring` | Two independent master-key implementations with **different safety behaviour** (the GUI correctly refuses to re-key when data exists; the CLI does not). GUI entries also omit host-binding metadata and use different naming, so the proxy cannot use them. |
| D20 | `cmd/sentinel-gui/storage.go` `updatePolicyDocument` | Persists only `entities.*.to_llm`, `entities.*.to_untrusted` and `custom_patterns`. Other edits are silently dropped. |
| D21 | `cmd/sentinel/main.go` `cmdScan` | No exit-code contract, so it cannot gate CI. Also no allowlist file, no redaction switch. |
| D22 | `go.mod` | Declares `go 1.27.0` with no `toolchain` directive. Any contributor or CI runner on an older toolchain is hard-blocked with a confusing error. |

### 3.3 What already works and must not regress

- AES-256-GCM sealing with a per-record nonce and the AAD `sentinel-vault` (`internal/vault`).
- Policy hot reload via mtime polling (`internal/policy.Watch`).
- Pseudonymisation session with alias rehydration on the inbound MCP direction (`internal/scrubber.Session`).
- Host-bound selective HTTPS interception with tunnelling for unbound hosts (`internal/egress`).
- GUI master-key refusal to overwrite existing data (`cmd/sentinel-gui/storage.go`). **This is the correct behaviour; WP-01 makes the CLI match it, not the reverse.**

---

## 4. Roadmap

Phases are strictly ordered. Do not start a phase while an earlier phase has an open WP, except for WPs marked *parallel-safe*.

| Phase | Theme | WPs |
|:--|:--|:--|
| **P0** | Stop the bleeding | WP-01 … WP-05 |
| **P1** | One vault, one truth | WP-06 … WP-09 |
| **P2** | The decision moment | WP-10 … WP-12 |
| **P3** | Adoption surface | WP-13 … WP-16 |
| **P4** | Observability and polish | WP-17 … WP-20 |

### Status table (update in every PR)

| WP | Title | Status | Owner | PR |
|:--|:--|:--|:--|:--|
| WP-01 | Master key safety | not started | | |
| WP-02 | Kill the plaintext passphrase | not started | | |
| WP-03 | Never echo, never print | not started | | |
| WP-04 | Scoped decryption, no plaintext snapshot | not started | | |
| WP-05 | Toolchain and CI baseline | not started | | |
| WP-06 | Vault schema v2 | not started | | |
| WP-07 | Unify CLI and GUI on one core | not started | | |
| WP-08 | Honest CLI surface | not started | | |
| WP-09 | Port management and `status` | not started | | |
| WP-10 | Approval broker | not started | | |
| WP-11 | Bind enforcement in inject mode | not started | | |
| WP-12 | Profiles, for real | not started | | |
| WP-13 | `scan` as a CI gate | not started | | |
| WP-14 | `doctor` | not started | | |
| WP-15 | Client config generator | not started | | |
| WP-16 | Release binaries | not started | | |
| WP-17 | Tamper-evident audit + live tail | not started | | |
| WP-18 | `policy test` | not started | | |
| WP-19 | MCP protocol conformance | not started | | |
| WP-20 | GUI: activity, onboarding, tray | not started | | |

---

## P0 — Stop the bleeding

### WP-01 — Master key safety

**Fixes:** D1. **Files:** `internal/keyring/keyring.go`, `cmd/sentinel/main.go`.

Split the single ambiguous entry point into explicit operations:

```go
// Load returns the existing master key. It never creates one.
func Load() ([]byte, error)

// Create generates and stores a new master key.
// It returns ErrVaultExists if any vault artifact is present in dir.
func Create(dir string) ([]byte, error)

var (
    ErrNotFound     = errors.New("keyring: no master key")
    ErrUnavailable  = errors.New("keyring: credential store unavailable")
    ErrVaultExists  = errors.New("keyring: vault data exists without a matching key")
)
```

Rules:

- `Load` distinguishes "store reachable, no entry" (`ErrNotFound`) from "store unreachable" (`ErrUnavailable`). Never conflate them.
- `Create` stats `vault.db` and any legacy passphrase file first and returns `ErrVaultExists` if either is present.
- Every command except `init` calls `Load`. `init` calls `Load`, and only on `ErrNotFound` calls `Create`.
- On `ErrUnavailable`, exit non-zero with remediation text. Do not fall back to anything.
- Use `encoding/hex`; delete the hand-rolled `bin2hex`/`hex2bin`.

**Acceptance criteria**

- [ ] No code path can produce a new master key while `vault.db` exists. Prove it with a test.
- [ ] Test: keychain returns `ErrNotFound` + `vault.db` present ⇒ `Create` returns `ErrVaultExists`, keychain is not written.
- [ ] Test: keychain returns a transport error ⇒ error surfaces, no write.
- [ ] Test: hex round-trip for the stored representation, including rejection of odd length and non-hex bytes.
- [ ] `keyring` package has a `credentialStore` seam so tests never touch the real OS keychain.
- [ ] README security notes updated to remove the "can attempt to create a new master key" warning, since the behaviour is gone.

---

### WP-02 — Kill the plaintext passphrase

**Fixes:** D2, D3. **Depends on:** WP-01. **Files:** `internal/keyring/`, `cmd/sentinel/main.go`.

The passphrase path stays available for users without a working keychain, but it becomes honest and correct.

- Delete all reading and writing of `~/.sentinel/passphrase`.
- Add `~/.sentinel/key.json` (mode `0600`) containing **no secret material**:

```json
{
  "version": 1,
  "kdf": "argon2id",
  "salt": "<32 random bytes, base64>",
  "time": 3,
  "memory_kib": 262144,
  "parallelism": 4,
  "verifier": "<base64 AES-GCM sealing of the literal 'sentinel-kdf-v1' under the derived key>"
}
```

- Per-install random 32-byte salt. Parameters read from the file so they can be raised later without breaking old vaults.
- The passphrase is read every time it is needed, from the TTY with echo disabled (see WP-03), and confirmed twice on creation. It is **never** persisted.
- `verifier` lets a wrong passphrase be reported as "wrong passphrase" instead of a confusing decrypt failure. Fail closed on mismatch.
- Gate the whole path behind `sentinel init --passphrase`. Without that flag, a missing keychain is a hard error.
- Prompt text must state plainly: the passphrase is not stored, losing it means losing the vault.

**Acceptance criteria**

- [ ] `rg -n "passphrase" -- ':!SPEC.md' ':!README*'` shows no write of passphrase bytes to any file.
- [ ] Test: two installs with the same passphrase derive **different** keys (distinct salts).
- [ ] Test: wrong passphrase ⇒ verifier mismatch ⇒ named error, no attempt to open the vault.
- [ ] Test: `key.json` is created with mode `0600`; on Windows assert the ACL narrowing helper is invoked.
- [ ] Migration: existing `~/.sentinel/passphrase` ⇒ `sentinel migrate-key` re-derives with a fresh salt, re-encrypts the vault, deletes the old file only after a successful verified read. Covered by a fixture test (I9).
- [ ] Documented in both READMEs, replacing the current "Plaintext fallback" warning.

---

### WP-03 — Never echo, never print

**Fixes:** D4, D5. *Parallel-safe with WP-01/02.* **Files:** `cmd/sentinel/`, new `internal/termsecret/`.

- New `internal/termsecret`: `Read(prompt string) ([]byte, error)` using `golang.org/x/term.ReadPassword` when stdin is a TTY, raw read when it is a pipe, always trimming exactly one trailing newline and no other whitespace. Returns `[]byte`, and callers `defer zero(...)`.
- `add` and `rotate` use it. Add `--from-env NAME`, `--from-file PATH`, and `--stdin` for non-interactive use.
- `scan` output: **never** print the matched value. Print `type`, `detector`, `confidence`, and a location as `line:col` plus a fingerprint (`sha256` of the match, first 8 hex chars) for correlating findings across runs.
- Add `--show-values` which prints matches, requires an interactive TTY, and prints a warning line to stderr first. Not usable from CI.
- Same rule for the GUI: reveal requires an explicit per-view confirmation and is audited.

**Acceptance criteria**

- [ ] Test: `scan` over a fixture containing a known vault value ⇒ stdout contains the finding type but **not** the value. Assert absence of the literal.
- [ ] Test: `--show-values` on a non-TTY exits non-zero without printing values.
- [ ] Test: piped `add` still stores the exact bytes, including a value containing spaces and `=`.
- [ ] Test: value with a trailing space is preserved (only the newline is stripped).
- [ ] Grep audit: no `fmt.Print*` in the repository takes a `Secret.Value` or `Finding.Value` argument.

---

### WP-04 — Scoped decryption, no plaintext snapshot

**Fixes:** D6. **Depends on:** WP-06 is *not* required; do this against the current schema. **Files:** `internal/vault/`, `internal/scrubber/`, `internal/mcp/`, `internal/egress/`.

Delete `ValuesSnapshot`. Replace vault-match scanning with a construct that never materialises plaintext:

```go
// Matcher answers "does this text contain a stored secret" without exposing values.
type Matcher interface {
    // FindAll returns findings with secret NAMES, never values.
    FindAll(text string) []Match // Match{Name string; Start, End int}
}
```

Implementation: build the matcher over decrypted values held in `[]byte`, aggressively zeroed; expose only names and offsets to callers. Cache invalidation on vault write. For substring search across many needles use a single pass (Aho-Corasick or equivalent) rather than N× `strings.Contains`; keep it in-repo, no new dependency.

**Acceptance criteria**

- [ ] `ValuesSnapshot` no longer exists. No `map[string]string` of plaintext anywhere.
- [ ] Test: matcher finds a stored secret embedded mid-text and reports the right name and offsets.
- [ ] Test: matcher reports overlapping and repeated occurrences correctly.
- [ ] Test: after `Close`, buffers are zeroed (assert via an injected allocator or an exported test hook).
- [ ] Benchmark: 200 secrets × 1 MiB of text stays under 50 ms on CI hardware. Record the number in the PR.
- [ ] Existing `internal/mcp/gateway_test.go` still passes, adapted to the new API.

---

### WP-05 — Toolchain and CI baseline

**Fixes:** D22. *Parallel-safe.* **Files:** `go.mod`, `.github/workflows/`.

- Verify which Go release is actually available to contributors. Add an explicit `toolchain` directive so `go` can fetch the right version instead of failing, and state the minimum in the README.
- New workflow `ci.yml`: matrix `ubuntu-latest`, `windows-latest`, `macos-latest`; steps `build`, `vet`, `test -race`, `gofmt -l`, and the frontend `typecheck`. CLI packages only for the Go job so Wails native deps do not gate CI.
- Add `staticcheck`. Add `govulncheck` as a non-blocking job that annotates.
- Keep the two existing workflows (`desktop-ux.yml`, `readme-quickstarts.yml`) working; do not duplicate their jobs.

**Acceptance criteria**

- [ ] A clean checkout builds on all three OSes in CI.
- [ ] `go test -race ./...` green on all three.
- [ ] `gofmt -l .` empty. Note: several existing files (`cmd/sentinel-gui/storage.go`, `internal/policy/policy.go`) are not gofmt-clean; fix them in this WP and in no other.
- [ ] Branch protection documented in the PR description (main requires CI green).

---

## P1 — One vault, one truth

### WP-06 — Vault schema v2

**Fixes:** D9, D10. **Files:** `internal/vault/`.

```sql
CREATE TABLE secrets (
  name         TEXT PRIMARY KEY,
  value        BLOB NOT NULL,
  nonce        BLOB NOT NULL,
  kind         TEXT NOT NULL,
  meta         TEXT NOT NULL,        -- JSON: hosts, paths, methods, inject_hdr, labels
  version      INTEGER NOT NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  expires_at   TEXT,
  last_used_at TEXT,
  use_count    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE secret_versions (
  name TEXT NOT NULL, version INTEGER NOT NULL,
  value BLOB NOT NULL, nonce BLOB NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (name, version)
);
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
```

- Replace comma `join`/`split` with **JSON** in `meta`. Delete both helpers.
- `Put` preserves `created_at` on conflict and sets `updated_at`.
- `rotate` writes the previous value into `secret_versions` and keeps the last N (default 3, configurable) so a bad rotation is recoverable. `sentinel rollback <name>` restores the previous version.
- `expires_at` support: `add --expires 30d`. Expired secrets are refused for injection with a clear error and listed by `ls` with a marker.
- `Touch(name)` updates `last_used_at` and `use_count` on every successful resolution.
- Enable `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`; set a busy timeout.
- Migration from v1 runs automatically, in a transaction, after copying `vault.db` to `vault.db.v1.bak`.

**Acceptance criteria**

- [ ] Fixture test: a committed v1 `vault.db` (built by a test helper, values known) migrates and every secret still decrypts to the same bytes.
- [ ] Test: a host value containing a comma survives a round trip.
- [ ] Test: `Put` twice ⇒ `created_at` stable, `updated_at` advances.
- [ ] Test: rotate ×5 with `keep=3` ⇒ exactly 3 versions retained, oldest pruned.
- [ ] Test: `rollback` restores the exact previous bytes.
- [ ] Test: expired secret is refused by the resolver and marked in `ls`.
- [ ] Test: two processes writing concurrently do not return `SQLITE_BUSY`.

---

### WP-07 — Unify CLI and GUI on one core

**Fixes:** D19, D20. **Depends on:** WP-01, WP-06. **Files:** new `internal/core/`, `cmd/sentinel/`, `cmd/sentinel-gui/`.

This is the WP that removes the README's most embarrassing sentence ("Desktop and CLI are not yet interchangeable").

- New `internal/core` package: the only API for open/init/add/list/get/rotate/remove/scan/policy-write. Both `cmd/sentinel` and `cmd/sentinel-gui` become thin adapters over it.
- Delete `loadMasterKey` from `cmd/sentinel-gui/storage.go`; the GUI calls `keyring.Load`/`Create`.
- Single canonical name normalisation function (`lower`, `-`/space ⇒ `_`, validated against `^[a-z0-9_]{1,64}$`), used by CLI, GUI, and `env import`. Reject invalid names with a clear message instead of silently rewriting.
- GUI secret creation gains the same required binding metadata as the CLI (`hosts`, optional `paths`/`methods`/`inject_hdr`). A GUI-created secret must be injectable by the proxy.
- Policy writing: keep the comment-preserving `yaml.Node` approach, but extend it to the **whole** `Policy` struct, not just three fields. Add a round-trip test asserting that an unknown top-level key written by a future version survives an edit.

**Acceptance criteria**

- [ ] Test: a secret created through the `core` API used by the GUI adapter is resolved by the egress proxy for its bound host.
- [ ] Test: name normalisation is identical across all three entry points (table-driven, shared fixture).
- [ ] Test: policy edit preserves comments **and** unrelated keys, including a nested `hosts:` map and an unknown key.
- [ ] Two master-key implementations no longer exist; `rg -n "sentinel-master"` shows one definition.
- [ ] README's "Desktop and CLI are not yet interchangeable" bullet is deleted and the quickstart no longer says "use the CLI throughout".

---

### WP-08 — Honest CLI surface

**Fixes:** D16. *Parallel-safe.* **Files:** `cmd/sentinel/`.

- Replace the hand-rolled `switch` + manual arg loops with per-command `flag.FlagSet`. The current loops mis-handle a flag in final position (`args[i]` after `i++` can panic) and ignore unknown flags entirely.
- `sentinel help`, `sentinel <cmd> --help`, and bare invocation list **every** command with one-line descriptions.
- `sentinel version` prints version, commit, build date, Go version, via `-ldflags`.
- Global flags: `--data-dir` (overrides `~/.sentinel`, also via `SENTINEL_DATA_DIR`), `--json`, `--quiet`, `--no-color`.
- Consistent exit codes: `0` ok, `1` runtime error, `2` usage error, `3` policy violation / blocked, `4` locked or approval denied.
- All machine-readable output behind `--json` on `ls`, `scan`, `audit`, `status`, `doctor`.

**Acceptance criteria**

- [ ] Test: every command in the dispatch table appears in `help` output. Enforce by iterating the table in the test so a new command without help text fails CI.
- [ ] Test: unknown flag ⇒ exit 2 with a message naming the flag.
- [ ] Test: `--bind` as the last argument with no value ⇒ exit 2, no panic.
- [ ] Test: `--data-dir` fully isolates state; a test can run without touching `$HOME`.
- [ ] Test: `--json` output parses and has a stable documented shape.

---

### WP-09 — Port management and `status`

**Fixes:** D17. *Parallel-safe.* **Files:** `cmd/sentinel/serve.go`, `cmd/sentinel/mcp.go`, new `internal/runtime/`.

- Default ports become distinct and documented: egress `18449`, MCP HTTP `18450`, LLM gateway `18451`. All overridable by flag and env.
- `--port 0` picks a free port and prints the chosen address.
- On bind failure, say which port and which process type is expected there, and suggest `--port`.
- Write `~/.sentinel/run/<service>.json` with `{pid, addr, service, started_at, version}` on start; remove on clean shutdown; detect and clear stale files by checking the pid.
- New `sentinel status`: which gateways are up, on which addresses, vault path, key source (keychain / passphrase), policy mtime, secret count, expired count. Never prints values.
- Graceful shutdown on SIGINT/SIGTERM: stop listeners, flush audit, zero keys. Replace the bare `select {}` in `cmdMCPServe`.

**Acceptance criteria**

- [ ] Test: two gateways start simultaneously with defaults and do not collide.
- [ ] Test: `--port 0` prints a parseable address that accepts a connection.
- [ ] Test: a stale run file with a dead pid is cleaned up, not reported as running.
- [ ] Test: SIGTERM ⇒ exit 0, run file removed, audit file ends with a complete JSON line.
- [ ] README's `mcp serve` / `llm-serve` port-collision note is deleted because the collision is gone.

---

## P2 — The decision moment

### WP-10 — Approval broker

**Fixes:** D7. **Depends on:** WP-04, WP-06, WP-09. **This is the flagship feature.** **Files:** new `internal/broker/`, `cmd/sentinel/`, GUI.

Today `mcp run --mode inject` hands over real credentials with no gate. Introduce a broker that every resolution path must go through.

```go
type Request struct {
    Secret    string        // vault name
    Consumer  string        // "mcp:<profile>:<child argv0>" | "egress:<host>" | "gui" | "cli"
    Dest      string        // host or tool name
    Reason    string        // "env injection" | "header substitution" | ...
    Requested time.Time
}

type Decision struct {
    Allow bool
    TTL   time.Duration  // 0 = single use
    Scope string         // "once" | "session" | "until"
    Rule  string         // which policy rule or "interactive"
}

type Broker interface { Ask(context.Context, Request) (Decision, error) }
```

Three implementations:

1. **Policy** — decides from `policy.yaml` without a human. Default for CI and headless use.
2. **Interactive** — prompts on the controlling terminal:
   `agent "filesystem-mcp" requests snt://github_token for api.github.com — [o]nce / [s]ession / [1]5m / [d]eny?`
3. **Auto** — allow-all, requires `--yes-i-know` and prints a warning. Exists only so the tests and demos are not annoying. Never the default.

Policy additions:

```yaml
approvals:
  default: ask            # ask | allow | deny
  rules:
    - secret: github_token
      consumer: "mcp:dev:*"
      dest: api.github.com
      decision: allow
      ttl: 15m
    - secret: "prod_*"
      decision: deny
  grant_cache: 15m        # remember an interactive "session" grant this long
  max_uses_per_minute: 30
```

Rules:

- Grants are held in memory by the broker process, keyed by `(secret, consumer, dest)`, and expire. They are never written to disk.
- Every decision emits an audit event with the request fields and the resulting decision and rule. Never the value (I1, I4).
- Fail closed: no broker, no reachable terminal, and `default: ask` ⇒ deny with exit code 4.
- A denial must not kill the child process. Leave the placeholder unresolved and let the server fail on its own terms; log it.

**Acceptance criteria**

- [ ] Test: `inject` with `default: deny` ⇒ child env keeps `snt://…` literal, audit shows `approval_denied`, exit code 4 when the wrapper is asked to fail hard via `--strict`.
- [ ] Test: matching allow rule ⇒ resolved, audit shows the rule name and the TTL.
- [ ] Test: TTL expiry ⇒ second resolution re-asks.
- [ ] Test: glob matching on `secret` and `consumer`, including that `prod_*` deny beats a later allow (first match wins, documented).
- [ ] Test: rate limit trips at the configured threshold and emits `approval_rate_limited`.
- [ ] Test: interactive broker with a scripted pty; both accept and deny paths.
- [ ] Test: broker interface is the **only** caller of the decrypt-for-injection path. Enforce with a test that greps the package graph or with an unexported constructor.
- [ ] README quickstart step 5 rewritten around approvals; the "Use it only for trusted servers" caveat becomes "approval required by default".

---

### WP-11 — Bind enforcement in inject mode

**Fixes:** D7 (second half). **Depends on:** WP-10. **Files:** `internal/mcp/`, `internal/policy/`.

README currently admits: "MCP environment injection does not enforce proxy bindings". Close that gap.

- A secret with `hosts: [api.github.com]` may be injected into a child only if the child is declared to talk to that host. Declaration source, in order: `--dest` flag on `mcp run`, the profile's `hosts` list in policy, else **deny**.
- Add `mode: broker` as a third MCP mode: the placeholder stays in the child env and the child resolves it through a loopback endpoint that applies the broker per call. Strictly better than `inject`; make it the documented default once it works, keeping `inject` behind an explicit flag.
- Every injection records `(secret, child argv0, declared dests)` in the audit log.

**Acceptance criteria**

- [ ] Test: host-bound secret with no declared dest ⇒ refused, named error.
- [ ] Test: declared dest matching the binding ⇒ allowed.
- [ ] Test: wildcard binding (`*`) requires `--allow-unbound` and warns.
- [ ] Test: `mode: broker` end-to-end against a stub MCP server in `testdata`.
- [ ] `_ = mode` and similar discard statements are gone from `internal/mcp/gateway.go`.

---

### WP-12 — Profiles, for real

**Fixes:** D11. **Depends on:** WP-10. **Files:** `internal/policy/`, `internal/mcp/`.

Replace the `mcp:deny:<tool>` entity hack with a first-class schema:

```yaml
profiles:
  dev:
    secrets: [github_token, openai_key]
    hosts: [api.github.com, api.openai.com]
    deny_tools: [shell, write_file]
    allow_tools: []          # empty = all except deny_tools
    scrub_to_llm: pseudonymize
    approvals: ask
  ci:
    secrets: []
    approvals: deny
```

- `--profile NAME` selects it; unknown name ⇒ exit 2. No profile ⇒ a built-in `default` profile that denies nothing but approves nothing automatically.
- `allow_tools` non-empty means allowlist mode: everything else is denied.
- Blocking must cover `tools/call`, `resources/read`, and `prompts/get`.

**Acceptance criteria**

- [ ] Test: a tool denied in profile `a` is allowed in profile `b` in the same policy file.
- [ ] Test: allowlist mode denies an unlisted tool.
- [ ] Test: unknown profile ⇒ exit 2.
- [ ] Test: `mcp:deny:*` entity keys are no longer consulted; a migration warning is printed if any are found.
- [ ] Denials return a well-formed JSON-RPC error with the **request's own id**, not `null` as `writeErr` does today.

---

## P3 — Adoption surface

### WP-13 — `scan` as a CI gate

**Fixes:** D21. *Parallel-safe.* **Files:** `cmd/sentinel/`, `internal/scrubber/`, new `.github/workflows/` example, new `action.yml`.

- Exit codes: `0` clean, `3` findings at or above threshold, `1` operational error. Documented as a stable contract.
- `--min-confidence`, `--fail-on TYPE,TYPE`, `--format text|json|sarif`.
- SARIF output so GitHub code scanning renders findings inline. This is the single highest-leverage adoption feature in the repo.
- `--redact` (default in non-TTY) and the fingerprints from WP-03.
- Recursive directory scan honouring `.gitignore` plus a new `.sentinelignore` (same syntax, path and pattern rules documented).
- `sentinel scan --staged` for a pre-commit hook; ship the hook in `scripts/`.
- Ship a composite GitHub Action at repo root `action.yml` so users write `uses: Ferrum-Sidereum/sentinel@v0`.

**Acceptance criteria**

- [ ] Test: clean fixture ⇒ exit 0; dirty fixture ⇒ exit 3.
- [ ] Test: `--fail-on CREDIT_CARD` ignores an `EMAIL`-only finding (exit 0).
- [ ] Test: SARIF output validates against the SARIF 2.1.0 schema and contains **no** secret values.
- [ ] Test: `.sentinelignore` excludes a path; `--no-ignore` includes it.
- [ ] Test: `--staged` uses the git index, not the working tree.
- [ ] Self-hosting: this repository runs its own action in CI and is clean.

---

### WP-14 — `doctor`

*Parallel-safe.* **Depends on:** WP-09 for the run-file checks. **Files:** new `cmd/sentinel/doctor.go`.

One command that resolves the whole Troubleshooting table. Each check reports `ok` / `warn` / `fail`, a one-line explanation, and a copy-pasteable fix.

Checks: binary on `PATH`; data dir exists with correct permissions; keychain reachable; key source and whether it matches the vault (verifier probe); vault opens and record count; policy parses and unknown keys reported; CA present, not expired, and whether the platform trust store has it; default ports free or owned by our own run files; Go toolchain version if the source tree is present; MCP client configs found on disk and whether their `sentinel` paths are absolute and exist; clock skew.

**Acceptance criteria**

- [ ] Every row of the README Troubleshooting table maps to a named check. Assert the mapping in a test using a table shared with the docs generator.
- [ ] Test: each check has both a passing and a failing fixture.
- [ ] `--json` output; exit 0 when no `fail`, 1 otherwise.
- [ ] Runs without a vault and says what to do (`sentinel init`), rather than erroring.

---

### WP-15 — Client config generator

*Parallel-safe.* **Files:** new `cmd/sentinel/client.go`, `examples/`.

Manual absolute paths and JSON backslash escaping on Windows are the top onboarding failure.

- `sentinel client add claude|cursor|vscode|windsurf --name NAME --profile P -- <cmd...>`: locates the client's config file per OS, inserts an `mcpServers` entry with the absolute path to the running `sentinel` binary, correct escaping, and the placeholder env mapping.
- `--dry-run` prints the JSON. `--print-only` never touches user files. Always back up the original next to it before writing.
- `sentinel client ls` shows detected clients and the Sentinel-managed entries in each.
- Regenerate `examples/claude_desktop_config.json` and `examples/cursor_mcp.json` from the same code path so they cannot drift.

**Acceptance criteria**

- [ ] Test per client per OS with a fake home directory; assert exact JSON output.
- [ ] Test: Windows paths escape correctly and round-trip through `json.Unmarshal`.
- [ ] Test: an existing unrelated `mcpServers` entry is preserved.
- [ ] Test: re-running is idempotent (no duplicate entry).
- [ ] Test: the committed `examples/*.json` match generator output; drift fails CI.

---

### WP-16 — Release binaries

*Parallel-safe.* **Depends on:** WP-05. **Files:** `.github/workflows/release.yml`, `.goreleaser.yaml`.

- Tag-triggered goreleaser build of the CLI for darwin/linux/windows × amd64/arm64.
- Checksums, and cosign keyless signing of artifacts and checksums.
- Homebrew tap and Scoop manifest for the CLI.
- SBOM per artifact.
- `sentinel version` reports the release tag.
- Docs: an install section that does not require a Go toolchain, replacing "not a promise of downloadable release binaries".

**Acceptance criteria**

- [ ] A prerelease tag produces all artifacts and they run `sentinel version` successfully on each OS in CI.
- [ ] Checksums verify; signature verification documented and tested in CI.
- [ ] Desktop builds are explicitly out of scope for this WP; say so in the release notes template.

---

## P4 — Observability and polish

### WP-17 — Tamper-evident audit + live tail

**Fixes:** D18. **Files:** `internal/audit/`, `cmd/sentinel/`.

- Each record gains `seq`, `ts` (RFC3339 UTC), `prev_hash`, `hash = sha256(canonical(record without hash) || prev_hash)`. Genesis record with a zero `prev_hash`.
- `sentinel audit verify` walks the chain and reports the first break with its sequence number.
- `sentinel audit tail -f` streams new records; `--since 1h`, `--type approval_denied`, `--secret NAME`, `--json`.
- Rotation honouring `policy.audit.retention`, with size-based rotation as a second trigger. Rotation must not break the chain: carry `prev_hash` into the new file's header.
- Fsync policy: durable write for security-relevant events (`approval_*`, `secret_*`), buffered for the rest.
- Assert in a test that no audit field can carry a secret value: audit payloads accept only a fixed set of typed fields, not arbitrary `any`.

**Acceptance criteria**

- [ ] Test: `verify` passes on a generated log, fails on a byte-flipped one and names the record.
- [ ] Test: rotation preserves chain continuity across files.
- [ ] Test: `tail -f` observes a record written by another process within 200 ms.
- [ ] Test: retention prunes by age and by size.
- [ ] Test: attempting to log a value that matches a stored secret is rejected or redacted by construction.

---

### WP-18 — `policy test`

**Files:** `cmd/sentinel/`, `internal/policy/`.

README says: "do not assume every gateway enforces every policy field. Review the relevant implementation." Replace that sentence with a tool.

- `sentinel policy lint` — schema validation, unknown keys, unreachable rules, invalid regexes in `custom_patterns`, contradictory approval rules. Exit 2 on error.
- `sentinel policy test --dest llm|untrusted|host:<h> --tool <name> [file]` — dry run over a sample; prints which entity rules fired, the resulting mode, and the transformed output with values redacted.
- `sentinel policy explain <field>` — prints which gateways actually read that field, generated from code annotations, so the coverage gaps are visible rather than folkloric.
- `sentinel policy diff <a> <b>` — behavioural diff between two policy files over a fixture corpus.

**Acceptance criteria**

- [ ] Test: an invalid regex in `custom_patterns` is caught by `lint`, not at runtime.
- [ ] Test: `policy test` on a fixture reports the exact rule that fired.
- [ ] Test: `policy explain` output is generated, not hand-maintained; adding a new policy field without wiring fails the test.
- [ ] README's "do not assume" caveat replaced by a pointer to `policy explain`.

---

### WP-19 — MCP protocol conformance

**Fixes:** D8, D12, D13, D14, D15. **Files:** `internal/mcp/`.

- Rewrite framing: detect the peer's framing once, then **respond in the same framing**. Handle `Content-Length` fully, honour `io.ReadFull` errors, enforce a max frame size, and reject malformed headers instead of falling through to line mode.
- Scrub by JSON **shape**, not by a hardcoded key list: walk every string leaf, with a configurable skip list for fields where redaction would break the protocol (`jsonrpc`, `id`, `method`, `uri`, schema fields). Document the skip list.
- Extend inbound checks to `resources/read`, `prompts/get`, and `completion/complete`. Report **all** findings, not just the first.
- Capture child `stderr`, scrub it through the same pipeline, then forward. Never pass it through raw.
- Propagate the child's exit code; on child crash, emit a JSON-RPC error to the client before exiting.
- Handle EOF and broken pipe on both directions without deadlock; add a context so shutdown is deterministic.
- Never buffer an unbounded frame: cap and error.

**Acceptance criteria**

- [ ] Test: `Content-Length`-framed client gets `Content-Length`-framed responses.
- [ ] Test: truncated `Content-Length` body ⇒ named error, no hang, no partial forward.
- [ ] Test: a secret in a field named `output` (not in the old key list) is scrubbed.
- [ ] Test: a secret written to child stderr is scrubbed before reaching the terminal.
- [ ] Test: child exits 7 ⇒ `sentinel` exits 7.
- [ ] Test: child killed mid-request ⇒ client receives a JSON-RPC error with the correct id.
- [ ] Test: 10 MiB frame ⇒ rejected, not buffered.
- [ ] Fuzz target for `readFrame`; runs in CI for 30s.

---

### WP-20 — GUI: activity, onboarding, tray

**Depends on:** WP-07, WP-10, WP-17. **Files:** `cmd/sentinel-gui/`.

- **Activity view:** live audit feed ("which agent asked for which secret, when, allowed or denied"), filterable, backed by WP-17's tail. `internal/metrics` already exists: surface counts of resolutions, denials, and redactions.
- **Approval surface:** when the desktop app is running it becomes the interactive broker, with a native prompt and one-click once / 15m / session / deny. This is the product's signature interaction; give it real design attention.
- **Onboarding wizard:** keychain check ⇒ init ⇒ add first secret ⇒ generate a client config (WP-15) ⇒ verify with a live test call. Every step shows the equivalent CLI command so the GUI teaches the CLI.
- **Tray:** status dot for each gateway, quick pause of all egress, recent-denials badge.
- **Secret list:** last used, use count, expiry, bound hosts, and a masked value with a confirmed, audited reveal.

**Acceptance criteria**

- [ ] Frontend `typecheck` and `build` pass; Go-side handlers unit-tested in `app_test.go` style.
- [ ] Test: approval prompt round-trips a decision to the broker; timeout ⇒ deny.
- [ ] Test: reveal emits an audit event and is refused when the app is locked.
- [ ] No secret value crosses the Wails bridge unless the user just confirmed a reveal.
- [ ] Wizard is idempotent and safe to re-run against an existing install.

---

## 5. Cross-cutting test strategy

| Layer | Requirement |
|:--|:--|
| Unit | Every new exported function. Table-driven. |
| Golden | CLI stdout/stderr for `ls`, `scan`, `status`, `doctor`, `--json` shapes. |
| Migration | One fixture per schema version, asserting byte-identical plaintext after migration. |
| Integration | Stub MCP server and stub HTTPS origin in `testdata/`; full `mcp run` and `run --` flows. |
| Fuzz | `readFrame`, placeholder parsing, policy YAML loading. |
| Race | `go test -race ./...` in CI on all three OSes. |
| **Leak assertion** | A shared helper `assertNoSecretIn(t, output, secrets...)` used by every test that captures output. Any new command must use it. |

Tests must never write to the real `~/.sentinel` or the real OS keychain. Use `--data-dir` and the injected credential store.

---

## 6. Out of scope for this spec

Do not build these without a spec amendment: multi-user or server-side vaults, cloud sync, team RBAC, browser extensions, non-MCP agent frameworks, secret discovery by scanning remote repos, mobile clients, a plugin system.

---

## 7. Amendment process

Amend by PR touching only this file plus, if needed, the WP being redefined. State: what changed, why, and which acceptance criteria are added or removed. Update the status table in the same PR that lands the code.
