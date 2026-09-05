# Sentinel

<p align="center">
  <a href="README.md"><strong>English</strong></a> ·
  <a href="README.ru.md">Русский</a>
</p>

<table>
  <tr>
    <td>
      <strong>Give agents references, not your keys.</strong><br>
      Sentinel is a local security companion for AI workflows: a secret vault, sensitive-data scanner, outbound HTTP(S) proxy, LLM gateway and MCP wrapper. Use references such as <code>snt://demo_token</code> in place of credentials, then choose explicitly where real values become available.
    </td>
  </tr>
</table>

**Development status:** experimental. This guide was checked against source code, not a successful build or end-to-end run. It is not a security audit or a production-readiness claim. Start with disposable test values and read [Security notes](#security-notes) before connecting real accounts.

## Stack

| Core | Desktop | Storage | Integrations |
|:--|:--|:--|:--|
| **Go**<br>CLI and local gateways | **Wails v2**<br>React · TypeScript · Vite | **SQLite**<br>Encrypted secret values · OS keychain | **HTTP(S) · LLM · MCP**<br>Outbound proxy and stdio wrapper |

## Choose your entry point

| You want to… | Start with… | Important distinction |
|:--|:--|:--|
| Store a secret and refer to it by name | `init`, `add`, `ls` | Storage alone does not protect other applications. |
| Inspect a file or pasted text | `scan` | Reports findings; does not rewrite or sanitize the input. |
| Run a proxy-aware program | `run -- <command>` | Starts the outbound proxy and sets proxy/CA environment variables. Not a sandbox. |
| Connect a local MCP server | `mcp run --mode inject -- <command>` | Resolves environment placeholders into real secrets for the child process. Trust that process. |
| Keep placeholders in an MCP child's environment | `mcp run --mode proxy -- <command>` | Requires a separately running outbound proxy and a compatible client. |

The [desktop shell](cmd/sentinel-gui) exposes vault management, scanning and policy editing. It is not a substitute for starting or connecting the CLI gateways. This quickstart uses CLI-created entries because desktop/CLI secret naming and host-binding metadata currently differ.

## Installation

### CLI from source

Requirements: Git, the Go toolchain required by [go.mod](go.mod), and access to an OS credential store. The current module declares **Go 1.27.0**. Confirm that this toolchain and the pinned dependencies are available in your environment; if not, installation is blocked. Do not simply lower the version directive and assume compatibility. Node.js and Wails are not needed for the CLI.

```bash
git clone https://github.com/Ferrum-Sidereum/sentinel.git
cd sentinel
go version
go mod download
go install ./cmd/sentinel
```

`go install` writes the executable to `GOBIN`, or to the first `GOPATH` entry's `bin` directory when `GOBIN` is unset. Add that directory to your `PATH`. With the default Go configuration:

```bash
# macOS / Linux, for this shell session
export PATH="$(go env GOPATH)/bin:$PATH"
```

```powershell
# Windows PowerShell, for this shell session
$env:Path = "$(go env GOPATH)\bin;$env:Path"
```

If you have configured `GOBIN`, use that directory instead. The commands below assume `sentinel` is on `PATH`. These are source-install instructions, not a promise of downloadable release binaries or tested platform support.

### Desktop development (optional)

Install Node.js/npm and the native prerequisites for Wails v2 on your platform. Use the Wails version pinned by this repository:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
cd cmd/sentinel-gui
wails doctor
wails dev
```

Run `wails build` from the same directory to request a desktop build. Wails invokes the frontend install/build scripts from [wails.json](cmd/sentinel-gui/wails.json). This workflow has not been executed as part of this documentation change.

## Quickstart

### 1. Initialize local storage

```bash
sentinel init
```

This creates local state under `~/.sentinel` (the current user's home directory), including `vault.db` and an initial `policy.yaml`. On the normal path, the master key is stored in the OS keychain.

**If initialization asks for a fallback passphrase, stop before using real secrets.** The current implementation writes that passphrase in plaintext to `~/.sentinel/passphrase`. Its prompt does not accurately describe storage protection; see [Security notes](#security-notes).

### 2. Add a disposable secret

```bash
sentinel add demo_token --bind api.example.com --header Authorization --kind bearer
```

At `value:`, enter this dummy value, not a real credential:

```text
sentinel-demo-value-1234567890
```

```bash
sentinel ls
```

The entry is named `demo_token`; its canonical reference is `snt://demo_token`. `api.example.com` is an illustrative binding, not a working test API. For a real integration, use only the intended API hostname, without a scheme or path. The command reads the value from stdin, but interactive input is not hidden.

The proxy substitutes text in an existing request; `--kind bearer` does not create an Authorization header for you. A compatible request would explicitly contain `Authorization: Bearer snt://demo_token`.

### 3. Scan text or a file

```bash
# macOS / Linux: scan the dummy value from stdin
printf '%s\n' 'sentinel-demo-value-1234567890' | sentinel scan
```

```powershell
# Windows PowerShell
'sentinel-demo-value-1234567890' | sentinel scan
```

Or create a UTF-8 file named `sample.txt` containing the dummy value and run:

```bash
sentinel scan sample.txt
```

For a working initialized vault, a known-value match should appear with a detector and confidence score. **CLI findings include the matched text itself.** Do not paste output containing real secrets into tickets, chats or CI logs. No findings is not proof that the input is safe, and `scan` does not provide a documented leak-detection exit-code contract for CI gating.

### 4. Run a program through the outbound proxy

With curl installed:

```bash
sentinel run -- curl https://example.com
```

On Windows PowerShell, use `curl.exe` in place of `curl` if needed. This is a routing smoke test with no credential, not a secret-injection test. It needs network access and a free local port `18449`.

`run` starts a proxy at `127.0.0.1:18449`, supplies `HTTP_PROXY`, `HTTPS_PROXY` and `SSL_CERT_FILE` (plus lowercase proxy variables), and launches the child. It does **not** populate that child's environment with placeholders from every vault entry. Supply only the placeholders your application actually needs.

Only clients that honor this proxy configuration are routed through Sentinel. HTTPS interception is selected for hosts bound to vault entries; other HTTPS destinations are tunneled without content inspection. Intercepted connections require the client to trust `~/.sentinel/ca.pem`. Some clients ignore `SSL_CERT_FILE` and need their own CA configuration. Do not work around certificate errors by disabling TLS verification.

`sentinel trust-ca` modifies the current user's Windows Root certificate store using `certutil`; it is not a cross-platform setup step. Prefer client-scoped trust while evaluating the project. Do not start `serve` and `run` on the same port at the same time.

### 5. Wrap a local MCP server

Install and test your chosen MCP server separately. Sentinel does not install it. In this example, Node.js and `/absolute/path/to/server.js` stand for an **existing, trusted stdio MCP server**; replace the executable, path and environment variable with those required by your server.

For an MCP client with a `mcpServers` configuration:

```json
{
  "mcpServers": {
    "sentinel-demo": {
      "command": "/absolute/path/to/sentinel",
      "args": ["mcp", "run", "--mode", "inject", "--", "node", "/absolute/path/to/server.js"],
      "env": {
        "API_TOKEN": "snt://demo_token"
      }
    }
  }
}
```

Use the absolute `sentinel.exe` path on Windows and escape backslashes in JSON. The executable path avoids differences between your terminal's `PATH` and the desktop client's environment.

Equivalent POSIX-shell launch syntax:

```bash
API_TOKEN='snt://demo_token' sentinel mcp run --mode inject -- node /absolute/path/to/server.js
```

This command speaks MCP over stdin/stdout; it is not an interactive chat prompt. A server waiting for client messages may appear idle. `inject` resolves the reference into the real child-process environment value, without applying the outbound proxy's host-binding checks. Use it only for trusted servers. The wrapper filters supported MCP text fields, not arbitrary output or child stderr.

For `proxy` mode, start the outbound proxy in a separate terminal:

```bash
sentinel serve 127.0.0.1:18449
```

Then launch the MCP wrapper from the client with `--mode proxy`, retaining placeholder environment values and configuring the child to use `http://127.0.0.1:18449` and the appropriate CA trust. `mcp run --mode proxy` does not start this proxy itself. Verify actual client routing before relying on it.

Additional templates: [Claude Desktop configuration](examples/claude_desktop_config.json) · [Cursor configuration](examples/cursor_mcp.json). Review paths, server packages, token variable names and trust boundaries before use; these are examples, not tested turnkey integrations.

## Local data and configuration

| Location | Purpose |
|:--|:--|
| `~/.sentinel/vault.db` | Secret vault. |
| OS keychain, service `sentinel-master` | CLI master-key storage on the normal path. |
| `~/.sentinel/passphrase` | Insecure plaintext fallback, if created. |
| `~/.sentinel/policy.yaml` | Filtering configuration. |
| `~/.sentinel/audit.jsonl` | Local audit events from supported operations. |
| `~/.sentinel/ca.pem` | Local CA certificate used for intercepted HTTPS. |

Back up vault data and matching key material securely. Do not commit the data directory, credentials or CA private material. A database copy without its matching key is not a recovery plan. The initial policy includes unknown-host tunneling, LLM pseudonymization and untrusted-output masking settings; do not assume every gateway enforces every policy field. Review the relevant implementation before relying on a rule.

## Security notes

- **Experimental, not a security boundary against hostile local code.** Sentinel does not isolate processes or force all network traffic through itself. A malicious or incompatible client can bypass proxy environment variables.
- **Plaintext fallback:** CLI initialization can write a passphrase to disk, and key derivation uses Argon2id with a fixed salt. This does not protect against an attacker who can read both fallback material and the vault. File permissions are not encryption. Do not use this fallback for production credentials.
- **Key recovery needs care:** the CLI can attempt to create a new master key after a keychain lookup failure. Stop on unexpected keychain or decryption errors; do not repeatedly initialize an existing vault or discard its original key.
- **Secrets can still reach processes and terminals.** MCP `inject` deliberately gives the child real secrets. `add` input may echo, `scan` prints matched values, and MCP child stderr is passed through unchanged.
- **No blanket sanitization guarantee.** MCP filtering covers selected JSON text fields. Unbound HTTPS tunnels are not inspected. Encoded data, unsupported protocols and client bypasses must be tested separately. Proxy substitution is not a universal data-loss-prevention system.
- **Bindings have limits.** MCP environment injection does not enforce proxy bindings, and a proxy header allowlist is not a guarantee that a secret cannot be substituted into a URL or body. Use tightly scoped test credentials and inspect the exact path you depend on.
- **Keep listeners local.** Use loopback addresses, not `0.0.0.0` or public interfaces. Do not expose the proxies as network services without a separate security review.
- **CA trust is powerful.** Installing a root certificate changes the trust boundary. Protect private CA material and prefer per-client trust. Never use `--insecure` as a setup fix.
- **Desktop and CLI are not yet interchangeable.** Desktop-created entries currently use different name conventions and omit the CLI's host-binding metadata. Use the CLI throughout this quickstart; do not assume a desktop entry can be injected by the proxy.

## Repository map

| Path | Contents |
|:--|:--|
| [`cmd/sentinel`](cmd/sentinel) | CLI entry points and commands. |
| [`cmd/sentinel-gui`](cmd/sentinel-gui) | Wails desktop shell and React frontend. |
| [`internal`](internal) | Vault, keyring, policy, scanner, CA, proxy, LLM, MCP and supporting packages. |
| [`examples`](examples) | MCP client configuration templates. |
| [`scripts`](scripts) | Existing Windows helper and verification scripts. |
| [`testdata`](testdata) | Test fixtures. |

## Development checks

From the repository root, with the required Go toolchain installed:

```bash
go build ./cmd/sentinel
go test ./internal/... ./cmd/sentinel
go vet ./internal/... ./cmd/sentinel
```

Frontend checks, separately:

```bash
cd cmd/sentinel-gui/frontend
npm ci
npm run typecheck
npm run build
```

Desktop checks require the native Wails prerequisites and generated frontend assets; use `wails doctor` and `wails build` from `cmd/sentinel-gui`, then run the GUI package tests in that environment. The commands above are verification instructions, not recorded passing results. This documentation change did not execute Go tests, launch the desktop app or verify real API/MCP traffic.

## Troubleshooting

| Symptom | Check |
|:--|:--|
| `sentinel` is not found | Add the Go install directory to `PATH`; use an absolute path in MCP clients. |
| Go toolchain or dependency download fails | Confirm availability of the versions pinned in `go.mod` and network access to the module sources. |
| Initialization requests a passphrase | Stop before adding real credentials; fix OS keychain access instead of relying on the plaintext fallback. |
| Port is already in use | `run` uses `18449`; do not run another outbound proxy on that port. |
| TLS verification fails | Configure the client's trust for the local CA, without disabling verification. |
| MCP appears to hang | Launch it from an MCP client; confirm the child executable, absolute paths and environment variable names. |
| A placeholder is not resolved | Confirm that the entry was added through the CLI, its name matches, and the correct injection mode or proxy route is active. |

`mcp serve` and `llm-serve` both default to port `18450`; assign different addresses if running both. The current no-argument CLI usage lists only some commands, so it is not a complete reference.
