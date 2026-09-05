# README quickstart checks

[Workflow](../.github/workflows/readme-quickstarts.yml) · [Test harness](test-readme-quickstarts.py)

GitHub Actions runs on pushes to `main`, pull requests and manual dispatch. It uses the Go version in `go.mod`; unavailable toolchains or dependencies fail setup rather than silently selecting another version. The job has read-only repository permissions, does not persist checkout credentials and does not use repository secrets.

## Coverage

| README path | Assertion |
|:--|:--|
| Source installation | Downloads and verifies modules, then runs `go install ./cmd/sentinel` into a temporary executable directory. |
| Both language versions | Checks the fenced CLI commands and parses the documented MCP configuration. Intentional example changes require updating the harness. |
| `init` | Starts with a temporary HOME; verifies database, policy and disposable fallback material are created. |
| `add`, `ls` | Adds the README dummy value and confirms its reference persists across separate CLI processes. |
| `scan` | Requires known-secret findings, matched dummy text and confidence output for stdin and file input. |
| `run` | Uses curl against a loopback HTTP origin. A second, host-bound dummy secret must arrive as a real header, with a proxy injection audit event. |
| `mcp run --mode inject` | A local stdio fixture completes initialization, tool discovery and a tool call. Asserts that the child receives the dummy secret but the client does not receive it back in text. |
| `mcp run --mode proxy` | The same round trip asserts that the child retains its placeholder. This checks environment semantics, not MCP server network routing. |
| Core code | Runs CLI/core package tests and `go vet`. |

The harness checks Markdown contracts but does not execute arbitrary code extracted from Markdown. `example.com` is replaced with a local HTTP origin, and the Node.js example MCP server is replaced with a small Python stdio peer. These substitutions make the tests deterministic without an API account, third-party server package or public endpoint. They are not claims that the external integrations have been tested.

## Run locally

Linux only; requires the project's Go toolchain, Python 3.10+ and curl. Run from the repository root:

```bash
go install ./cmd/sentinel
python3 scripts/test-readme-quickstarts.py --sentinel "$(go env GOPATH)/bin/sentinel"
```

If `GOBIN` is configured, use its executable path instead. Port `18449` must be free. The HTTP fixture selects its own ephemeral origin port. Every CLI subprocess has a timeout, and the temporary HOME is cleaned up on normal completion and test exceptions.

## Deliberate security constraints

The harness forces keychain access to fail using a nonexistent D-Bus session socket inside its temporary HOME. It then initializes the **existing insecure plaintext fallback with a disposable test passphrase**. This tests the current headless behavior without touching the runner's real keychain, installing a root certificate or providing production credentials. It does not endorse the fallback. Once fallback handling is fixed, update the harness to test the replacement rather than reintroducing plaintext storage to satisfy CI.

No vaults, logs, fallback files or CA material are uploaded as artifacts. The workflow summary describes scope even when a step fails; only the individual step/job results establish success.

## Not covered

Native OS keychains; Windows/macOS installation; PowerShell command execution; GUI builds and GUI/CLI interoperability; external API credentials; real Claude Desktop or Cursor integration; HTTPS CONNECT/interception and certificate trust; full MCP protocol conformance; or resistance to malicious clients. A green run demonstrates only the contracts above, not production readiness or a security audit.

These checks were added without a local Go runtime. The first Actions run is the first opportunity to establish actual build and CLI execution results. Failures should be investigated, not changed into skipped or always-passing tests.
