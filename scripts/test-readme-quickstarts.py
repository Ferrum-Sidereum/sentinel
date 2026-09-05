#!/usr/bin/env python3
"""README CLI integration contracts, using disposable data and local fixtures.

Run from any directory:
  python3 scripts/test-readme-quickstarts.py --sentinel /absolute/path/to/sentinel

See scripts/README-quickstarts.md for boundaries. No third-party Python packages.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
DUMMY = "sentinel-demo-value-1234567890"
REFERENCE = "snt://demo_token"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def mcp_fixture() -> None:
    """Tiny real stdio peer: initialization, tools/list, tools/call and EOF."""
    token = os.environ.get("API_TOKEN", "")
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sentinel-ci-fixture", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": [{
                "name": "probe",
                "description": "Inspect disposable test environment only",
                "inputSchema": {"type": "object", "properties": {}},
            }]}
        elif method == "tools/call":
            result = {
                "content": [{"type": "text", "text": "fixture value: " + token}],
                "_meta": {
                    "injected": token == DUMMY,
                    "placeholderRetained": token == REFERENCE,
                },
            }
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                              "error": {"code": -32601, "message": "Unknown method"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


def check_readmes() -> None:
    # Check only fenced examples, never execute arbitrary Markdown as shell code.
    # New or intentionally changed command contracts require updating this harness.
    required = [
        "go install ./cmd/sentinel",
        "sentinel init",
        "sentinel add demo_token --bind api.example.com --header Authorization --kind bearer",
        "sentinel ls",
        "printf '%s\\n' 'sentinel-demo-value-1234567890' | sentinel scan",
        "sentinel scan sample.txt",
        "sentinel run -- curl https://example.com",
        "API_TOKEN='snt://demo_token' sentinel mcp run --mode inject -- node /absolute/path/to/server.js",
    ]
    for name in ("README.md", "README.ru.md"):
        source = (ROOT / name).read_text(encoding="utf-8")
        blocks = re.findall(r"```([^\n]*)\n(.*?)```", source, flags=re.S)
        shell_lines = {line.strip() for lang, body in blocks if lang.strip() == "bash"
                       for line in body.splitlines()}
        for command in required:
            require(command in shell_lines, f"{name}: quickstart contract changed: {command}")
        configs = [json.loads(body) for lang, body in blocks if lang.strip() == "json"]
        peers = [config.get("mcpServers", {}).get("sentinel-demo") for config in configs]
        require(any(peer and peer.get("command") == "/absolute/path/to/sentinel"
                    and peer.get("args") == ["mcp", "run", "--mode", "inject", "--",
                                             "node", "/absolute/path/to/server.js"]
                    and peer.get("env", {}).get("API_TOKEN") == REFERENCE
                    for peer in peers), f"{name}: MCP configuration contract changed")
        print(f"PASS {name}: documented CLI and MCP contracts", flush=True)


def exercise(binary: str) -> None:
    curl = shutil.which("curl")
    require(curl is not None, "curl is required for the run quickstart")
    with tempfile.TemporaryDirectory(prefix="sentinel-readme-") as directory:
        home = Path(directory)
        env = os.environ.copy()
        # No inherited credentials/proxy configuration are needed for any child.
        for name in list(env):
            if name.lower().endswith("_proxy") or name in ("API_TOKEN", "SSL_CERT_FILE", "SSL_CERT_DIR"):
                env.pop(name, None)
        env.update({
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CACHE_HOME": str(home / "cache"),
            # A nonexistent explicit session bus prevents touching any real keyring.
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(home / "no-session-bus"),
        })

        def cli(*args: str, stdin: str = "", extra: dict | None = None) -> str:
            child_env = dict(env)
            child_env.update(extra or {})
            result = subprocess.run([binary, *args], input=stdin, text=True,
                                    capture_output=True, cwd=home, env=child_env, timeout=35)
            require(result.returncode == 0,
                    f"sentinel {args[0]} failed ({result.returncode})\n"
                    f"stdout: {result.stdout}\nstderr: {result.stderr}")
            return result.stdout

        cli("init", stdin="ci-only-disposable-passphrase\n")
        state = home / ".sentinel"
        for name in ("vault.db", "policy.yaml", "passphrase"):
            require((state / name).is_file(), f"init did not create {name}")
        require((state / "passphrase").read_text() == "ci-only-disposable-passphrase",
                "fallback fixture changed; review the test isolation and security notes")
        print("PASS init: isolated disposable fallback vault (not native keychain coverage)", flush=True)

        added = cli("add", "demo_token", "--bind", "api.example.com", "--header",
                    "Authorization", "--kind", "bearer", stdin=DUMMY + "\n")
        require(REFERENCE in added, "add did not return the documented reference")
        require(REFERENCE in cli("ls"), "ls did not persist the newly added entry")
        print("PASS add / ls: stored reference survives a separate process", flush=True)

        (home / "sample.txt").write_text(DUMMY + "\n", encoding="utf-8")
        for args, data in (((), DUMMY + "\n"), (("sample.txt",), "")):
            output = cli("scan", *args, stdin=data)
            require(DUMMY in output and "SECRET" in output and "conf=" in output,
                    "scan failed to report the known vault value with confidence")
        print("PASS scan: stdin and file both find the dummy secret", flush=True)

        requests = []

        class Origin(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                authorization = self.headers.get("Authorization")
                requests.append((self.path, authorization))
                body = b"sentinel-local-origin-ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            # The local origin replaces example.com to avoid external uptime and DNS.
            # Empty noproxy is essential: curl normally bypasses proxies for localhost.
            flags = ["--noproxy", "", "--fail", "--silent", "--show-error", "--max-time", "10"]
            response = cli("run", "--", curl, *flags, url + "/smoke")
            require(response.strip() == "sentinel-local-origin-ok", "run did not fetch the local origin")
            cli("add", "local_demo", "--bind", "127.0.0.1", "--header", "Authorization",
                "--kind", "bearer", stdin="ci-local-only-value-9876543210\n")
            response = cli("run", "--", curl, *flags, "--header",
                           "Authorization: Bearer snt://local_demo", url + "/injection")
            require(response.strip() == "sentinel-local-origin-ok", "injection request failed")
            require(("/injection", "Bearer ci-local-only-value-9876543210") in requests,
                    "origin did not receive the injected dummy credential; proxy may have been bypassed")
            events = [json.loads(line) for line in (state / "audit.jsonl").read_text().splitlines() if line.strip()]
            require(any("secret_injected" in json.dumps(event) for event in events),
                    "no secret_injected audit event proves the proxy path")
            print("PASS run: local HTTP routing and actual proxy credential injection", flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "sentinel-ci", "version": "1.0.0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "probe", "arguments": {}}},
        ]
        wire = "".join(json.dumps(message) + "\n" for message in messages)
        for mode in ("inject", "proxy"):
            output = cli("mcp", "run", "--mode", mode, "--", sys.executable,
                         str(SELF), "--mcp-fixture", stdin=wire, extra={"API_TOKEN": REFERENCE})
            replies = [json.loads(line) for line in output.splitlines() if line.strip()]
            require(len(replies) == 3, f"MCP {mode}: expected three JSON-RPC replies")
            by_id = {reply.get("id"): reply for reply in replies}
            require(set(by_id) == {1, 2, 3}, f"MCP {mode}: response IDs not preserved")
            require(all(reply.get("jsonrpc") == "2.0" and "error" not in reply for reply in replies),
                    f"MCP {mode}: invalid or error response")
            require(by_id[1]["result"]["serverInfo"]["name"] == "sentinel-ci-fixture",
                    "MCP initialization did not reach fixture")
            require(by_id[2]["result"]["tools"][0]["name"] == "probe", "MCP tool discovery failed")
            meta = by_id[3]["result"]["_meta"]
            require(meta["injected"] == (mode == "inject"), f"MCP {mode}: wrong injection behavior")
            require(meta["placeholderRetained"] == (mode == "proxy"),
                    f"MCP {mode}: wrong placeholder behavior")
            require(DUMMY not in output, f"MCP {mode}: dummy secret leaked to client")
            if mode == "inject":
                require(by_id[3]["result"]["content"][0]["text"] != "fixture value: " + DUMMY,
                        "MCP inject did not scrub returned secret text")
            print(f"PASS mcp {mode}: initialize, tool discovery, tool call and secret handling", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sentinel")
    parser.add_argument("--mcp-fixture", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.mcp_fixture:
        mcp_fixture()
        return
    if not args.sentinel:
        parser.error("--sentinel is required")
    require(sys.platform.startswith("linux"), "This headless fallback harness is Linux-only")
    binary = Path(args.sentinel).resolve()
    require(binary.is_file(), "Build/install the sentinel CLI before running this harness")
    check_readmes()
    exercise(str(binary))
    print("PASS all README CLI smoke checks; see documentation for untested boundaries", flush=True)


if __name__ == "__main__":
    main()
