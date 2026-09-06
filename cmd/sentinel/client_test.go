package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testHome(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("SENTINEL_TEST_HOME", h)
	t.Setenv("APPDATA", filepath.Join(h, "AppData", "Roaming"))
	return h
}

func TestClientConfigPathPerOS(t *testing.T) {
	home := "/fake/home"
	cases := map[string]map[string]string{
		"claude":   {"windows": "Claude", "darwin": "Claude", "linux": ".config"},
		"cursor":   {"windows": ".cursor", "darwin": ".cursor", "linux": ".cursor"},
		"vscode":   {"windows": "Code", "darwin": "Code", "linux": ".config"},
		"windsurf": {"windows": ".codeium", "darwin": ".codeium", "linux": ".codeium"},
	}
	for client, oss := range cases {
		for osName, frag := range oss {
			p, err := clientConfigPath(client, osName, home)
			if err != nil {
				t.Fatalf("%s/%s: %v", client, osName, err)
			}
			if !strings.Contains(p, frag) {
				t.Fatalf("%s/%s: path %q lacks %q", client, osName, p, frag)
			}
		}
	}
	if _, err := clientConfigPath("nope", "linux", home); err == nil {
		t.Fatal("unknown client must error")
	}
}

func TestMergeExactJSON(t *testing.T) {
	e := clientEntry{Command: "/usr/bin/sentinel", Args: []string{"mcp", "run", "--mode", "inject", "--", "npx", "x"}, Env: map[string]string{"K": "snt://v"}}
	out, err := mergeConfig(nil, "srv", e)
	if err != nil {
		t.Fatal(err)
	}
	var cfg clientConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MCPServers["srv"].Command != "/usr/bin/sentinel" {
		t.Fatalf("got %+v", cfg.MCPServers["srv"])
	}
	if cfg.MCPServers["srv"].Env["K"] != "snt://v" {
		t.Fatal("env lost")
	}
}

func TestWindowsPathRoundTrip(t *testing.T) {
	win := `C:\Users\Bob\App Data\sentinel.exe`
	t.Setenv("APPDATA", `C:\Users\Bob\AppData\Roaming`)
	p, err := clientConfigPath("claude", "windows", `C:\Users\Bob`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "Claude") {
		t.Fatalf("bad path %q", p)
	}
	e := clientEntry{Command: win, Args: []string{"mcp", "run"}}
	out, err := mergeConfig(nil, "s", e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `C:\\Users\\Bob`) {
		t.Fatalf("not escaped: %s", out)
	}
	var cfg clientConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MCPServers["s"].Command != win {
		t.Fatalf("round-trip failed: %q", cfg.MCPServers["s"].Command)
	}
}

func TestMergePreservesUnrelated(t *testing.T) {
	existing := `{"mcpServers":{"other":{"command":"node","args":["s.js"]}}}`
	out, err := mergeConfig([]byte(existing), "new", clientEntry{Command: "sentinel", Args: []string{"mcp"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg clientConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MCPServers["other"].Command != "node" {
		t.Fatal("unrelated entry lost")
	}
	if _, ok := cfg.MCPServers["new"]; !ok {
		t.Fatal("new entry missing")
	}
}

func TestMergeIdempotent(t *testing.T) {
	e := clientEntry{Command: "sentinel", Args: []string{"mcp", "run"}}
	once, err := mergeConfig(nil, "s", e)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := mergeConfig(once, "s", e)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent:\n%s\n%s", once, twice)
	}
}

func TestClientAddDryRunAndPrintOnly(t *testing.T) {
	home := testHome(t)
	if code := cmdClient([]string{"add", "cursor", "--name", "s", "--print-only", "--", "npx", "x"}); code != ExitOK {
		t.Fatalf("print-only exit %d", code)
	}
	p, _ := clientConfigPath("cursor", runtime.GOOS, home)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("print-only touched files")
	}
	if code := cmdClient([]string{"add", "cursor", "--name", "s", "--dry-run", "--profile", "P", "--env", "K=snt://v", "--", "npx", "x"}); code != ExitOK {
		t.Fatalf("dry-run exit %d", code)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("dry-run touched files")
	}
}

func TestClientAddWritesAndBackups(t *testing.T) {
	home := testHome(t)
	p, _ := clientConfigPath("cursor", runtime.GOOS, home)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := `{"mcpServers":{"other":{"command":"node","args":["s.js"]}}}`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	addArgs := []string{"add", "cursor", "--name", "s", "--profile", "P", "--env", "K=snt://v", "--", "npx", "x"}
	if code := cmdClient(addArgs); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	bak, err := os.ReadFile(p + ".bak")
	if err != nil || string(bak) != orig {
		t.Fatalf("backup missing/wrong: %v %q", err, bak)
	}
	data, _ := os.ReadFile(p)
	var cfg clientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MCPServers["other"].Command != "node" || cfg.MCPServers["s"].Env["K"] != "snt://v" {
		t.Fatalf("merge wrong: %s", data)
	}
	before := string(data)
	if code := cmdClient(addArgs); code != ExitOK {
		t.Fatalf("rerun exit %d", code)
	}
	after, _ := os.ReadFile(p)
	if string(after) != before {
		t.Fatalf("not idempotent:\n%s\n%s", before, after)
	}
}

func TestClientLs(t *testing.T) {
	testHome(t)
	if code := cmdClient([]string{"ls"}); code != ExitOK {
		t.Fatalf("ls exit %d", code)
	}
	g.json = true
	defer func() { g.json = false }()
	if code := cmdClient([]string{"ls"}); code != ExitOK {
		t.Fatalf("ls --json exit %d", code)
	}
}

func exampleClaude() []byte {
	return renderExample(map[string]clientEntry{
		"github": {
			Command: "sentinel",
			Args:    []string{"mcp", "run", "--mode", "inject", "--profile", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"},
			Env:     map[string]string{"GITHUB_TOKEN": "snt://github_pat"},
		},
		"proxy-mode-example": {
			Command: "sentinel",
			Args:    []string{"mcp", "run", "--mode", "proxy", "--", "node", "server.js"},
			Env:     map[string]string{"API_TOKEN": "snt://some_token", "HTTPS_PROXY": "http://127.0.0.1:18449"},
		},
	})
}

func exampleCursor() []byte {
	return renderExample(map[string]clientEntry{
		"github-stdio": {
			Command: "sentinel",
			Args:    []string{"mcp", "run", "--mode", "inject", "--", "npx", "-y", "@modelcontextprotocol/server-github"},
			Env:     map[string]string{"GITHUB_TOKEN": "snt://github_pat"},
		},
		"remote-http": {
			URL:     "http://127.0.0.1:18450/mcp",
			Headers: map[string]string{"Authorization": "Bearer snt://remote_mcp_token"},
		},
	})
}

func TestExamplesDrift(t *testing.T) {
	for file, want := range map[string][]byte{
		"../../examples/claude_desktop_config.json": exampleClaude(),
		"../../examples/cursor_mcp.json":            exampleCursor(),
	} {
		got, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s drifted:\nwant:\n%s\ngot:\n%s", file, want, got)
		}
	}
}
