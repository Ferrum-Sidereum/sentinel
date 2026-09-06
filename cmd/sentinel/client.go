package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// client.go (WP-15): generates MCP client configs pointing at this binary.
//
// Usage:
// sentinel client add claude|cursor|vscode|windsurf --name NAME --profile P [--env K=snt://v ...] [--dry-run] [--print-only] -- <cmd...>
// sentinel client ls [--json]

func cmdClient(args []string) int {
	if len(args) < 1 {
		return failUsage("sentinel client add ... | sentinel client ls ...")
	}
	switch args[0] {
	case "add":
		return cmdClientAdd(args[1:])
	case "ls":
		return cmdClientLs(args[1:])
	default:
		return failUsage("sentinel client add ... | sentinel client ls ...")
	}
}

// clientEntry is one mcpServers entry.
type clientEntry struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type clientConfig struct {
	MCPServers map[string]clientEntry `json:"mcpServers"`
}

// sentinelBin returns absolute path to the running binary.
func sentinelBin() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func homeDir() string {
	if h := os.Getenv("SENTINEL_TEST_HOME"); h != "" {
		return h
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// clientConfigPath locates the client's config file for the given OS.
// osName is runtime.GOOS; tests pass other values with SENTINEL_TEST_HOME as home.
func clientConfigPath(client, osName, home string) (string, error) {
	appData := os.Getenv("APPDATA")
	if osName == "windows" && appData == "" && runtime.GOOS == "windows" {
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	// In tests on non-windows hosts simulating windows, derive from home.
	if osName == "windows" && appData == "" {
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	switch client {
	case "claude":
		switch osName {
		case "windows":
			return filepath.Join(appData, "Claude", "claude_desktop_config.json"), nil
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		default:
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "vscode":
		switch osName {
		case "windows":
			return filepath.Join(appData, "Code", "User", "mcp.json"), nil
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json"), nil
		default:
			return filepath.Join(home, ".config", "Code", "User", "mcp.json"), nil
		}
	case "windsurf":
		return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil
	}
	return "", fmt.Errorf("unknown client %q (claude|cursor|vscode|windsurf)", client)
}

// buildEntry builds the mcpServers entry for one managed server.
func buildEntry(bin, profile string, cmd []string, env map[string]string) clientEntry {
	args := []string{"mcp", "run", "--mode", "inject"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	args = append(args, "--")
	args = append(args, cmd...)
	if env == nil {
		env = map[string]string{}
	}
	return clientEntry{Command: bin, Args: args, Env: env}
}

// mergeConfig inserts/replaces entry name, preserving unrelated entries.
func mergeConfig(raw []byte, name string, e clientEntry) ([]byte, error) {
	cfg := clientConfig{MCPServers: map[string]clientEntry{}}
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("parse existing config: %w", err)
		}
		if cfg.MCPServers == nil {
			cfg.MCPServers = map[string]clientEntry{}
		}
	}
	cfg.MCPServers[name] = e
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func cmdClientAdd(args []string) int {
	fs := newFlagSet("client add", "sentinel client add claude|cursor|vscode|windsurf --name NAME --profile P [--env K=snt://v] [--dry-run] [--print-only] -- <cmd...>")
	var name, profile string
	var envPairs multiFlag
	var dryRun, printOnly bool
	fs.StringVar(&name, "name", "", "server entry name")
	fs.StringVar(&profile, "profile", "", "profile name")
	fs.Var(&envPairs, "env", "placeholder env mapping KEY=snt://name (repeatable)")
	fs.BoolVar(&dryRun, "dry-run", false, "print resulting JSON instead of writing")
	fs.BoolVar(&printOnly, "print-only", false, "print resulting JSON and never touch files")
	// Client name is the first positional; flags may follow it.
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return failUsage("client name required: claude|cursor|vscode|windsurf")
	}
	client := args[0]
	args = args[1:]
	// Split off child command after "--".
	var child []string
	for i, a := range args {
		if a == "--" {
			child = args[i+1:]
			args = args[:i]
			break
		}
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if name == "" {
		return failUsage("--name is required")
	}
	if len(child) == 0 {
		return failUsage("child command required after --")
	}
	env, err := parseEnvPairs(envPairs)
	if err != nil {
		return failUsage(err.Error())
	}
	bin, err := sentinelBin()
	if err != nil {
		return failRuntime(err)
	}
	entry := buildEntry(bin, profile, child, env)
	path, err := clientConfigPath(client, runtime.GOOS, homeDir())
	if err != nil {
		return failUsage(err.Error())
	}

	var existing []byte
	if data, err := os.ReadFile(path); err == nil {
		existing = data
	}
	merged, err := mergeConfig(existing, name, entry)
	if err != nil {
		return failRuntime(err)
	}
	if dryRun || printOnly {
		fmt.Println(string(merged))
		return ExitOK
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return failRuntime(err)
	}
	if len(existing) > 0 {
		if err := os.WriteFile(path+".bak", existing, 0o600); err != nil {
			return failRuntime(err)
		}
	}
	if err := os.WriteFile(path, merged, 0o600); err != nil {
		return failRuntime(err)
	}
	fmt.Println(string(merged))
	return ExitOK
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func parseEnvPairs(pairs []string) (map[string]string, error) {
	env := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --env %q (want KEY=value)", p)
		}
		env[k] = v
	}
	return env, nil
}

func cmdClientLs(args []string) int {
	fs := newFlagSet("client ls", "sentinel client ls [--json]")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	asJSON := g.json
	type lsRow struct {
		Client  string   `json:"client"`
		Path    string   `json:"path"`
		Present bool     `json:"present"`
		Servers []string `json:"servers"`
	}
	var rows []lsRow
	for _, c := range []string{"claude", "cursor", "vscode", "windsurf"} {
		p, err := clientConfigPath(c, runtime.GOOS, homeDir())
		if err != nil {
			continue
		}
		row := lsRow{Client: c, Path: p, Servers: []string{}}
		data, err := os.ReadFile(p)
		if err != nil {
			rows = append(rows, row)
			continue
		}
		row.Present = true
		var cfg clientConfig
		if err := json.Unmarshal(data, &cfg); err == nil {
			for n := range cfg.MCPServers {
				row.Servers = append(row.Servers, n)
			}
			sort.Strings(row.Servers)
		}
		rows = append(rows, row)
	}
	if asJSON {
		emitJSON(map[string]any{"clients": rows})
		return ExitOK
	}
	for _, r := range rows {
		status := "missing"
		if r.Present {
			status = "present"
		}
		fmt.Printf("%-8s %-6s %s", r.Client, status, r.Path)
		if len(r.Servers) > 0 {
			fmt.Printf(" [%s]", strings.Join(r.Servers, ", "))
		}
		fmt.Println()
	}
	return ExitOK
}

// renderExample renders examples/*.json content from the same merge path.
func renderExample(entries map[string]clientEntry) []byte {
	cfg := clientConfig{MCPServers: entries}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return append(out, '\n')
}
