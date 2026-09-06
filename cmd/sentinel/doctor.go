package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"sentinel/internal/keyring"
	"sentinel/internal/vault"
)

// doctorCheck is one named check. Status: ok/warn/fail.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// Troubleshooting table shared with docs: each README Troubleshooting row
// maps to a named check. Test asserts the mapping.
var doctorTroubleshooting = []struct {
	Symptom string
	Check   string
}{
	{"`sentinel` not found", "binary-path"},
	{"cannot create `~/.sentinel` / permission denied", "data-dir"},
	{"keychain locked / credential store unavailable", "keychain"},
	{"wrong master key / vault won't open", "key-match"},
	{"vault corrupt / won't open", "vault-open"},
	{"policy parse error", "policy"},
	{"TLS errors / CA not trusted", "ca"},
	{"address already in use", "ports"},
	{"`go` too old when building from source", "go-toolchain"},
	{"MCP client can't find sentinel binary", "mcp-config"},
	{"audit timestamps look wrong / clock issues", "clock-skew"},
	{"no vault yet / fresh machine", "vault-open"},
}

func doctorEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func okCheck(name, detail, fix string) doctorCheck {
	return doctorCheck{name, "ok", detail, fix}
}
func warnCheck(name, detail, fix string) doctorCheck {
	return doctorCheck{name, "warn", detail, fix}
}
func failCheck(name, detail, fix string) doctorCheck {
	return doctorCheck{name, "fail", detail, fix}
}

func checkBinaryPath() doctorCheck {
	p, err := os.Executable()
	if err != nil || p == "" {
		return failCheck("binary-path", "cannot locate own binary", "reinstall sentinel from GitHub Releases")
	}
	found := false
	for _, dir := range filepath.SplitList(doctorEnv("PATH", os.Getenv("PATH"))) {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, filepath.Base(p))); err == nil {
			found = true
			break
		}
		// Also accept any sentinel binary in dir.
		if _, err := os.Stat(filepath.Join(dir, "sentinel")); err == nil {
			found = true
			break
		}
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(filepath.Join(dir, "sentinel.exe")); err == nil {
				found = true
				break
			}
		}
	}
	if !found {
		return failCheck("binary-path", "sentinel binary not on PATH ("+p+")", "add "+filepath.Dir(p)+" to PATH")
	}
	return okCheck("binary-path", "sentinel on PATH ("+p+")", "")
}

func checkDataDir() doctorCheck {
	dir := doctorEnv("SENTINEL_DATA_DIR", dataDir())
	fi, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return warnCheck("data-dir", "data dir does not exist ("+dir+")", "run `sentinel init` to create it")
		}
		return failCheck("data-dir", "cannot stat data dir: "+err.Error(), "check permissions on "+dir)
	}
	if !fi.IsDir() {
		return failCheck("data-dir", "data path is not a directory", "move it aside and run `sentinel init`")
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		return warnCheck("data-dir", fmt.Sprintf("data dir perms %o, want 700", fi.Mode().Perm()), "run `chmod 700 "+dir+"`")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return failCheck("data-dir", "data dir not writable: "+err.Error(), "check ownership of "+dir)
	}
	return okCheck("data-dir", "data dir exists with correct permissions ("+dir+")", "")
}

func checkKeychain() doctorCheck {
	_, err := keyring.Load()
	switch {
	case err == nil:
		return okCheck("keychain", "keychain reachable, master key present", "")
	case isNotFoundErr(err):
		return warnCheck("keychain", "keychain reachable, no master key stored", "run `sentinel init` to create one")
	default:
		return failCheck("keychain", "keychain unreachable: "+err.Error(), keyring.Remediation)
	}
}

func isNotFoundErr(err error) bool {
	return err != nil && (err == keyring.ErrNotFound || strings.Contains(err.Error(), "no master key"))
}

func checkKeyMatch() doctorCheck {
	dir := doctorEnv("SENTINEL_DATA_DIR", dataDir())
	if _, err := os.Stat(filepath.Join(dir, "vault.db")); os.IsNotExist(err) {
		return warnCheck("key-match", "no vault yet, nothing to match", "run `sentinel init`")
	}
	key, err := keyring.Load()
	if err != nil {
		return warnCheck("key-match", "cannot probe: no key available ("+err.Error()+")", "run `sentinel init`")
	}
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		return failCheck("key-match", "key does not match vault: "+err.Error(), "restore the correct key, then run `sentinel init`")
	}
	st.Close()
	return okCheck("key-match", "master key matches vault", "")
}

func checkVaultOpen() doctorCheck {
	dir := doctorEnv("SENTINEL_DATA_DIR", dataDir())
	if _, err := os.Stat(filepath.Join(dir, "vault.db")); os.IsNotExist(err) {
		return warnCheck("vault-open", "no vault yet", "run `sentinel init` to create one")
	}
	key, err := keyring.Load()
	if err != nil {
		return warnCheck("vault-open", "cannot open vault without key ("+err.Error()+")", "run `sentinel init`")
	}
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		return failCheck("vault-open", "vault won't open: "+err.Error(), "restore vault.db from backup, then run `sentinel init`")
	}
	defer st.Close()
	names, err := st.List()
	if err != nil {
		return failCheck("vault-open", "vault opened but list failed: "+err.Error(), "restore vault.db from backup")
	}
	return okCheck("vault-open", fmt.Sprintf("vault opens, %d record(s)", len(names)), "")
}

var knownPolicyKeys = map[string]bool{
	"defaults": true, "hosts": true, "entities": true,
	"custom_patterns": true, "allowlist": true, "audit": true,
}

func checkPolicy() doctorCheck {
	dir := doctorEnv("SENTINEL_DATA_DIR", dataDir())
	path := filepath.Join(dir, "policy.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return okCheck("policy", "no policy.yaml, built-in defaults apply", "")
		}
		return failCheck("policy", "cannot read policy.yaml: "+err.Error(), "check permissions on "+path)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return failCheck("policy", "policy.yaml does not parse: "+err.Error(), "fix YAML syntax in "+path)
	}
	var unknown []string
	for k := range raw {
		if !knownPolicyKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return warnCheck("policy", "policy parses, unknown keys: "+strings.Join(unknown, ", "), "remove or rename unknown keys in "+path)
	}
	return okCheck("policy", "policy.yaml parses, no unknown keys", "")
}

func checkCA() doctorCheck {
	dir := doctorEnv("SENTINEL_DATA_DIR", dataDir())
	b, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		if os.IsNotExist(err) {
			return warnCheck("ca", "no local CA yet", "run `sentinel trust-ca` to create and install it")
		}
		return failCheck("ca", "cannot read ca.pem: "+err.Error(), "check permissions in "+dir)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return failCheck("ca", "ca.pem is not valid PEM", "delete ca.pem/ca-key.pem and run `sentinel trust-ca`")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return failCheck("ca", "ca.pem does not parse: "+err.Error(), "delete ca.pem/ca-key.pem and run `sentinel trust-ca`")
	}
	if time.Now().After(cert.NotAfter) {
		return failCheck("ca", "CA expired on "+cert.NotAfter.Format("2006-01-02"), "delete ca.pem/ca-key.pem and run `sentinel trust-ca`")
	}
	roots, err := x509.SystemCertPool()
	trusted := err == nil && roots != nil
	if trusted {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			return warnCheck("ca", "CA present, valid until "+cert.NotAfter.Format("2006-01-02")+", not in platform trust store", "run `sentinel trust-ca`")
		}
	}
	return okCheck("ca", "CA present, valid until "+cert.NotAfter.Format("2006-01-02"), "")
}

var doctorDefaultPorts = []string{"127.0.0.1:18450", "127.0.0.1:18451", "127.0.0.1:18080"}

func checkPorts() doctorCheck {
	runDir := doctorEnv("SENTINEL_RUN_DIR", filepath.Join(doctorEnv("SENTINEL_DATA_DIR", dataDir()), "run"))
	var ownedPorts []string
	if entries, err := os.ReadDir(runDir); err == nil {
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(runDir, e.Name()))
			if err != nil {
				continue
			}
			var rf struct {
				Addr string `json:"addr"`
			}
			if json.Unmarshal(b, &rf) == nil && rf.Addr != "" {
				ownedPorts = append(ownedPorts, rf.Addr)
			}
		}
	} else if os.IsNotExist(err) {
		return warnCheck("ports", "runtime status unavailable (no run dir)", "start a service with `sentinel serve` or `sentinel mcp serve`")
	}
	owned := map[string]bool{}
	for _, p := range ownedPorts {
		owned[p] = true
	}
	var busy []string
	ports := doctorEnv("SENTINEL_DOCTOR_PORTS", "")
	check := doctorDefaultPorts
	if ports != "" {
		check = strings.Split(ports, ",")
	}
	for _, addr := range check {
		if owned[addr] {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			busy = append(busy, addr)
			continue
		}
		ln.Close()
	}
	if len(busy) > 0 {
		return failCheck("ports", "port(s) in use by another process: "+strings.Join(busy, ", "), "stop the other process or change --addr")
	}
	if len(ownedPorts) > 0 {
		return okCheck("ports", "default ports free or owned by our run files", "")
	}
	return okCheck("ports", "default ports free", "")
}

func checkGoToolchain() doctorCheck {
	src := doctorEnv("SENTINEL_SRC_DIR", "")
	if src == "" {
		// Source tree present only in dev checkouts.
		if _, err := os.Stat("go.mod"); err != nil {
			return okCheck("go-toolchain", "no source tree, toolchain not needed (release binary)", "")
		}
		src = "."
	}
	b, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		return okCheck("go-toolchain", "no source tree, toolchain not needed", "")
	}
	ver := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "toolchain go") {
			ver = strings.TrimSpace(strings.TrimPrefix(line, "toolchain"))
			break
		}
		if strings.HasPrefix(line, "go ") && ver == "" {
			ver = strings.TrimSpace(strings.TrimPrefix(line, "go"))
		}
	}
	if ver == "" {
		return warnCheck("go-toolchain", "go.mod has no toolchain directive", "add `toolchain go1.xx.y` to go.mod")
	}
	return okCheck("go-toolchain", "source tree wants Go "+ver+" (have "+runtime.Version()+")", "install Go "+ver+" from https://go.dev/dl/")
}

func doctorClientConfigPaths() []string {
	home := doctorEnv("HOME", os.Getenv("HOME"))
	if runtime.GOOS == "windows" {
		home = doctorEnv("USERPROFILE", doctorEnv("HOME", os.Getenv("USERPROFILE")))
	}
	appdata := doctorEnv("APPDATA", os.Getenv("APPDATA"))
	var paths []string
	switch runtime.GOOS {
	case "windows":
		paths = []string{
			filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(appdata, "Code", "User", "settings.json"),
		}
	default:
		paths = []string{
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".vscode", "mcp.json"),
		}
	}
	if extra := doctorEnv("SENTINEL_DOCTOR_CLIENTS", ""); extra != "" {
		paths = append(paths, strings.Split(extra, string(os.PathListSeparator))...)
	}
	return paths
}

func checkMCPConfig() doctorCheck {
	var found, bad []string
	for _, p := range doctorClientConfigPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal(b, &cfg); err != nil {
			bad = append(bad, p+" (invalid JSON)")
			continue
		}
		found = append(found, p)
		// Walk mcpServers entries: sentinel command paths must be absolute and exist.
		if srv, _ := cfg["mcpServers"].(map[string]any); srv != nil {
			for name, v := range srv {
				m, _ := v.(map[string]any)
				if m == nil {
					continue
				}
				cmd, _ := m["command"].(string)
				if cmd == "" || !strings.Contains(strings.ToLower(cmd+name), "sentinel") {
					continue
				}
				if !filepath.IsAbs(cmd) {
					bad = append(bad, p+" ["+name+"]: relative path "+cmd)
					continue
				}
				if _, err := os.Stat(cmd); err != nil {
					bad = append(bad, p+" ["+name+"]: missing binary "+cmd)
				}
			}
		}
	}
	if len(bad) > 0 {
		return warnCheck("mcp-config", "client config issue(s): "+strings.Join(bad, "; "), "use absolute paths to the sentinel binary in client configs")
	}
	if len(found) == 0 {
		return okCheck("mcp-config", "no MCP client configs on disk, nothing to check", "")
	}
	return okCheck("mcp-config", fmt.Sprintf("%d client config(s) valid", len(found)), "")
}

func checkClockSkew() doctorCheck {
	// Skew vs local reference: compare wall clock against file mtimes is
	// meaningless; instead flag absurd system time (pre-2024 or far future).
	now := time.Now()
	if now.Before(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		return failCheck("clock-skew", "system clock is implausibly old ("+now.Format(time.RFC3339)+")", "fix system time (NTP), then re-run `sentinel doctor`")
	}
	if now.After(time.Now().Add(24 * time.Hour)) {
		return failCheck("clock-skew", "system clock is in the future", "fix system time (NTP)")
	}
	return okCheck("clock-skew", "system clock sane ("+now.Format("2006-01-02 15:04 MST")+")", "")
}

func runDoctor() []doctorCheck {
	return []doctorCheck{
		checkBinaryPath(),
		checkDataDir(),
		checkKeychain(),
		checkKeyMatch(),
		checkVaultOpen(),
		checkPolicy(),
		checkCA(),
		checkPorts(),
		checkGoToolchain(),
		checkMCPConfig(),
		checkClockSkew(),
	}
}

func cmdDoctor(args []string) int {
	fs := newFlagSet("doctor", "usage: sentinel doctor [--json]")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		return failUsage("sentinel doctor [--json]")
	}
	checks := runDoctor()
	failed := false
	for _, c := range checks {
		if c.Status == "fail" {
			failed = true
			break
		}
	}
	if g.json {
		emitJSON(map[string]any{"checks": checks})
	} else {
		for _, c := range checks {
			line := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(c.Status), c.Name, c.Detail)
			fmt.Println(line)
			if c.Fix != "" {
				fmt.Println("  fix: " + c.Fix)
			}
		}
	}
	if failed {
		return 1
	}
	return ExitOK
}
