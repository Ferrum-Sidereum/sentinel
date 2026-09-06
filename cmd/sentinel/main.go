package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sentinel/internal/audit"
	"sentinel/internal/keyring"
	"sentinel/internal/memguard"
	"sentinel/internal/placeholder"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/termsecret"
	"sentinel/internal/vault"
)

func init() {
	register(
		command{"init", "initialize vault and policy", "sentinel init", cmdInit},
		command{"add", "add a secret bound to a host", "sentinel add <name> --bind host [--header H] [--kind K] [--from-env E|--from-file P|--stdin]", cmdAdd},
		command{"ls", "list secret names (never values)", "sentinel ls [--json]", cmdLs},
		command{"rm", "remove a secret", "sentinel rm <name>", cmdRm},
		command{"env", "import/export env-style secrets", "sentinel env import --bind host [--prefix P] [file] | sentinel env export", cmdEnv},
		command{"scan", "scan text for secret leaks", "sentinel scan [--show-values] [--json] [file]", cmdScan},
		command{"serve", "run egress proxy", "sentinel serve [--addr ADDR]", cmdServe},
		command{"run", "run a command under the egress proxy", "sentinel run -- <cmd...>", cmdRun},
		command{"trust-ca", "install local CA into user store", "sentinel trust-ca", cmdTrustCA},
		command{"llm-serve", "run LLM gateway", "sentinel llm-serve [listen-addr] [upstream-base]", cmdLLMServe},
		command{"mcp", "run MCP proxy", "sentinel mcp run ... | sentinel mcp serve ...", cmdMCP},
		command{"audit", "show audit log tail", "sentinel audit [-n N] [--json]", cmdAudit},
		command{"rotate", "rotate a secret value", "sentinel rotate <name> [--from-env E|--from-file P|--stdin]", cmdRotate},
		command{"migrate-key", "migrate legacy passphrase file to key.json KDF", "sentinel migrate-key", cmdMigrateKeyAdapter},
		command{"rollback", "restore previous secret version", "sentinel rollback <name>", cmdRollbackAdapter},
	)
}

func openStore() (*vault.Store, error) {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if keyring.HasPassphrase(dir) {
		pw, err := termsecret.Read("Enter passphrase: ")
		if err != nil {
			return nil, err
		}
		defer memguard.Zero(pw)
		key, err := keyring.OpenPassphrase(dir, pw)
		if err != nil {
			return nil, err
		}
		defer memguard.Zero(key)
		k := make([]byte, 32)
		copy(k, key)
		st, err := vault.Open(filepath.Join(dir, "vault.db"), k)
		memguard.Zero(k)
		return st, err
	}
	key, err := keyring.Load()
	if err != nil {
		if errors.Is(err, keyring.ErrUnavailable) {
			return nil, errors.New(keyring.Remediation)
		}
		return nil, err
	}
	return vault.Open(filepath.Join(dataDir(), "vault.db"), key)
}

func openAudit() *audit.Logger {
	l, _ := audit.Open(filepath.Join(dataDir(), "audit.jsonl"))
	return l
}

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

func cmdMigrateKeyAdapter(args []string) int {
	if len(args) != 0 {
		return failUsage("migrate-key takes no arguments")
	}
	cmdMigrateKey()
	return ExitOK
}

func cmdInit(args []string) int {
	fs := newFlagSet("init", "usage: sentinel init [--passphrase]")
	var usePassphrase bool
	fs.BoolVar(&usePassphrase, "passphrase", false, "use passphrase KDF instead of keychain")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		return failUsage("init takes no arguments")
	}
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	def := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(def); os.IsNotExist(err) {
		os.WriteFile(def, []byte("defaults:\n  unknown_host: tunnel\n  scrub_to_llm: pseudonymize\n  scrub_to_untrusted: mask\n  confidence_threshold: 0.7\naudit:\n  level: events\n  retention: 30d\n"), 0o600)
	}
	if usePassphrase {
		cmdInitPassphrase(dir)
		return ExitOK
	}
	key, err := keyring.Load()
	switch {
	case err == nil:
	case errors.Is(err, keyring.ErrNotFound):
		key, err = keyring.Create(dir)
		if err != nil {
			if errors.Is(err, keyring.ErrVaultExists) {
				fmt.Fprintln(os.Stderr, "init refused: vault data exists without a matching key; restore the key or remove the data dir")
				return ExitRuntime
			}
			return failRuntime(fmt.Errorf("init failed: %w", err))
		}
	case errors.Is(err, keyring.ErrUnavailable):
		fmt.Fprintln(os.Stderr, keyring.Remediation)
		return ExitRuntime
	default:
		return failRuntime(fmt.Errorf("init failed: %w", err))
	}
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		return failRuntime(fmt.Errorf("init failed: %w", err))
	}
	st.Close()
	if !g.quiet {
		fmt.Println("initialized", dir)
	}
	return ExitOK
}

func cmdAdd(args []string) int {
	fs := newFlagSet("add", "usage: sentinel add <name> --bind host [--header H] [--kind K] [--from-env NAME|--from-file PATH|--stdin]")
	var bind, header, kind, fromEnv, fromFile, expires string
	var fromStdin bool
	fs.StringVar(&bind, "bind", "", "host to bind the secret to")
	fs.StringVar(&header, "header", "", "injection header")
	fs.StringVar(&kind, "kind", "bearer", "secret kind")
	fs.StringVar(&fromEnv, "from-env", "", "read value from env var")
	fs.StringVar(&fromFile, "from-file", "", "read value from file")
	fs.StringVar(&expires, "expires", "", "expiry like 30d, 12h, 45m, 90s")
	fs.BoolVar(&fromStdin, "stdin", false, "read value from stdin")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	// Go's flag stops at the first positional arg, so flags after the name
	// land in Args unparsed. Reject a string flag only when it is dangling:
	rest := fs.Args()
	for i, r := range rest {
		if r == "--bind" || r == "--header" || r == "--kind" || r == "--from-env" || r == "--from-file" || r == "--expires" {
			if i+1 >= len(rest) || strings.HasPrefix(rest[i+1], "-") {
				return failUsage(fmt.Sprintf("flag %s requires a value", r))
			}
		}
	}
	if len(rest) < 1 {
		return failUsage("sentinel add <name> --bind host [...]")
	}
	name := rest[0]
	_ = bind // optional here; WP-07 makes binding metadata required.
	val, err := readSecretValue(fromEnv, fromFile, fromStdin, "value: ")
	if err != nil {
		return failRuntime(err)
	}
	defer memguard.Zero(val)
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	exp, err := parseExpires(expires)
	if err != nil {
		return failRuntime(err)
	}
	sec := vault.Secret{Name: name, Value: val, Kind: kind, Version: 1, ExpiresAt: exp}
	if header != "" {
		sec.InjectHdr = []string{header}
	}
	if err := st.Put(sec); err != nil {
		return failRuntime(err)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_added", map[string]any{"name": name})
		l.Close()
	}
	if !g.quiet {
		fmt.Println("added", placeholder.Canonical(name), "|", placeholder.Safe(name))
	}
	return ExitOK
}

// readSecretValue resolves the secret bytes from exactly one non-interactive
// source or, when none is given, from no-echo terminal/pipe input.
// Exactly one trailing newline is stripped; other whitespace is preserved.
func readSecretValue(fromEnv, fromFile string, fromStdin bool, prompt string) ([]byte, error) {
	n := 0
	if fromEnv != "" {
		n++
	}
	if fromFile != "" {
		n++
	}
	if fromStdin {
		n++
	}
	if n > 1 {
		return nil, errors.New("use only one of --from-env, --from-file, --stdin")
	}
	if fromEnv != "" {
		v, ok := os.LookupEnv(fromEnv)
		if !ok || v == "" {
			return nil, fmt.Errorf("env %s is not set or empty", fromEnv)
		}
		return []byte(v), nil
	}
	if fromFile != "" {
		b, err := os.ReadFile(fromFile)
		if err != nil {
			return nil, err
		}
		b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\r'})
		if len(b) == 0 {
			return nil, errors.New("empty value")
		}
		return b, nil
	}
	if fromStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\r'})
		if len(b) == 0 {
			return nil, errors.New("empty value")
		}
		return b, nil
	}
	return termsecret.Read(prompt)
}

func cmdLs(args []string) int {
	fs := newFlagSet("ls", "usage: sentinel ls [--json]")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	names, err := st.List()
	if err != nil {
		return failRuntime(err)
	}
	if g.json {
		type entry struct {
			Name        string `json:"name"`
			Placeholder string `json:"placeholder"`
			Safe        string `json:"safe"`
		}
		out := map[string]any{"secrets": []entry{}}
		list := []entry{}
		for _, n := range names {
			list = append(list, entry{n, placeholder.Canonical(n), placeholder.Safe(n)})
		}
		out["secrets"] = list
		emitJSON(out)
		return ExitOK
	}
	for _, n := range names {
		mark := ""
		if sec, err := st.Get(n); err == nil && sec.Expired() {
			mark = " [expired]"
		}
		fmt.Println(n, placeholder.Canonical(n)+mark)
	}
	return ExitOK
}

func cmdRm(args []string) int {
	fs := newFlagSet("rm", "usage: sentinel rm <name>")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() < 1 {
		return failUsage("sentinel rm <name>")
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	if err := st.Delete(fs.Arg(0)); err != nil {
		return failRuntime(err)
	}
	if !g.quiet {
		fmt.Println("removed", fs.Arg(0))
	}
	return ExitOK
}

func cmdEnv(args []string) int {
	fs := newFlagSet("env", "usage: sentinel env import|export ...")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return failUsage("sentinel env import|export ...")
	}
	switch rest[0] {
	case "export":
		st, err := openStore()
		if err != nil {
			return failRuntime(err)
		}
		defer st.Close()
		names, _ := st.List()
		for _, n := range names {
			fmt.Printf("%s=%s\n", strings.ToUpper(n), placeholder.Canonical(n))
		}
		return ExitOK
	case "import":
		return cmdEnvImport(rest[1:])
	default:
		return failUsage("sentinel env import|export ...")
	}
}

func cmdScan(args []string) int {
	fs := newFlagSet("scan", "usage: sentinel scan [--show-values] [--json] [file]")
	var showValues bool
	fs.BoolVar(&showValues, "show-values", false, "print matched values (TTY only)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	files := fs.Args()
	if showValues && !termsecret.IsTTY(os.Stdout) {
		fmt.Fprintln(os.Stderr, "refusing --show-values on non-interactive output")
		return ExitBlocked
	}
	var text string
	if len(files) > 0 {
		b, err := os.ReadFile(files[0])
		if err != nil {
			return failRuntime(err)
		}
		text = string(b)
	} else {
		r := bufio.NewReader(os.Stdin)
		var sb strings.Builder
		for {
			line, err := r.ReadString('\n')
			sb.WriteString(line)
			if err != nil {
				break
			}
		}
		text = sb.String()
	}
	p, _ := policy.Load(filepath.Join(dataDir(), "policy.yaml"))
	allow := map[string]bool{}
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	var vm vault.Matcher
	if st, err := openStore(); err == nil {
		if m, err := st.NewMatcher(); err == nil {
			vm = m
			defer m.Close()
		}
		defer st.Close()
	}
	placeholders := []string{}
	for _, m := range placeholder.Find(text) {
		placeholders = append(placeholders, m)
	}
	findings := scrubber.ScanWithMatcher(text, vm, allow, nil)
	if g.json {
		type finding struct {
			Type       string  `json:"type"`
			Detector   string  `json:"detector"`
			Confidence float64 `json:"confidence"`
			Line       int     `json:"line"`
			Col        int     `json:"col"`
			FP         string  `json:"fp"`
			Value      string  `json:"value,omitempty"`
		}
		out := []finding{}
		for _, f := range findings {
			line, col := lineCol(text, f.Span[0])
			sum := sha256.Sum256([]byte(f.Value))
			fd := finding{f.Type, f.Detector, f.Confidence, line, col, hex.EncodeToString(sum[:])[:8], ""}
			if showValues {
				fd.Value = f.Value
			}
			out = append(out, fd)
		}
		emitJSON(map[string]any{"findings": out, "placeholders": placeholders})
		if showValues {
			fmt.Fprintln(os.Stderr, "WARNING: printing matched secret values to an interactive terminal")
		}
		return ExitOK
	}
	for _, m := range placeholders {
		fmt.Println("PLACEHOLDER", m)
	}
	if showValues {
		fmt.Fprintln(os.Stderr, "WARNING: printing matched secret values to an interactive terminal")
	}
	for _, f := range findings {
		line, col := lineCol(text, f.Span[0])
		sum := sha256.Sum256([]byte(f.Value))
		if showValues {
			fmt.Printf("%s [%s conf=%.2f] %d:%d fp=%s %q\n", f.Type, f.Detector, f.Confidence, line, col, hex.EncodeToString(sum[:])[:8], f.Value)
			continue
		}
		fmt.Printf("%s [%s conf=%.2f] %d:%d fp=%s\n", f.Type, f.Detector, f.Confidence, line, col, hex.EncodeToString(sum[:])[:8])
	}
	return ExitOK
}

func lineCol(text string, off int) (line, col int) {
	line, col = 1, 1
	for i := 0; i < off && i < len(text); i++ {
		if text[i] == '\n' {
			line++
			col = 1
			continue
		}
		col++
	}
	return line, col
}

func mustList(st *vault.Store) []string {
	n, _ := st.List()
	return n
}
