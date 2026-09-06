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

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentinel")
}

func openStore() (*vault.Store, error) {
	if err := os.MkdirAll(dataDir(), 0700); err != nil {
		return nil, err
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
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit()
	case "add":
		cmdAdd(os.Args[2:])
	case "ls":
		cmdLs()
	case "rm":
		cmdRm(os.Args[2:])
	case "env":
		cmdEnv(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "trust-ca":
		cmdTrustCA()
	case "llm-serve":
		cmdLLMServe(os.Args[2:])
	case "mcp":
		cmdMCP(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "rotate":
		cmdRotate(os.Args[2:])
	case "rollback":
		cmdRollback(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`sentinel init|add|ls|rm|env|scan`)
}

func cmdInit() {
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	def := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(def); os.IsNotExist(err) {
		os.WriteFile(def, []byte("defaults:\n  unknown_host: tunnel\n  scrub_to_llm: pseudonymize\n  scrub_to_untrusted: mask\n  confidence_threshold: 0.7\naudit:\n  level: events\n  retention: 30d\n"), 0o600)
	}
	key, err := keyring.Load()
	switch {
	case err == nil:
		// key exists, proceed to open vault below
	case errors.Is(err, keyring.ErrNotFound):
		key, err = keyring.Create(dir)
		if err != nil {
			if errors.Is(err, keyring.ErrVaultExists) {
				fmt.Println("init refused: vault data exists without a matching key; restore the key or remove the data dir")
				os.Exit(1)
			}
			fmt.Println("init failed:", err)
			os.Exit(1)
		}
	case errors.Is(err, keyring.ErrUnavailable):
		fmt.Println(keyring.Remediation)
		os.Exit(1)
	default:
		fmt.Println("init failed:", err)
		os.Exit(1)
	}
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		fmt.Println("init failed:", err)
		os.Exit(1)
	}
	st.Close()
	fmt.Println("initialized", dir)
}

func cmdAdd(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: sentinel add <name> --bind host [--header H] [--kind bearer] [--from-env NAME|--from-file PATH|--stdin]")
		os.Exit(2)
	}
	name := args[0]
	bind, header, kind := "", "", "bearer"
	expires := ""
	fromEnv, fromFile, fromStdin := "", "", false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--bind":
			i++
			bind = args[i]
		case "--header":
			i++
			header = args[i]
		case "--kind":
			i++
			kind = args[i]
		case "--expires":
			i++
			expires = args[i]
		case "--from-env":
			i++
			fromEnv = args[i]
		case "--from-file":
			i++
			fromFile = args[i]
		case "--stdin":
			fromStdin = true
		}
	}
	if bind == "" {
		fmt.Println("bind host required")
		os.Exit(2)
	}
	val, err := readSecretValue(fromEnv, fromFile, fromStdin, "value: ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer memguard.Zero(val)
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	exp, err := parseExpires(expires)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	sec := vault.Secret{Name: name, Value: val, Kind: kind, Hosts: []string{bind}, Version: 1, ExpiresAt: exp}
	if header != "" {
		sec.InjectHdr = []string{header}
	}
	if err := st.Put(sec); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_added", map[string]any{"name": name, "host": bind})
		l.Close()
	}
	fmt.Println("added", placeholder.Canonical(name), "|", placeholder.Safe(name))
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

func cmdLs() {
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	names, err := st.List()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, n := range names {
		mark := ""
		if sec, err := st.Get(n); err == nil && sec.Expired() {
			mark = " [expired]"
		}
		fmt.Println(n, placeholder.Canonical(n)+mark)
	}
}

func cmdRm(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: sentinel rm <name>")
		os.Exit(2)
	}
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Delete(args[0]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("removed", args[0])
}

func cmdEnv(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: sentinel env import|export ...")
		os.Exit(2)
	}
	switch args[0] {
	case "export":
		st, err := openStore()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer st.Close()
		names, _ := st.List()
		for _, n := range names {
			fmt.Printf("%s=%s\n", strings.ToUpper(n), placeholder.Canonical(n))
		}
	case "import":
		cmdEnvImport(args[1:])
	default:
		fmt.Println("usage: sentinel env import|export ...")
	}
}

func cmdScan(args []string) {
	showValues := false
	files := args[:0:0]
	for _, a := range args {
		if a == "--show-values" {
			showValues = true
			continue
		}
		files = append(files, a)
	}
	if showValues && !termsecret.IsTTY(os.Stdout) {
		fmt.Fprintln(os.Stderr, "refusing --show-values on non-interactive output")
		os.Exit(1)
	}
	var text string
	if len(files) > 0 {
		b, err := os.ReadFile(files[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
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
	for _, m := range placeholder.Find(text) {
		fmt.Println("PLACEHOLDER", m)
	}
	if showValues {
		fmt.Fprintln(os.Stderr, "WARNING: printing matched secret values to an interactive terminal")
	}
	for _, f := range scrubber.ScanWithMatcher(text, vm, allow, nil) {
		line, col := lineCol(text, f.Span[0])
		sum := sha256.Sum256([]byte(f.Value))
		if showValues {
			fmt.Printf("%s [%s conf=%.2f] %d:%d fp=%s %q\n", f.Type, f.Detector, f.Confidence, line, col, hex.EncodeToString(sum[:])[:8], f.Value)
			continue
		}
		fmt.Printf("%s [%s conf=%.2f] %d:%d fp=%s\n", f.Type, f.Detector, f.Confidence, line, col, hex.EncodeToString(sum[:])[:8])
	}
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
