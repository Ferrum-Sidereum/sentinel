package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinel/internal/audit"
	"sentinel/internal/keyring"
	"sentinel/internal/placeholder"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentinel")
}

func openStore() (*vault.Store, error) {
	key, err := keyring.LoadOrCreate()
	if err != nil {
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
	key, err := keyring.LoadOrCreate()
	if err != nil {
		fmt.Println("keychain unavailable, enter passphrase for fallback key (stored hashed via argon2id on first add):")
		r := bufio.NewReader(os.Stdin)
		pw, _ := r.ReadString('\n')
		pw = strings.TrimSpace(pw)
		if pw == "" {
			fmt.Println("empty passphrase")
			os.Exit(1)
		}
		os.WriteFile(filepath.Join(dir, "passphrase"), []byte(pw), 0o600)
		key, err = keyring.LoadOrCreate()
		if err != nil {
			fmt.Println("init failed:", err)
			os.Exit(1)
		}
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
		fmt.Println("usage: sentinel add <name> --bind host [--header H] [--kind bearer]")
		os.Exit(2)
	}
	name := args[0]
	bind, header, kind := "", "", "bearer"
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
		}
	}
	if bind == "" {
		fmt.Println("bind host required")
		os.Exit(2)
	}
	fmt.Print("value: ")
	r := bufio.NewReader(os.Stdin)
	val, _ := r.ReadString('\n')
	val = strings.TrimSpace(val)
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	sec := vault.Secret{Name: name, Value: []byte(val), Kind: kind, Hosts: []string{bind}, Version: 1}
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
		fmt.Println(n, placeholder.Canonical(n))
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
	var text string
	if len(args) > 0 {
		b, err := os.ReadFile(args[0])
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
	for _, f := range scrubber.ScanWithMatcher(text, vm, allow, nil) {
		fmt.Printf("%s [%s conf=%.2f] %q\n", f.Type, f.Detector, f.Confidence, f.Value)
	}
}

func mustList(st *vault.Store) []string {
	n, _ := st.List()
	return n
}
