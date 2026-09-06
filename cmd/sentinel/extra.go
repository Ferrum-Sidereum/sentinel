package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinel/internal/memguard"
	"sentinel/internal/placeholder"
	"sentinel/internal/vault"
)

// sentinel env import --bind host [--prefix P] [file]
// stdin or file with KEY=VALUE lines; values stored as secrets named lower(KEY).
func cmdEnvImport(args []string) int {
	fs := newFlagSet("env import", "usage: sentinel env import --bind host [--prefix P] [file]")
	var bind, prefix string
	fs.StringVar(&bind, "bind", "", "host to bind imported secrets to")
	fs.StringVar(&prefix, "prefix", "", "name prefix")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	file := ""
	if fs.NArg() > 0 {
		file = fs.Arg(0)
	}
	if bind == "" {
		return failUsage("sentinel env import --bind host [--prefix P] [file]")
	}
	var lines []string
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return failRuntime(err)
		}
		lines = strings.Split(string(b), "\n")
	} else {
		r := bufio.NewReader(os.Stdin)
		for {
			l, err := r.ReadString('\n')
			lines = append(lines, strings.TrimRight(l, "\r\n"))
			if err != nil {
				break
			}
		}
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	n := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || !strings.Contains(l, "=") {
			continue
		}
		kv := strings.SplitN(l, "=", 2)
		k := strings.TrimSpace(kv[0])
		v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
		if k == "" || v == "" {
			continue
		}
		name := strings.ToLower(prefix + k)
		name = strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), " ", "_")
		sec := vault.Secret{Name: name, Value: []byte(v), Kind: "bearer", Hosts: []string{bind}, Version: 1}
		if err := st.Put(sec); err != nil {
			fmt.Println("skip", k, err)
			continue
		}
		fmt.Printf("%s=%s\n", k, placeholder.Canonical(name))
		n++
	}
	if l := openAudit(); l != nil {
		l.Log("", "env_imported", map[string]any{"count": n, "host": bind})
		l.Close()
	}
	fmt.Fprintf(os.Stderr, "imported %d\n", n)
	return ExitOK
}

// sentinel audit [tail] [-n N]
// JSON shape: {"events":[<raw objects>]}
func cmdAudit(args []string) int {
	fs := newFlagSet("audit", "usage: sentinel audit [-n N] [--json]")
	var n int
	fs.IntVar(&n, "n", 20, "tail lines")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	p := filepath.Join(dataDir(), "audit.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		return failRuntime(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if g.json {
		events := []any{}
		for _, l := range lines {
			var v any
			if err := json.Unmarshal([]byte(l), &v); err != nil {
				events = append(events, l)
				continue
			}
			events = append(events, v)
		}
		emitJSON(map[string]any{"events": events})
		return ExitOK
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return ExitOK
}

// sentinel rotate <name> [--from-env NAME|--from-file PATH|--stdin] : new value, version++
func cmdRotate(args []string) int {
	fs := newFlagSet("rotate", "usage: sentinel rotate <name> [--from-env NAME|--from-file PATH|--stdin]")
	var fromEnv, fromFile string
	var fromStdin bool
	fs.StringVar(&fromEnv, "from-env", "", "read value from env var")
	fs.StringVar(&fromFile, "from-file", "", "read value from file")
	fs.BoolVar(&fromStdin, "stdin", false, "read value from stdin")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() < 1 {
		return failUsage("sentinel rotate <name> [--from-env NAME|--from-file PATH|--stdin]")
	}
	name := fs.Arg(0)
	val, err := readSecretValue(fromEnv, fromFile, fromStdin, "new value: ")
	if err != nil {
		return failRuntime(err)
	}
	defer memguard.Zero(val)
	if len(val) == 0 {
		fmt.Fprintln(os.Stderr, "empty value")
		return ExitRuntime
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	old, err := st.Get(name)
	if err != nil {
		return failRuntime(err)
	}
	old.Value = append([]byte(nil), val...)
	old.Version++
	if err := st.Put(old); err != nil {
		return failRuntime(err)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_rotated", map[string]any{"name": name, "version": old.Version})
		l.Close()
	}
	if !g.quiet {
		fmt.Println("rotated", name, "v", old.Version)
	}
	return ExitOK
}
