package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinel/internal/placeholder"
	"sentinel/internal/vault"
)

// sentinel env import --bind host [--prefix P] [file]
// stdin or file with KEY=VALUE lines; values stored as secrets named lower(KEY).
func cmdEnvImport(args []string) {
	bind, prefix, file := "", "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bind":
			i++
			if i < len(args) {
				bind = args[i]
			}
		case "--prefix":
			i++
			if i < len(args) {
				prefix = args[i]
			}
		default:
			if !strings.HasPrefix(args[i], "--") {
				file = args[i]
			}
		}
	}
	if bind == "" {
		fmt.Println("usage: sentinel env import --bind host [--prefix P] [file]")
		os.Exit(2)
	}
	var lines []string
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
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
		fmt.Println(err)
		os.Exit(1)
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
		// print export mapping
		fmt.Printf("%s=%s\n", k, placeholder.Canonical(name))
		n++
	}
	if l := openAudit(); l != nil {
		l.Log("", "env_imported", map[string]any{"count": n, "host": bind})
		l.Close()
	}
	fmt.Fprintf(os.Stderr, "imported %d\n", n)
}

// sentinel audit [tail] [-n N]
func cmdAudit(args []string) {
	n := 20
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-n" {
			fmt.Sscanf(args[i+1], "%d", &n)
		}
	}
	p := filepath.Join(dataDir(), "audit.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		fmt.Println(l)
	}
}

// sentinel rotate <name> : new value from stdin, version++
func cmdRotate(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: sentinel rotate <name>")
		os.Exit(2)
	}
	name := args[0]
	r := bufio.NewReader(os.Stdin)
	val, _ := r.ReadString('\n')
	val = strings.TrimSpace(val)
	if val == "" {
		fmt.Println("empty value")
		os.Exit(1)
	}
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	old, err := st.Get(name)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	old.Value = []byte(val)
	old.Version++
	if err := st.Put(old); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_rotated", map[string]any{"name": name, "version": old.Version})
		l.Close()
	}
	fmt.Println("rotated", name, "v", old.Version)
}
