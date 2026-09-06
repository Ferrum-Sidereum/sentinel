package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/memguard"
	"sentinel/internal/placeholder"
	"sentinel/internal/vault"
)

// parseExpires accepts durations like 30d, 12h, 45m, 90s (d=24h) and returns
// the absolute expiry time. Empty input returns nil.
func parseExpires(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	mult := time.Second
	num := s
	switch {
	case strings.HasSuffix(s, "d"):
		mult = 24 * time.Hour
		num = strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "h"):
		mult = time.Hour
		num = strings.TrimSuffix(s, "h")
	case strings.HasSuffix(s, "m"):
		mult = time.Minute
		num = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "s"):
		num = strings.TrimSuffix(s, "s")
	}
	n, err := strconv.Atoi(num)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("invalid --expires %q: use e.g. 30d, 12h", s)
	}
	t := time.Now().Add(time.Duration(n) * mult)
	return &t, nil
}

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

// sentinel rotate <name> [--from-env NAME|--from-file PATH|--stdin] : new value, version++
func cmdRotate(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: sentinel rotate <name> [--from-env NAME|--from-file PATH|--stdin]")
		os.Exit(2)
	}
	name := args[0]
	fromEnv, fromFile, fromStdin := "", "", false
	for i := 1; i < len(args); i++ {
		switch args[i] {
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
	val, err := readSecretValue(fromEnv, fromFile, fromStdin, "new value: ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer memguard.Zero(val)
	if len(val) == 0 {
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
	if err := st.Rotate(name, val, vault.DefaultKeepVersions); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_rotated", map[string]any{"name": name, "version": old.Version + 1})
		l.Close()
	}
	fmt.Println("rotated", name, "v", old.Version+1)
}

// sentinel rollback <name> : restore the most recent retained version.
func cmdRollback(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: sentinel rollback <name>")
		os.Exit(2)
	}
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Rollback(args[0]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_rolled_back", map[string]any{"name": args[0]})
		l.Close()
	}
	fmt.Println("rolled back", args[0])
}
