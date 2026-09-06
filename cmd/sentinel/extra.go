package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/audit"
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

// sentinel audit [tail] [-n N] | sentinel audit verify | sentinel audit tail [-f] [--since 1h] [--type T] [--secret NAME] [--json]
// JSON shape: {"events":[<raw objects>]}
func cmdAudit(args []string) int {
	if len(args) > 0 && args[0] == "verify" {
		return cmdAuditVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "tail" {
		return cmdAuditTail(args[1:])
	}
	return cmdAuditTail(args)
}

func cmdAuditVerify(args []string) int {
	fs := newFlagSet("audit verify", "usage: sentinel audit verify")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	p := filepath.Join(dataDir(), "audit.jsonl")
	if err := audit.Verify(p); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return ExitRuntime
	}
	if g.json {
		emitJSON(map[string]any{"ok": true})
		return ExitOK
	}
	fmt.Println("audit chain OK")
	return ExitOK
}

func cmdAuditTail(args []string) int {
	fs := newFlagSet("audit tail", "usage: sentinel audit [tail] [-n N] [-f] [--since 1h] [--type T] [--secret NAME] [--json]")
	var n int
	var follow bool
	var sinceS, typF, secretF string
	fs.IntVar(&n, "n", 20, "tail lines")
	fs.BoolVar(&follow, "f", false, "follow new records")
	fs.StringVar(&sinceS, "since", "", "only records newer than duration ago (e.g. 1h)")
	fs.StringVar(&typF, "type", "", "filter by event type")
	fs.StringVar(&secretF, "secret", "", "filter by secret name")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	p := filepath.Join(dataDir(), "audit.jsonl")
	files := audit.ChainFilesFor(p)
	recs, err := audit.ReadAll(files)
	if err != nil {
		return failRuntime(err)
	}
	var since time.Time
	if sinceS != "" {
		d, err := time.ParseDuration(sinceS)
		if err != nil {
			return failUsage("bad --since (try 1h, 30m)")
		}
		since = time.Now().Add(-d)
	}
	filtered := recs[:0:0]
	for _, r := range recs {
		ts, _ := time.Parse(time.RFC3339, r.Ts)
		if !since.IsZero() && ts.Before(since) {
			continue
		}
		if typF != "" && r.Type != typF {
			continue
		}
		if secretF != "" && (r.Fields == nil || r.Fields["name"] != secretF) {
			continue
		}
		filtered = append(filtered, r)
	}
	if len(filtered) > n {
		filtered = filtered[len(filtered)-n:]
	}
	printRec := func(r audit.Record) {
		if g.json {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
			return
		}
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
	}
	if g.json && !follow {
		emitJSON(map[string]any{"events": filtered})
		return ExitOK
	}
	for _, r := range filtered {
		printRec(r)
	}
	if follow {
		var last uint64
		if len(recs) > 0 {
			last = recs[len(recs)-1].Seq
		}
		audit.TailPoll(files, last, since, typF, secretF, nil, printRec)
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
	if err := st.Rotate(name, val, vault.DefaultKeepVersions); err != nil {
		return failRuntime(err)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_rotated", map[string]any{"name": name, "version": old.Version + 1})
		l.Close()
	}
	if !g.quiet {
		fmt.Println("rotated", name, "v", old.Version+1)
	}
	return ExitOK
}

// sentinel rollback <name> : restore the most recent retained version.
func cmdRollbackAdapter(args []string) int {
	if len(args) < 1 {
		return failUsage("sentinel rollback <name>")
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	if err := st.Rollback(args[0]); err != nil {
		return failRuntime(err)
	}
	if l := openAudit(); l != nil {
		l.Log("", "secret_rolled_back", map[string]any{"name": args[0]})
		l.Close()
	}
	if !g.quiet {
		fmt.Println("rolled back", args[0])
	}
	return ExitOK
}
