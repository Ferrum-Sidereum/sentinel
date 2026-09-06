package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Exit codes (WP-08): 0 ok, 1 runtime error, 2 usage error,
// 3 policy violation/blocked, 4 locked/approval denied.
const (
	ExitOK      = 0
	ExitRuntime = 1
	ExitUsage   = 2
	ExitBlocked = 3
	ExitLocked  = 4
)

// ldflags-injected build metadata:
// go build -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=..."
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// globals holds CLI-wide flags.
type globals struct {
	dataDir string
	json    bool
	quiet   bool
	noColor bool
}

var g globals

func dataDir() string {
	if g.dataDir != "" {
		return g.dataDir
	}
	if v := os.Getenv("SENTINEL_DATA_DIR"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentinel")
}

type command struct {
	name  string
	desc  string
	usage string
	run   func(args []string) int
}

var commands []command

func register(cmds ...command) {
	commands = append(commands, cmds...)
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// JSON output shapes (stable, documented):
//
//	ls:    {"secrets":[{"name":...,"placeholder":...,"safe":...}]}
//	scan:  {"findings":[{"type":...,"detector":...,"confidence":...,"line":...,"col":...,"fp":...}],"placeholders":[...]} (+ "value" per finding only with --show-values on a TTY)
//	audit: {"events":[<raw jsonl objects>]}
func emitJSON(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}
func newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	// Global flags are accepted both before the command
	// (parseGlobals) and after it (here, writing to the same g).
	fs.BoolVar(&g.json, "json", g.json, "machine-readable JSON output")
	fs.BoolVar(&g.quiet, "quiet", g.quiet, "suppress informational output")
	fs.BoolVar(&g.noColor, "no-color", g.noColor, "disable color")
	fs.StringVar(&g.dataDir, "data-dir", g.dataDir, "state directory (overrides ~/.sentinel, SENTINEL_DATA_DIR)")
	return fs
}

// parseGlobals extracts global flags appearing before the command name.
// Returns remaining args (starting at command). Unknown --flag before the
// command is a usage error naming the flag.
func parseGlobals(args []string) ([]string, int) {
	g = globals{}
	i := 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break
		}
		switch {
		case a == "--json":
			g.json = true
		case a == "--quiet":
			g.quiet = true
		case a == "--no-color":
			g.noColor = true
		case a == "--data-dir" || strings.HasPrefix(a, "--data-dir="):
			v, rest, err := flagValue("--data-dir", a, args, &i)
			if err != nil {
				return nil, failUsage(err.Error())
			}
			g.dataDir = v
			_ = rest
		case a == "-h" || a == "--help" || a == "help":
			printHelp()
			return nil, -1
		default:
			return nil, failUsage(fmt.Sprintf("unknown global flag %s", a))
		}
		i++
	}
	return args[i:], 0
}

// flagValue resolves --name value | --name=value, erroring on missing value.
func flagValue(name, arg string, args []string, i *int) (string, []string, error) {
	if strings.HasPrefix(arg, name+"=") {
		return strings.TrimPrefix(arg, name+"="), args, nil
	}
	if *i+1 >= len(args) {
		return "", nil, fmt.Errorf("flag %s requires a value", name)
	}
	*i++
	return args[*i], args, nil
}

func failUsage(msg string) int {
	fmt.Fprintln(os.Stderr, "usage error:", msg)
	return ExitUsage
}

func failRuntime(err error) int {
	fmt.Fprintln(os.Stderr, "error:", err)
	return ExitRuntime
}

func printHelp() {
	fmt.Println("sentinel — secret vault CLI")
	fmt.Println()
	fmt.Println("usage: sentinel [--data-dir DIR] [--json] [--quiet] [--no-color] <command> [flags]")
	fmt.Println()
	fmt.Println("commands:")
	for _, c := range commands {
		fmt.Printf("  %-10s %s\n", c.name, c.desc)
	}
	fmt.Println()
	fmt.Println("run 'sentinel <command> --help' for command flags.")
}

func cmdHelp(args []string) int {
	if len(args) > 0 {
		if c := findCommand(args[0]); c != nil {
			fmt.Printf("sentinel %s — %s\n\nusage: %s\n", c.name, c.desc, c.usage)
			return ExitOK
		}
		return failUsage(fmt.Sprintf("unknown command %q", args[0]))
	}
	printHelp()
	return ExitOK
}

func cmdVersion(args []string) int {
	fs := newFlagSet("version", "usage: sentinel version")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if g.json {
		emitJSON(map[string]string{
			"version":   version,
			"commit":    commit,
			"buildDate": buildDate,
			"goVersion": runtime.Version(),
		})
		return ExitOK
	}
	fmt.Printf("sentinel %s (commit %s, built %s, %s)\n", version, commit, buildDate, runtime.Version())
	return ExitOK
}

// dispatch runs the CLI; returns process exit code. code -1 means already handled.
func dispatch(argv []string) int {
	rest, code := parseGlobals(argv)
	if code == -1 {
		return ExitOK
	}
	if code != 0 {
		return code
	}
	if len(rest) == 0 {
		printHelp()
		return ExitUsage
	}
	name := rest[0]
	if name == "help" {
		return cmdHelp(rest[1:])
	}
	if name == "version" {
		return cmdVersion(rest[1:])
	}
	// <cmd> --help without running the command.
	for _, a := range rest[1:] {
		if a == "--help" || a == "-h" {
			return cmdHelp([]string{name})
		}
	}
	c := findCommand(name)
	if c == nil {
		printHelp()
		return failUsage(fmt.Sprintf("unknown command %q", name))
	}
	return c.run(rest[1:])
}
