package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sentinel/internal/policy"
)

// usage: sentinel policy lint [file]
//
//	sentinel policy test --dest llm|untrusted|host:<h> --tool <name> [file]
//	sentinel policy explain <field> | --list
//	sentinel policy diff <a> <b>
func cmdPolicy(args []string) int {
	if len(args) < 1 {
		return failUsage("sentinel policy lint [file] | test --dest D --tool T [file] | explain <field>|--list | diff <a> <b>")
	}
	switch args[0] {
	case "lint":
		return cmdPolicyLint(args[1:])
	case "test":
		return cmdPolicyTest(args[1:])
	case "explain":
		return cmdPolicyExplain(args[1:])
	case "diff":
		return cmdPolicyDiff(args[1:])
	default:
		return failUsage("unknown policy subcommand " + args[0])
	}
}

func policyPathOrDefault(args []string) (string, []string) {
	if len(args) >= 1 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return filepath.Join(dataDir(), "policy.yaml"), args
}

func cmdPolicyLint(args []string) int {
	path, _ := policyPathOrDefault(args)
	raw, _ := os.ReadFile(path)
	p, err := policy.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return ExitUsage
	}
	issues := policy.Lint(&p, raw)
	if len(issues) == 0 {
		fmt.Println("policy OK:", path)
		return ExitOK
	}
	for _, is := range issues {
		fmt.Fprintln(os.Stderr, is.Rule+": "+is.Message)
	}
	return ExitUsage
}

func cmdPolicyTest(args []string) int {
	fs := newFlagSet("policy test", "usage: sentinel policy test --dest llm|untrusted|host:<h> --tool <name> [file]")
	var dest, tool string
	fs.StringVar(&dest, "dest", "", "destination: llm|untrusted|host:<h>")
	fs.StringVar(&tool, "tool", "", "tool name")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if dest == "" || tool == "" {
		return failUsage("sentinel policy test --dest llm|untrusted|host:<h> --tool <name> [file]")
	}
	rest := fs.Args()
	path, rest := policyPathOrDefault(rest)
	p, err := policy.Load(path)
	if err != nil {
		return failRuntime(err)
	}
	var sample string
	if len(rest) >= 1 && rest[0] != "-" {
		b, err := os.ReadFile(rest[0])
		if err != nil {
			return failRuntime(err)
		}
		sample = string(b)
	} else {
		sample = "contact ivan@example.com, call +7 916 123-45-67, card 4111 1111 1111 1111"
	}
	r := policy.DryRun(&p, sample, policy.DestKey(dest), tool)
	fmt.Printf("dest: %s tool: %s mode: %s\n", dest, tool, r.Mode)
	if len(r.Fired) == 0 {
		fmt.Println("fired: (none)")
	} else {
		for _, f := range r.Fired {
			fmt.Printf("fired: %s (finding %s, mode %s)\n", f.Entity, f.Type, f.Mode)
		}
	}
	fmt.Println("transform:", r.Transform)
	fmt.Println("output:", r.Output)
	return ExitOK
}

func cmdPolicyExplain(args []string) int {
	if len(args) == 1 && args[0] == "--list" {
		for _, f := range policy.AllFields() {
			fmt.Println(f)
		}
		return ExitOK
	}
	if len(args) != 1 {
		return failUsage("sentinel policy explain <field> | --list")
	}
	w, err := policy.Explain(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return ExitUsage
	}
	gws := w.Gateways
	if len(gws) == 0 {
		gws = []string{"(none — parsed but unenforced)"}
	}
	sort.Strings(gws)
	fmt.Printf("field: %s\ngateways: %s\nnote: %s\n", w.Field, strings.Join(gws, ", "), w.Note)
	return ExitOK
}

func cmdPolicyDiff(args []string) int {
	if len(args) != 2 {
		return failUsage("sentinel policy diff <a> <b>")
	}
	pa, err := policy.Load(args[0])
	if err != nil {
		return failRuntime(err)
	}
	pb, err := policy.Load(args[1])
	if err != nil {
		return failRuntime(err)
	}
	entries := policy.Diff(&pa, &pb)
	if len(entries) == 0 {
		fmt.Println("no behavioural differences over fixture corpus")
		return ExitOK
	}
	for _, e := range entries {
		fmt.Println(e.String())
	}
	return ExitOK
}
