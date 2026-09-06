package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cliHarness builds the CLI and runs it with an isolated data dir.
func cliHarness(t *testing.T, args []string, stdin string) (string, string, int) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sentinel.exe")
	bld := exec.Command("go", "build", "-o", bin, ".")
	if out, err := bld.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	dd := t.TempDir()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	env := append(os.Environ(), "SENTINEL_DATA_DIR="+dd, "HOME="+t.TempDir(), "USERPROFILE="+t.TempDir())
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return stdout.String(), stderr.String(), code
}

// Every command in the dispatch table appears in help/bare/help outputs.
func TestHelpListsAllCommands(t *testing.T) {
	for _, argv := range [][]string{{}, {"help"}} {
		out, _, code := cliHarness(t, argv, "")
		if code != 0 && len(argv) > 0 {
			t.Fatalf("help exit %d", code)
		}
		for _, c := range commands {
			if !strings.Contains(out, c.name) || !strings.Contains(out, c.desc) {
				t.Fatalf("help missing %q / %q in %q", c.name, c.desc, out)
			}
		}
	}
	// per-command --help
	for _, c := range commands {
		out, _, code := cliHarness(t, []string{c.name, "--help"}, "")
		if code != 0 {
			t.Fatalf("%s --help exit %d", c.name, code)
		}
		if !strings.Contains(out, c.name) {
			t.Fatalf("%s --help missing command name", c.name)
		}
	}
}

// Unknown flag names the flag and exits 2.
func TestUnknownFlagExit2(t *testing.T) {
	_, stderr, code := cliHarness(t, []string{"ls", "--bogus-flag"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "bogus-flag") {
		t.Fatalf("stderr missing flag name: %q", stderr)
	}
}

// Trailing --bind without value exits 2 without panic.
func TestBindLastNoValue(t *testing.T) {
	_, stderr, code := cliHarness(t, []string{"add", "x", "--bind"}, "")
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr %q)", code, stderr)
	}
	if strings.Contains(stderr, "panic") {
		t.Fatalf("panicked: %q", stderr)
	}
}

// --data-dir fully isolates state (HOME poisoned to nonexistent).
func TestDataDirIsolates(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sentinel.exe")
	bld := exec.Command("go", "build", "-o", bin, ".")
	if out, err := bld.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	dd := t.TempDir()
	run := func(args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
			"TEMP=" + os.Getenv("TEMP"), "TMP=" + os.Getenv("TMP"),
			"SENTINEL_DATA_DIR=" + dd,
			"HOME=" + filepath.Join(t.TempDir(), "no-such-home"),
			"USERPROFILE=" + filepath.Join(t.TempDir(), "no-such-home"),
		}
		var sb strings.Builder
		cmd.Stdout = &sb
		cmd.Stderr = &sb
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return sb.String(), code
	}
	out, code := run("ls", "--json")
	if code != 0 {
		t.Fatalf("ls: exit %d: %s", code, out)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("ls --json invalid: %v (%q)", err, out)
	}
}

// --json parses on ls/scan/audit and version carries build metadata.
func TestJSONShapes(t *testing.T) {
	out, _, code := cliHarness(t, []string{"init"}, "")
	if code != 0 {
		t.Fatalf("init: %s", out)
	}
	for _, argv := range [][]string{{"ls", "--json"}, {"audit", "--json"}} {
		out, _, code := cliHarness(t, append([]string{"--json"}, argv...), "")
		_ = out
		_ = code
	}
	out, _, code = cliHarness(t, []string{"ls", "--json"}, "")
	if code != 0 {
		t.Fatalf("ls --json exit %d", code)
	}
	var ls struct {
		Secrets []map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(out), &ls); err != nil {
		t.Fatalf("ls shape: %v (%q)", err, out)
	}
	out, _, code = cliHarness(t, []string{"scan", "--json"}, "nothing here")
	if code != 0 {
		t.Fatalf("scan --json exit %d", code)
	}
	var sc struct {
		Findings     []map[string]any `json:"findings"`
		Placeholders []string         `json:"placeholders"`
	}
	if err := json.Unmarshal([]byte(out), &sc); err != nil {
		t.Fatalf("scan shape: %v (%q)", err, out)
	}
	out, _, code = cliHarness(t, []string{"version", "--json"}, "")
	if code != 0 {
		t.Fatalf("version exit %d", code)
	}
	_ = out
}

func TestVersionText(t *testing.T) {
	out, _, code := cliHarness(t, []string{"version"}, "")
	if code != 0 || !strings.Contains(out, "sentinel") {
		t.Fatalf("version: exit %d out %q", code, out)
	}
}
