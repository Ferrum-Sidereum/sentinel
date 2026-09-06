package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gateBuild builds the CLI once for gate tests.
func gateBuild(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sentinel.exe")
	bld := exec.Command("go", "build", "-o", bin, ".")
	if out, err := bld.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	return bin
}

func gateRun(t *testing.T, bin string, args []string, stdin, dir, home string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
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

// clean fixture => 0, dirty fixture => 3.
func TestGateCleanDirty(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	bin := gateBuild(t)
	home := t.TempDir()
	if _, _, code := gateRun(t, bin, []string{"scan"}, "nothing here", "", home); code != 0 {
		t.Fatalf("clean exit %d, want 0", code)
	}
	if _, _, code := gateRun(t, bin, []string{"scan"}, "contact user@example.com", "", home); code != 3 {
		t.Fatalf("dirty exit %d, want 3", code)
	}
}

// --fail-on CREDIT_CARD ignores EMAIL-only (0).
func TestGateFailOn(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	bin := gateBuild(t)
	home := t.TempDir()
	out, _, code := gateRun(t, bin, []string{"scan", "--fail-on", "CREDIT_CARD"}, "contact user@example.com", "", home)
	if code != 0 {
		t.Fatalf("fail-on mismatch exit %d, want 0 (out %q)", code, out)
	}
	if !strings.Contains(out, "EMAIL") {
		t.Fatalf("fail-on should still print EMAIL finding, got %q", out)
	}
	if _, _, code := gateRun(t, bin, []string{"scan", "--fail-on", "EMAIL"}, "contact user@example.com", "", home); code != 3 {
		t.Fatalf("fail-on match exit %d, want 3", code)
	}
}

// SARIF validates structurally (2.1.0, runs[0].tool.driver + results) and
// contains no secret values.
func TestGateSARIF(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	bin := gateBuild(t)
	home := t.TempDir()
	secret := "user@example.com"
	out, _, code := gateRun(t, bin, []string{"scan", "--format", "sarif"}, "leak "+secret, "", home)
	if code != 3 {
		t.Fatalf("sarif dirty exit %d, want 3", code)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("SARIF contains secret value")
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF invalid JSON: %v (%q)", err, out)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("SARIF version %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "sentinel" {
		t.Fatalf("SARIF runs/driver wrong: %+v", log.Runs)
	}
	if len(log.Runs[0].Results) == 0 {
		t.Fatal("SARIF has no results for dirty input")
	}
	for _, r := range log.Runs[0].Results {
		if strings.Contains(r.Message.Text, secret) {
			t.Fatalf("SARIF message leaks value: %q", r.Message.Text)
		}
	}
	// --json and --format json agree.
	j1, _, _ := gateRun(t, bin, []string{"scan", "--json"}, "leak "+secret, "", home)
	j2, _, _ := gateRun(t, bin, []string{"scan", "--format", "json"}, "leak "+secret, "", home)
	var v1, v2 struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(j1), &v1); err != nil {
		t.Fatalf("--json invalid: %v", err)
	}
	if err := json.Unmarshal([]byte(j2), &v2); err != nil {
		t.Fatalf("--format json invalid: %v", err)
	}
	if len(v1.Findings) != len(v2.Findings) || len(v1.Findings) == 0 {
		t.Fatalf("--json vs --format json mismatch: %d vs %d", len(v1.Findings), len(v2.Findings))
	}
}

// .sentinelignore excludes a path; --no-ignore includes it.
func TestGateSentinelIgnore(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	bin := gateBuild(t)
	home := t.TempDir()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dirty.txt"), []byte("contact user@example.com"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".sentinelignore"), []byte("dirty.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := gateRun(t, bin, []string{"scan", dir}, "", "", home); code != 0 {
		t.Fatalf("ignored path exit %d, want 0", code)
	}
	_, _, code := gateRun(t, bin, []string{"scan", "--no-ignore", dir}, "", "", home)
	if code != 3 {
		t.Fatalf("--no-ignore exit %d, want 3", code)
	}
}

// --staged reads the git index, not the worktree.
func TestGateStaged(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	bin := gateBuild(t)
	home := t.TempDir()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t")
	run("config", "user.name", "t")
	// staged content is dirty, worktree is clean.
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("contact user@example.com"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("nothing here"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, code := gateRun(t, bin, []string{"scan", "--staged"}, "", dir, home)
	if code != 3 {
		t.Fatalf("--staged on dirty index exit %d, want 3 (must read index, not worktree)", code)
	}
}
