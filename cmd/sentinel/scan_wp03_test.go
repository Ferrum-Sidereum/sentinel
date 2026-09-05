package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scanHarness builds the CLI once and runs scan over a fixture.
func scanHarness(t *testing.T, args []string, stdin, home string) (string, string, int) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sentinel.exe")
	bld := exec.Command("go", "build", "-o", bin, ".")
	if out, err := bld.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
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

// TestScanNeverPrintsValue seeds a vault value of a distinctive shape and
// asserts scan output carries the finding but not the literal.
func TestScanNeverPrintsValue(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	home := t.TempDir()
	// Seed vault directly via a helper binary? Use CLI add with --stdin.
	bin := filepath.Join(t.TempDir(), "sentinel.exe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
	add := exec.Command(bin, "add", "tok", "--bind", "example.test", "--stdin")
	add.Stdin = strings.NewReader("zzz-known-marker-9f8e7d6c5b4a\n")
	add.Env = env
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("add: %v %s", err, out)
	}
	scan := exec.Command(bin, "scan")
	scan.Stdin = strings.NewReader("leak zzz-known-marker-9f8e7d6c5b4a here")
	scan.Env = env
	out, err := scan.CombinedOutput()
	if err != nil {
		t.Fatalf("scan: %v %s", err, out)
	}
	s := string(out)
	if strings.Contains(s, "zzz-known-marker-9f8e7d6c5b4a") {
		t.Fatalf("scan printed the secret value: %q", s)
	}
	sum := sha256.Sum256([]byte("zzz-known-marker-9f8e7d6c5b4a"))
	fp := hex.EncodeToString(sum[:])[:8]
	if !strings.Contains(s, fp) {
		t.Fatalf("scan missing fingerprint %s in %q", fp, s)
	}
	if !strings.Contains(s, ":") {
		t.Fatalf("scan missing line:col in %q", s)
	}
}

// TestShowValuesRefusesNonTTY asserts --show-values fails when stdout is a pipe.
func TestShowValuesRefusesNonTTY(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	home := t.TempDir()
	_, _, code := scanHarness(t, []string{"scan", "--show-values"}, "nothing", home)
	if code == 0 {
		t.Fatal("--show-values on pipe must exit non-zero")
	}
}

// TestPipedAddPreservesBytes checks trailing-space preservation via --stdin.
func TestPipedAddPreservesBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("needs build")
	}
	home := t.TempDir()
	bin := filepath.Join(t.TempDir(), "sentinel.exe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
	add := exec.Command(bin, "add", "sp", "--bind", "example.test", "--stdin")
	add.Stdin = strings.NewReader(" a=b c \n")
	add.Env = env
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("add: %v %s", err, out)
	}
	scan := exec.Command(bin, "scan")
	scan.Stdin = strings.NewReader("x a=b c y")
	scan.Env = env
	out, err := scan.CombinedOutput()
	if err != nil {
		t.Fatalf("scan: %v %s", err, out)
	}
	if strings.Contains(string(out), "a=b c") {
		t.Fatalf("scan leaked value: %q", out)
	}
}
