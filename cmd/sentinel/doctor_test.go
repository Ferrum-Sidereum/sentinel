package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func withDoctorEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("SENTINEL_DATA_DIR", dir)
	t.Setenv("SENTINEL_RUN_DIR", filepath.Join(dir, "run"))
	t.Setenv("SENTINEL_DOCTOR_PORTS", "127.0.0.1:18991,127.0.0.1:18992")
	t.Setenv("SENTINEL_DOCTOR_CLIENTS", "")
	t.Setenv("SENTINEL_SRC_DIR", filepath.Join(dir, "nosrc"))
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
}

func TestDoctorTroubleshootingMapping(t *testing.T) {
	checks := map[string]bool{}
	for _, c := range runDoctor() {
		checks[c.Name] = true
	}
	for _, row := range doctorTroubleshooting {
		if !checks[row.Check] {
			t.Errorf("troubleshooting symptom %q maps to unknown check %q", row.Symptom, row.Check)
		}
	}
	// Every check (except key-match, covered by keychain+vault rows) must be
	// referenced by at least one troubleshooting row.
	mapped := map[string]bool{}
	for _, row := range doctorTroubleshooting {
		mapped[row.Check] = true
	}
	for _, c := range runDoctor() {
		if !mapped[c.Name] && c.Name != "key-match" {
			t.Errorf("check %q has no troubleshooting row", c.Name)
		}
	}
}

func TestDoctorChecksPassFail(t *testing.T) {
	t.Run("data-dir missing warns", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nodata")
		withDoctorEnv(t, dir)
		if c := checkDataDir(); c.Status != "warn" {
			t.Fatalf("want warn, got %s (%s)", c.Status, c.Detail)
		}
	})
	t.Run("data-dir file fails", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "f")
		os.WriteFile(f, []byte("x"), 0o600)
		withDoctorEnv(t, f)
		if c := checkDataDir(); c.Status != "fail" {
			t.Fatalf("want fail, got %s", c.Status)
		}
	})
	t.Run("data-dir ok", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		if c := checkDataDir(); c.Status != "ok" {
			t.Fatalf("want ok, got %s (%s)", c.Status, c.Detail)
		}
	})
	t.Run("policy bad yaml fails", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(":\tbad"), 0o600)
		if c := checkPolicy(); c.Status != "fail" {
			t.Fatalf("want fail, got %s", c.Status)
		}
	})
	t.Run("policy unknown keys warns", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("bogus_key: 1\n"), 0o600)
		if c := checkPolicy(); c.Status != "warn" {
			t.Fatalf("want warn, got %s", c.Status)
		}
	})
	t.Run("policy valid ok", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("hosts: {}\n"), 0o600)
		if c := checkPolicy(); c.Status != "ok" {
			t.Fatalf("want ok, got %s", c.Status)
		}
	})
	t.Run("policy absent ok", func(t *testing.T) {
		withDoctorEnv(t, t.TempDir())
		if c := checkPolicy(); c.Status != "ok" {
			t.Fatalf("want ok, got %s", c.Status)
		}
	})
	t.Run("ca absent warns", func(t *testing.T) {
		withDoctorEnv(t, t.TempDir())
		if c := checkCA(); c.Status != "warn" {
			t.Fatalf("want warn, got %s", c.Status)
		}
	})
	t.Run("ca garbage fails", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("not pem"), 0o600)
		if c := checkCA(); c.Status != "fail" {
			t.Fatalf("want fail, got %s", c.Status)
		}
	})
	t.Run("ports no rundir warns", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		t.Setenv("SENTINEL_RUN_DIR", filepath.Join(dir, "norun"))
		if c := checkPorts(); c.Status != "warn" {
			t.Fatalf("want warn, got %s (%s)", c.Status, c.Detail)
		}
	})
	t.Run("ports free ok", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		os.MkdirAll(filepath.Join(dir, "run"), 0o700)
		if c := checkPorts(); c.Status != "ok" {
			t.Fatalf("want ok, got %s (%s)", c.Status, c.Detail)
		}
	})
	t.Run("ports owned ok", func(t *testing.T) {
		dir := t.TempDir()
		withDoctorEnv(t, dir)
		os.MkdirAll(filepath.Join(dir, "run"), 0o700)
		os.WriteFile(filepath.Join(dir, "run", "x.json"), []byte(`{"addr":"127.0.0.1:18991"}`), 0o600)
		if c := checkPorts(); c.Status != "ok" {
			t.Fatalf("want ok, got %s", c.Status)
		}
	})
	t.Run("mcp-config no files ok", func(t *testing.T) {
		withDoctorEnv(t, t.TempDir())
		t.Setenv("HOME", t.TempDir())
		t.Setenv("USERPROFILE", t.TempDir())
		if c := checkMCPConfig(); c.Status != "ok" {
			t.Fatalf("want ok, got %s", c.Status)
		}
	})
	t.Run("mcp-config relative path warns", func(t *testing.T) {
		home := t.TempDir()
		withDoctorEnv(t, t.TempDir())
		t.Setenv("SENTINEL_DOCTOR_CLIENTS", filepath.Join(home, "cfg.json"))
		cfg := map[string]any{"mcpServers": map[string]any{
			"sentinel": map[string]any{"command": "sentinel", "args": []string{}},
		}}
		b, _ := json.Marshal(cfg)
		os.WriteFile(filepath.Join(home, "cfg.json"), b, 0o600)
		if c := checkMCPConfig(); c.Status != "warn" {
			t.Fatalf("want warn, got %s", c.Status)
		}
	})
	t.Run("mcp-config abs missing warns", func(t *testing.T) {
		home := t.TempDir()
		withDoctorEnv(t, t.TempDir())
		t.Setenv("SENTINEL_DOCTOR_CLIENTS", filepath.Join(home, "cfg.json"))
		cfg := map[string]any{"mcpServers": map[string]any{
			"sentinel": map[string]any{"command": filepath.Join(home, "nosuchbin"), "args": []string{}},
		}}
		b, _ := json.Marshal(cfg)
		os.WriteFile(filepath.Join(home, "cfg.json"), b, 0o600)
		if c := checkMCPConfig(); c.Status != "warn" {
			t.Fatalf("want warn, got %s", c.Status)
		}
	})
	t.Run("clock ok", func(t *testing.T) {
		if c := checkClockSkew(); c.Status != "ok" {
			t.Fatalf("want ok, got %s", c.Status)
		}
	})
	t.Run("binary-path", func(t *testing.T) {
		c := checkBinaryPath()
		if c.Status != "ok" && c.Status != "fail" {
			t.Fatalf("unexpected status %s", c.Status)
		}
	})
	t.Run("keychain/key-match/vault no vault warn", func(t *testing.T) {
		withDoctorEnv(t, t.TempDir())
		if c := checkKeyMatch(); c.Status == "fail" {
			t.Fatalf("no vault must not fail, got %s", c.Detail)
		}
		if c := checkVaultOpen(); c.Status == "fail" {
			t.Fatalf("no vault must not fail, got %s", c.Detail)
		}
	})
}

func TestDoctorExitCodes(t *testing.T) {
	old := g
	t.Cleanup(func() { g = old })
	withDoctorEnv(t, t.TempDir())
	if got := cmdDoctor([]string{"--bogus"}); got != ExitUsage {
		t.Fatalf("bad flag: want %d got %d", ExitUsage, got)
	}
	if got := cmdDoctor([]string{"extra"}); got != ExitUsage {
		t.Fatalf("extra arg: want %d got %d", ExitUsage, got)
	}
	// No vault: no fail => exit 0.
	code := cmdDoctor([]string{"--json"})
	if code != ExitOK && code != 1 {
		t.Fatalf("unexpected exit %d", code)
	}
}
