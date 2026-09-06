package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentinel/internal/keyring"
	"sentinel/internal/runtime"
)

type gatewayStatus struct {
	Service string `json:"service"`
	Up      bool   `json:"up"`
	Addr    string `json:"addr,omitempty"`
	Stale   bool   `json:"stale,omitempty"`
}

type statusReport struct {
	Gateways   []gatewayStatus `json:"gateways"`
	VaultPath  string          `json:"vault_path"`
	KeySource  string          `json:"key_source"`
	PolicyMT   string          `json:"policy_mtime,omitempty"`
	Secrets    int             `json:"secret_count"`
	Expired    int             `json:"expired_count"`
	SecretsErr string          `json:"secrets_error,omitempty"`
}

func keySource(dir string) string {
	if keyring.HasPassphrase(dir) {
		return "passphrase"
	}
	return "keychain"
}
func cmdStatus(args []string) int {
	fs := newFlagSet("status", "usage: sentinel status [--json]")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	asJSON := g.json
	dir := dataDir()
	cleaned := runtime.SweepStale(dir)
	_ = cleaned

	rep := statusReport{
		VaultPath: filepath.Join(dir, "vault.db"),
		KeySource: keySource(dir),
	}
	if fi, err := os.Stat(filepath.Join(dir, "policy.yaml")); err == nil {
		rep.PolicyMT = fi.ModTime().UTC().Format(time.RFC3339)
	}
	for _, svc := range []string{runtime.ServiceEgress, runtime.ServiceMCP, runtime.ServiceLLM} {
		gs := gatewayStatus{Service: svc}
		rf, err := runtime.ReadRunFile(dir, svc)
		if err != nil {
			rep.Gateways = append(rep.Gateways, gs)
			continue
		}
		if !runtime.IsAlive(rf.PID) {
			gs.Stale = true
			rep.Gateways = append(rep.Gateways, gs)
			continue
		}
		gs.Up = true
		gs.Addr = rf.Addr
		rep.Gateways = append(rep.Gateways, gs)
	}
	if st, err := openStore(); err != nil {
		rep.SecretsErr = err.Error()
	} else {
		names, err := st.List()
		if err != nil {
			rep.SecretsErr = err.Error()
		} else {
			rep.Secrets = len(names)
			for _, n := range names {
				sec, err := st.Get(n)
				if err == nil && sec.Expired() {
					rep.Expired++
				}
			}
		}
		_ = st.Close()
	}
	if asJSON || g.json {
		emitJSON(rep)
		return ExitOK
	}
	for _, gs := range rep.Gateways {
		state := "down"
		if gs.Up {
			state = "up " + gs.Addr
		} else if gs.Stale {
			state = "stale (cleaned)"
		}
		fmt.Printf("%-8s %s\n", gs.Service, state)
	}
	fmt.Println("vault:   ", rep.VaultPath)
	fmt.Println("key:     ", rep.KeySource)
	if rep.PolicyMT != "" {
		fmt.Println("policy:  ", rep.PolicyMT)
	}
	if rep.SecretsErr != "" {
		fmt.Println("secrets: ", "unavailable ("+shortErr(rep.SecretsErr)+")")
	} else {
		fmt.Printf("secrets:  %d (%d expired)\n", rep.Secrets, rep.Expired)
	}
	return ExitOK
}

func shortErr(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
