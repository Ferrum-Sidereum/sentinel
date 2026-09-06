package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/broker"
	"sentinel/internal/core"
)

func writeAuditLine(t *testing.T, dir, typ string, fields map[string]any) {
	t.Helper()
	l, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Log("test", typ, fields)
}

func TestApprovalRoundTripToBroker(t *testing.T) {
	a := testApp(t)
	done := make(chan broker.Decision, 1)
	go func() {
		d, err := a.Ask(context.Background(), broker.Request{Secret: "OPENAI_KEY", Consumer: "egress:test", Dest: "api.test.com", Reason: "env injection"})
		if err != nil {
			t.Errorf("Ask: %v", err)
		}
		done <- d
	}()
	time.Sleep(50 * time.Millisecond)
	pend, err := a.PendingApprovals()
	if err != nil || len(pend) != 1 || pend[0].Secret != "OPENAI_KEY" {
		t.Fatalf("pending = %+v, err = %v", pend, err)
	}
	res, err := a.ResolveApproval("OPENAI_KEY", "15m")
	if err != nil || !res.Allow || res.Scope != "15m" {
		t.Fatalf("resolve = %+v, err = %v", res, err)
	}
	select {
	case d := <-done:
		if !d.Allow || d.Rule != "interactive" {
			t.Fatalf("decision = %+v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ask never resolved")
	}
}

func TestApprovalTimeoutDenies(t *testing.T) {
	a := testApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	d, err := a.Ask(ctx, broker.Request{Secret: "X", Consumer: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow || d.Scope != "deny" {
		t.Fatalf("timeout must deny, got %+v", d)
	}
}

func TestFeedFilterAndCounters(t *testing.T) {
	a := testApp(t)
	writeAuditLine(t, a.dir, broker.EventApproved, map[string]any{"name": "A", "host": "h1", "decision": "once"})
	writeAuditLine(t, a.dir, broker.EventDenied, map[string]any{"name": "B", "host": "h2"})
	writeAuditLine(t, a.dir, "pii_redacted", map[string]any{"count": 3})
	page, err := a.ActivityFeed(FeedFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Counters.Resolutions < 1 || page.Counters.Denials < 1 || page.Counters.Redactions < 3 {
		t.Fatalf("counters = %+v", page.Counters)
	}
	f, err := a.ActivityFeed(FeedFilter{Type: broker.EventDenied})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range f.Entries {
		if e.Type != broker.EventDenied {
			t.Fatalf("unfiltered entry %+v", e)
		}
	}
}

func TestNoSecretValueCrossesBridge(t *testing.T) {
	a := testApp(t)
	st, key, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Add(st, core.AddInput{Name: "BRIDGE_KEY", Value: []byte("super-secret-value"), Hosts: []string{"h.example"}}); err != nil {
		t.Fatal(err)
	}
	closeStore(st, key)
	list, err := a.SecretList()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, err = %v", list, err)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "super-secret-value") {
		t.Fatal("plaintext crossed the bridge via SecretList")
	}
	feed, _ := a.ActivityFeed(FeedFilter{})
	b, _ = json.Marshal(feed)
	if strings.Contains(string(b), "super-secret-value") {
		t.Fatal("plaintext crossed the bridge via ActivityFeed")
	}
	tray, _ := a.Tray()
	b, _ = json.Marshal(tray)
	if strings.Contains(string(b), "super-secret-value") {
		t.Fatal("plaintext crossed the bridge via Tray")
	}
	if list[0].Masked == "BRIDGE_KEY" || list[0].Masked == "" {
		t.Fatalf("value not masked: %q", list[0].Masked)
	}
	if len(list[0].Hosts) != 1 || list[0].Hosts[0] != "h.example" {
		t.Fatalf("hosts = %v", list[0].Hosts)
	}
}

func TestRevealLockedRefused(t *testing.T) {
	a := testApp(t)
	st, key, _ := a.openStore()
	_ = core.Add(st, core.AddInput{Name: "LOCKME", Value: []byte("v")})
	closeStore(st, key)
	a.keyLoad = func() ([]byte, error) { return nil, errors.New("locked") }
	if _, err := a.RevealSecret("LOCKME", "LOCKME"); err == nil {
		t.Fatal("reveal must fail when locked")
	}
	raw, _ := os.ReadFile(filepath.Join(a.dir, "audit.jsonl"))
	if strings.Contains(string(raw), "\"value\"") {
		t.Fatal("audit contains value field")
	}
}

func TestWizardIdempotent(t *testing.T) {
	a := testApp(t)
	first, err := a.WizardInit()
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.WizardInit()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 5 || len(second) != 5 {
		t.Fatalf("steps = %d / %d", len(first), len(second))
	}
	for _, s := range second {
		if s.CLI == "" {
			t.Fatalf("step %s has no CLI equivalent", s.ID)
		}
	}
	k1, _ := a.keyLoad()
	k2, _ := a.keyLoad()
	if string(k1) != string(k2) {
		t.Fatal("re-run changed the key")
	}
}

func TestTrayPauseAndBadge(t *testing.T) {
	a := testApp(t)
	writeAuditLine(t, a.dir, broker.EventDenied, map[string]any{"name": "B"})
	st, err := a.SetEgressPaused(true)
	if err != nil || !st.Paused {
		t.Fatalf("pause = %+v, err = %v", st, err)
	}
	for _, v := range st.Gateways {
		if v {
			t.Fatal("gateway dot must be red when paused")
		}
	}
	if st.RecentDenies < 1 {
		t.Fatalf("badge = %d", st.RecentDenies)
	}
	st, err = a.SetEgressPaused(false)
	if err != nil || st.Paused {
		t.Fatalf("unpause = %+v, err = %v", st, err)
	}
}
