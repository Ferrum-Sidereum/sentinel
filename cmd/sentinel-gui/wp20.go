package main

// WP-20: activity feed, approval surface (interactive broker), onboarding
// wizard, tray state, enriched secret list. No secret-read methods added;
// values cross the bridge only via the existing just-confirmed RevealSecret.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/broker"
	"sentinel/internal/core"
)

// FeedEntry is one live audit row: who asked which secret, when, allowed/denied.
type FeedEntry struct {
	Seq     uint64 `json:"seq"`
	Time    string `json:"time"`
	Type    string `json:"type"`
	Secret  string `json:"secret"`
	Host    string `json:"host"`
	Decided string `json:"decided"`
	Count   int    `json:"count"`
}

// FeedFilter narrows the live feed; empty fields mean no filtering.
type FeedFilter struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
	Since  string `json:"since"` // RFC3339, optional
	Limit  int    `json:"limit"`
}

// FeedPage is a filtered slice of the audit tail plus metric counters.
type FeedPage struct {
	Entries   []FeedEntry  `json:"entries"`
	Counters  FeedCounters `json:"counters"`
	Truncated bool         `json:"truncated"`
}

// FeedCounters surfaces resolution/denial/redaction counts.
type FeedCounters struct {
	Resolutions int `json:"resolutions"`
	Denials     int `json:"denials"`
	Redactions  int `json:"redactions"`
}

// ApprovalRequest is the native prompt payload: once / 15m / session / deny.
type ApprovalRequest struct {
	Secret   string `json:"secret"`
	Consumer string `json:"consumer"`
	Dest     string `json:"dest"`
	Reason   string `json:"reason"`
	TimeoutS int    `json:"timeoutS"`
}

// ApprovalResult is the verdict returned to the prompter.
type ApprovalResult struct {
	Allow bool   `json:"allow"`
	Scope string `json:"scope"` // "once" | "15m" | "session" | "deny"
}

// TrayState is the status-dot / pause / denials-badge payload.
type TrayState struct {
	Paused       bool            `json:"paused"`
	Gateways     map[string]bool `json:"gateways"`
	RecentDenies int             `json:"recentDenies"`
}

// WizardStep is one idempotent onboarding step with its CLI equivalent.
type WizardStep struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Done   bool   `json:"done"`
	CLI    string `json:"cli"`
	Detail string `json:"detail"`
}

// SecretMeta enriches the secret list without exposing values.
type SecretMeta struct {
	Name     string   `json:"name"`
	LastUsed string   `json:"lastUsed"`
	UseCount int64    `json:"useCount"`
	Expiry   string   `json:"expiry"`
	Expired  bool     `json:"expired"`
	Hosts    []string `json:"hosts"`
	Masked   string   `json:"masked"`
}

// --- approval plumbing: App acts as interactive broker ---

var errApprovalTimeout = errors.New("approval timed out: denied by default")

type pendingApproval struct {
	req  broker.Request
	done chan broker.Decision
}

var approvalsMu sync.Mutex
var approvalsQueue []*pendingApproval

// Ask implements broker.Broker: enqueue a native prompt, block for the verdict.
// Context timeout/cancel resolves to deny (safe default).
func (a *App) Ask(ctx context.Context, req broker.Request) (broker.Decision, error) {
	p := &pendingApproval{req: req, done: make(chan broker.Decision, 1)}
	approvalsMu.Lock()
	approvalsQueue = append(approvalsQueue, p)
	approvalsMu.Unlock()
	select {
	case d := <-p.done:
		return d, nil
	case <-ctx.Done():
		removePending(p)
		return broker.Decision{Allow: false, Scope: "deny", Rule: "interactive-timeout"}, nil
	}
}

func removePending(p *pendingApproval) {
	approvalsMu.Lock()
	defer approvalsMu.Unlock()
	for i, q := range approvalsQueue {
		if q == p {
			approvalsQueue = append(approvalsQueue[:i], approvalsQueue[i+1:]...)
			return
		}
	}
}

// PendingApprovals drains the current prompt queue for the native UI.
func (a *App) PendingApprovals() ([]ApprovalRequest, error) {
	if err := a.lock(); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	approvalsMu.Lock()
	defer approvalsMu.Unlock()
	out := make([]ApprovalRequest, 0, len(approvalsQueue))
	for _, p := range approvalsQueue {
		out = append(out, ApprovalRequest{
			Secret: p.req.Secret, Consumer: p.req.Consumer,
			Dest: p.req.Dest, Reason: p.req.Reason, TimeoutS: 120,
		})
	}
	return out, nil
}

// ResolveApproval answers the oldest pending prompt for secret.
// Scope: "once" (TTL 0) | "15m" | "session" | anything else = deny.
func (a *App) ResolveApproval(secret, scope string) (ApprovalResult, error) {
	if err := a.lock(); err != nil {
		return ApprovalResult{}, err
	}
	defer a.mu.Unlock()
	approvalsMu.Lock()
	defer approvalsMu.Unlock()
	for i, p := range approvalsQueue {
		if p.req.Secret != secret {
			continue
		}
		approvalsQueue = append(approvalsQueue[:i], approvalsQueue[i+1:]...)
		d := broker.Decision{Allow: false, Scope: "deny", Rule: "interactive"}
		res := ApprovalResult{Allow: false, Scope: "deny"}
		switch scope {
		case "once":
			d = broker.Decision{Allow: true, TTL: 0, Scope: "once", Rule: "interactive"}
			res = ApprovalResult{Allow: true, Scope: "once"}
		case "15m":
			d = broker.Decision{Allow: true, TTL: 15 * time.Minute, Scope: "until", Rule: "interactive"}
			res = ApprovalResult{Allow: true, Scope: "15m"}
		case "session":
			d = broker.Decision{Allow: true, Scope: "session", Rule: "interactive"}
			res = ApprovalResult{Allow: true, Scope: "session"}
		}
		auditDecision(a.dir, d, p.req)
		select {
		case p.done <- d:
		default:
		}
		return res, nil
	}
	return ApprovalResult{}, errors.New("No pending approval for that secret.")
}

func auditDecision(dir string, d broker.Decision, req broker.Request) {
	typ := broker.EventDenied
	if d.Allow {
		typ = broker.EventApproved
	}
	if l, err := audit.Open(filepath.Join(dir, "audit.jsonl")); err == nil && l != nil {
		l.LogTyped("gui", typ, audit.TypedFields{Name: req.Secret, Host: req.Dest, Decision: d.Scope, Reason: req.Reason})
		_ = l.Close()
	}
}

// --- activity feed: filterable tail over the audit log ---

func parseFeedLine(line []byte) (FeedEntry, bool) {
	var raw struct {
		Seq    uint64         `json:"seq"`
		Time   string         `json:"time"`
		Ts     string         `json:"ts"`
		Type   string         `json:"type"`
		Fields map[string]any `json:"fields"`
	}
	if json.Unmarshal(line, &raw) != nil || raw.Type == "" {
		return FeedEntry{}, false
	}
	ts := raw.Time
	if ts == "" {
		ts = raw.Ts
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return FeedEntry{}, false
	}
	e := FeedEntry{Seq: raw.Seq, Time: ts, Type: raw.Type}
	for k, v := range raw.Fields {
		s, _ := v.(string)
		switch k {
		case "name", "secret":
			e.Secret = s
		case "host", "dest":
			e.Host = s
		case "decision", "verdict":
			e.Decided = s
		case "count":
			if f, ok := v.(float64); ok && f >= 0 && f <= 1000000 {
				e.Count = int(f)
			}
		}
	}
	return e, true
}

func matchFeed(e FeedEntry, f FeedFilter, since time.Time) bool {
	if f.Type != "" && e.Type != f.Type {
		return false
	}
	if f.Secret != "" && !strings.Contains(strings.ToLower(e.Secret), strings.ToLower(f.Secret)) {
		return false
	}
	if !since.IsZero() {
		t, err := time.Parse(time.RFC3339, e.Time)
		if err != nil || t.Before(since) {
			return false
		}
	}
	return true
}

// ActivityFeed returns the filterable live audit tail plus counters.
func (a *App) ActivityFeed(f FeedFilter) (FeedPage, error) {
	if err := a.lock(); err != nil {
		return FeedPage{}, err
	}
	defer a.mu.Unlock()
	page := FeedPage{Entries: []FeedEntry{}}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var since time.Time
	if f.Since != "" {
		since, _ = time.Parse(time.RFC3339, f.Since)
	}
	recs, err := audit.ReadFile(filepath.Join(a.dir, "audit.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return page, nil
		}
		return FeedPage{}, errors.New("Cannot read the local audit log.")
	}
	for i := len(recs) - 1; i >= 0; i-- {
		b, _ := json.Marshal(recs[i])
		e, ok := parseFeedLine(b)
		if !ok {
			continue
		}
		switch e.Type {
		case broker.EventApproved, "secret_injected", "secret.add":
			page.Counters.Resolutions++
		case broker.EventDenied, "secret_blocked", "llm_blocked":
			page.Counters.Denials++
		case "pii_redacted":
			page.Counters.Redactions += e.Count
			if e.Count == 0 {
				page.Counters.Redactions++
			}
		}
		if len(page.Entries) >= limit {
			page.Truncated = true
			continue
		}
		if matchFeed(e, f, since) {
			page.Entries = append(page.Entries, e)
		}
	}
	return page, nil
}

// --- tray: status dot per gateway, global pause, denials badge ---

func egressPaused(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "egress.paused"))
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// Tray returns gateway status dots, the global egress pause flag and the
// recent-denials badge count (last 24h approval_denied / secret_blocked).
func (a *App) Tray() (TrayState, error) {
	if err := a.lock(); err != nil {
		return TrayState{}, err
	}
	defer a.mu.Unlock()
	return trayLocked(a.dir), nil
}

func trayLocked(dir string) TrayState {
	paused := egressPaused(dir)
	recs, _ := audit.ReadFile(filepath.Join(dir, "audit.jsonl"))
	cutoff := time.Now().Add(-24 * time.Hour)
	denies := 0
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Type != broker.EventDenied && recs[i].Type != "secret_blocked" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, recs[i].Ts); err == nil && t.After(cutoff) {
			denies++
		}
	}
	return TrayState{
		Paused:       paused,
		Gateways:     map[string]bool{"llm": !paused, "mcp": !paused, "egress": !paused},
		RecentDenies: denies,
	}
}

// SetEgressPaused flips the global egress pause flag.
func (a *App) SetEgressPaused(paused bool) (TrayState, error) {
	if err := a.lock(); err != nil {
		return TrayState{}, err
	}
	defer a.mu.Unlock()
	v := "0"
	if paused {
		v = "1"
	}
	if err := atomicWrite(filepath.Join(a.dir, "egress.paused"), []byte(v)); err != nil {
		return TrayState{}, errors.New("Cannot update the pause flag.")
	}
	return trayLocked(a.dir), nil
}

// --- onboarding wizard: idempotent, every step shows its CLI equivalent ---

// Wizard returns the step list; Done is derived from real state (safe re-run).
func (a *App) Wizard() ([]WizardStep, error) {
	if err := a.lock(); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	steps, werr := wizardLocked(a)
	return steps, werr
}

func wizardClientConfigPaths() []string {
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	return []string{
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".vscode", "mcp.json"),
	}
}

func wizardLocked(a *App) ([]WizardStep, error) {
	_, keyErr := a.keyLoad()
	hasSecrets := false
	hasClientCfg := false
	if keyErr == nil {
		if st, key, err := a.openStore(); err == nil {
			names, _ := st.List()
			hasSecrets = len(names) > 0
			closeStore(st, key)
		}
	}
	for _, p := range wizardClientConfigPaths() {
		if _, err := os.Stat(p); err == nil {
			hasClientCfg = true
			break
		}
	}
	return []WizardStep{
		{ID: "keychain", Title: "Keychain check", Done: keyErr == nil, CLI: "sentinel doctor", Detail: keychainDetail(keyErr)},
		{ID: "init", Title: "Initialize vault", Done: keyErr == nil, CLI: "sentinel init", Detail: "Creates the encrypted vault and master key."},
		{ID: "first-secret", Title: "Add first secret", Done: hasSecrets, CLI: "sentinel add OPENAI_API_KEY --hosts api.openai.com", Detail: "Store one API key bound to its host."},
		{ID: "client-config", Title: "Configure client", Done: hasClientCfg, CLI: "sentinel client --claude", Detail: "Writes the MCP/egress client snippet."},
		{ID: "test-call", Title: "Live test call", Done: false, CLI: "sentinel run -- curl -s https://api.openai.com/v1/models", Detail: "Proves injection works end to end. Run it when ready."},
	}, nil
}

func keychainDetail(err error) string {
	if err == nil {
		return "Master key loads from the OS keychain."
	}
	return "No key yet — run init to create one."
}

// WizardInit performs the init step idempotently (existing key is reused).
func (a *App) WizardInit() ([]WizardStep, error) {
	if err := a.lock(); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	if _, err := a.keyLoad(); err != nil {
		if _, err := a.keyCreate(a.dir); err != nil {
			return nil, errors.New("Cannot create the master key.")
		}
	}
	if err := core.EnsurePolicy(a.dir); err != nil {
		return nil, errors.New("Cannot write the default policy.")
	}
	return wizardLocked(a)
}

// --- enriched secret list: metadata only, values stay in the vault ---

func maskName(name string) string {
	if len(name) <= 4 {
		return "••••"
	}
	return name[:2] + "••••" + name[len(name)-2:]
}

// SecretList returns last-used/use-count/expiry/hosts/masked value per secret.
func (a *App) SecretList() ([]SecretMeta, error) {
	if err := a.lock(); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	st, key, err := a.openStore()
	if err != nil {
		return nil, err
	}
	defer closeStore(st, key)
	names, err := st.List()
	if err != nil {
		return nil, errors.New("Cannot read vault entries.")
	}
	out := make([]SecretMeta, 0, len(names))
	for _, n := range names {
		sec, err := st.Get(n)
		if err != nil {
			continue
		}
		// sec.Value is plaintext in memory here; wipe before it escapes scope.
		m := SecretMeta{Name: n, UseCount: sec.UseCount, Hosts: append([]string(nil), sec.Hosts...), Masked: maskName(n), Expired: sec.Expired()}
		wipe(sec.Value)
		if sec.LastUsedAt != nil {
			m.LastUsed = sec.LastUsedAt.UTC().Format(time.RFC3339)
		}
		if sec.ExpiresAt != nil {
			m.Expiry = sec.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
