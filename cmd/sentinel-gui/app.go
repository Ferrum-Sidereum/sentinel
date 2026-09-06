package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"sentinel/internal/audit"
	"sentinel/internal/core"
	"sentinel/internal/keyring"
	"sentinel/internal/placeholder"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxScanBytes = 64 << 10
const maxPolicyBytes = 1 << 20

// Only these exported App methods are bound. No shell, arbitrary-path,
// network, secret-read or plaintext-export API is exposed.
type App struct {
	ctxMu sync.RWMutex
	ctx context.Context
	mu sync.Mutex
	dir string
	initErr error
	keyLoad func() ([]byte, error)
	keyCreate func(dir string) ([]byte, error)
}
type SecretInfo struct {
	Name        string `json:"name"`
	Placeholder string `json:"placeholder"`
}
type EntityInfo struct {
	Name        string `json:"name"`
	ToLLM       string `json:"toLLM"`
	ToUntrusted string `json:"toUntrusted"`
}
type PatternInfo struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
}
type PolicyInfo struct {
	Revision string        `json:"revision"`
	Entities []EntityInfo  `json:"entities"`
	Patterns []PatternInfo `json:"patterns"`
}
type Snapshot struct {
	Secrets []SecretInfo `json:"secrets"`
	Policy  PolicyInfo   `json:"policy"`
	Version string       `json:"version"`
}
type FindingInfo struct {
	Category   string  `json:"category"`
	Detector   string  `json:"detector"`
	Confidence float64 `json:"confidence"`
	StartByte  int     `json:"startByte"`
	EndByte    int     `json:"endByte"`
}
type ScanResult struct {
	Findings  []FindingInfo `json:"findings"`
	ElapsedMS int64         `json:"elapsedMs"`
	Bytes     int           `json:"bytes"`
}
func newApp() *App {
	home, err := os.UserHomeDir()
	a := &App{keyLoad: keyring.Load, keyCreate: keyring.Create}
	if err != nil || home == "" {
		a.initErr = errors.New("Your user profile directory is unavailable.")
		return a
	}
	a.dir = filepath.Join(home, ".sentinel")
	return a
}
func (a *App) startup(ctx context.Context) { a.ctxMu.Lock(); a.ctx = ctx; a.ctxMu.Unlock() }
func (a *App) lock() error {
	if !a.mu.TryLock() {
		return errors.New("Another operation is running. Wait and retry.")
	}
	if a.initErr != nil {
		a.mu.Unlock()
		return a.initErr
	}
	if err := os.MkdirAll(a.dir, 0700); err != nil {
		a.mu.Unlock()
		return errors.New("Cannot access the Sentinel data directory.")
	}
	return nil
}
func (a *App) openStore() (*vault.Store, []byte, error) {
	load := a.keyLoad
	if load == nil {
		load = keyring.Load
	}
	create := a.keyCreate
	if create == nil {
		create = keyring.Create
	}
	key, err := load()
	if err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return nil, nil, errors.New("The credential store is unavailable. Unlock your session and retry.")
		}
		for _, name := range []string{"vault.db", "passphrase"} {
			if _, se := os.Stat(filepath.Join(a.dir, name)); se == nil {
				return nil, nil, errors.New("Existing Sentinel data has no matching credential. Restore the original key.")
			}
		}
		key, err = create(a.dir)
		if err != nil {
			return nil, nil, errors.New("Cannot save the master key in the credential store.")
		}
	}
	st, err := openVaultAt(a.dir, key)
	if err != nil {
		wipe(key)
		return nil, nil, err
	}
	return st, key, nil
}
func closeStore(st *vault.Store, key []byte) { _ = st.Close(); wipe(key) }
func secretInfos(st *vault.Store) ([]SecretInfo, error) {
	names, err := st.List()
	if err != nil {
		return nil, errors.New("Cannot read vault entries.")
	}
	out := make([]SecretInfo, 0, len(names))
	for _, n := range names {
		ph := n
		if !strings.HasPrefix(ph, "snt://") {
			ph = placeholder.Canonical(ph)
		}
		out = append(out, SecretInfo{Name: n, Placeholder: ph})
	}
	return out, nil
}
func (a *App) Snapshot() (Snapshot, error) {
	if err := a.lock(); err != nil {
		return Snapshot{}, err
	}
	defer a.mu.Unlock()
	st, key, err := a.openStore()
	if err != nil {
		return Snapshot{}, err
	}
	defer closeStore(st, key)
	entries, err := secretInfos(st)
	if err != nil {
		return Snapshot{}, err
	}
	// Listing alone doesn't decrypt. Verify before declaring the vault ready.
	for _, item := range entries {
		sec, err := st.Get(item.Name)
		if err != nil {
			return Snapshot{}, errors.New("A vault entry cannot be decrypted. Restore the matching master key before continuing.")
		}
		wipe(sec.Value)
	}
	p, raw, err := a.readPolicy()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Secrets: entries, Policy: policyInfo(p, raw), Version: "0.2.0-shell"}, nil
}

var secretNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func (a *App) AddSecret(name, value string) ([]SecretInfo, error) {
	return a.AddSecretBound(name, value, "", nil, nil, nil)
}

// AddSecretBound creates a secret with CLI-equivalent binding metadata so the
// egress proxy can resolve GUI-created entries for the bound host.
func (a *App) AddSecretBound(name, value, hosts string, paths, methods, headers []string) ([]SecretInfo, error) {
	if err := a.lock(); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	canon, err := core.NormalizeName(name)
	if err != nil {
		return nil, errors.New("Use 1-64 letters, digits, hyphens or underscores for the name.")
	}
	if len(value) == 0 || len(value) > 16<<10 || !utf8.ValidString(value) {
		return nil, errors.New("The secret must contain 1-16384 UTF-8 bytes.")
	}
	var bound []string
	for _, h := range strings.Split(hosts, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			bound = append(bound, h)
		}
	}
	if len(bound) == 0 {
		return nil, errors.New("At least one bound host is required so the proxy can resolve this secret.")
	}
	st, key, err := a.openStore()
	if err != nil {
		return nil, err
	}
	defer closeStore(st, key)
	entries, err := secretInfos(st)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name == canon {
			return nil, errors.New("That name already exists. Existing values and binding metadata are never overwritten here.")
		}
	}
	b := []byte(value)
	defer wipe(b)
	if err := core.Add(st, core.AddInput{Name: canon, Value: b, Kind: "bearer", Hosts: bound, Paths: paths, Methods: methods, InjectHdr: headers}); err != nil {
		return nil, errors.New("The secret could not be saved.")
	}
	return secretInfos(st)
}
func (a *App) DeleteSecret(name, confirmation string) ([]SecretInfo, error) {
	if err := a.lock(); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	if name == "" || confirmation != name {
		return nil, errors.New("Type the exact stored name to confirm deletion.")
	}
	st, key, err := a.openStore()
	if err != nil {
		return nil, err
	}
	defer closeStore(st, key)
	entries, err := secretInfos(st)
	if err != nil {
		return nil, err
	}
	exists := false
	for _, e := range entries {
		if e.Name == name {
			exists = true
		}
	}
	if !exists {
		return nil, errors.New("That entry no longer exists. Refresh the vault.")
	}
	if err := st.Delete(name); err != nil {
		return nil, errors.New("The secret could not be deleted.")
	}
	return secretInfos(st)

}
// RevealSecret returns the plaintext only when confirmation matches the
// stored name exactly; the reveal is audited without the value.
func (a *App) RevealSecret(name, confirmation string) (string, error) {
	if err := a.lock(); err != nil {
		return "", err
	}
	defer a.mu.Unlock()
	if name == "" || confirmation != name {
		return "", errors.New("Type the exact stored name to confirm reveal.")
	}
	st, key, err := a.openStore()
	if err != nil {
		return "", err
	}
	defer closeStore(st, key)
	sec, err := st.Get(name)
	if err != nil {
		return "", errors.New("That entry no longer exists. Refresh the vault.")
	}
	defer wipe(sec.Value)
	if l, err := audit.Open(filepath.Join(a.dir, "audit.jsonl")); err == nil && l != nil {
		l.Log("", "secret_revealed", map[string]any{"name": name})
		l.Close()
	}
	out := make([]byte, len(sec.Value))
	copy(out, sec.Value)
	return string(out), nil
}
func (a *App) Scan(text string) (result ScanResult, err error) {
	if err = a.lock(); err != nil {
		return result, err
	}
	defer a.mu.Unlock()
	defer func() {
		if recover() != nil {
			result = ScanResult{}
			err = errors.New("The scanner failed. No successful result is available.")
		}
	}()
	if len(text) == 0 || len(text) > maxScanBytes || !utf8.ValidString(text) {
		return result, errors.New("Enter between 1 and 65536 UTF-8 bytes.")
	}
	p, _, err := a.readPolicy()
	if err != nil {
		return result, err
	}
	if err = validatePatterns(p.CustomPatterns); err != nil {
		return result, err
	}
	st, key, err := a.openStore()
	if err != nil {
		return result, err
	}
	defer closeStore(st, key)
	m, err := st.NewMatcher()
	if err != nil {
		return result, errors.New("Cannot decrypt a vault entry. Scan cancelled.")
	}
	defer m.Close()
	allow := map[string]bool{}
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	start := time.Now()
	findings := scrubber.ScanWithMatcher(text, m, allow, scrubber.CompileCustomPatterns(p.CustomPatterns))
	for _, f := range findings {
		category := f.Type
		if strings.HasPrefix(category, "SECRET") {
			category = "SECRET"
		}
		result.Findings = append(result.Findings, FindingInfo{Category: category, Detector: f.Detector, Confidence: f.Confidence, StartByte: f.Span[0], EndByte: f.Span[1]})
	}
	sort.SliceStable(result.Findings, func(i, j int) bool { return result.Findings[i].StartByte < result.Findings[j].StartByte })
	result.ElapsedMS = time.Since(start).Milliseconds()
	return result, nil
}
func revision(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (a *App) readPolicy() (policy.Policy, []byte, error) {
	raw, err := readBounded(filepath.Join(a.dir, "policy.yaml"), maxPolicyBytes)
	if os.IsNotExist(err) {
		return policy.Default(), nil, nil
	}
	if err != nil {
		return policy.Policy{}, nil, errors.New("Cannot read policy.yaml, or it exceeds 1 MiB.")
	}
	p := policy.Default()
	if err = yaml.Unmarshal(raw, &p); err != nil {
		return policy.Policy{}, nil, errors.New("policy.yaml is invalid. Fix it before continuing; defaults were not substituted.")
	}
	return p, raw, nil
}
func policyInfo(p policy.Policy, raw []byte) PolicyInfo {
	out := PolicyInfo{Revision: revision(raw), Entities: []EntityInfo{}, Patterns: []PatternInfo{}}
	for n, e := range p.Entities {
		out.Entities = append(out.Entities, EntityInfo{n, e.ToLLM, e.ToUntrusted})
	}
	for n, r := range p.CustomPatterns {
		out.Patterns = append(out.Patterns, PatternInfo{n, r})
	}
	sort.Slice(out.Entities, func(i, j int) bool { return out.Entities[i].Name < out.Entities[j].Name })
	sort.Slice(out.Patterns, func(i, j int) bool { return out.Patterns[i].Name < out.Patterns[j].Name })
	return out
}
func validMode(s string) bool {
	switch s {
	case "", "off", "allow", "mask", "pseudonymize", "hash", "block", "block_unless_placeholder":
		return true
	}
	return false
}
func validatePatterns(patterns map[string]string) error {
	if len(patterns) > 128 {
		return errors.New("At most 128 custom patterns are supported.")
	}
	for name, expr := range patterns {
		if !secretNameRE.MatchString(name) || len(expr) == 0 || len(expr) > 4096 {
			return errors.New("Each pattern needs a valid 1-64 character name and a 1-4096 byte expression.")
		}
		if _, err := regexp.Compile(expr); err != nil {
			return fmt.Errorf("Pattern %q is not valid Go RE2 syntax.", name)
		}
	}
	return nil
}
func (a *App) SavePolicy(expectedRevision string, entities []EntityInfo, patterns []PatternInfo) (PolicyInfo, error) {
	if err := a.lock(); err != nil {
		return PolicyInfo{}, err
	}
	defer a.mu.Unlock()
	p, raw, err := a.readPolicy()
	if err != nil {
		return PolicyInfo{}, err
	}
	if revision(raw) != expectedRevision {
		return PolicyInfo{}, errors.New("Policy changed on disk. Discard edits and reload before saving.")
	}
	if len(entities) != len(p.Entities) {
		return PolicyInfo{}, errors.New("Reload the policy before changing entity rules.")
	}
	seen := map[string]bool{}
	for _, e := range entities {
		old, ok := p.Entities[e.Name]
		if !ok || seen[e.Name] || !validMode(e.ToLLM) || !validMode(e.ToUntrusted) {
			return PolicyInfo{}, errors.New("An entity rule is invalid.")
		}
		seen[e.Name] = true
		old.ToLLM, old.ToUntrusted = e.ToLLM, e.ToUntrusted
		p.Entities[e.Name] = old
	}
	customs := map[string]string{}
	for _, pat := range patterns {
		if _, exists := customs[pat.Name]; exists {
			return PolicyInfo{}, errors.New("Pattern names must be unique.")
		}
		customs[pat.Name] = pat.Expression
	}
	if err = validatePatterns(customs); err != nil {
		return PolicyInfo{}, err
	}
	p.CustomPatterns = customs
	out, err := updatePolicyDocument(raw, p)
	if err != nil {
		return PolicyInfo{}, errors.New("Cannot encode the policy.")
	}
	path := filepath.Join(a.dir, "policy.yaml")
	if len(raw) > 0 {
		backup := path + ".bak-" + time.Now().UTC().Format("20060102T150405.000000000")
		if err = writeNewPrivate(backup, raw); err != nil {
			return PolicyInfo{}, errors.New("Cannot back up the policy. Nothing was changed.")
		}
	}
	if err = atomicWrite(path, out); err != nil {
		return PolicyInfo{}, errors.New("Cannot save policy.yaml. The previous file was retained.")
	}
	return policyInfo(p, out), nil
}
