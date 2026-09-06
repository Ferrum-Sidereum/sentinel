package policy

import (
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type HostRule struct {
	Class        string `yaml:"class"`
	ScanResponse bool   `yaml:"scan_response"`
}

type EntityRule struct {
	ToLLM       string   `yaml:"to_llm"`
	ToUntrusted string   `yaml:"to_untrusted"`
	Detector    []string `yaml:"detector"`
}

type Profile struct {
	Secrets    []string `yaml:"secrets"`
	Hosts      []string `yaml:"hosts"`
	DenyTools  []string `yaml:"deny_tools"`
	AllowTools []string `yaml:"allow_tools"`
	ScrubToLLM string   `yaml:"scrub_to_llm"`
	Approvals  string   `yaml:"approvals"`
}

type Policy struct {
	Defaults struct {
		UnknownHost         string  `yaml:"unknown_host"`
		ScrubToLLM          string  `yaml:"scrub_to_llm"`
		ScrubToUntrusted    string  `yaml:"scrub_to_untrusted"`
		ConfidenceThreshold float64 `yaml:"confidence_threshold"`
	} `yaml:"defaults"`
	Hosts          map[string]HostRule   `yaml:"hosts"`
	Entities       map[string]EntityRule `yaml:"entities"`
	CustomPatterns map[string]string     `yaml:"custom_patterns"`
	Allowlist      struct {
		Values   []string `yaml:"values"`
		Domains  []string `yaml:"domains"`
		Patterns []string `yaml:"patterns"`
	} `yaml:"allowlist"`
	Audit struct {
		Level     string `yaml:"level"`
		Retention string `yaml:"retention"`
	} `yaml:"audit"`
	Approvals Approvals          `yaml:"approvals"`
	Profiles  map[string]Profile `yaml:"profiles"`
}

// ErrUnknownProfile is returned when --profile names a missing profile.
// Callers map it to exit code 2.
var ErrUnknownProfile = errUnknownProfile{}

type errUnknownProfile struct{ Name string }

func (e errUnknownProfile) Error() string { return "unknown profile: " + e.Name }

// LegacyDenyTools returns entity keys mcp:deny:<tool> (deprecated, ignored).
// IsUnknownProfile reports whether err is an unknown-profile error.
func IsUnknownProfile(err error) bool {
	if err == nil {
		return false
	}
	var t errUnknownProfile
	if err == ErrUnknownProfile {
		return true
	}
	return asErrUnknown(err, &t)
}

func asErrUnknown(err error, t *errUnknownProfile) bool {
	for err != nil {
		if e, ok := err.(errUnknownProfile); ok {
			*t = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
func (p *Policy) LegacyDenyTools() []string {
	var out []string
	for k := range p.Entities {
		if len(k) > len("mcp:deny:") && k[:len("mcp:deny:")] == "mcp:deny:" {
			out = append(out, k[len("mcp:deny:"):])
		}
	}
	return out
}

// ResolveProfile returns the deny set for profile name.
// Empty name = built-in default (denies nothing). Unknown name = ErrUnknownProfile.
// Note: allowlist mode is evaluated via ProfileAllows, not this map.
func (p *Policy) ResolveProfile(name string) (map[string]bool, error) {
	if name == "" {
		return map[string]bool{}, nil
	}
	prof, ok := p.Profiles[name]
	if !ok {
		return nil, errUnknownProfile{Name: name}
	}
	deny := map[string]bool{}
	for _, t := range prof.DenyTools {
		deny[t] = true
	}
	return deny, nil
}

// ProfileAllows reports whether tool is permitted under profile name.
func (p *Policy) ProfileAllows(name, tool string) (bool, error) {
	if name == "" {
		return true, nil
	}
	prof, ok := p.Profiles[name]
	if !ok {
		return false, errUnknownProfile{Name: name}
	}
	for _, t := range prof.DenyTools {
		if t == tool {
			return false, nil
		}
	}
	if len(prof.AllowTools) > 0 {
		for _, t := range prof.AllowTools {
			if t == tool {
				return true, nil
			}
		}
		return false, nil
	}
	return true, nil
}

// ApprovalRule is one allow/deny/ask rule. Empty Secret/Consumer/Dest match
// anything; glob patterns supported. First match wins.
type ApprovalRule struct {
	Name     string `yaml:"name"`
	Secret   string `yaml:"secret"`
	Consumer string `yaml:"consumer"`
	Dest     string `yaml:"dest"`
	Decision string `yaml:"decision"` // allow | deny | ask
	TTL      string `yaml:"ttl"`      // duration text, e.g. "15m"; "" = single use
}

// Approvals configures the WP-10 approval broker.
type Approvals struct {
	Default          string         `yaml:"default"` // ask | allow | deny; "" = allow (legacy compat, documented)
	Rules            []ApprovalRule `yaml:"rules"`
	GrantCache       string         `yaml:"grant_cache"`
	MaxUsesPerMinute int            `yaml:"max_uses_per_minute"`
}

// GrantCacheDuration parses GrantCache; "" = 15m.
func (a Approvals) GrantCacheDuration() time.Duration {
	if a.GrantCache == "" {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(a.GrantCache)
	if err != nil {
		return 15 * time.Minute
	}
	return d
}

// TTLDuration parses an ApprovalRule TTL; "" or unparsable = 0 (single use).
func (r ApprovalRule) TTLDuration() time.Duration {
	if r.TTL == "" {
		return 0
	}
	d, err := time.ParseDuration(r.TTL)
	if err != nil {
		return 0
	}
	return d
}

func Default() Policy {
	var p Policy
	p.Defaults.UnknownHost = "tunnel"
	p.Defaults.ScrubToLLM = "pseudonymize"
	p.Defaults.ScrubToUntrusted = "mask"
	p.Defaults.ConfidenceThreshold = 0.7
	p.Audit.Level = "events"
	p.Audit.Retention = "30d"
	p.Entities = map[string]EntityRule{
		"SNILS":       {ToLLM: "pseudonymize", ToUntrusted: "mask", Detector: []string{"regex"}},
		"INN_FL":      {ToLLM: "pseudonymize", ToUntrusted: "mask", Detector: []string{"regex"}},
		"PASSPORT_RU": {ToLLM: "pseudonymize", ToUntrusted: "mask", Detector: []string{"regex"}},
		"PHONE":       {ToLLM: "pseudonymize", ToUntrusted: "mask", Detector: []string{"regex"}},
		"EMAIL":       {ToLLM: "pseudonymize", ToUntrusted: "mask", Detector: []string{"regex"}},
		"CREDIT_CARD": {ToLLM: "block", ToUntrusted: "block", Detector: []string{"regex"}},
		"SECRET_*":    {ToLLM: "block_unless_placeholder", ToUntrusted: "block_unless_placeholder", Detector: []string{"vault"}},
	}
	return p
}

func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, err
	}
	if err := yaml.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, nil
}

// Watcher hot-reloads policy.yaml on change (poll mtime).
type Watcher struct {
	Path string
	Pol  *Policy
	stop chan struct{}
}

func Watch(path string, p *Policy, interval time.Duration, onErr func(error)) *Watcher {
	w := &Watcher{Path: path, Pol: p, stop: make(chan struct{})}
	go func() {
		var last time.Time
		if st, err := os.Stat(path); err == nil {
			last = st.ModTime()
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-t.C:
				st, err := os.Stat(path)
				if err != nil {
					continue
				}
				if st.ModTime().After(last) {
					np, err := Load(path)
					if err != nil {
						if onErr != nil {
							onErr(err)
						}
						continue
					}
					*w.Pol = np
					last = st.ModTime()
				}
			}
		}
	}()
	return w
}

func (w *Watcher) Stop() { close(w.stop) }

// ModeFor returns per-entity mode for dest ("llm"|"untrusted"), "" if unset.
func (p *Policy) ModeFor(entity, dest string) string {
	if p == nil {
		return ""
	}
	r, ok := p.Entities[entity]
	if !ok && strings.HasPrefix(entity, "SECRET") {
		r, ok = p.Entities["SECRET_*"]
	}
	if !ok {
		return ""
	}
	if dest == "llm" {
		return r.ToLLM
	}
	return r.ToUntrusted
}
