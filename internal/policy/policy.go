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
