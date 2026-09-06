package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func unmarshalYAML(b []byte, v any) error { return yaml.Unmarshal(b, v) }

type LintIssue struct {
	Rule    string // category: schema | unknown-key | unreachable | invalid-regex | approval
	Message string
}

func (e LintIssue) Error() string { return e.Rule + ": " + e.Message }

// validModes is the closed set of enforcement modes understood by gateways.
var validModes = map[string]bool{
	"allow": true, "mask": true, "pseudonymize": true,
	"block": true, "block_unless_placeholder": true, "tunnel": true,
}

var validDetectors = map[string]bool{
	"regex": true, "vault": true, "entropy": true, "dict": true, "custom": true, "decode": true,
}

// knownTopKeys mirrors the Policy struct's yaml keys.
var knownTopKeys = map[string]bool{
	"defaults": true, "hosts": true, "entities": true,
	"custom_patterns": true, "allowlist": true, "audit": true,
}

// Lint validates a Policy: schema values, unknown top-level keys, unreachable
// rules, invalid custom_patterns regexes, contradictory approval rules.
// raw is the original file bytes (used for unknown-key detection); may be nil.
func Lint(p *Policy, raw []byte) []LintIssue {
	var out []LintIssue
	if p == nil {
		return []LintIssue{{Rule: "schema", Message: "nil policy"}}
	}
	// schema: defaults modes
	for _, f := range []struct{ name, val string }{
		{"defaults.scrub_to_llm", p.Defaults.ScrubToLLM},
		{"defaults.scrub_to_untrusted", p.Defaults.ScrubToUntrusted},
		{"defaults.unknown_host", p.Defaults.UnknownHost},
	} {
		if f.val != "" && !validModes[f.val] {
			out = append(out, LintIssue{"schema", fmt.Sprintf("%s: unknown mode %q", f.name, f.val)})
		}
	}
	if p.Defaults.ConfidenceThreshold < 0 || p.Defaults.ConfidenceThreshold > 1 {
		out = append(out, LintIssue{"schema", fmt.Sprintf("defaults.confidence_threshold %v out of [0,1]", p.Defaults.ConfidenceThreshold)})
	}
	// schema: entity rules
	names := make([]string, 0, len(p.Entities))
	for n := range p.Entities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := p.Entities[n]
		if r.ToLLM != "" && !validModes[r.ToLLM] {
			out = append(out, LintIssue{"schema", fmt.Sprintf("entities.%s.to_llm: unknown mode %q", n, r.ToLLM)})
		}
		if r.ToUntrusted != "" && !validModes[r.ToUntrusted] {
			out = append(out, LintIssue{"schema", fmt.Sprintf("entities.%s.to_untrusted: unknown mode %q", n, r.ToUntrusted)})
			for _, d := range r.Detector {
				if !validDetectors[d] {
					out = append(out, LintIssue{"schema", fmt.Sprintf("entities.%s.detector: unknown detector %q", n, d)})
				}
			}
		}
		// schema: host rules
		hnames := make([]string, 0, len(p.Hosts))
		for n := range p.Hosts {
			hnames = append(hnames, n)
		}
		sort.Strings(hnames)
		if c := p.Hosts[n].Class; c != "" && c != "trusted" && c != "untrusted" && c != "llm" {
			out = append(out, LintIssue{"schema", fmt.Sprintf("hosts.%s.class: unknown class %q (want trusted|untrusted|llm)", n, c)})
		}
	}
	// unknown top-level keys from raw yaml
	if len(raw) > 0 {
		var m map[string]any
		if err := unmarshalYAML(raw, &m); err != nil {
			out = append(out, LintIssue{"schema", "yaml parse: " + err.Error()})
		} else {
			for k := range m {
				if !knownTopKeys[k] {
					out = append(out, LintIssue{"unknown-key", fmt.Sprintf("unknown top-level key %q", k)})
				}
			}
		}
	}
	// invalid regexes in custom_patterns — caught here, never at runtime
	cnames := make([]string, 0, len(p.CustomPatterns))
	for n := range p.CustomPatterns {
		cnames = append(cnames, n)
	}
	sort.Strings(cnames)
	for _, n := range cnames {
		if _, err := regexp.Compile(p.CustomPatterns[n]); err != nil {
			out = append(out, LintIssue{"invalid-regex", fmt.Sprintf("custom_patterns.%s: %v", n, err)})
		}
	}
	// unreachable rules: entity wildcard shadowed by... (a literal rule that can
	// never match because an earlier broader rule wins). ModeFor does exact
	// match + SECRET_* prefix fallback, so a rule named "SECRET_FOO" is
	// reachable, but a rule whose detector list is empty never fires.
	for _, n := range names {
		r := p.Entities[n]
		if len(r.Detector) == 0 && r.ToLLM == "" && r.ToUntrusted == "" {
			out = append(out, LintIssue{"unreachable", fmt.Sprintf("entities.%s: empty rule never fires", n)})
		}
		if strings.Contains(n, "*") && n != "SECRET_*" {
			out = append(out, LintIssue{"unreachable", fmt.Sprintf("entities.%s: wildcard %q is not matched by ModeFor (only SECRET_* prefix is)", n, n)})
		}
	}
	// contradictory approval rules: block_unless_placeholder on one dest with
	// allow on the other, or allow vs block across dests for the same entity.
	for _, n := range names {
		r := p.Entities[n]
		if (r.ToLLM == "allow" && r.ToUntrusted == "block") ||
			(r.ToLLM == "block" && r.ToUntrusted == "allow") {
			out = append(out, LintIssue{"approval", fmt.Sprintf("entities.%s: contradictory modes llm=%q vs untrusted=%q", n, r.ToLLM, r.ToUntrusted)})
		}
	}
	return out
}
