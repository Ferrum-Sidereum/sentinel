package policy

import (
	"sort"
	"strings"

	"sentinel/internal/scrubber"
)

// DryRunResult is the outcome of a policy dry run over one sample.
type DryRunResult struct {
	Dest      string
	Tool      string
	Fired     []FiredRule // entity rules that matched, in order
	Mode      string      // resulting mode for the dest
	Output    string      // transformed sample with values redacted
	Transform string      // human-readable description of the transform
}

// FiredRule names the exact entity rule that fired for a finding.
type FiredRule struct {
	Entity string // policy entities key (e.g. EMAIL, SECRET_*)
	Type   string // finding type
	Value  string // matched value (redacted in Output, kept here pre-transform)
	Mode   string // mode resolved for this entity+dest
}

// DryRun scans sample with scrubber, resolves each finding to its entity rule
// via ModeFor, and redacts matched values from the output.
func DryRun(p *Policy, sample, dest, tool string) DryRunResult {
	r := DryRunResult{Dest: dest, Tool: tool}
	customs := scrubber.CompileCustomPatterns(p.CustomPatterns)
	allow := map[string]bool{}
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	findings := scrubber.ScanCustom(sample, nil, allow, customs)
	seen := map[string]bool{}
	for _, f := range findings {
		ent := entityFor(f.Type)
		mode := p.ModeFor(ent, dest)
		if mode == "" {
			if dest == "llm" {
				mode = p.Defaults.ScrubToLLM
			} else {
				mode = p.Defaults.ScrubToUntrusted
			}
		}
		if mode == "" {
			mode = "pseudonymize"
		}
		if !seen[ent] {
			seen[ent] = true
			r.Fired = append(r.Fired, FiredRule{Entity: ent, Type: f.Type, Value: f.Value, Mode: mode})
		}
	}
	// resulting mode: most restrictive among fired, else default
	r.Mode = resultingMode(p, dest, r.Fired)
	out := sample
	for _, fr := range r.Fired {
		if fr.Value != "" {
			out = strings.ReplaceAll(out, fr.Value, "[REDACTED:"+fr.Entity+"]")
		}
	}
	r.Output = out
	r.Transform = describeTransform(r.Mode)
	return r
}

func entityFor(findingType string) string {
	if strings.HasPrefix(findingType, "SECRET:") {
		return "SECRET_*"
	}
	return findingType
}

var modeRank = map[string]int{
	"allow": 0, "pseudonymize": 1, "mask": 2, "tunnel": 2,
	"block_unless_placeholder": 3, "block": 4,
}

func resultingMode(p *Policy, dest string, fired []FiredRule) string {
	best, rank := "", -1
	for _, fr := range fired {
		if rk, ok := modeRank[fr.Mode]; ok && rk > rank {
			rank, best = rk, fr.Mode
		}
	}
	if best != "" {
		return best
	}
	if dest == "llm" {
		if p.Defaults.ScrubToLLM != "" {
			return p.Defaults.ScrubToLLM
		}
		return "pseudonymize"
	}
	if p.Defaults.ScrubToUntrusted != "" {
		return p.Defaults.ScrubToUntrusted
	}
	return "mask"
}

func describeTransform(mode string) string {
	switch mode {
	case "block", "block_unless_placeholder":
		return "output blocked (" + mode + ")"
	case "mask":
		return "values masked"
	case "pseudonymize":
		return "values pseudonymized"
	case "allow":
		return "passed through"
	default:
		return "mode " + mode
	}
}

// SortedEntities lists entity names for stable output.
func SortedEntities(p *Policy) []string {
	out := make([]string, 0, len(p.Entities))
	for n := range p.Entities {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// DestKey normalizes --dest values: host:<h> maps to untrusted semantics.
func DestKey(dest string) string {
	if strings.HasPrefix(dest, "host:") || dest == "untrusted" {
		return "untrusted"
	}
	return dest
}
