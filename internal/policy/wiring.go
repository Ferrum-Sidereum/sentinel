package policy

import (
	"fmt"
	"sort"
	"strings"
)

// FieldWiring describes which gateways actually read a policy field.
// GENERATED from the registry below — never hand-maintained per call site.
// Gateways register their field usage via RegisterWiring (typically from the
// package that consumes the field).
type FieldWiring struct {
	Field    string   // e.g. "defaults.scrub_to_llm"
	Gateways []string // e.g. ["llm", "mcp"]
	Note     string
}

var wiringRegistry = map[string]FieldWiring{}

func RegisterWiring(field string, gateways []string, note string) {
	wiringRegistry[field] = FieldWiring{Field: field, Gateways: append([]string(nil), gateways...), Note: note}
}

func init() {
	// Wiring as observed in code (see grep: internal/llm/gateway.go,
	// internal/mcp/gateway.go, internal/mcp/proxy.go, cmd/sentinel/main.go).
	// Fields with empty Gateways are parsed but read by NO gateway — the
	// coverage gaps `policy explain` makes visible.
	RegisterWiring("defaults.unknown_host", nil, "parsed; no gateway branches on it (egress uses vault secret bindings)")
	RegisterWiring("defaults.scrub_to_llm", []string{"llm", "mcp"}, "fallback mode in llm/gateway.go, mcp/gateway.go, mcp/proxy.go")
	RegisterWiring("defaults.scrub_to_untrusted", nil, "parsed; no gateway requests dest=untrusted")
	RegisterWiring("defaults.confidence_threshold", []string{"llm", "mcp"}, "threshold in llm/gateway.go, mcp/gateway.go, mcp/proxy.go")
	RegisterWiring("hosts", nil, "policy hosts map unread; egress/mcp match vault secret bindings instead")
	RegisterWiring("hosts.*.class", nil, "no reader")
	RegisterWiring("hosts.*.scan_response", nil, "no reader")
	RegisterWiring("entities.*.to_llm", []string{"llm"}, "via ModeFor(entity, llm) in llm/gateway.go")
	RegisterWiring("entities.*.to_untrusted", nil, "via ModeFor(entity, untrusted) — no gateway passes untrusted")
	RegisterWiring("entities.*.detector", nil, "declared; scrubber runs all detectors unconditionally")
	RegisterWiring("custom_patterns", []string{"sentinel-gui"}, "compiled only in sentinel-gui; gateways never call CompileCustomPatterns")
	RegisterWiring("allowlist.values", []string{"llm", "mcp", "scan"}, "allow map in llm/gateway.go, mcp/gateway.go, mcp/proxy.go, cmd/sentinel/main.go scan")
	RegisterWiring("allowlist.domains", nil, "parsed; no reader")
	RegisterWiring("allowlist.patterns", nil, "parsed; no reader")
	RegisterWiring("audit.level", nil, "parsed; audit logger uses fixed level")
	RegisterWiring("audit.retention", nil, "parsed; no reader")
}

// AllFields is the closed set of policy fields explain knows about.
// Adding a Policy struct field/yaml key WITHOUT registering wiring here
// (and in init above) fails TestExplainCoverage — by design.
func AllFields() []string {
	out := make([]string, 0, len(wiringRegistry))
	for f := range wiringRegistry {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Explain returns the wiring for a field, or an error listing known fields.
// Concrete names normalize to wildcards: entities.EMAIL.to_llm -> entities.*.to_llm.
func Explain(field string) (FieldWiring, error) {
	if w, ok := wiringRegistry[field]; ok {
		return w, nil
	}
	parts := strings.Split(field, ".")
	if len(parts) == 3 && parts[0] == "entities" {
		if w, ok := wiringRegistry["entities.*."+parts[2]]; ok {
			w.Field = field
			return w, nil
		}
	}
	if len(parts) == 3 && parts[0] == "hosts" {
		if w, ok := wiringRegistry["hosts.*."+parts[2]]; ok {
			w.Field = field
			return w, nil
		}
	}
	if len(parts) == 2 && parts[0] == "hosts" {
		if w, ok := wiringRegistry["hosts"]; ok {
			w.Field = field
			return w, nil
		}
	}
	return FieldWiring{}, fmt.Errorf("unknown policy field %q (see `sentinel policy explain --list`)", field)
}
