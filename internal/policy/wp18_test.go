package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Invalid regex in custom_patterns must be caught by lint, not at runtime.
func TestLintInvalidRegex(t *testing.T) {
	p := Default()
	p.CustomPatterns = map[string]string{"BROKEN": "([a-z"}
	if issues := Lint(&p, nil); !hasRule(issues, "invalid-regex") {
		t.Fatalf("expected invalid-regex issue, got %v", issues)
	}
}

func TestLintUnknownKey(t *testing.T) {
	p := Default()
	raw := []byte("defaults:\n  scrub_to_llm: mask\nbogus_key: 1\n")
	if issues := Lint(&p, raw); !hasRule(issues, "unknown-key") {
		t.Fatalf("expected unknown-key issue, got %v", issues)
	}
}

func TestLintContradictoryApproval(t *testing.T) {
	p := Default()
	p.Entities["X"] = EntityRule{ToLLM: "allow", ToUntrusted: "block", Detector: []string{"regex"}}
	if issues := Lint(&p, nil); !hasRule(issues, "approval") {
		t.Fatalf("expected approval issue, got %v", issues)
	}
}

func TestLintUnreachableWildcard(t *testing.T) {
	p := Default()
	p.Entities["FOO_*"] = EntityRule{ToLLM: "mask", Detector: []string{"regex"}}
	if issues := Lint(&p, nil); !hasRule(issues, "unreachable") {
		t.Fatalf("expected unreachable issue, got %v", issues)
	}
}

func TestLintDefaultClean(t *testing.T) {
	p := Default()
	if issues := Lint(&p, nil); len(issues) != 0 {
		t.Fatalf("default policy should lint clean, got %v", issues)
	}
}

// policy test on a fixture must report the exact rule that fired.
func TestDryRunExactRule(t *testing.T) {
	p := Default()
	r := DryRun(&p, "mail ivan@example.com here", "llm", "t")
	if len(r.Fired) != 1 || r.Fired[0].Entity != "EMAIL" {
		t.Fatalf("expected exactly EMAIL fired, got %+v", r.Fired)
	}
	if r.Mode != "pseudonymize" {
		t.Fatalf("expected pseudonymize, got %q", r.Mode)
	}
	if strings.Contains(r.Output, "ivan@example.com") {
		t.Fatalf("output not redacted: %q", r.Output)
	}
}

func TestDryRunCardBlocked(t *testing.T) {
	p := Default()
	r := DryRun(&p, "card 4111 1111 1111 1111", "llm", "t")
	if r.Mode != "block" {
		t.Fatalf("expected block, got %q", r.Mode)
	}
}

// explain output is generated from the registry, not hand-maintained:
// every yaml key of the Policy struct must have wiring, or this fails.
func TestExplainCoverage(t *testing.T) {
	fields := yamlKeys(t)
	known := map[string]bool{}
	for _, f := range AllFields() {
		known[f] = true
	}
	var missing []string
	for _, f := range fields {
		if !known[f] && !known[strings.ReplaceAll(f, "*", "*")] {
			// allow wildcard forms: entities.*.to_llm covers entities.<name>.to_llm
			covered := false
			for _, k := range AllFields() {
				if wildcardCover(k, f) {
					covered = true
					break
				}
			}
			if !covered {
				missing = append(missing, f)
			}
		}
	}
	if len(missing) > 0 {
		t.Fatalf("policy fields without wiring (add RegisterWiring): %v", missing)
	}
	// reverse: every registered field must correspond to a real struct key
	for _, f := range AllFields() {
		if !fieldExists(fields, f) {
			t.Fatalf("registered wiring %q matches no Policy field (stale?)", f)
		}
	}
}

// yamlKeys flattens the Policy struct's yaml keys via reflection.
func yamlKeys(t *testing.T) []string {
	t.Helper()
	var out []string
	walkType(reflect.TypeOf(Policy{}), "", &out)
	return out
}

func walkType(rt reflect.Type, prefix string, out *[]string) {
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("yaml")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.Struct:
			walkType(ft, full, out)
		case reflect.Map:
			et := ft.Elem()
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				walkType(et, full+".*", out)
			} else {
				*out = append(*out, full)
			}
		default:
			*out = append(*out, full)
		}
	}
}

func wildcardCover(pattern, field string) bool {
	pp, fp := strings.Split(pattern, "."), strings.Split(field, ".")
	if len(pp) != len(fp) {
		return false
	}
	for i := range pp {
		if pp[i] != "*" && pp[i] != fp[i] {
			return false
		}
	}
	return true
}

func fieldExists(fields []string, pattern string) bool {
	for _, f := range fields {
		if f == pattern || wildcardCover(pattern, f) {
			return true
		}
		if strings.HasPrefix(f, pattern+".") {
			return true
		}
	}
	return false
}

var _ = yaml.Unmarshal // keep import if unused in future edits

func TestDiffDetectsChange(t *testing.T) {
	a := Default()
	b := Default()
	b.Entities["EMAIL"] = EntityRule{ToLLM: "block", ToUntrusted: "mask", Detector: []string{"regex"}}
	entries := Diff(&a, &b)
	found := false
	for _, e := range entries {
		if e.Fixture == "email" && e.Dest == "llm" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected email/llm diff, got %v", entries)
	}
	if entries := Diff(&a, &a); len(entries) != 0 {
		t.Fatalf("identical policies should not diff, got %v", entries)
	}
}

func TestDiffViaFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yaml")
	b := filepath.Join(dir, "b.yaml")
	os.WriteFile(a, []byte("defaults:\n  scrub_to_llm: pseudonymize\n  scrub_to_untrusted: mask\n"), 0o600)
	os.WriteFile(b, []byte("defaults:\n  scrub_to_llm: block\n  scrub_to_untrusted: mask\n"), 0o600)
	pa, err := Load(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := Load(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(Diff(&pa, &pb)) == 0 {
		t.Fatal("expected behavioural diff between mask and block policies")
	}
}

func hasRule(issues []LintIssue, rule string) bool {
	for _, is := range issues {
		if is.Rule == rule {
			return true
		}
	}
	return false
}
