package policy

import (
	"fmt"
	"sort"
)

// Fixture is one sample of the builtin corpus used by Diff.
type Fixture struct {
	Name   string
	Sample string
}

// FixtureCorpus is a small fixed corpus covering the main entity types.
func FixtureCorpus() []Fixture {
	return []Fixture{
		{"email", "contact ivan@example.com for details"},
		{"phone", "call +7 916 123-45-67 tomorrow"},
		{"card", "card 4111 1111 1111 1111 charged"},
		{"clean", "hello world, no secrets here"},
	}
}

// DiffEntry describes a behavioural difference for one fixture+dest.
type DiffEntry struct {
	Fixture string
	Dest    string
	A       string // mode under policy A ("" if identical)
	B       string // mode under policy B ("" if identical)
	FiredA  []string
	FiredB  []string
}

// Diff runs both policies over the fixture corpus (dests llm + untrusted)
// and returns entries where mode or fired rules differ.
func Diff(a, b *Policy) []DiffEntry {
	var out []DiffEntry
	for _, fx := range FixtureCorpus() {
		for _, dest := range []string{"llm", "untrusted"} {
			ra := DryRun(a, fx.Sample, dest, "diff")
			rb := DryRun(b, fx.Sample, dest, "diff")
			fa := firedNames(ra)
			fb := firedNames(rb)
			if ra.Mode != rb.Mode || !equalStr(fa, fb) {
				out = append(out, DiffEntry{Fixture: fx.Name, Dest: dest, A: ra.Mode, B: rb.Mode, FiredA: fa, FiredB: fb})
			}
		}
	}
	return out
}

func firedNames(r DryRunResult) []string {
	var out []string
	for _, f := range r.Fired {
		out = append(out, f.Entity+"="+f.Mode)
	}
	sort.Strings(out)
	return out
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (e DiffEntry) String() string {
	return fmt.Sprintf("%s/%s: mode %q -> %q fired %v -> %v", e.Fixture, e.Dest, e.A, e.B, e.FiredA, e.FiredB)
}
