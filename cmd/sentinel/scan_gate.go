package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

// scanInput is one scanned source: file path ("" for stdin) + text.
type scanInput struct {
	name string
	text string
}

// gateFinding is one finding with file/line/col context for output + gating.
type gateFinding struct {
	File       string
	Type       string
	Detector   string
	Confidence float64
	Line       int
	Col        int
	FP         string
}

func fpOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

// scanText runs ScanWithMatcher and converts to gateFindings with positions.
func scanText(file, text string, vm vault.Matcher, allow map[string]bool) []gateFinding {
	out := []gateFinding{}
	for _, f := range scrubber.ScanWithMatcher(text, vm, allow, nil) {
		line, col := lineCol(text, f.Span[0])
		out = append(out, gateFinding{file, f.Type, f.Detector, f.Confidence, line, col, fpOf(f.Value)})
	}
	return out
}

// gateFilter applies --min-confidence and --fail-on; returns failing subset.
func gateFilter(fs []gateFinding, minConf float64, failOn map[string]bool) []gateFinding {
	var out []gateFinding
	for _, f := range fs {
		if f.Confidence < minConf {
			continue
		}
		if len(failOn) > 0 && !failOn[strings.ToUpper(f.Type)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func parseFailOn(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	m := map[string]bool{}
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(strings.ToUpper(t))
		if t != "" {
			m[t] = true
		}
	}
	return m
}

// ---- ignore files (.gitignore + .sentinelignore, same syntax) ----

// ignoreRule is one pattern line.
type ignoreRule struct {
	pattern string
	dirOnly bool
	negate  bool
}

func parseIgnore(data []byte) []ignoreRule {
	var out []ignoreRule
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimRight(ln, "\r")
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		r := ignoreRule{}
		if strings.HasPrefix(t, "!") {
			r.negate = true
			t = t[1:]
		}
		if strings.HasSuffix(t, "/") {
			r.dirOnly = true
			t = strings.TrimSuffix(t, "/")
		}
		r.pattern = t
		out = append(out, r)
	}
	return out
}

// matchIgnore reports whether rel (slash-separated, relative to scan root)
// is ignored. dir indicates the path is a directory. Last matching rule wins.
func matchIgnore(rules []ignoreRule, rel string, dir bool) bool {
	ignored := false
	rel = filepath.ToSlash(rel)
	base := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		base = rel[i+1:]
	}
	for _, r := range rules {
		if r.dirOnly && !dir && !strings.HasPrefix(rel, strings.TrimPrefix(r.pattern, "/")+"/") {
			continue
		}
		hit := false
		p := strings.TrimPrefix(r.pattern, "/")
		if strings.Contains(p, "/") {
			// path-anchored rule
			if ok, _ := filepath.Match(p, rel); ok {
				hit = true
			}
			if strings.HasPrefix(rel, p+"/") {
				hit = true
			}
		} else {
			// basename pattern
			if ok, _ := filepath.Match(p, base); ok {
				hit = true
			}
		}
		if hit {
			ignored = !r.negate
		}
	}
	return ignored
}

func loadIgnoreFile(root, name string) []ignoreRule {
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return nil
	}
	return parseIgnore(b)
}

// collectFiles expands file/dir args; directories scanned recursively with
// .gitignore + .sentinelignore unless noIgnore.
func collectFiles(args []string, noIgnore bool) ([]string, error) {
	var files []string
	for _, a := range args {
		fi, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			files = append(files, a)
			continue
		}
		root := a
		var rules []ignoreRule
		if !noIgnore {
			rules = append(rules, loadIgnoreFile(root, ".gitignore")...)
			rules = append(rules, loadIgnoreFile(root, ".sentinelignore")...)
		}
		err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if rel == "." {
				return nil
			}
			if info.IsDir() {
				if !noIgnore {
					if info.Name() == ".git" || matchIgnore(rules, rel, true) {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !noIgnore && matchIgnore(rules, rel, false) {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// stagedFiles reads git index (staged, added/copied/modified) via git diff.
func stagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff --cached: %v: %s", err, stderr.String())
	}
	var out []string
	for _, f := range strings.Split(stdout.String(), "\x00") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if fi, err := os.Stat(f); err == nil && !fi.IsDir() {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out, nil
}

// stagedBlob reads the staged (index) content of a file via git show.
func stagedBlob(path string) ([]byte, error) {
	cmd := exec.Command("git", "show", ":"+path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git show :%s: %v: %s", path, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// ---- SARIF 2.1.0 ----

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules"`
}
type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}
type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLoc `json:"locations"`
}
type sarifLoc struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// sarifOf builds a SARIF 2.1.0 log. NEVER includes secret values — only
// finding type + fingerprint in the message.
func sarifOf(fs []gateFinding) sarifLog {
	seen := map[string]bool{}
	var rules []sarifRule
	for _, f := range fs {
		if !seen[f.Type] {
			seen[f.Type] = true
			r := sarifRule{ID: "sentinel/" + f.Type}
			r.ShortDescription.Text = "Possible " + f.Type + " secret leak detected by sentinel"
			rules = append(rules, r)
		}
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	results := []sarifResult{}
	for _, f := range fs {
		uri := f.File
		if uri == "" || uri == "<stdin>" {
			uri = "stdin"
		}
		var res sarifResult
		res.RuleID = "sentinel/" + f.Type
		res.Level = "error"
		res.Message.Text = fmt.Sprintf("%s [%s conf=%.2f] %s:%d:%d fp=%s",
			f.Type, f.Detector, f.Confidence, uri, f.Line, f.Col, f.FP)
		var loc sarifLoc
		loc.PhysicalLocation.ArtifactLocation.URI = uri
		loc.PhysicalLocation.Region.StartLine = f.Line
		loc.PhysicalLocation.Region.StartColumn = f.Col
		res.Locations = []sarifLoc{loc}
		results = append(results, res)
	}
	return sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "sentinel",
				Version:        version,
				InformationURI: "https://github.com/Ferrum-Sidereum/sentinel",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// jsonGateOut is the --format json shape (superset of legacy --json).
type jsonGateOut struct {
	Findings []jsonGateFinding `json:"findings"`
}

type jsonGateFinding struct {
	File       string  `json:"file,omitempty"`
	Type       string  `json:"type"`
	Detector   string  `json:"detector"`
	Confidence float64 `json:"confidence"`
	Line       int     `json:"line"`
	Col        int     `json:"col"`
	FP         string  `json:"fp"`
	Value      string  `json:"value,omitempty"`
}

func openMatcher() (vault.Matcher, func(), error) {
	st, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	m, err := st.NewMatcher()
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	cleanup := func() {
		m.Close()
		st.Close()
	}
	return m, cleanup, nil
}

func loadAllowlist() map[string]bool {
	allow := map[string]bool{}
	p, _ := policy.Load(filepath.Join(dataDir(), "policy.yaml"))
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	return allow
}

// redactMode reports whether values must be hidden. Text/JSON gate output
// never prints values without --show-values, so redact is a compatibility
// marker: explicit --redact/--no-redact wins, otherwise default redacts in
// non-TTY (CI) and relaxes on a TTY.
func redactMode(isTTY bool, redactFlag *bool) bool {
	if redactFlag != nil {
		return *redactFlag
	}
	return !isTTY
}

// emitGateText prints text format: one line per finding, never values.
func emitGateText(fs []gateFinding) {
	for _, f := range fs {
		name := f.File
		if name == "" {
			name = "<stdin>"
		}
		fmt.Printf("%s:%d:%d: %s [%s conf=%.2f] fp=%s\n",
			name, f.Line, f.Col, f.Type, f.Detector, f.Confidence, f.FP)
	}
}
