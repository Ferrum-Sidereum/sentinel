package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is a tamper-evident audit record (WP-17).
type Record struct {
	Seq      uint64         `json:"seq"`
	Ts       string         `json:"ts"` // RFC3339 UTC
	Session  string         `json:"session,omitempty"`
	Type     string         `json:"type"`
	Fields   map[string]any `json:"fields,omitempty"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// TypedFields is the fixed set of allowed payload fields.
// No arbitrary secret values: only names, counts, versions, decisions.
type TypedFields struct {
	Name     string `json:"name,omitempty"`
	Host     string `json:"host,omitempty"`
	Count    *int   `json:"count,omitempty"`
	Version  *int   `json:"version,omitempty"`
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// canonical returns canonical bytes of record without hash.
func canonical(r Record) []byte {
	m := map[string]any{
		"seq": r.Seq, "ts": r.Ts, "type": r.Type, "prev_hash": r.PrevHash,
	}
	if r.Session != "" {
		m["session"] = r.Session
	}
	if len(r.Fields) > 0 {
		m["fields"] = r.Fields
	}
	// deterministic: marshal via sorted keys manually
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		sb.Write(kb)
		sb.WriteByte(':')
		sb.Write(vb)
	}
	sb.WriteByte('}')
	return []byte(sb.String())
}

// ComputeHash = sha256(canonical(record без hash) || prev_hash).
func ComputeHash(r Record) string {
	h := sha256.New()
	h.Write(canonical(r))
	h.Write([]byte(r.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// Logger appends chained records to a JSONL file with rotation support.
type Logger struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	seq      uint64
	prevHash string
	maxSize  int64 // size-based rotation trigger; 0 = disabled
	maxAge   time.Duration
	retDir   string
}

type Option func(*Logger)

func WithMaxSize(n int64) Option      { return func(l *Logger) { l.maxSize = n } }
func WithMaxAge(d time.Duration) Option { return func(l *Logger) { l.maxAge = d } }

// Open opens (or creates) the log, recovering seq/prev_hash from tail.
func Open(path string, opts ...Option) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Logger{f: f, path: path, prevHash: zeroHash, retDir: dirOf(path)}
	for _, o := range opts {
		o(l)
	}
	// recover chain state from existing files (including rotated)
	recs, _ := ReadAll(l.chainFiles())
	if len(recs) > 0 {
		last := recs[len(recs)-1]
		l.seq = last.Seq
		l.prevHash = last.Hash
	}
	return l, nil
}

// Log keeps the existing signature (session, type, map payload).
// Internally converts to typed fields + sanitize; secret-like values rejected/redacted.
func (l *Logger) Log(session, typ string, fields map[string]any) {
	typed := ToTypedFields(fields)
	san := Sanitize(typedToMap(typed))
	l.append(session, typ, san, typ != "")
}

func (l *Logger) append(session, typ string, fields map[string]any, fsyncDurable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.maybeRotateLocked()
	r := Record{
		Seq: l.seq + 1, Ts: time.Now().UTC().Format(time.RFC3339),
		Session: session, Type: typ, Fields: fields, PrevHash: l.prevHash,
	}
	r.Hash = ComputeHash(r)
	b, _ := json.Marshal(r)
	l.f.Write(append(b, '\n'))
	if durable(typ) {
		l.f.Sync()
	}
	l.seq = r.Seq
	l.prevHash = r.Hash
}

// LogTyped is the preferred typed entry point (new code).
func (l *Logger) LogTyped(session, typ string, tf TypedFields) {
	l.append(session, typ, Sanitize(typedToMap(tf)), true)
}

func durable(typ string) bool {
	return strings.HasPrefix(typ, "approval_") || strings.HasPrefix(typ, "secret_")
}

func (l *Logger) Close() error { return l.f.Close() }

// Verify walks the chain, reporting the first break seq.
func Verify(path string) error {
	recs, err := ReadFile(path)
	if err != nil {
		return err
	}
	prev := zeroHash
	for _, r := range recs {
		if r.PrevHash != prev {
			return fmt.Errorf("audit chain break at seq %d: prev_hash mismatch", r.Seq)
		}
		if ComputeHash(r) != r.Hash {
			return fmt.Errorf("audit chain break at seq %d: hash mismatch", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// ReadFile reads one JSONL file (skips header lines starting with #).
func ReadFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("bad record: %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// ReadAll reads multiple files in order.
func ReadAll(paths []string) ([]Record, error) {
	var out []Record
	for _, p := range paths {
		recs, err := ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

// ToTypedFields whitelists allowed fields; secret-like values are dropped.
func ToTypedFields(fields map[string]any) TypedFields {
	var tf TypedFields
	for k, v := range fields {
		lk := strings.ToLower(k)
		if secretKeys[lk] {
			continue // by construction: never logged
		}
		s := fmt.Sprint(v)
		if looksSecret(s) && len(s) > 0 {
			continue // value-like payload rejected by construction
		}
		switch lk {
		case "name":
			tf.Name, _ = v.(string)
		case "host":
			tf.Host, _ = v.(string)
		case "count":
			tf.Count = toInt(v)
		case "version":
			tf.Version = toInt(v)
		case "decision":
			tf.Decision, _ = v.(string)
		case "reason":
			tf.Reason, _ = v.(string)
		case "mode":
			tf.Mode, _ = v.(string)
		}
	}
	return tf
}

func toInt(v any) *int {
	var n int
	switch t := v.(type) {
	case int:
		n = t
	case int64:
		n = int(t)
	case float64:
		n = int(t)
	default:
		return nil
	}
	return &n
}

func typedToMap(tf TypedFields) map[string]any {
	m := map[string]any{}
	if tf.Name != "" {
		m["name"] = tf.Name
	}
	if tf.Host != "" {
		m["host"] = tf.Host
	}
	if tf.Count != nil {
		m["count"] = *tf.Count
	}
	if tf.Version != nil {
		m["version"] = *tf.Version
	}
	if tf.Decision != "" {
		m["decision"] = tf.Decision
	}
	if tf.Reason != "" {
		m["reason"] = tf.Reason
	}
	if tf.Mode != "" {
		m["mode"] = tf.Mode
	}
	return m
}
