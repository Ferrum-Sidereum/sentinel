package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type ActivityRow struct {
	Time  string `json:"time"`
	Type  string `json:"type"`
	Count int    `json:"count"`
}
type ActivityPage struct {
	Rows      []ActivityRow `json:"rows"`
	Truncated bool          `json:"truncated"`
	Skipped   int           `json:"skipped"`
}

func (a *App) Activity() (ActivityPage, error) {
	if err := a.lock(); err != nil {
		return ActivityPage{}, err
	}
	defer a.mu.Unlock()
	return readActivity(filepath.Join(a.dir, "audit.jsonl"))
}
func readActivity(path string) (ActivityPage, error) {
	out := ActivityPage{Rows: []ActivityRow{}}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, errors.New("Cannot read the local audit log.")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return out, errors.New("Cannot inspect the audit log.")
	}
	const maxBytes int64 = 256 << 10
	start := st.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	out.Truncated = start > 0
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return out, errors.New("Cannot seek in the audit log.")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return out, errors.New("Cannot read the audit log.")
	}
	if start > 0 {
		if n := bytes.IndexByte(b, '\n'); n >= 0 {
			b = b[n+1:]
		} else {
			b = nil
		}
	}
	if n := bytes.LastIndexByte(b, '\n'); n >= 0 {
		b = b[:n]
	} else {
		b = nil
	}
	lines := bytes.Split(b, []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		if len(out.Rows) >= 100 {
			out.Truncated = true
			break
		}
		var event struct {
			Time   time.Time                  `json:"time"`
			Type   string                     `json:"type"`
			Fields map[string]json.RawMessage `json:"fields"`
		}
		if json.Unmarshal(lines[i], &event) != nil || event.Time.IsZero() {
			out.Skipped++
			continue
		}
		kind := "legacy.event"
		switch event.Type {
		case "pii_redacted", "llm_blocked", "secret.add", "secret_blocked", "secret_injected", "placeholder_invalid":
			kind = event.Type
		}
		count := 0
		if b, ok := event.Fields["count"]; ok {
			if json.Unmarshal(b, &count) != nil || count < 0 || count > 1000000 {
				count = 0
			}
		}
		out.Rows = append(out.Rows, ActivityRow{event.Time.UTC().Format(time.RFC3339), kind, count})
	}
	return out, nil
}
