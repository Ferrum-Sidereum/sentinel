package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func dirOf(p string) string {
	d := filepath.Dir(p)
	if d == "" {
		return "."
	}
	return d
}

func baseOf(p string) string {
	b := filepath.Base(p)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// chainFiles returns rotated files + current, oldest first.
// Rotation files: <base>.YYYYMMDD-HHMMSS.jsonl
func (l *Logger) chainFiles() []string {
	dir := l.retDir
	base := baseOf(l.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{l.path}
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if n == filepath.Base(l.path) {
			continue
		}
		if strings.HasPrefix(n, base+".") && strings.HasSuffix(n, ".jsonl") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return append(out, l.path)
}

// maybeRotateLocked rotates on size trigger; carries prev_hash via header line.
func (l *Logger) maybeRotateLocked() error {
	if l.maxSize <= 0 {
		return nil
	}
	st, err := l.f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() < l.maxSize {
		return nil
	}
	return l.rotateLocked()
}

func (l *Logger) rotateLocked() error {
	l.f.Close()
	ts := time.Now().UTC().Format("20060102-150405.000000000")
	dst := filepath.Join(l.retDir, fmt.Sprintf("%s.%s.jsonl", baseOf(l.path), ts))
	for i := 1; ; i++ {
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			break
		}
		dst = filepath.Join(l.retDir, fmt.Sprintf("%s.%s-%d.jsonl", baseOf(l.path), ts, i))
	}
	if err := os.Rename(l.path, dst); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.f = f
	// header carries chain: comment line with prev_hash so chain never breaks
	fmt.Fprintf(l.f, "# prev_hash=%s seq=%d\n", l.prevHash, l.seq)
	l.f.Sync()
	Prune(l.retDir, baseOf(l.path), l.maxAge, 0)
	return nil
}

// Prune removes rotated files older than maxAge or exceeding maxTotalBytes (0 = disabled).
func Prune(dir, base string, maxAge time.Duration, maxTotalBytes int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		mod  time.Time
		size int64
	}
	var files []fi
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, base+".") && strings.HasSuffix(n, ".jsonl") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			files = append(files, fi{filepath.Join(dir, n), info.ModTime(), info.Size()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	now := time.Now()
	for _, f := range files {
		if maxAge > 0 && now.Sub(f.mod) > maxAge {
			os.Remove(f.path)
		}
	}
	if maxTotalBytes > 0 {
		entries2, _ := os.ReadDir(dir)
		var rest []fi
		var total int64
		for _, e := range entries2 {
			n := e.Name()
			if strings.HasPrefix(n, base+".") && strings.HasSuffix(n, ".jsonl") {
				info, _ := e.Info()
				rest = append(rest, fi{filepath.Join(dir, n), info.ModTime(), info.Size()})
				total += info.Size()
			}
		}
		sort.Slice(rest, func(i, j int) bool { return rest[i].mod.Before(rest[j].mod) })
		for _, f := range rest {
			if total <= maxTotalBytes {
				break
			}
			os.Remove(f.path)
			total -= f.size
		}
	}
}

// ParseRetention parses "30d", "12h", "1h" etc.
func ParseRetention(s string) time.Duration {
	if s == "" {
		return 30 * 24 * time.Hour
	}
	var n int
	var unit string
	fmt.Sscanf(s, "%d%s", &n, &unit)
	switch unit {
	case "d":
		return time.Duration(n) * 24 * time.Hour
	case "h":
		return time.Duration(n) * time.Hour
	case "m":
		return time.Duration(n) * time.Minute
	}
	return 30 * 24 * time.Hour
}
