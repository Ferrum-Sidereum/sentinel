package audit

import (
	"os"
	"time"
)

// TailPoll polls for new records after lastSeq, calling fn for each match.
// Filters: since (time), typ, secret name. Stops when stop chan closed.
func TailPoll(files []string, lastSeq uint64, since time.Time, typ, secret string, stop <-chan struct{}, fn func(Record)) uint64 {
	seen := lastSeq
	for {
		select {
		case <-stop:
			return seen
		default:
		}
		recs, _ := ReadAll(files)
		for _, r := range recs {
			if r.Seq <= seen {
				continue
			}
			seen = r.Seq
			ts, _ := time.Parse(time.RFC3339, r.Ts)
			if !since.IsZero() && ts.Before(since) {
				continue
			}
			if typ != "" && r.Type != typ {
				continue
			}
			if secret != "" && (r.Fields == nil || r.Fields["name"] != secret) {
				continue
			}
			fn(r)
		}
		select {
		case <-stop:
			return seen
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// CurrentSeq returns max seq across files (for --since polling offset).
func CurrentSeq(files []string) uint64 {
	recs, _ := ReadAll(files)
	if len(recs) == 0 {
		return 0
	}
	return recs[len(recs)-1].Seq
}

// ChainFilesFor returns ordered files for a log path (for CLI tail).
func ChainFilesFor(path string) []string {
	l := &Logger{path: path, retDir: dirOf(path)}
	return l.chainFiles()
}

var _ = os.PathSeparator
