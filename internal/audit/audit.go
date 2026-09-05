package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time    time.Time      `json:"time"`
	Session string         `json:"session,omitempty"`
	Type    string         `json:"type"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type Logger struct {
	mu sync.Mutex
	f  *os.File
}

func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

func (l *Logger) Log(session, typ string, fields map[string]any) {
	e := Event{Time: time.Now().UTC(), Session: session, Type: typ, Fields: Sanitize(fields)}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.f.Write(append(b, '\n'))
}

func (l *Logger) Close() error { return l.f.Close() }
