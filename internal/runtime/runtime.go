package runtime

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultEgressPort = 18449
	DefaultMCPPort    = 18450
	DefaultLLMPort    = 18451

	EnvEgressPort = "SENTINEL_EGRESS_PORT"
	EnvMCPPort    = "SENTINEL_MCP_PORT"
	EnvLLMPort    = "SENTINEL_LLM_PORT"
)

// Service names for run files and bind-failure hints.
const (
	ServiceEgress = "egress"
	ServiceMCP    = "mcp"
	ServiceLLM    = "llm"
)

// ResolvePort: flag > env > default. flag=-1 means unset.
func ResolvePort(flag int, envName string, def int) int {
	if flag >= 0 {
		return flag
	}
	if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
			return n
		}
	}
	return def
}

// DialConnect verifies addr accepts TCP connections.
func DialConnect(addr string) error {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// ResolveAddr splits addr into host:port, applying port override when >=0.
// port==0 stays 0 so the listener picks a free port.
func ResolveAddr(addr, host string, portOverride int, def int) string {
	h, p := host, def
	if hh, pp, err := net.SplitHostPort(addr); err == nil {
		h = hh
		if n, err := strconv.Atoi(pp); err == nil {
			p = n
		}
	}
	if portOverride >= 0 {
		p = portOverride
	}
	if h == "" {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, strconv.Itoa(p))
}

// AddrPort extracts the numeric port from addr, -1 on failure.
func AddrPort(addr string) int {
	_, pp, err := net.SplitHostPort(addr)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(pp)
	if err != nil {
		return -1
	}
	return n
}

// ExpectedService maps a default port to the process type expected there.
func ExpectedService(port int) string {
	switch port {
	case DefaultEgressPort:
		return ServiceEgress
	case DefaultMCPPort:
		return ServiceMCP
	case DefaultLLMPort:
		return ServiceLLM
	}
	return ""
}

// BindError wraps a listen failure with port, expected service, and hint.
type BindError struct {
	Addr     string
	Port     int
	Expected string
	Err      error
}

func (e *BindError) Error() string {
	s := fmt.Sprintf("cannot bind %s (port %d)", e.Addr, e.Port)
	if e.Expected != "" {
		s += fmt.Sprintf(": %s gateway is expected there", e.Expected)
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	s += "; retry with --port <free-port> (or --port 0 for a free port)"
	return s
}

func (e *BindError) Unwrap() error { return e.Err }

// WrapBind annotates a listen error on addr.
func WrapBind(addr string, err error) error {
	if err == nil {
		return nil
	}
	p := AddrPort(addr)
	return &BindError{Addr: addr, Port: p, Expected: ExpectedService(p), Err: err}
}

// Listen binds TCP and returns the listener; errors are wrapped via WrapBind.
// port 0 in addr lets the OS pick a free port; use ln.Addr() for the result.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, WrapBind(addr, err)
	}
	return ln, nil
}

// RunFile is the ~/.sentinel/run/<service>.json shape.
type RunFile struct {
	PID       int    `json:"pid"`
	Addr      string `json:"addr"`
	Service   string `json:"service"`
	StartedAt string `json:"started_at"`
	Version   string `json:"version"`
}

func RunDir(dataDir string) string { return filepath.Join(dataDir, "run") }

func RunPath(dataDir, service string) string {
	return filepath.Join(RunDir(dataDir), service+".json")
}

// WriteRunFile writes the run file atomically (0600).
func WriteRunFile(dataDir, service, addr, version string) error {
	if err := os.MkdirAll(RunDir(dataDir), 0o700); err != nil {
		return err
	}
	rf := RunFile{
		PID:       os.Getpid(),
		Addr:      addr,
		Service:   service,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Version:   version,
	}
	buf, err := json.Marshal(rf)
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	tmp := RunPath(dataDir, service) + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, RunPath(dataDir, service))
}

// ReadRunFile reads and parses a run file.
func ReadRunFile(dataDir, service string) (*RunFile, error) {
	buf, err := os.ReadFile(RunPath(dataDir, service))
	if err != nil {
		return nil, err
	}
	var rf RunFile
	if err := json.Unmarshal(buf, &rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

// RemoveRunFile deletes the run file; missing file is not an error.
func RemoveRunFile(dataDir, service string) error {
	err := os.Remove(RunPath(dataDir, service))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// IsAlive reports whether pid refers to a live process.
func IsAlive(pid int) bool {
	return isAlive(pid)
}

// SweepStale removes run files whose pid is dead; returns cleaned services.
func SweepStale(dataDir string) []string {
	var cleaned []string
	for _, svc := range []string{ServiceEgress, ServiceMCP, ServiceLLM} {
		rf, err := ReadRunFile(dataDir, svc)
		if err != nil {
			continue
		}
		if !IsAlive(rf.PID) {
			_ = RemoveRunFile(dataDir, svc)
			cleaned = append(cleaned, svc)
		}
	}
	return cleaned
}
