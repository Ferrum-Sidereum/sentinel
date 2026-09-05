package vault

import "sentinel/internal/scrubber"

// Match reports a stored secret occurrence: name only, never the value.
type Match = scrubber.Match

// Matcher answers "does this text contain a stored secret" without exposing values.
// It returns findings with secret NAMES, never values.
// FindAll returns findings with secret names and offsets.
// Close zeroes decrypted buffers.
type Matcher = scrubber.VaultMatcher

// matcher is a single-pass Aho-Corasick over decrypted secret bytes.
type matcher struct {
	next  []map[byte]int
	fail  []int
	out   [][]int // pattern ids ending at node
	pats  [][]byte
	names []string
	lens  []int
	zero  func()
}

func buildMatcher(names []string, vals [][]byte) *matcher {
	m := &matcher{next: []map[byte]int{{}}, fail: []int{0}, out: [][]int{nil}}
	addNode := func() int {
		m.next = append(m.next, map[byte]int{})
		m.fail = append(m.fail, 0)
		m.out = append(m.out, nil)
		return len(m.next) - 1
	}
	for i, v := range vals {
		if len(v) == 0 {
			continue
		}
		node := 0
		for _, b := range v {
			nx, ok := m.next[node][b]
			if !ok {
				nx = addNode()
				m.next[node][b] = nx
			}
			node = nx
		}
		m.out[node] = append(m.out[node], i)
	}
	// BFS failure links
	var q []int
	for _, nx := range m.next[0] {
		m.fail[nx] = 0
		q = append(q, nx)
	}
	for len(q) > 0 {
		v := q[0]
		q = q[1:]
		for b, nx := range m.next[v] {
			f := m.fail[v]
			for f != 0 {
				if _, ok := m.next[f][b]; ok {
					break
				}
				f = m.fail[f]
			}
			if dst, ok := m.next[f][b]; ok {
				m.fail[nx] = dst
			} else {
				m.fail[nx] = 0
			}
			m.out[nx] = append(m.out[nx], m.out[m.fail[nx]]...)
			q = append(q, nx)
		}
	}
	m.pats = vals
	m.names = names
	m.lens = make([]int, len(vals))
	for i, v := range vals {
		m.lens[i] = len(v)
	}
	m.zero = func() {
		for _, v := range vals {
			for i := range v {
				v[i] = 0
			}
		}
	}
	return m
}

// FindAll scans text in one pass. Reports overlapping and repeated occurrences.
func (m *matcher) FindAll(text string) []scrubber.Match {
	if m == nil {
		return nil
	}
	var out []scrubber.Match
	state := 0
	for i := range len(text) {
		b := text[i]
		for state != 0 {
			if _, ok := m.next[state][b]; ok {
				break
			}
			state = m.fail[state]
		}
		if nx, ok := m.next[state][b]; ok {
			state = nx
		} else {
			state = 0
		}
		for _, pid := range m.out[state] {
			out = append(out, scrubber.Match{Name: m.names[pid], Start: i - m.lens[pid] + 1, End: i + 1})
		}
	}
	return out
}

// Close zeroes decrypted buffers. Double close is safe.
func (m *matcher) Close() {
	if m == nil || m.zero == nil {
		return
	}
	m.zero()
	m.zero = nil
	m.pats = nil
}

// NewMatcher builds a Matcher over decrypted values held in []byte.
// Only names and offsets leave the matcher; values never do.
// The matcher snapshots current vault state; writes invalidate the store cache.
func (s *Store) NewMatcher() (Matcher, error) {
	if s == nil {
		return buildMatcher(nil, nil), nil
	}
	s.mMu.Lock()
	defer s.mMu.Unlock()
	if s.mCache != nil && s.mGen == s.cacheGen {
		return s.mCache.shared(), nil
	}
	if s.mCache != nil {
		s.mCache.Close()
		s.mCache = nil
	}
	names, err := s.List()
	if err != nil {
		return nil, err
	}
	vals := make([][]byte, 0, len(names))
	keep := make([]string, 0, len(names))
	for _, n := range names {
		sec, err := s.Get(n)
		if err != nil || len(sec.Value) == 0 {
			zero(sec.Value)
			continue
		}
		if isPlaceholder(string(sec.Value)) {
			zero(sec.Value)
			continue
		}
		vals = append(vals, sec.Value) // owned []byte, zeroed on Close
		keep = append(keep, n)
	}
	m := buildMatcher(keep, vals)
	s.mCache = m
	s.cacheGen = s.mGen
	return m.shared(), nil
}

// shared returns a handle sharing the automaton but with independent Close
// semantics: Close on a shared handle is a no-op; the owner (store cache)
// zeroes buffers on invalidation. Per-call Close by consumers stays safe.
func (m *matcher) shared() Matcher { return sharedMatcher{m} }

type sharedMatcher struct{ m *matcher }

func (s sharedMatcher) FindAll(text string) []scrubber.Match { return s.m.FindAll(text) }
func (s sharedMatcher) Close()                               {}
