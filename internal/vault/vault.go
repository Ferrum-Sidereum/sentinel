package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Secret struct {
	Name      string
	Value     []byte // plaintext only in memory
	Kind      string
	Hosts     []string
	Paths     []string
	Methods   []string
	InjectHdr []string
	Version   int
	CreatedAt time.Time
}

type Store struct {
	db  *sql.DB
	key []byte // master key (32B)
	mMu      sync.Mutex
	mCache   *matcher
	mGen     uint64
	cacheGen uint64
}

func Open(path string, masterKey []byte) (*Store, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, key: masterKey}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS secrets(
		name TEXT PRIMARY KEY, value BLOB NOT NULL, nonce BLOB NOT NULL,
		kind TEXT, hosts TEXT, paths TEXT, methods TEXT, inject_hdr TEXT,
		version INTEGER, created_at TEXT)`)
	return err
}

func (s *Store) seal(plain []byte) (ct, nonce []byte, err error) {
	blk, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return g.Seal(nil, nonce, plain, []byte("sentinel-vault")), nonce, nil
}

func (s *Store) open(ct, nonce []byte) ([]byte, error) {
	blk, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, []byte("sentinel-vault"))
}

func join(ss []string) string {
	out := ""
	for i, v := range ss {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func (s *Store) Put(sec Secret) error {
	ct, nonce, err := s.seal(sec.Value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO secrets(name,value,nonce,kind,hosts,paths,methods,inject_hdr,version,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
		value=excluded.value,nonce=excluded.nonce,kind=excluded.kind,hosts=excluded.hosts,
		paths=excluded.paths,methods=excluded.methods,inject_hdr=excluded.inject_hdr,
		version=excluded.version,created_at=excluded.created_at`,
		sec.Name, ct, nonce, sec.Kind, join(sec.Hosts), join(sec.Paths),
		join(sec.Methods), join(sec.InjectHdr), sec.Version, time.Now().UTC().Format(time.RFC3339))
	if err == nil {
		s.invalidateMatcher()
	}
	return err
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	return append(out, cur)
}

func (s *Store) Get(name string) (Secret, error) {
	var sec Secret
	var ct, nonce []byte
	var hosts, paths, methods, hdrs, created string
	err := s.db.QueryRow(`SELECT name,value,nonce,kind,hosts,paths,methods,inject_hdr,version,created_at
		FROM secrets WHERE name=?`, name).Scan(
		&sec.Name, &ct, &nonce, &sec.Kind, &hosts, &paths, &methods, &hdrs, &sec.Version, &created)
	if err != nil {
		return sec, err
	}
	plain, err := s.open(ct, nonce)
	if err != nil {
		return sec, fmt.Errorf("decrypt %s: %w", name, err)
	}
	sec.Value = plain
	sec.Hosts, sec.Paths, sec.Methods, sec.InjectHdr = split(hosts), split(paths), split(methods), split(hdrs)
	sec.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return sec, nil
}

func (s *Store) List() ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) Delete(name string) error {
	_, err := s.db.Exec(`DELETE FROM secrets WHERE name=?`, name)
	if err == nil {
		s.invalidateMatcher()
	}
	return err
}

func (s *Store) Close() error {
	s.invalidateMatcher()
	return s.db.Close()
}

func (s *Store) invalidateMatcher() {
	s.mMu.Lock()
	defer s.mMu.Unlock()
	s.mGen++
	if s.mCache != nil {
		s.mCache.Close()
		s.mCache = nil
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func isPlaceholder(v string) bool {
	return len(v) > 6 && v[:6] == "snt://"
}
