package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DefaultKeepVersions is the default number of previous versions retained.
const DefaultKeepVersions = 3

// ErrExpired is returned when a secret is past its expires_at.
var ErrExpired = errors.New("secret expired")

// Secret is the in-memory form. Value is plaintext only in memory.
type Secret struct {
	Name       string
	Value      []byte // plaintext only in memory
	Kind       string
	Hosts      []string
	Paths      []string
	Methods    []string
	InjectHdr  []string
	Labels     map[string]string
	Version    int
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	UseCount   int64
}

// Expired reports whether the secret is past expires_at.
func (s Secret) Expired() bool {
	return s.ExpiresAt != nil && !time.Now().Before(*s.ExpiresAt)
}

// metaJSON is the on-disk JSON form of meta.
type metaJSON struct {
	Hosts     []string          `json:"hosts,omitempty"`
	Paths     []string          `json:"paths,omitempty"`
	Methods   []string          `json:"methods,omitempty"`
	InjectHdr []string          `json:"inject_hdr,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

func encodeMeta(sec Secret) (string, error) {
	m := metaJSON{Hosts: sec.Hosts, Paths: sec.Paths, Methods: sec.Methods, InjectHdr: sec.InjectHdr, Labels: sec.Labels}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeMeta(raw string, sec *Secret) error {
	if raw == "" {
		return nil
	}
	var m metaJSON
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return err
	}
	sec.Hosts, sec.Paths, sec.Methods, sec.InjectHdr, sec.Labels = m.Hosts, m.Paths, m.Methods, m.InjectHdr, m.Labels
	return nil
}

type Store struct {
	path     string
	db       *sql.DB
	key      []byte // master key (32B)
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
	db.SetMaxOpenConns(1)
	for _, pr := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
		`PRAGMA synchronous=NORMAL`,
	} {
		if _, err := db.Exec(pr); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pr, err)
		}
	}
	s := &Store{path: path, db: db, key: masterKey}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

const schemaV2 = `
CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL, nonce BLOB NOT NULL, kind TEXT NOT NULL, meta TEXT NOT NULL, version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT, last_used_at TEXT, use_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS secret_versions (name TEXT NOT NULL, version INTEGER NOT NULL, value BLOB NOT NULL, nonce BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (name, version));
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`

func (s *Store) migrate() error {
	var ver string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&ver)
	if err == nil {
		if ver == "2" {
			_, err = s.db.Exec(schemaV2)
			return err
		}
		return fmt.Errorf("unsupported schema version %q", ver)
	}
	// No schema_meta: v1 or fresh. Detect v1 by legacy columns.
	var hasSecrets int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='secrets'`).Scan(&hasSecrets); err != nil {
		return err
	}
	if hasSecrets == 0 {
		if _, err := s.db.Exec(schemaV2); err != nil {
			return err
		}
		_, err = s.db.Exec(`INSERT INTO schema_meta(key,value) VALUES('schema_version','2')`)
		return err
	}
	var hasMeta int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('secrets') WHERE name='meta'`).Scan(&hasMeta); err != nil {
		return err
	}
	if hasMeta == 1 {
		// Already v2-shaped without stamp (should not happen); stamp it.
		if _, err := s.db.Exec(schemaV2); err != nil {
			return err
		}
		_, err = s.db.Exec(`INSERT INTO schema_meta(key,value) VALUES('schema_version','2') ON CONFLICT(key) DO UPDATE SET value='2'`)
		return err
	}
	return s.migrateV1toV2()
}

// migrateV1toV2 copies vault.db to vault.db.v1.bak, then migrates in a transaction.
func (s *Store) migrateV1toV2() error {
	if s.path != "" && s.path != ":memory:" {
		bak := s.path + ".v1.bak"
		b, err := os.ReadFile(s.path)
		if err != nil {
			return fmt.Errorf("backup read: %w", err)
		}
		if err := os.WriteFile(bak, b, 0o600); err != nil {
			return fmt.Errorf("backup write: %w", err)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT name,value,nonce,kind,hosts,paths,methods,inject_hdr,version,created_at FROM secrets`)
	if err != nil {
		return err
	}
	type v1row struct {
		name, kind, hosts, paths, methods, hdrs, created string
		value, nonce                                     []byte
		version                                          sql.NullInt64
	}
	var all []v1row
	for rows.Next() {
		var r v1row
		if err := rows.Scan(&r.name, &r.value, &r.nonce, &r.kind, &r.hosts, &r.paths, &r.methods, &r.hdrs, &r.version, &r.created); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE secrets`); err != nil {
		return err
	}
	if _, err := tx.Exec(schemaV2); err != nil {
		return err
	}
	for _, r := range all {
		sec := Secret{Name: r.name, Kind: r.kind, Hosts: splitComma(r.hosts), Paths: splitComma(r.paths), Methods: splitComma(r.methods), InjectHdr: splitComma(r.hdrs)}
		meta, err := encodeMeta(sec)
		if err != nil {
			return err
		}
		created := r.created
		if created == "" {
			created = time.Now().UTC().Format(time.RFC3339)
		}
		version := 1
		if r.version.Valid {
			version = int(r.version.Int64)
		}
		if _, err := tx.Exec(`INSERT INTO secrets(name,value,nonce,kind,meta,version,created_at,updated_at,expires_at,last_used_at,use_count) VALUES(?,?,?,?,?,?,?,?,NULL,NULL,0)`,
			r.name, r.value, r.nonce, r.kind, meta, version, created, created); err != nil {
			return fmt.Errorf("migrate %s: %w", r.name, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_meta(key,value) VALUES('schema_version','2')`); err != nil {
		return err
	}
	return tx.Commit()
}

// splitComma decodes legacy v1 comma-joined columns. Migration-only.
func splitComma(s string) []string {
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

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func parseTimePtr(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, ns.String)
	if err != nil {
		return nil
	}
	return &t
}

// Put inserts or replaces a secret. created_at is preserved on conflict,
// updated_at advances on every write.
func (s *Store) Put(sec Secret) error {
	ct, nonce, err := s.seal(sec.Value)
	if err != nil {
		return err
	}
	meta, err := encodeMeta(sec)
	if err != nil {
		return err
	}
	now := fmtTime(time.Now())
	var exp sql.NullString
	if sec.ExpiresAt != nil {
		exp = sql.NullString{String: fmtTime(*sec.ExpiresAt), Valid: true}
	}
	_, err = s.db.Exec(`INSERT INTO secrets(name,value,nonce,kind,meta,version,created_at,updated_at,expires_at,last_used_at,use_count)
		VALUES(?,?,?,?,?,?,?,?,?,?,0) ON CONFLICT(name) DO UPDATE SET
		value=excluded.value,nonce=excluded.nonce,kind=excluded.kind,meta=excluded.meta,
		version=excluded.version,updated_at=excluded.updated_at,expires_at=excluded.expires_at`,
		sec.Name, ct, nonce, sec.Kind, meta, sec.Version, now, now, exp, nil)
	if err == nil {
		s.invalidateMatcher()
	}
	return err
}

func (s *Store) scanSecret(row interface {
	Scan(...any) error
}) (Secret, []byte, []byte, error) {
	var sec Secret
	var ct, nonce []byte
	var meta, created, updated string
	var exp, lastUsed sql.NullString
	var useCount int64
	err := row.Scan(&sec.Name, &ct, &nonce, &sec.Kind, &meta, &sec.Version, &created, &updated, &exp, &lastUsed, &useCount)
	if err != nil {
		return sec, nil, nil, err
	}
	if err := decodeMeta(meta, &sec); err != nil {
		return sec, nil, nil, fmt.Errorf("decode meta %s: %w", sec.Name, err)
	}
	sec.CreatedAt, sec.UpdatedAt = parseTime(created), parseTime(updated)
	sec.ExpiresAt, sec.LastUsedAt, sec.UseCount = parseTimePtr(exp), parseTimePtr(lastUsed), useCount
	return sec, ct, nonce, nil
}

func (s *Store) Get(name string) (Secret, error) {
	sec, ct, nonce, err := s.scanSecret(s.db.QueryRow(
		`SELECT name,value,nonce,kind,meta,version,created_at,updated_at,expires_at,last_used_at,use_count FROM secrets WHERE name=?`, name))
	if err != nil {
		return sec, err
	}
	plain, err := s.open(ct, nonce)
	if err != nil {
		return sec, fmt.Errorf("decrypt %s: %w", name, err)
	}
	sec.Value = plain
	return sec, nil
}

// Resolve returns the secret for injection: expired secrets are refused with
// ErrExpired, and every successful resolution records Touch.
func (s *Store) Resolve(name string) (Secret, error) {
	sec, err := s.Get(name)
	if err != nil {
		return sec, err
	}
	if sec.Expired() {
		zero(sec.Value)
		return sec, fmt.Errorf("%s: %w", name, ErrExpired)
	}
	if err := s.Touch(name); err != nil {
		zero(sec.Value)
		return sec, err
	}
	// Re-read to reflect updated counters.
	sec2, err := s.Get(name)
	if err != nil {
		zero(sec.Value)
		return sec, err
	}
	zero(sec.Value)
	return sec2, nil
}

// Touch records one successful use: last_used_at=now, use_count++.
func (s *Store) Touch(name string) error {
	r, err := s.db.Exec(`UPDATE secrets SET last_used_at=?, use_count=use_count+1 WHERE name=?`, fmtTime(time.Now()), name)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Rotate replaces the value (version+1), archiving the previous ciphertext
// into secret_versions and pruning to the last keep entries (keep<=0 ⇒ default).
func (s *Store) Rotate(name string, value []byte, keep int) error {
	if keep <= 0 {
		keep = DefaultKeepVersions
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur Secret
	var ct, nonce []byte
	var meta, created, updated string
	var exp, lastUsed sql.NullString
	var useCount int64
	err = tx.QueryRow(`SELECT name,value,nonce,kind,meta,version,created_at,updated_at,expires_at,last_used_at,use_count FROM secrets WHERE name=?`, name).
		Scan(&cur.Name, &ct, &nonce, &cur.Kind, &meta, &cur.Version, &created, &updated, &exp, &lastUsed, &useCount)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO secret_versions(name,version,value,nonce,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(name,version) DO UPDATE SET value=excluded.value,nonce=excluded.nonce,created_at=excluded.created_at`,
		name, cur.Version, ct, nonce, fmtTime(time.Now())); err != nil {
		return err
	}
	newCT, newNonce, err := s.seal(value)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE secrets SET value=?,nonce=?,version=?,updated_at=? WHERE name=?`,
		newCT, newNonce, cur.Version+1, fmtTime(time.Now()), name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM secret_versions WHERE name=? AND version NOT IN (SELECT version FROM secret_versions WHERE name=? ORDER BY version DESC LIMIT ?)`,
		name, name, keep); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.invalidateMatcher()
	return nil
}

// Versions returns retained previous version numbers, oldest first.
func (s *Store) Versions(name string) ([]int, error) {
	rows, err := s.db.Query(`SELECT version FROM secret_versions WHERE name=? ORDER BY version`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Rollback restores the most recent retained version as current.
func (s *Store) Rollback(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var curVersion int
	var curCT, curNonce []byte
	if err := tx.QueryRow(`SELECT version,value,nonce FROM secrets WHERE name=?`, name).Scan(&curVersion, &curCT, &curNonce); err != nil {
		return err
	}
	var prevVersion int
	var prevCT, prevNonce []byte
	var prevCreated string
	if err := tx.QueryRow(`SELECT version,value,nonce,created_at FROM secret_versions WHERE name=? ORDER BY version DESC LIMIT 1`, name).
		Scan(&prevVersion, &prevCT, &prevNonce, &prevCreated); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE secrets SET value=?,nonce=?,version=?,updated_at=? WHERE name=?`,
		prevCT, prevNonce, curVersion+1, fmtTime(time.Now()), name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM secret_versions WHERE name=? AND version=?`, name, prevVersion); err != nil {
		return err
	}
	_ = prevCreated
	if err := tx.Commit(); err != nil {
		return err
	}
	s.invalidateMatcher()
	return nil
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
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM secret_versions WHERE name=?`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM secrets WHERE name=?`, name); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.invalidateMatcher()
	return nil
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
