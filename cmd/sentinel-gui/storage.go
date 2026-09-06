package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sentinel/internal/core"
	"sentinel/internal/policy"
	"sentinel/internal/vault"
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func openVaultAt(dir string, key []byte) (*vault.Store, error) {
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		return nil, errors.New("cannot open the existing vault. No credentials were replaced.")
	}
	return st, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file too large")
	}
	return b, nil
}

func writeNewPrivate(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func atomicWrite(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".sentinel-policy-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return replaceFile(tmp, path)
}

// updatePolicyDocument is the comment-preserving whole-Policy writer (core).
func updatePolicyDocument(raw []byte, p policy.Policy) ([]byte, error) {
	return core.UpdatePolicyDocument(raw, p)
}
