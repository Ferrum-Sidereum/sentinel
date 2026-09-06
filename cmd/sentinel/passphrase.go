package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sentinel/internal/keyring"
	"sentinel/internal/memguard"
	"sentinel/internal/termsecret"
	"sentinel/internal/vault"
)

const passphraseNotice = "The passphrase is not stored anywhere. Losing it means losing the vault."

func readPassphraseTwice() ([]byte, error) {
	fmt.Fprintln(os.Stderr, passphraseNotice)
	pw1, err := termsecret.Read("Enter new passphrase: ")
	if err != nil {
		return nil, err
	}
	defer memguard.Zero(pw1)
	pw2, err := termsecret.Read("Confirm passphrase: ")
	if err != nil {
		return nil, err
	}
	defer memguard.Zero(pw2)
	if len(pw1) != len(pw2) {
		return nil, errors.New("passphrases do not match")
	}
	var diff byte
	for i := range pw1 {
		diff |= pw1[i] ^ pw2[i]
	}
	if diff != 0 {
		return nil, errors.New("passphrases do not match")
	}
	out := make([]byte, len(pw1))
	copy(out, pw1)
	return out, nil
}

func cmdInitPassphrase(dir string) {
	pw, err := readPassphraseTwice()
	if err != nil {
		fmt.Println("init failed:", err)
		os.Exit(1)
	}
	defer memguard.Zero(pw)
	key, err := keyring.CreatePassphrase(dir, pw)
	if err != nil {
		fmt.Println("init failed:", err)
		os.Exit(1)
	}
	defer memguard.Zero(key)
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		fmt.Println("init failed:", err)
		os.Exit(1)
	}
	st.Close()
	fmt.Println("initialized", dir)
}

func cmdMigrateKey() {
	if err := migrateLegacy(dataDir(), readPassphraseTwice); err != nil {
		fmt.Println("migrate-key failed:", err)
		os.Exit(1)
	}
	fmt.Println("migrated", dataDir())
}

func migrateLegacy(dir string, prompt func() ([]byte, error)) error {
	legacy := filepath.Join(dir, "passphrase")
	raw, err := os.ReadFile(legacy)
	if err != nil {
		return fmt.Errorf("no legacy passphrase file: %w", err)
	}
	if len(raw) == 0 {
		return errors.New("legacy passphrase file is empty")
	}
	oldKey := keyring.DeriveLegacy(raw)
	defer memguard.Zero(oldKey)
	oldStore, err := vault.Open(filepath.Join(dir, "vault.db"), oldKey)
	if err != nil {
		return fmt.Errorf("cannot open vault with legacy key: %w", err)
	}
	names, err := oldStore.List()
	if err != nil {
		oldStore.Close()
		return err
	}
	secrets := make([]vault.Secret, 0, len(names))
	for _, n := range names {
		sec, err := oldStore.Get(n)
		if err != nil {
			oldStore.Close()
			return fmt.Errorf("cannot decrypt %s: %w", n, err)
		}
		secrets = append(secrets, sec)
	}
	oldStore.Close()

	pw, err := prompt()
	if err != nil {
		return err
	}
	defer memguard.Zero(pw)
	newKey, err := keyring.CreatePassphrase(dir, pw)
	if err != nil {
		return err
	}
	defer memguard.Zero(newKey)
	newStore, err := vault.Open(filepath.Join(dir, "vault.db"), newKey)
	if err != nil {
		return err
	}
	for _, sec := range secrets {
		if err := newStore.Put(sec); err != nil {
			newStore.Close()
			return fmt.Errorf("cannot re-encrypt %s: %w", sec.Name, err)
		}
		memguard.Zero(sec.Value)
	}
	for _, sec := range secrets {
		if _, err := newStore.Get(sec.Name); err != nil {
			newStore.Close()
			return fmt.Errorf("verified read failed for %s: %w", sec.Name, err)
		}
	}
	newStore.Close()
	if err := os.Remove(legacy); err != nil {
		return fmt.Errorf("re-encryption verified but legacy file removal failed: %w", err)
	}
	return nil
}
