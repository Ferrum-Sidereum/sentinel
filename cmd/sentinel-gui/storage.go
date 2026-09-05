package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	oskeyring "github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"sentinel/internal/policy"
)

type credentialStore interface {
	get() (string, error)
	set(string) error
}
type nativeCredentials struct{}

func (nativeCredentials) get() (string, error) { return oskeyring.Get("sentinel-master", "master") }
func (nativeCredentials) set(v string) error   { return oskeyring.Set("sentinel-master", "master", v) }

func loadMasterKey(dir string, credentials credentialStore) ([]byte, error) {
	stored, err := credentials.get()
	if err == nil {
		key, decodeErr := hex.DecodeString(stored)
		if decodeErr != nil || len(key) != 32 {
			wipe(key)
			return nil, errors.New("The stored master key is invalid. It was not replaced.")
		}
		return key, nil
	}
	if !errors.Is(err, oskeyring.ErrNotFound) {
		return nil, errors.New("Windows Credential Manager is unavailable. Unlock your session and retry.")
	}
	for _, name := range []string{"vault.db", "passphrase"} {
		_, statErr := os.Stat(filepath.Join(dir, name))
		if statErr == nil {
			return nil, errors.New("Existing Sentinel data has no matching Windows credential. Restore the original key; legacy passphrase migration is not automatic.")
		}
		if !os.IsNotExist(statErr) {
			return nil, errors.New("Cannot check existing Sentinel data. No master key was created.")
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("Cannot generate a master key.")
	}
	if err := credentials.set(hex.EncodeToString(key)); err != nil {
		wipe(key)
		return nil, errors.New("Cannot save the master key in Windows Credential Manager.")
	}
	return key, nil
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
func mappingSet(n *yaml.Node, name string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, value)
}
func mappingGet(n *yaml.Node, name string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			return n.Content[i+1]
		}
	}
	return nil
}
func updatePolicyDocument(raw []byte, p policy.Policy) ([]byte, error) {
	if len(raw) == 0 {
		return yaml.Marshal(p)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("policy root must be a mapping")
	}
	root := doc.Content[0]
	entities := mappingGet(root, "entities")
	if entities == nil {
		entities = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		mappingSet(root, "entities", entities)
	}
	if entities.Kind != yaml.MappingNode {
		return nil, errors.New("entities must be a mapping")
	}
	for name, rule := range p.Entities {
		node := mappingGet(entities, name)
		if node == nil {
			node = &yaml.Node{}
			if err := node.Encode(rule); err != nil {
				return nil, err
			}
			mappingSet(entities, name, node)
		}
		if node.Kind != yaml.MappingNode {
			return nil, errors.New("entity must be a mapping")
		}
		for key, value := range map[string]string{"to_llm": rule.ToLLM, "to_untrusted": rule.ToUntrusted} {
			mappingSet(node, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
		}
	}
	custom := &yaml.Node{}
	if err := custom.Encode(p.CustomPatterns); err != nil {
		return nil, err
	}
	mappingSet(root, "custom_patterns", custom)
	return yaml.Marshal(&doc)
}
