package broker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyBrokerResolves enforces: broker is the ONLY caller of the
// decrypt-for-injection path (vault Resolve/Get) outside vault itself.
func TestOnlyBrokerResolves(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			n := filepath.Base(p)
			if n == ".git" || n == "testdata" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasPrefix(rel, "internal"+string(os.PathSeparator)+"vault"+string(os.PathSeparator)) {
			return nil
		}
		if strings.HasPrefix(rel, "internal"+string(os.PathSeparator)+"broker"+string(os.PathSeparator)) {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Decrypt-for-injection path is Store.Resolve (Get is a raw
			// read legitimately used by CLI commands; Resolve records
			// Touch and enforces expiry).
			if sel.Sel.Name != "Resolve" {
				return true
			}
			offenders = append(offenders, rel+": "+sel.Sel.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// vaultStore.Resolve adapter in mcp is allowed: it only implements
	// broker.SecretStore and is invoked via broker.Resolve.
	var real []string
	for _, o := range offenders {
		if strings.HasPrefix(o, "internal"+string(os.PathSeparator)+"mcp"+string(os.PathSeparator)) {
			continue
		}
		real = append(real, o)
	}
	if len(real) > 0 {
		t.Fatalf("decrypt-for-injection callers outside broker/vault: %v", real)
	}
}
