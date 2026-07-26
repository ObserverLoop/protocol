package protocol

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIdentifierAccepts(t *testing.T) {
	accepted := []string{
		"a",
		"0",
		"-",
		"tenant-1",
		"0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e21", // canonical UUIDv7 text form
		strings.Repeat("a", IdentifierMaxLength),
	}
	for _, s := range accepted {
		id, err := ParseIdentifier(s)
		require.NoError(t, err, s)
		require.Equal(t, s, id.String())
	}
}

func TestParseIdentifierRejects(t *testing.T) {
	rejected := map[string]string{
		"empty":              "",
		"dot":                "a.b",
		"nats wildcard star": "a*",
		"nats wildcard gt":   "a>",
		"nats full wildcard": ">",
		"space":              "a b",
		"leading space":      " a",
		"tab":                "a\tb",
		"newline":            "a\nb",
		"uppercase":          "Tenant",
		"all uppercase":      "TENANT",
		"underscore":         "a_b",
		"slash":              "a/b",
		"colon":              "a:b",
		"non-ascii":          "tenanté",
		"null byte":          "a\x00b",
		"too long":           strings.Repeat("a", IdentifierMaxLength+1),
		"embedded newline":   "ok\nnot-ok",
	}
	for name, s := range rejected {
		t.Run(name, func(t *testing.T) {
			_, err := ParseIdentifier(s)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrBadIdentifier)
		})
	}
}

// TestExactlyOneRegularExpression is the architectural assertion behind
// "ParseIdentifier is the single validator": a second regular expression
// anywhere in the module is a second grammar waiting to drift from this one.
func TestExactlyOneRegularExpression(t *testing.T) {
	moduleRoot, err := filepath.Abs("..")
	require.NoError(t, err)

	var found []string
	require.NoError(t, filepath.WalkDir(moduleRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		// A file that does not import regexp cannot compile one.
		imported := false
		for _, spec := range file.Imports {
			if spec.Path.Value == `"regexp"` {
				imported = true
			}
		}
		if !imported {
			return nil
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "regexp" {
				return true
			}
			if strings.HasPrefix(selector.Sel.Name, "MustCompile") || strings.HasPrefix(selector.Sel.Name, "Compile") {
				rel, _ := filepath.Rel(moduleRoot, path)
				found = append(found, rel+": regexp."+selector.Sel.Name)
			}
			return true
		})
		return nil
	}))

	require.Equal(t, []string{"protocol/identifier.go: regexp.MustCompile"}, found,
		"the identifier grammar must be compiled in exactly one place")
}

func TestParseIdentifierErrorIsNotMatchedByString(t *testing.T) {
	_, err := ParseIdentifier("NOPE")
	require.True(t, errors.Is(err, ErrBadIdentifier))
}
