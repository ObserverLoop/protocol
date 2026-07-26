package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaDir is the hand-written schema tree, relative to the repository root.
const schemaDir = "schemas"

// embeddedSchemaDir is the verbatim mirror of schemaDir inside the Go package.
// Go's embed directive cannot reach outside its own module directory, and the
// module lives in go/, so the schemas are copied rather than referenced. The
// copy is generated, and `make generate` plus `git diff --exit-code` is what
// keeps it identical to the source.
var embeddedSchemaDir = filepath.Join(goPackageDir, schemaDir)

// genSchemas validates every schema, checks that the registry and the schema
// tree agree, and mirrors the tree into the Go package for embedding.
func genSchemas(root string, reg *registry) error {
	sources, err := collectSchemas(root)
	if err != nil {
		return err
	}
	if err := checkSchemaCoverage(reg, sources); err != nil {
		return err
	}
	if err := compileSchemas(sources); err != nil {
		return err
	}
	return mirrorSchemas(root, sources)
}

// schemaSource is one schema file: its slash-separated path relative to the
// repository root, its $id, and its bytes.
type schemaSource struct {
	rel  string
	id   string
	body []byte
}

func collectSchemas(root string) ([]schemaSource, error) {
	base := filepath.Join(root, schemaDir)
	var out []schemaSource

	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		//nolint:gosec // p comes from walking the schema directory under -root
		body, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading %s: %w", p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return fmt.Errorf("relativising %s: %w", p, err)
		}
		id, err := schemaID(body)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		out = append(out, schemaSource{rel: filepath.ToSlash(rel), id: id, body: body})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", schemaDir, err)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

func schemaID(body []byte) (string, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("decoding: %w", err)
	}
	object, ok := doc.(map[string]any)
	if !ok {
		return "", fmt.Errorf("is not a JSON object")
	}
	id, ok := object["$id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("has no $id")
	}
	return id, nil
}

// checkSchemaCoverage asserts the registry and the schema tree describe the
// same set: one payload schema per event, no orphans, and an $id that agrees
// with the file's location.
func checkSchemaCoverage(reg *registry, sources []schemaSource) error {
	const idBase = "https://schemas.observerloop.com/ol/v1/"

	byRel := make(map[string]schemaSource, len(sources))
	for _, s := range sources {
		byRel[s.rel] = s

		want := idBase + strings.TrimPrefix(s.rel, schemaDir+"/")
		if s.id != want {
			return fmt.Errorf("%s declares $id %q, expected %q", s.rel, s.id, want)
		}
	}

	payloads := map[string]bool{}
	for _, s := range sources {
		if strings.HasPrefix(s.rel, schemaDir+"/payload/") {
			payloads[s.rel] = false
		}
	}

	for _, e := range reg.Events {
		if _, ok := byRel[e.Schema]; !ok {
			return fmt.Errorf("event %q has no schema at %s", e.Type, e.Schema)
		}
		payloads[e.Schema] = true
	}
	for rel, used := range payloads {
		if !used {
			return fmt.Errorf("%s is in no registry entry", rel)
		}
	}
	return nil
}

// compileSchemas proves every schema is valid Draft 2020-12 and that every
// cross-file $ref resolves, before anything is mirrored.
func compileSchemas(sources []schemaSource) error {
	compiler := jsonschema.NewCompiler()
	for _, s := range sources {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(s.body))
		if err != nil {
			return fmt.Errorf("decoding %s: %w", s.rel, err)
		}
		if err := compiler.AddResource(s.id, doc); err != nil {
			return fmt.Errorf("adding %s: %w", s.rel, err)
		}
	}
	for _, s := range sources {
		if _, err := compiler.Compile(s.id); err != nil {
			return fmt.Errorf("compiling %s: %w", s.rel, err)
		}
	}
	return nil
}

// mirrorSchemas copies the schema tree into the Go package and deletes anything
// there that the source no longer contains.
func mirrorSchemas(root string, sources []schemaSource) error {
	want := map[string]bool{}
	for _, s := range sources {
		rel := strings.TrimPrefix(s.rel, schemaDir+"/")
		want[rel] = true
		dst := filepath.Join(root, embeddedSchemaDir, filepath.FromSlash(rel))
		if err := writeFile(dst, s.body); err != nil {
			return err
		}
	}

	base := filepath.Join(root, embeddedSchemaDir)
	return filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		if want[path.Clean(filepath.ToSlash(rel))] {
			return nil
		}
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("removing stale %s: %w", p, err)
		}
		return nil
	})
}
