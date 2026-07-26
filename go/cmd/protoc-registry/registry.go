package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// typeToken is the placeholder every subject template ends with. It is the only
// token that may contain a dot, because it holds the registry type token.
const typeToken = "{type}"

const (
	registryFile   = "registry.yaml"
	registrySchema = "registry.schema.json"
)

type registry struct {
	Version        string            `yaml:"version"`
	SubjectClasses map[string]string `yaml:"subject_classes"`
	Streams        []streamEntry     `yaml:"streams"`
	Events         []eventEntry      `yaml:"events"`
}

type streamEntry struct {
	Name            string   `yaml:"name"`
	SubjectClasses  []string `yaml:"subject_classes"`
	Retention       string   `yaml:"retention"`
	MaxAge          string   `yaml:"max_age"`
	Discard         string   `yaml:"discard"`
	DuplicateWindow string   `yaml:"duplicate_window"`
}

type eventEntry struct {
	Type         string   `yaml:"type"`
	Schema       string   `yaml:"schema"`
	SubjectClass string   `yaml:"subject_class"`
	Durability   string   `yaml:"durability"`
	TrustDomains []string `yaml:"trust_domains"`
	Capabilities []string `yaml:"capabilities"`
}

// classNames returns the subject class names in sorted order.
func (r *registry) classNames() []string {
	names := make([]string, 0, len(r.SubjectClasses))
	for name := range r.SubjectClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// trustDomainSet returns every trust domain named by any event, sorted.
func (r *registry) trustDomainSet() []string { return unionOf(r.Events, eventEntry.domains) }

// capabilitySet returns every capability named by any event, sorted.
func (r *registry) capabilitySet() []string { return unionOf(r.Events, eventEntry.caps) }

func (e eventEntry) domains() []string { return e.TrustDomains }
func (e eventEntry) caps() []string    { return e.Capabilities }

func unionOf(events []eventEntry, pick func(eventEntry) []string) []string {
	seen := map[string]struct{}{}
	for _, e := range events {
		for _, v := range pick(e) {
			seen[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// loadRegistry reads registry.yaml, validates it against registry.schema.json,
// applies the cross-field rules JSON Schema cannot express, and returns the
// events sorted by type so that generated output is deterministic.
func loadRegistry(root string) (*registry, error) {
	//nolint:gosec // path is composed from the -root flag and generator constants
	raw, err := os.ReadFile(filepath.Join(root, registryFile))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", registryFile, err)
	}

	if err := validateAgainstSchema(root, raw); err != nil {
		return nil, err
	}

	var reg registry
	if err := yaml.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", registryFile, err)
	}
	if err := reg.check(); err != nil {
		return nil, err
	}

	sort.Slice(reg.Events, func(i, j int) bool { return reg.Events[i].Type < reg.Events[j].Type })
	return &reg, nil
}

func validateAgainstSchema(root string, raw []byte) error {
	compiled, err := compileRegistrySchema(root)
	if err != nil {
		return err
	}
	instance, err := yamlAsJSONInstance(raw)
	if err != nil {
		return err
	}
	if err := compiled.Validate(instance); err != nil {
		return fmt.Errorf("%s violates %s: %w", registryFile, registrySchema, err)
	}
	return nil
}

func compileRegistrySchema(root string) (*jsonschema.Schema, error) {
	//nolint:gosec // path is composed from the -root flag and generator constants
	raw, err := os.ReadFile(filepath.Join(root, registrySchema))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", registrySchema, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", registrySchema, err)
	}

	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource(registrySchema, doc); err != nil {
		return nil, fmt.Errorf("adding %s: %w", registrySchema, err)
	}
	compiled, err := compiler.Compile(registrySchema)
	if err != nil {
		return nil, fmt.Errorf("compiling %s: %w", registrySchema, err)
	}
	return compiled, nil
}

// yamlAsJSONInstance round-trips YAML through JSON so that the instance the
// validator sees has exactly the shape a JSON consumer would see.
func yamlAsJSONInstance(raw []byte) (any, error) {
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", registryFile, err)
	}
	encoded, err := yaml.MarshalWithOptions(doc, yaml.JSON())
	if err != nil {
		return nil, fmt.Errorf("re-encoding %s: %w", registryFile, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("re-decoding %s: %w", registryFile, err)
	}
	return instance, nil
}

// check applies the rules that span fields: references resolve, tokens are
// unique, no template is dead, and durability agrees with the stream bindings.
func (r *registry) check() error {
	classUsed := map[string]bool{}
	seenType := map[string]bool{}

	for _, e := range r.Events {
		if seenType[e.Type] {
			return fmt.Errorf("event type %q is declared twice", e.Type)
		}
		seenType[e.Type] = true

		if _, ok := r.SubjectClasses[e.SubjectClass]; !ok {
			return fmt.Errorf("event %q names undefined subject class %q", e.Type, e.SubjectClass)
		}
		classUsed[e.SubjectClass] = true

		want := "schemas/payload/" + e.Type + ".json"
		if e.Schema != want {
			return fmt.Errorf("event %q must use schema %q, has %q", e.Type, want, e.Schema)
		}
	}

	for name, template := range r.SubjectClasses {
		if !classUsed[name] {
			return fmt.Errorf("subject class %q is used by no event", name)
		}
		if !strings.HasSuffix(template, "."+typeToken) {
			return fmt.Errorf("subject class %q must end with .%s", name, typeToken)
		}
		if strings.Count(template, typeToken) != 1 {
			return fmt.Errorf("subject class %q must interpolate %s exactly once", name, typeToken)
		}
	}

	streamed, err := r.streamedClasses()
	if err != nil {
		return err
	}
	for _, e := range r.Events {
		bound := streamed[e.SubjectClass] != ""
		switch {
		case e.Durability == "jetstream" && !bound:
			return fmt.Errorf("event %q is jetstream but subject class %q is bound to no stream", e.Type, e.SubjectClass)
		case e.Durability == "core" && bound:
			return fmt.Errorf("event %q is core but subject class %q is bound to stream %q", e.Type, e.SubjectClass, streamed[e.SubjectClass])
		}
	}
	return nil
}

// streamedClasses maps each subject class to the single stream that binds it.
func (r *registry) streamedClasses() (map[string]string, error) {
	out := map[string]string{}
	seenName := map[string]bool{}
	for _, s := range r.Streams {
		if seenName[s.Name] {
			return nil, fmt.Errorf("stream %q is declared twice", s.Name)
		}
		seenName[s.Name] = true

		for _, class := range s.SubjectClasses {
			if _, ok := r.SubjectClasses[class]; !ok {
				return nil, fmt.Errorf("stream %q names undefined subject class %q", s.Name, class)
			}
			if prev, ok := out[class]; ok {
				return nil, fmt.Errorf("subject class %q is bound to both %q and %q", class, prev, s.Name)
			}
			out[class] = s.Name
		}
	}
	return out, nil
}
