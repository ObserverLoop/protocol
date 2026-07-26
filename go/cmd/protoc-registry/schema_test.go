package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// forbiddenProperties are the property names no payload schema may declare, at
// any depth. This is the protocol-layer half of the chain-of-thought rule: a
// harness may emit reasoning, but there is nowhere in the wire format to put it.
// Enforced here mechanically rather than by review.
var forbiddenProperties = []string{"reasoning", "thinking", "chain_of_thought"}

func TestNoSchemaDeclaresAReasoningProperty(t *testing.T) {
	sources, err := collectSchemas(repoRoot(t))
	require.NoError(t, err)
	require.NotEmpty(t, sources)

	for _, s := range sources {
		var doc any
		decoder := json.NewDecoder(bytes.NewReader(s.body))
		decoder.UseNumber()
		require.NoError(t, decoder.Decode(&doc), s.rel)

		for _, name := range declaredProperties(doc) {
			for _, forbidden := range forbiddenProperties {
				require.NotEqual(t, forbidden, strings.ToLower(name),
					"%s declares a %q property; the protocol has no place for reasoning content", s.rel, name)
			}
		}
	}
}

// TestForbiddenPropertyWalkerFindsOne guards the guard: a walker that silently
// finds nothing would let the rule above pass vacuously forever.
func TestForbiddenPropertyWalkerFindsOne(t *testing.T) {
	var doc any
	require.NoError(t, json.Unmarshal([]byte(`{
		"type": "object",
		"properties": {
			"note": {
				"type": "object",
				"$defs": {"inner": {"properties": {"reasoning": {"type": "string"}}}}
			}
		}
	}`), &doc))

	require.Contains(t, declaredProperties(doc), "reasoning")
}

// declaredProperties returns every property name any subschema declares,
// following properties, patternProperties, $defs, and every other nested
// object or array, so a name cannot hide behind a combinator.
func declaredProperties(node any) []string {
	var out []string
	switch value := node.(type) {
	case map[string]any:
		for _, keyword := range []string{"properties", "patternProperties"} {
			if declared, ok := value[keyword].(map[string]any); ok {
				for name := range declared {
					out = append(out, name)
				}
			}
		}
		for key, child := range value {
			// A property named "properties" would otherwise hide its children.
			if key == "properties" || key == "patternProperties" {
				if declared, ok := child.(map[string]any); ok {
					for _, sub := range declared {
						out = append(out, declaredProperties(sub)...)
					}
					continue
				}
			}
			out = append(out, declaredProperties(child)...)
		}
	case []any:
		for _, child := range value {
			out = append(out, declaredProperties(child)...)
		}
	}
	return out
}

// TestSchemaPayloadRootsAreClosed asserts the other half of the rule: an
// unknown property cannot slip into a payload, so a field the schema forbids
// cannot be carried anyway.
func TestSchemaPayloadRootsAreClosed(t *testing.T) {
	sources, err := collectSchemas(repoRoot(t))
	require.NoError(t, err)

	for _, s := range sources {
		if !strings.HasPrefix(s.rel, schemaDir+"/payload/") {
			continue
		}
		var doc map[string]any
		require.NoError(t, json.Unmarshal(s.body, &doc), s.rel)
		require.Equal(t, false, doc["additionalProperties"],
			fmt.Sprintf("%s must set additionalProperties: false at the payload root", s.rel))
	}
}
