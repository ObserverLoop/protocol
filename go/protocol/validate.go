package protocol

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaFS is a verbatim copy of the repository's schemas/ tree, mirrored here
// by protoc-registry because embed cannot reach outside the module directory.
//
//go:embed schemas
var schemaFS embed.FS

// SchemaFS exposes the embedded schema tree so that a consumer can serve or
// re-validate the published schemas without vendoring them. Paths are rooted at
// "schemas", matching the paths SchemaPathFor returns.
func SchemaFS() fs.FS { return schemaFS }

// compiled holds the schema set. Compilation is deferred to first use and done
// once: it costs a few milliseconds and most consumers validate many envelopes.
var compiled = sync.OnceValues(compileSchemaSet)

type schemaSet struct {
	envelope *jsonschema.Schema
	payloads map[EventType]*jsonschema.Schema
}

func compileSchemaSet() (*schemaSet, error) {
	compiler := jsonschema.NewCompiler()

	ids := map[string]string{} // schema path -> $id
	err := fs.WalkDir(schemaFS, "schemas", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		body, err := schemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("decoding %s: %w", path, err)
		}
		object, ok := doc.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not a JSON object", path)
		}
		id, ok := object["$id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("%s has no $id", path)
		}
		if err := compiler.AddResource(id, doc); err != nil {
			return fmt.Errorf("adding %s: %w", path, err)
		}
		ids[path] = id
		return nil
	})
	if err != nil {
		return nil, err
	}

	envelope, err := compiler.Compile(ids["schemas/envelope.json"])
	if err != nil {
		return nil, fmt.Errorf("compiling envelope schema: %w", err)
	}

	set := &schemaSet{envelope: envelope, payloads: make(map[EventType]*jsonschema.Schema, len(eventTypes))}
	for _, t := range eventTypes {
		path := schemaPaths[t]
		id, ok := ids[path]
		if !ok {
			return nil, fmt.Errorf("no embedded schema at %s for %s", path, t)
		}
		payload, err := compiler.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("compiling %s: %w", path, err)
		}
		set.payloads[t] = payload
	}
	return set, nil
}

// Validate checks the envelope against the embedded envelope schema and the
// payload against the schema registered for EventType. It also applies the two
// rules the schemas deliberately do not restate: the protocol MAJOR must be
// supported, and every identifier must satisfy the grammar - the schemas carry
// only the length bound, because ParseIdentifier is the single validator.
//
// It does not verify the signature. That is the verifier's job, and it needs a
// key store this package must not depend on.
func (e *Envelope) Validate() error {
	set, err := compiled()
	if err != nil {
		return err
	}

	if err = CheckProtocolVersion(e.ProtocolVersion); err != nil {
		return err
	}

	payloadSchema, ok := set.payloads[e.EventType]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEventType, e.EventType)
	}

	raw, err := e.Marshal()
	if err != nil {
		return err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: envelope is not valid JSON: %w", ErrSchemaViolation, err)
	}
	if err = set.envelope.Validate(instance); err != nil {
		return fmt.Errorf("%w: envelope: %w", ErrSchemaViolation, err)
	}

	payload, err := jsonschema.UnmarshalJSON(bytes.NewReader(e.Payload))
	if err != nil {
		return fmt.Errorf("%w: payload is not valid JSON: %w", ErrSchemaViolation, err)
	}
	if err := payloadSchema.Validate(payload); err != nil {
		return fmt.Errorf("%w: %s payload: %w", ErrSchemaViolation, e.EventType, err)
	}

	return e.validateIdentifiers()
}

// validateIdentifiers runs every identifier-typed field through the single
// validator. Optional fields are checked only when present.
func (e *Envelope) validateIdentifiers() error {
	required := map[string]Identifier{
		"event_id":       e.EventID,
		"tenant_id":      e.TenantID,
		"workspace_id":   e.WorkspaceID,
		"correlation_id": e.CorrelationID,
	}
	for field, value := range required {
		if _, err := ParseIdentifier(value.String()); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	optional := map[string]*Identifier{
		"thread_id":                e.ThreadID,
		"activity_id":              e.ActivityID,
		"source_conductor_id":      e.SourceConductorID,
		"source_agent_id":          e.SourceAgentID,
		"destination_conductor_id": e.DestinationConductorID,
		"destination_agent_id":     e.DestinationAgentID,
		"causation_id":             e.CausationID,
	}
	for field, value := range optional {
		if value == nil {
			continue
		}
		if _, err := ParseIdentifier(value.String()); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	for i, delegation := range e.DelegationChain {
		if _, err := ParseIdentifier(delegation); err != nil {
			return fmt.Errorf("delegation_chain[%d]: %w", i, err)
		}
	}
	return nil
}
