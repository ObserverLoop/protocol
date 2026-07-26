package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAcceptsASampleEnvelope(t *testing.T) {
	e := sampleEnvelope()
	require.NoError(t, e.Validate())
}

func TestValidateAcceptsAnUnknownMinor(t *testing.T) {
	// Forward compatibility: a newer MINOR may add optional fields, and this
	// binding must keep processing the envelope rather than reject it.
	e := sampleEnvelope()
	e.ProtocolVersion = "1.9999"
	require.NoError(t, e.Validate())
}

func TestValidateRejectsAnUnknownMajor(t *testing.T) {
	for _, version := range []string{"2.0", "0.9", "99.1"} {
		e := sampleEnvelope()
		e.ProtocolVersion = version
		require.ErrorIs(t, e.Validate(), ErrUnsupportedMajor, version)
	}
}

func TestValidateRejectsAMalformedVersion(t *testing.T) {
	for _, version := range []string{"", "1", "one.zero", "1.x"} {
		e := sampleEnvelope()
		e.ProtocolVersion = version
		require.ErrorIs(t, e.Validate(), ErrUnsupportedMajor, version)
	}
}

func TestValidateRejectsAnUnknownEventType(t *testing.T) {
	e := sampleEnvelope()
	e.EventType = "chat.whisper"
	require.ErrorIs(t, e.Validate(), ErrUnknownEventType)
}

func TestValidateRejectsAPayloadThatFailsItsSchema(t *testing.T) {
	tests := map[string]json.RawMessage{
		"missing required field": json.RawMessage(`{"role":"human"}`),
		"unknown role":           json.RawMessage(`{"role":"oracle","text":"x"}`),
		"wrong type":             json.RawMessage(`{"role":"human","text":42}`),
		"additional property":    json.RawMessage(`{"role":"human","text":"x","reasoning":"because"}`),
		"empty object":           json.RawMessage(`{}`),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			e := sampleEnvelope()
			e.Payload = payload
			require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
		})
	}
}

func TestValidateRejectsAMalformedEnvelope(t *testing.T) {
	t.Run("missing signature", func(t *testing.T) {
		e := sampleEnvelope()
		e.Signature = ""
		require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
	})

	t.Run("signature of the wrong length", func(t *testing.T) {
		e := sampleEnvelope()
		e.Signature = "aaaa"
		require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
	})

	t.Run("unknown trust domain", func(t *testing.T) {
		e := sampleEnvelope()
		e.TrustDomain = "browser"
		require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
	})

	t.Run("negative sequence", func(t *testing.T) {
		e := sampleEnvelope()
		e.Sequence = -1
		require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
	})

	t.Run("conductor id without an epoch", func(t *testing.T) {
		e := sampleEnvelope()
		e.SourceConductorID = ptr(Identifier("0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e24"))
		require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
	})

	t.Run("delegation chain deeper than two", func(t *testing.T) {
		e := sampleEnvelope()
		e.DelegationChain = []string{"a", "b", "c"}
		require.ErrorIs(t, e.Validate(), ErrSchemaViolation)
	})
}

// TestValidateEnforcesTheIdentifierGrammar covers what the schemas deliberately
// do not restate: the character class lives only in ParseIdentifier, so
// validation has to call it.
func TestValidateEnforcesTheIdentifierGrammar(t *testing.T) {
	t.Run("tenant id with a wildcard", func(t *testing.T) {
		e := sampleEnvelope()
		e.TenantID = "acme*"
		require.ErrorIs(t, e.Validate(), ErrBadIdentifier)
	})

	t.Run("uppercase workspace id", func(t *testing.T) {
		e := sampleEnvelope()
		e.WorkspaceID = "Platform"
		require.ErrorIs(t, e.Validate(), ErrBadIdentifier)
	})

	t.Run("optional identifier with a dot", func(t *testing.T) {
		e := sampleEnvelope()
		e.ActivityID = ptr(Identifier("a.b"))
		require.ErrorIs(t, e.Validate(), ErrBadIdentifier)
	})

	t.Run("delegation id with a wildcard", func(t *testing.T) {
		e := sampleEnvelope()
		e.DelegationChain = []string{"ok", "not>ok"}
		require.ErrorIs(t, e.Validate(), ErrBadIdentifier)
	})
}

// TestValidateIgnoresUnknownEnvelopeFields is the other half of the MINOR rule:
// an unknown optional field must survive a decode, not fail one.
func TestValidateIgnoresUnknownEnvelopeFields(t *testing.T) {
	e := sampleEnvelope()
	raw, err := e.Marshal()
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	fields["introduced_in_1_1"] = json.RawMessage(`"value"`)
	extended, err := json.Marshal(fields)
	require.NoError(t, err)

	decoded, err := Unmarshal(extended)
	require.NoError(t, err)
	require.NoError(t, decoded.Validate())
}

func TestEveryEventTypeHasACompiledPayloadSchema(t *testing.T) {
	set, err := compiled()
	require.NoError(t, err)

	for _, eventType := range AllEventTypes() {
		require.Contains(t, set.payloads, eventType)

		path, err := SchemaPathFor(eventType)
		require.NoError(t, err)
		require.Equal(t, "schemas/payload/"+eventType.String()+".json", path)

		_, err = SchemaFS().Open(path)
		require.NoError(t, err, "the embedded tree must contain %s", path)
	}
}

func TestSchemaPathForRejectsAnUnknownType(t *testing.T) {
	_, err := SchemaPathFor("chat.whisper")
	require.ErrorIs(t, err, ErrUnknownEventType)
}
