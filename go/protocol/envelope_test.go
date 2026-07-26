package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// sampleEnvelope is a minimal valid chat.message envelope. Tests mutate a copy.
func sampleEnvelope() Envelope {
	return Envelope{
		ProtocolVersion: ProtocolVersion,
		EventID:         "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e21",
		EventType:       EventChatMessage,
		TrustDomain:     TrustDomainTenant,
		TenantID:        "acme",
		WorkspaceID:     "platform",
		ThreadID:        ptr(Identifier("0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e22")),
		OccurredAt:      time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		Sequence:        1,
		CorrelationID:   "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e23",
		Payload:         json.RawMessage(`{"role":"human","text":"ship it"}`),
		SignerKeyID:     strings.Repeat("A", 52),
		DelegationChain: []string{},
		Signature:       strings.Repeat("a", 86),
	}
}

func ptr[T any](v T) *T { return &v }

func TestEnvelopeTimestampsAreMillisecondPrecision(t *testing.T) {
	e := sampleEnvelope()
	// A sub-millisecond component and a non-UTC zone must both be normalised,
	// or two logically identical envelopes would sign to different bytes.
	e.OccurredAt = time.Date(2026, 7, 26, 14, 0, 0, 123456789, time.FixedZone("CEST", 2*3600))
	e.ExpiresAt = ptr(time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC))

	raw, err := e.Marshal()
	require.NoError(t, err)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, "2026-07-26T12:00:00.123Z", fields["occurred_at"])
	require.Equal(t, "2026-07-27T14:00:00.000Z", fields["expires_at"], "a zero fraction must still be written")
}

func TestEnvelopeRoundTrip(t *testing.T) {
	e := sampleEnvelope()
	e.ExpiresAt = ptr(time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC))
	e.ConductorEpoch = ptr(int64(7))
	e.SourceConductorID = ptr(Identifier("0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e24"))

	raw, err := e.Marshal()
	require.NoError(t, err)

	decoded, err := Unmarshal(raw)
	require.NoError(t, err)

	again, err := decoded.Marshal()
	require.NoError(t, err)
	require.Equal(t, string(raw), string(again))
}

func TestSigningBytesOmitsSignature(t *testing.T) {
	e := sampleEnvelope()

	signing, err := e.SigningBytes()
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(signing, &fields))
	require.NotContains(t, fields, "signature")
	require.Contains(t, fields, "payload")
	require.Len(t, fields, 13, "every other field survives")
}

func TestSigningBytesIgnoresTheSignatureValue(t *testing.T) {
	// This is the property that makes verification possible: the bytes signed
	// cannot depend on the signature that is about to be attached.
	unsigned := sampleEnvelope()
	unsigned.Signature = ""

	signed := sampleEnvelope()
	signed.Signature = strings.Repeat("z", 86)

	a, err := unsigned.SigningBytes()
	require.NoError(t, err)
	b, err := signed.SigningBytes()
	require.NoError(t, err)
	require.Equal(t, string(a), string(b))
}

func TestSigningBytesAreCanonical(t *testing.T) {
	e := sampleEnvelope()

	signing, err := e.SigningBytes()
	require.NoError(t, err)

	// RFC 8785 sorts object keys and emits no insignificant whitespace. The
	// only space in the output is inside a string value.
	require.NotContains(t, string(signing), `: `)
	require.NotContains(t, string(signing), `, `)
	require.NotContains(t, string(signing), "\n")
	require.True(t, strings.HasPrefix(string(signing), `{"correlation_id":`), string(signing))

	// It is idempotent: canonicalising the canonical form changes nothing.
	again, err := Canonicalize(signing)
	require.NoError(t, err)
	require.Equal(t, string(signing), string(again))
}

func TestSigningBytesAreStableAcrossEncodings(t *testing.T) {
	e := sampleEnvelope()
	// Payload with reordered keys and insignificant whitespace must produce the
	// same signing bytes, or a forwarder would invalidate a signature.
	e.Payload = json.RawMessage(`{ "text" : "ship it",  "role":"human" }`)

	a, err := e.SigningBytes()
	require.NoError(t, err)

	e.Payload = json.RawMessage(`{"role":"human","text":"ship it"}`)
	b, err := e.SigningBytes()
	require.NoError(t, err)

	require.Equal(t, string(a), string(b))
}

func TestMarshalWritesEmptyDelegationChainForARootSigner(t *testing.T) {
	e := sampleEnvelope()
	e.DelegationChain = nil

	raw, err := e.Marshal()
	require.NoError(t, err)
	require.Contains(t, string(raw), `"delegation_chain":[]`)
	require.NoError(t, e.Validate())
}

// TestUnknownFieldsSurviveARoundTrip is what makes forwarding without
// re-signing possible: a field added by a newer MINOR must come back out
// byte-identical, or the canonical form changes and the signature dies.
func TestUnknownFieldsSurviveARoundTrip(t *testing.T) {
	e := sampleEnvelope()
	raw, err := e.Marshal()
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	fields["introduced_in_1_1"] = json.RawMessage(`{"nested":[1,2,3]}`)
	extended, err := json.Marshal(fields)
	require.NoError(t, err)

	decoded, err := Unmarshal(extended)
	require.NoError(t, err)

	again, err := decoded.Marshal()
	require.NoError(t, err)
	require.JSONEq(t, string(extended), string(again))

	// And therefore the signing bytes are unchanged by the round trip.
	before, err := Canonicalize(withoutSignature(t, extended))
	require.NoError(t, err)
	after, err := decoded.SigningBytes()
	require.NoError(t, err)
	require.Equal(t, string(before), string(after))
}

func withoutSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	delete(fields, "signature")
	out, err := json.Marshal(fields)
	require.NoError(t, err)
	return out
}

func TestUnmarshalRejectsATimestampThatIsNotMillisecondPrecision(t *testing.T) {
	rejected := map[string]string{
		"no fraction":         "2026-07-26T12:00:00Z",
		"microseconds":        "2026-07-26T12:00:00.123456Z",
		"offset instead of Z": "2026-07-26T14:00:00.000+02:00",
		"not a timestamp":     "yesterday",
	}
	for name, value := range rejected {
		t.Run(name, func(t *testing.T) {
			e := sampleEnvelope()
			raw, err := e.Marshal()
			require.NoError(t, err)

			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &fields))
			encoded, err := json.Marshal(value)
			require.NoError(t, err)
			fields["occurred_at"] = encoded
			mutated, err := json.Marshal(fields)
			require.NoError(t, err)

			_, err = Unmarshal(mutated)
			require.Error(t, err)
		})
	}
}
