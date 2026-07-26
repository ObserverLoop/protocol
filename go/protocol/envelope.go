package protocol

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// timestampLayout is RFC 3339 UTC at exactly millisecond precision. Fixed
// precision matters: the timestamp is inside the canonical form that is signed,
// and Go's default time encoding elides trailing zero fractions, which would
// make two logically identical envelopes produce two different signatures.
const timestampLayout = "2006-01-02T15:04:05.000Z"

// signatureField is the one field excluded from the signing form.
const signatureField = "signature"

// Envelope is the signed unit of the protocol. Field order matches the
// specification; the wire encoding is key-sorted, because RFC 8785 sorts.
type Envelope struct {
	ProtocolVersion        string          `json:"protocol_version"`
	EventID                Identifier      `json:"event_id"`
	EventType              EventType       `json:"event_type"`
	TrustDomain            TrustDomain     `json:"trust_domain"`
	TenantID               Identifier      `json:"tenant_id"`
	WorkspaceID            Identifier      `json:"workspace_id"`
	ThreadID               *Identifier     `json:"thread_id,omitempty"`
	ActivityID             *Identifier     `json:"activity_id,omitempty"`
	SourceConductorID      *Identifier     `json:"source_conductor_id,omitempty"`
	ConductorEpoch         *int64          `json:"conductor_epoch,omitempty"`
	SourceAgentID          *Identifier     `json:"source_agent_id,omitempty"`
	DestinationConductorID *Identifier     `json:"destination_conductor_id,omitempty"`
	DestinationAgentID     *Identifier     `json:"destination_agent_id,omitempty"`
	DefinitionDigest       *string         `json:"definition_digest,omitempty"`
	OccurredAt             time.Time       `json:"occurred_at"`
	Sequence               int64           `json:"sequence"`
	CorrelationID          Identifier      `json:"correlation_id"`
	CausationID            *Identifier     `json:"causation_id,omitempty"`
	ExpiresAt              *time.Time      `json:"expires_at,omitempty"`
	Payload                json.RawMessage `json:"payload"`
	SignerKeyID            string          `json:"signer_key_id"`
	DelegationChain        []string        `json:"delegation_chain"`
	Signature              string          `json:"signature"`

	// extra holds fields this binding does not know about. A newer MINOR may
	// add optional fields, and they must survive a decode-encode cycle intact:
	// dropping them would change the canonical form and invalidate a signature
	// this binding never had any business invalidating.
	extra map[string]json.RawMessage
}

// knownFields is the set of JSON names the struct itself declares, derived from
// the struct tags so the two can never disagree.
var knownFields = func() map[string]struct{} {
	fields := reflect.VisibleFields(reflect.TypeOf(Envelope{}))
	out := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out[name] = struct{}{}
		}
	}
	return out
}()

// MarshalJSON encodes the envelope with timestamps normalised to UTC at
// millisecond precision. Every other field is encoded from its struct tag, so
// the field set is declared exactly once.
func (e Envelope) MarshalJSON() ([]byte, error) {
	// The alias sheds this method, so json.Marshal does not recurse.
	type alias Envelope

	raw, err := json.Marshal(alias(e))
	if err != nil {
		return nil, fmt.Errorf("encoding envelope: %w", err)
	}

	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("re-reading encoded envelope: %w", err)
	}

	for name, value := range e.extra {
		fields[name] = value
	}

	fields["occurred_at"] = encodeTimestamp(e.OccurredAt)
	if e.ExpiresAt != nil {
		fields["expires_at"] = encodeTimestamp(*e.ExpiresAt)
	}
	if e.DelegationChain == nil {
		// The field is required and is an empty list for a root signer; a nil
		// slice would encode as null and fail the envelope schema.
		fields["delegation_chain"] = json.RawMessage("[]")
	}

	out, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encoding envelope: %w", err)
	}
	return out, nil
}

func encodeTimestamp(t time.Time) json.RawMessage {
	return json.RawMessage(`"` + t.UTC().Format(timestampLayout) + `"`)
}

// UnmarshalJSON decodes a wire envelope, keeps any field this binding does not
// know about, and rejects a timestamp that is not exactly RFC 3339 UTC at
// millisecond precision. The strictness is deliberate: Go's time decoder would
// happily accept a coarser or finer form, re-encode it in the canonical one,
// and produce signing bytes that differ from the bytes the signer signed.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	// The alias sheds this method, so json.Unmarshal does not recurse.
	type alias Envelope

	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("decoding envelope: %w", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decoding envelope: %w", err)
	}

	for _, name := range []string{"occurred_at", "expires_at"} {
		raw, present := fields[name]
		if !present {
			continue
		}
		if err := checkTimestamp(raw); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	for name := range knownFields {
		delete(fields, name)
	}

	*e = Envelope(decoded)
	if len(fields) > 0 {
		e.extra = fields
	}
	return nil
}

func checkTimestamp(raw json.RawMessage) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("%w: not a string", ErrSchemaViolation)
	}
	if _, err := time.Parse(timestampLayout, text); err != nil {
		return fmt.Errorf("%w: %q is not RFC 3339 UTC at millisecond precision", ErrSchemaViolation, text)
	}
	return nil
}

// Marshal encodes the envelope for the wire.
func (e *Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

// Unmarshal decodes a wire envelope. It does not validate: call Validate.
func Unmarshal(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("decoding envelope: %w", err)
	}
	return &e, nil
}

// SigningBytes returns the RFC 8785 canonical form of the envelope with
// signature omitted. This is the exact byte sequence that is signed and
// verified; nothing else may be signed.
func (e *Envelope) SigningBytes() ([]byte, error) {
	raw, err := e.Marshal()
	if err != nil {
		return nil, err
	}

	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("re-reading encoded envelope: %w", err)
	}
	delete(fields, signatureField)

	unsigned, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encoding signing form: %w", err)
	}
	return Canonicalize(unsigned)
}
