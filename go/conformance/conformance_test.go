package conformance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ObserverLoop/protocol/go/protocol"
)

// repoRoot is two levels above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(root, "registry.yaml"))
	return root
}

func read(t *testing.T, root, rel string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	require.NoError(t, err)
	return body
}

type manifestDoc struct {
	Version string `json:"version"`
	Events  []struct {
		Type         string   `json:"type"`
		Schema       string   `json:"schema"`
		Durability   string   `json:"durability"`
		TrustDomains []string `json:"trust_domains"`
		Capabilities []string `json:"capabilities"`
		Fixtures     []string `json:"fixtures"`
	} `json:"events"`
	Invalid []struct {
		Fixture string `json:"fixture"`
		Reason  string `json:"reason"`
	} `json:"invalid"`
	SigningKey     string `json:"signing_key"`
	SigningVectors string `json:"signing_vectors"`
}

func loadManifest(t *testing.T, root string) manifestDoc {
	t.Helper()
	var doc manifestDoc
	require.NoError(t, json.Unmarshal(read(t, root, "fixtures/manifest.json"), &doc))
	require.NotEmpty(t, doc.Events)
	return doc
}

// TestManifestMatchesTheBinding is the first thing to fail if the registry and
// the compiled binding ever diverge.
func TestManifestMatchesTheBinding(t *testing.T) {
	root := repoRoot(t)
	manifest := loadManifest(t, root)

	require.Equal(t, protocol.ProtocolVersion, manifest.Version)
	require.Len(t, manifest.Events, len(protocol.AllEventTypes()))

	for _, event := range manifest.Events {
		eventType, ok := protocol.ParseEventType(event.Type)
		require.True(t, ok, event.Type)

		schema, err := protocol.SchemaPathFor(eventType)
		require.NoError(t, err)
		require.Equal(t, event.Schema, schema)

		require.Equal(t, protocol.Durability(event.Durability), protocol.DurabilityFor(eventType))

		domains := make([]string, 0, len(event.TrustDomains))
		for _, d := range protocol.TrustDomainsFor(eventType) {
			domains = append(domains, string(d))
		}
		require.Equal(t, event.TrustDomains, domains, event.Type)

		capabilities := make([]string, 0, len(event.Capabilities))
		for _, c := range protocol.CapabilitiesFor(eventType) {
			capabilities = append(capabilities, string(c))
		}
		require.Equal(t, event.Capabilities, capabilities, event.Type)

		require.NotEmpty(t, event.Fixtures, "%s has no fixture", event.Type)
	}
}

// TestValidFixtures is the positive half of the contract: every published
// fixture must decode, validate, and survive a round trip unchanged.
func TestValidFixtures(t *testing.T) {
	root := repoRoot(t)
	manifest := loadManifest(t, root)

	seen := 0
	for _, event := range manifest.Events {
		for _, path := range event.Fixtures {
			t.Run(path, func(t *testing.T) {
				body := read(t, root, path)

				envelope, err := protocol.Unmarshal(body)
				require.NoError(t, err)
				require.NoError(t, envelope.Validate())
				require.Equal(t, event.Type, envelope.EventType.String())

				// Re-encoding must reproduce the fixture exactly, or a
				// forwarder would break the signature over it.
				again, err := envelope.Marshal()
				require.NoError(t, err)
				require.JSONEq(t, string(body), string(again))
			})
			seen++
		}
	}
	require.GreaterOrEqual(t, seen, len(protocol.AllEventTypes()))
}

// TestInvalidFixtures is the negative half. A binding that accepts any of these
// is not conformant, and the reason field says exactly what it failed to catch.
func TestInvalidFixtures(t *testing.T) {
	root := repoRoot(t)
	manifest := loadManifest(t, root)
	require.NotEmpty(t, manifest.Invalid)

	var rejectedByDecode, rejectedByValidate int
	for _, entry := range manifest.Invalid {
		t.Run(entry.Fixture, func(t *testing.T) {
			var doc struct {
				Reason   string          `json:"reason"`
				Envelope json.RawMessage `json:"envelope"`
			}
			require.NoError(t, json.Unmarshal(read(t, root, entry.Fixture), &doc))
			require.Equal(t, entry.Reason, doc.Reason)

			// Rejection may happen at either gate: a malformed wire form fails
			// to decode, a well-formed but illegal one fails to validate.
			envelope, err := protocol.Unmarshal(doc.Envelope)
			if err != nil {
				rejectedByDecode++
				return
			}
			require.Error(t, envelope.Validate(), "must be rejected: %s", doc.Reason)
			rejectedByValidate++
		})
	}

	// Both gates must actually be exercised. A suite where everything failed at
	// one gate would pass while proving nothing about the other.
	require.Positive(t, rejectedByDecode, "no fixture exercises rejection at decode")
	require.Positive(t, rejectedByValidate, "no fixture exercises rejection at validation")
	require.Equal(t, len(manifest.Invalid), rejectedByDecode+rejectedByValidate)
}

type signingKeyDoc struct {
	Algorithm string `json:"algorithm"`
	Seed      string `json:"seed_base64url"`
	PublicKey string `json:"public_key_base64url"`
	KeyID     string `json:"key_id"`
}

type signingVector struct {
	Name      string          `json:"name"`
	Fixture   string          `json:"fixture"`
	EventType string          `json:"event_type"`
	Canonical string          `json:"canonical_base64"`
	Digest    string          `json:"canonical_sha256"`
	Signature string          `json:"signature"`
	Envelope  json.RawMessage `json:"envelope"`
}

// TestSigningVectors is the cross-language contract. Every assertion here is
// one a binding in another language must also be able to make, using the same
// files and nothing else.
func TestSigningVectors(t *testing.T) {
	root := repoRoot(t)
	manifest := loadManifest(t, root)

	var key signingKeyDoc
	require.NoError(t, json.Unmarshal(read(t, root, manifest.SigningKey), &key))
	require.Equal(t, "ed25519", key.Algorithm)

	public, err := base64.RawURLEncoding.DecodeString(key.PublicKey)
	require.NoError(t, err)
	require.Len(t, public, ed25519.PublicKeySize)

	seed, err := base64.RawURLEncoding.DecodeString(key.Seed)
	require.NoError(t, err)
	require.Equal(t, ed25519.PublicKey(public), ed25519.NewKeyFromSeed(seed).Public(),
		"the published public key must be the one the published seed derives")

	var vectors []signingVector
	require.NoError(t, json.Unmarshal(read(t, root, manifest.SigningVectors), &vectors))
	require.NotEmpty(t, vectors)

	covered := map[string]bool{}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := base64.StdEncoding.DecodeString(vector.Canonical)
			require.NoError(t, err)

			digest := sha256.Sum256(canonical)
			require.Equal(t, vector.Digest, hex(digest[:]),
				"the published digest must cover the published canonical bytes")

			signature, err := base64.RawURLEncoding.DecodeString(vector.Signature)
			require.NoError(t, err)
			require.Len(t, signature, ed25519.SignatureSize)
			require.True(t, ed25519.Verify(public, canonical, signature),
				"the signature must verify over exactly the published bytes")

			// The binding must reproduce those bytes from the envelope alone.
			envelope, err := protocol.Unmarshal(vector.Envelope)
			require.NoError(t, err)
			require.NoError(t, envelope.Validate())
			require.Equal(t, vector.EventType, envelope.EventType.String())
			require.Equal(t, vector.Signature, envelope.Signature)

			signing, err := envelope.SigningBytes()
			require.NoError(t, err)
			require.Equal(t, string(canonical), string(signing),
				"SigningBytes must equal the canonical form the vector was signed over")

			// And a tampered envelope must not verify, or the vector would
			// prove nothing about integrity.
			tampered := *envelope
			tampered.Sequence++
			tamperedBytes, err := tampered.SigningBytes()
			require.NoError(t, err)
			require.False(t, ed25519.Verify(public, tamperedBytes, signature))
		})
		covered[vector.EventType] = true
	}

	for _, eventType := range protocol.AllEventTypes() {
		require.True(t, covered[eventType.String()], "%s has no signing vector", eventType)
	}
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// TestEmbeddedSchemasMatchTheSource closes the gap the module layout opens: the
// Go binding validates against a copy of schemas/, so the copy must be byte
// identical to the source. Every property asserted about the source - closed
// payload roots, no reasoning property - then holds for what actually runs.
func TestEmbeddedSchemasMatchTheSource(t *testing.T) {
	root := repoRoot(t)
	embedded := protocol.SchemaFS()

	count := 0
	require.NoError(t, fs.WalkDir(embedded, "schemas", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(embedded, path)
		require.NoError(t, err)
		require.Equal(t, string(read(t, root, path)), string(body), path)
		count++
		return nil
	}))

	// And nothing on disk is missing from the copy.
	onDisk := 0
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "schemas"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		onDisk++
		return nil
	}))
	require.Equal(t, onDisk, count)
}

// TestSubjectsBuildForEveryFixture ties the fixtures to the subject grammar:
// an envelope that cannot be addressed cannot be published.
func TestSubjectsBuildForEveryFixture(t *testing.T) {
	root := repoRoot(t)
	manifest := loadManifest(t, root)

	for _, event := range manifest.Events {
		for _, path := range event.Fixtures {
			envelope, err := protocol.Unmarshal(read(t, root, path))
			require.NoError(t, err)

			params := protocol.SubjectParams{
				TenantID:    envelope.TenantID,
				WorkspaceID: envelope.WorkspaceID,
				ConductorID: "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e93",
				CommandID:   "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e83",
				AgentID:     "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e92",
			}
			if envelope.ThreadID != nil {
				params.ThreadID = *envelope.ThreadID
			}

			subject, err := protocol.SubjectFor(envelope.EventType, params)
			require.NoError(t, err, path)

			gotType, _, err := protocol.ParseSubject(subject)
			require.NoError(t, err, subject)
			require.Equal(t, envelope.EventType, gotType)
		}
	}
}
