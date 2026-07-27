package conformance

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
)

// fixtures is the conformance corpus, mirrored into this package by
// cmd/protoc-registry so that embed can reach it. Paths inside it are exactly
// the paths the manifest names — "fixtures/valid/chat.message.agent.json" and
// so on — so a manifest entry can be opened against it without rewriting.
//
//go:embed fixtures
var fixtures embed.FS

// FS returns the conformance corpus: the manifest, the valid and invalid
// envelope fixtures, and the signing vectors.
//
// It is the whole contract, available to anyone who has the module. A consumer
// does not need this repository checked out, does not need to know where the
// module cache put it, and cannot be broken by a relative path that was correct
// on one machine.
func FS() fs.FS { return fixtures }

// SigningKey is the conformance signing key from fixtures/signing/key.json.
//
// It signs nothing outside the corpus. It is derived from a published seed
// precisely so that any implementation can reproduce the vectors rather than
// take them on trust.
type SigningKey struct {
	// Algorithm is always "ed25519" in this revision.
	Algorithm string
	// Seed is the 32-byte Ed25519 seed the key is derived from.
	Seed []byte
	// PublicKey is the 32-byte Ed25519 public key the seed derives.
	PublicKey []byte
	// KeyID is the identifier form the protocol uses: base32-nopad over the
	// SHA-256 of PublicKey.
	KeyID string
}

// SigningVector is one entry of fixtures/signing/vectors.json: an envelope, the
// exact bytes it was signed over, and the signature.
type SigningVector struct {
	// Name identifies the vector, and is the fixture's file name without its
	// extension.
	Name string
	// Fixture is the corpus path of the envelope this vector was built from.
	Fixture string
	// EventType is the envelope's event type.
	EventType string
	// Canonical is the exact byte sequence the signature covers. An
	// implementation's own canonicalisation must reproduce it.
	Canonical []byte
	// Digest is the hex SHA-256 of Canonical.
	Digest string
	// Signature is base64url-unpadded, as it appears in the envelope, so it can
	// be compared against a signed envelope's field without re-encoding.
	Signature string
	// Envelope is the signed envelope, as published.
	Envelope json.RawMessage
}

// Signing returns the conformance signing key and every vector.
//
// The two are returned together because neither is usable without the other:
// verifying a vector needs the key, and the key alone asserts nothing.
func Signing() (SigningKey, []SigningVector, error) {
	var manifest struct {
		SigningKey     string `json:"signing_key"`
		SigningVectors string `json:"signing_vectors"`
	}
	if err := readJSON("fixtures/manifest.json", &manifest); err != nil {
		return SigningKey{}, nil, err
	}

	var keyDoc struct {
		Algorithm string `json:"algorithm"`
		Seed      string `json:"seed_base64url"`
		PublicKey string `json:"public_key_base64url"`
		KeyID     string `json:"key_id"`
	}
	if err := readJSON(manifest.SigningKey, &keyDoc); err != nil {
		return SigningKey{}, nil, err
	}

	seed, err := base64.RawURLEncoding.DecodeString(keyDoc.Seed)
	if err != nil {
		return SigningKey{}, nil, fmt.Errorf("decoding the signing key seed: %w", err)
	}
	public, err := base64.RawURLEncoding.DecodeString(keyDoc.PublicKey)
	if err != nil {
		return SigningKey{}, nil, fmt.Errorf("decoding the signing key: %w", err)
	}

	var vectorDocs []struct {
		Name      string          `json:"name"`
		Fixture   string          `json:"fixture"`
		EventType string          `json:"event_type"`
		Canonical string          `json:"canonical_base64"`
		Digest    string          `json:"canonical_sha256"`
		Signature string          `json:"signature"`
		Envelope  json.RawMessage `json:"envelope"`
	}
	if err := readJSON(manifest.SigningVectors, &vectorDocs); err != nil {
		return SigningKey{}, nil, err
	}

	vectors := make([]SigningVector, 0, len(vectorDocs))
	for _, doc := range vectorDocs {
		canonical, err := base64.StdEncoding.DecodeString(doc.Canonical)
		if err != nil {
			return SigningKey{}, nil, fmt.Errorf("decoding the canonical bytes of %s: %w", doc.Name, err)
		}
		vectors = append(vectors, SigningVector{
			Name:      doc.Name,
			Fixture:   doc.Fixture,
			EventType: doc.EventType,
			Canonical: canonical,
			Digest:    doc.Digest,
			Signature: doc.Signature,
			Envelope:  doc.Envelope,
		})
	}

	return SigningKey{
		Algorithm: keyDoc.Algorithm,
		Seed:      seed,
		PublicKey: public,
		KeyID:     keyDoc.KeyID,
	}, vectors, nil
}

// readJSON decodes one corpus file.
func readJSON(name string, into any) error {
	body, err := fs.ReadFile(fixtures, name)
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("decoding %s: %w", name, err)
	}
	return nil
}
