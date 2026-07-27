package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
)

const (
	fixtureDir      = "fixtures"
	validFixtureDir = fixtureDir + "/valid"
	badFixtureDir   = fixtureDir + "/invalid"
	signingDir      = fixtureDir + "/signing"

	// fixtureKeyMaterial derives the conformance signing key. A fixed input
	// keeps the key, and therefore every published vector, reproducible: Ed25519
	// signing is deterministic, so regenerating produces byte-identical output.
	fixtureKeyMaterial = "observerloop.protocol.fixtures.v1"
)

// embeddedFixtureDir is the verbatim mirror of fixtureDir inside the Go module.
//
// The corpus is part of the contract, not scaffolding for this repository's own
// tests: a consumer that has the module but cannot run the vectors has half of
// what the module is for. Go's embed directive cannot reach outside its own
// module directory and the module lives in go/, so the corpus is copied rather
// than referenced — the same arrangement, for the same reason, as the schema
// tree. The copy is generated, and `make generate` plus `git diff --exit-code`
// is what keeps it identical to the source.
//
// It lives beside the conformance runner rather than in go/protocol because
// go/protocol is linked into every consumer's production binary and the corpus
// is only ever needed by tests. Nothing that imports the wire binding pays for
// it.
var embeddedFixtureDir = filepath.Join("go", "conformance", fixtureDir)

// genFixtures writes the coverage manifest and the cross-language Ed25519
// signing vectors. The fixture envelopes themselves are hand-written; only the
// signatures over them, and the index of what covers what, are generated.
func genFixtures(root string, reg *registry) error {
	valid, err := readFixtures(filepath.Join(root, validFixtureDir))
	if err != nil {
		return err
	}
	invalid, err := readFixtures(filepath.Join(root, badFixtureDir))
	if err != nil {
		return err
	}

	index, err := indexValidFixtures(reg, valid)
	if err != nil {
		return err
	}
	invalidEntries, err := describeInvalidFixtures(invalid)
	if err != nil {
		return err
	}

	if err := writeManifest(root, reg, index, invalidEntries); err != nil {
		return err
	}
	if err := writeSigningVectors(root, valid); err != nil {
		return err
	}

	// Last, and it must stay last: the mirror copies what the steps above have
	// just written, so a mirror taken before them would publish the previous
	// run's manifest and vectors.
	return mirrorFixtures(root)
}

// mirrorFixtures copies the fixture tree into the Go module and deletes
// anything there the source no longer contains, so a fixture that is renamed or
// withdrawn cannot survive in the embedded copy.
func mirrorFixtures(root string) error {
	base := filepath.Join(root, fixtureDir)
	want := map[string]bool{}

	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return fmt.Errorf("relativising %s: %w", p, err)
		}
		//nolint:gosec // p comes from walking the fixture directory under -root
		body, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading %s: %w", p, err)
		}
		want[path.Clean(filepath.ToSlash(rel))] = true
		return writeFile(filepath.Join(root, embeddedFixtureDir, rel), body)
	})
	if err != nil {
		return fmt.Errorf("walking %s: %w", fixtureDir, err)
	}

	mirror := filepath.Join(root, embeddedFixtureDir)
	return filepath.WalkDir(mirror, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(mirror, p)
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

// fixture is one fixture file: its name without extension, and its bytes.
type fixture struct {
	name string
	body []byte
}

func readFixtures(dir string) ([]fixture, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	out := make([]fixture, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		//nolint:gosec // dir is composed from the -root flag and generator constants
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		out = append(out, fixture{name: strings.TrimSuffix(entry.Name(), ".json"), body: body})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// indexValidFixtures maps each event type to the fixtures that exercise it, and
// fails when the registry and the fixture set disagree. A registry entry with no
// fixture is an untested event type.
func indexValidFixtures(reg *registry, fixtures []fixture) (map[string][]string, error) {
	known := map[string]bool{}
	for _, e := range reg.Events {
		known[e.Type] = true
	}

	index := map[string][]string{}
	for _, f := range fixtures {
		envelope, err := decodeEnvelope(f.body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		eventType, err := stringField(envelope, "event_type")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		if !known[eventType] {
			return nil, fmt.Errorf("%s has event_type %q, which is in no registry entry", f.name, eventType)
		}
		if err := checkFixtureIdentifiers(envelope); err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		index[eventType] = append(index[eventType], validFixtureDir+"/"+f.name+".json")
	}

	for _, e := range reg.Events {
		if len(index[e.Type]) == 0 {
			return nil, fmt.Errorf("event %q has no fixture in %s", e.Type, validFixtureDir)
		}
	}
	return index, nil
}

// checkFixtureIdentifiers asserts the identifiers a fixture publishes are real
// UUIDv7 values where the specification says they must be, so a hand-written
// fixture cannot quietly teach a consumer the wrong shape.
func checkFixtureIdentifiers(envelope map[string]json.RawMessage) error {
	for _, field := range []string{"event_id", "correlation_id"} {
		value, err := stringField(envelope, field)
		if err != nil {
			return err
		}
		parsed, err := uuid.Parse(value)
		if err != nil {
			return fmt.Errorf("%s %q is not a UUID: %w", field, value, err)
		}
		if parsed.Version() != 7 {
			return fmt.Errorf("%s %q is UUIDv%d, expected v7", field, value, parsed.Version())
		}
	}
	return nil
}

type manifestInvalid struct {
	Fixture string `json:"fixture"`
	Reason  string `json:"reason"`
}

func describeInvalidFixtures(fixtures []fixture) ([]manifestInvalid, error) {
	out := make([]manifestInvalid, 0, len(fixtures))
	for _, f := range fixtures {
		var doc struct {
			Reason   string          `json:"reason"`
			Envelope json.RawMessage `json:"envelope"`
		}
		if err := json.Unmarshal(f.body, &doc); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", f.name, err)
		}
		if doc.Reason == "" {
			return nil, fmt.Errorf("%s has no reason; an invalid fixture must say what is wrong with it", f.name)
		}
		if len(doc.Envelope) == 0 {
			return nil, fmt.Errorf("%s has no envelope", f.name)
		}
		out = append(out, manifestInvalid{Fixture: badFixtureDir + "/" + f.name + ".json", Reason: doc.Reason})
	}
	return out, nil
}

type manifestEvent struct {
	Type         string   `json:"type"`
	Schema       string   `json:"schema"`
	SubjectClass string   `json:"subject_class"`
	Durability   string   `json:"durability"`
	TrustDomains []string `json:"trust_domains"`
	Capabilities []string `json:"capabilities"`
	Fixtures     []string `json:"fixtures"`
}

type manifestDoc struct {
	Version        string            `json:"version"`
	Events         []manifestEvent   `json:"events"`
	Invalid        []manifestInvalid `json:"invalid"`
	SigningKey     string            `json:"signing_key"`
	SigningVectors string            `json:"signing_vectors"`
}

func writeManifest(root string, reg *registry, index map[string][]string, invalid []manifestInvalid) error {
	doc := manifestDoc{
		Version:        reg.Version,
		Events:         make([]manifestEvent, 0, len(reg.Events)),
		Invalid:        invalid,
		SigningKey:     signingDir + "/key.json",
		SigningVectors: signingDir + "/vectors.json",
	}
	for _, e := range reg.Events {
		fixtures := append([]string(nil), index[e.Type]...)
		sort.Strings(fixtures)
		doc.Events = append(doc.Events, manifestEvent{
			Type:         e.Type,
			Schema:       e.Schema,
			SubjectClass: e.SubjectClass,
			Durability:   e.Durability,
			TrustDomains: e.TrustDomains,
			Capabilities: e.Capabilities,
			Fixtures:     fixtures,
		})
	}
	return writeJSON(filepath.Join(root, fixtureDir, "manifest.json"), doc)
}

type signingKeyDoc struct {
	Algorithm string `json:"algorithm"`
	Seed      string `json:"seed_base64url"`
	PublicKey string `json:"public_key_base64url"`
	KeyID     string `json:"key_id"`
	Note      string `json:"note"`
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

func writeSigningVectors(root string, fixtures []fixture) error {
	seed := sha256.Sum256([]byte(fixtureKeyMaterial))
	private := ed25519.NewKeyFromSeed(seed[:])
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("deriving the fixture public key")
	}
	keyID := keyIDFor(public)

	key := signingKeyDoc{
		Algorithm: "ed25519",
		Seed:      base64.RawURLEncoding.EncodeToString(seed[:]),
		PublicKey: base64.RawURLEncoding.EncodeToString(public),
		KeyID:     keyID,
		Note: "Conformance key only. Derived from the SHA-256 of " + fixtureKeyMaterial +
			", so every vector is reproducible. It signs nothing outside this repository.",
	}
	if err := writeJSON(filepath.Join(root, signingDir, "key.json"), key); err != nil {
		return err
	}

	vectors := make([]signingVector, 0, len(fixtures))
	for _, f := range fixtures {
		envelope, err := decodeEnvelope(f.body)
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		signer, err := stringField(envelope, "signer_key_id")
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		if signer != keyID {
			return fmt.Errorf("%s has signer_key_id %q, expected the fixture key %q", f.name, signer, keyID)
		}
		eventType, err := stringField(envelope, "event_type")
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}

		// The canonical form is computed from the fixture bytes directly rather
		// than through the Go envelope type, so the vectors are an independent
		// statement about the wire format that the binding is then tested
		// against, not a restatement of the binding.
		canonical, err := canonicalWithoutSignature(envelope)
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		signature := ed25519.Sign(private, canonical)
		digest := sha256.Sum256(canonical)

		envelope["signature"] = mustQuote(base64.RawURLEncoding.EncodeToString(signature))
		signed, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("%s: encoding the signed envelope: %w", f.name, err)
		}

		vectors = append(vectors, signingVector{
			Name:      f.name,
			Fixture:   validFixtureDir + "/" + f.name + ".json",
			EventType: eventType,
			Canonical: base64.StdEncoding.EncodeToString(canonical),
			Digest:    fmt.Sprintf("%x", digest),
			Signature: base64.RawURLEncoding.EncodeToString(signature),
			Envelope:  signed,
		})
	}

	return writeJSON(filepath.Join(root, signingDir, "vectors.json"), vectors)
}

// keyIDFor is the identifier form used throughout the protocol: base32-nopad
// over the SHA-256 of the public key.
func keyIDFor(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
}

func canonicalWithoutSignature(envelope map[string]json.RawMessage) ([]byte, error) {
	unsigned := make(map[string]json.RawMessage, len(envelope))
	for name, value := range envelope {
		if name == "signature" {
			continue
		}
		unsigned[name] = value
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("encoding the signing form: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing: %w", err)
	}
	return canonical, nil
}

func decodeEnvelope(body []byte) (map[string]json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}
	return envelope, nil
}

func stringField(envelope map[string]json.RawMessage, name string) (string, error) {
	raw, ok := envelope[name]
	if !ok {
		return "", fmt.Errorf("has no %s", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s is not a string: %w", name, err)
	}
	return value, nil
}

func mustQuote(s string) json.RawMessage {
	quoted, err := json.Marshal(s)
	if err != nil {
		panic(err) // a Go string always encodes
	}
	return quoted
}

func writeJSON(path string, doc any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	return writeFile(path, buffer.Bytes())
}
