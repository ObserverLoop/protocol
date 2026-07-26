package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// splitVersion parses the registry's MAJOR.MINOR version. The registry schema
// has already constrained its shape.
func splitVersion(version string) (major, minor int, err error) {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("version %q is not MAJOR.MINOR", version)
	}
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, fmt.Errorf("version %q major: %w", version, err)
	}
	if minor, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, fmt.Errorf("version %q minor: %w", version, err)
	}
	return major, minor, nil
}

// genEvents emits the EventType token set: the type, one constant per registry
// entry, and the ordered slice the hand-written accessors read.
func genEvents(root string, reg *registry) error {
	var b bytes.Buffer

	b.WriteString(`
// EventType is a registry type token. It is simultaneously the envelope
// event_type, the trailing token of the subject, and the payload schema
// basename, so the three can never drift.
type EventType string

// The protocol version this binding implements, from the registry. The subject
// root carries MAJOR only: an unknown MAJOR is rejected, an unknown MINOR is
// accepted.
const (
`)
	major, minor, err := splitVersion(reg.Version)
	if err != nil {
		return err
	}
	fmt.Fprintf(&b, "\tProtocolVersion = %s\n", quote(reg.Version))
	fmt.Fprintf(&b, "\tProtocolMajor = %d\n", major)
	fmt.Fprintf(&b, "\tProtocolMinor = %d\n", minor)
	b.WriteString(")\n\nconst (\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s EventType = %s\n", goName(e.Type), quote(e.Type))
	}
	b.WriteString(")\n\n")

	b.WriteString("// eventTypes is sorted by token so that AllEventTypes is deterministic.\nvar eventTypes = []EventType{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s,\n", goName(e.Type))
	}
	b.WriteString("}\n\n")

	b.WriteString("// eventTypeSet backs ParseEventType.\nvar eventTypeSet = map[EventType]struct{}{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s: {},\n", goName(e.Type))
	}
	b.WriteString("}\n\n")

	b.WriteString("// schemaPaths maps each event type to its payload schema, relative to the\n// repository root and to the embedded schema filesystem alike.\nvar schemaPaths = map[EventType]string{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s: %s,\n", goName(e.Type), quote(e.Schema))
	}
	b.WriteString("}\n")

	return writeGo(root, "events_gen.go", &b)
}

// genAuthz emits the trust-domain, capability, and durability tables. These are
// the tables subject authorisation consults; they exist only here.
func genAuthz(root string, reg *registry) error {
	var b bytes.Buffer

	b.WriteString(`
// TrustDomain names the class of key that signed an envelope. Every envelope
// declares exactly one.
type TrustDomain string

const (
`)
	for _, d := range reg.trustDomainSet() {
		fmt.Fprintf(&b, "\tTrustDomain%s TrustDomain = %s\n", goName(d), quote(d))
	}
	b.WriteString(`)

// Capability is a token a signer must hold, resolved through its delegation
// chain, before an event type may be accepted from it.
type Capability string

const (
`)
	for _, c := range reg.capabilitySet() {
		fmt.Fprintf(&b, "\tCapability%s Capability = %s\n", goName(c), quote(c))
	}
	b.WriteString(`)

// Durability selects the transport guarantee for an event type.
type Durability string

const (
	// DurabilityJetStream events are published to a JetStream stream and are
	// redelivered until acknowledged.
	DurabilityJetStream Durability = "jetstream"
	// DurabilityCore events are published to core NATS with no stream behind
	// them; they are request-scoped and are not replayed.
	DurabilityCore Durability = "core"
)

`)

	b.WriteString("var eventTrustDomains = map[EventType][]TrustDomain{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s: {", goName(e.Type))
		for i, d := range e.TrustDomains {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "TrustDomain%s", goName(d))
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\n")

	b.WriteString("var eventCapabilities = map[EventType][]Capability{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s: {", goName(e.Type))
		for i, c := range e.Capabilities {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "Capability%s", goName(c))
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\n")

	b.WriteString("var eventDurability = map[EventType]Durability{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s: Durability%s,\n", goName(e.Type), goName(e.Durability))
	}
	b.WriteString("}\n")

	return writeGo(root, "authz_gen.go", &b)
}

// genSubjects emits the subject templates and the event-to-class mapping. The
// build and parse algorithms are hand-written in subject.go; only the data is
// generated.
func genSubjects(root string, reg *registry) error {
	var b bytes.Buffer

	b.WriteString(`
// subjectClass selects a subject template.
type subjectClass string

const (
`)
	for _, name := range reg.classNames() {
		fmt.Fprintf(&b, "\tsubjectClass%s subjectClass = %s\n", goName(name), quote(name))
	}
	b.WriteString(")\n\n")

	b.WriteString("// subjectTemplates is the subject grammar. {type} is always the final token\n// and is the only token that may contain a dot.\nvar subjectTemplates = map[subjectClass]string{\n")
	for _, name := range reg.classNames() {
		fmt.Fprintf(&b, "\tsubjectClass%s: %s,\n", goName(name), quote(reg.SubjectClasses[name]))
	}
	b.WriteString("}\n\n")

	b.WriteString("var eventSubjectClasses = map[EventType]subjectClass{\n")
	for _, e := range reg.Events {
		fmt.Fprintf(&b, "\tEvent%s: subjectClass%s,\n", goName(e.Type), goName(e.SubjectClass))
	}
	b.WriteString("}\n")

	return writeGo(root, "subjects_gen.go", &b)
}
