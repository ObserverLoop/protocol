package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseEventType reports whether s is a registry type token, and returns it.
// It is a lookup, not a parse: the permitted set is generated from the
// registry and is closed.
func ParseEventType(s string) (EventType, bool) {
	t := EventType(s)
	_, ok := eventTypeSet[t]
	if !ok {
		return "", false
	}
	return t, true
}

// AllEventTypes returns every registry type token, sorted. The caller receives
// a copy: the generated table is not exposed to mutation.
func AllEventTypes() []EventType {
	out := make([]EventType, len(eventTypes))
	copy(out, eventTypes)
	return out
}

// String returns the type token.
func (t EventType) String() string { return string(t) }

// SchemaPathFor returns the payload schema path registered for t, relative to
// the repository root and to the embedded schema filesystem alike.
func SchemaPathFor(t EventType) (string, error) {
	path, ok := schemaPaths[t]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownEventType, t)
	}
	return path, nil
}

// TrustDomainsFor returns the trust domains permitted to sign t, or nil when t
// is unknown. The caller receives a copy.
func TrustDomainsFor(t EventType) []TrustDomain {
	return append([]TrustDomain(nil), eventTrustDomains[t]...)
}

// CapabilitiesFor returns the capabilities a signer must hold for t, or nil
// when t is unknown. The caller receives a copy.
func CapabilitiesFor(t EventType) []Capability {
	return append([]Capability(nil), eventCapabilities[t]...)
}

// DurabilityFor returns the transport guarantee registered for t. An unknown
// type has no registered durability and returns the empty Durability, which is
// never a publishable value.
func DurabilityFor(t EventType) Durability { return eventDurability[t] }

// ParseProtocolVersion splits a MAJOR.MINOR version token.
func ParseProtocolVersion(s string) (major, minor int, err error) {
	majorText, minorText, found := strings.Cut(s, ".")
	if !found {
		return 0, 0, fmt.Errorf("%w: %q is not MAJOR.MINOR", ErrUnsupportedMajor, s)
	}
	if major, err = strconv.Atoi(majorText); err != nil {
		return 0, 0, fmt.Errorf("%w: %q has a non-numeric major", ErrUnsupportedMajor, s)
	}
	if minor, err = strconv.Atoi(minorText); err != nil {
		return 0, 0, fmt.Errorf("%w: %q has a non-numeric minor", ErrUnsupportedMajor, s)
	}
	return major, minor, nil
}

// CheckProtocolVersion applies the compatibility rule: an unknown MAJOR is
// rejected because the subject root carries MAJOR and a MAJOR bump is an
// enrollment-level operation, while an unknown MINOR is accepted because
// unknown optional fields are ignored and preserved.
func CheckProtocolVersion(s string) error {
	major, _, err := ParseProtocolVersion(s)
	if err != nil {
		return err
	}
	if major != ProtocolMajor {
		return fmt.Errorf("%w: %q, this binding implements %d.x", ErrUnsupportedMajor, s, ProtocolMajor)
	}
	return nil
}
