package protocol

import (
	"fmt"
	"regexp"
)

// IdentifierMaxLength bounds every identifier. It is chosen so that a canonical
// lowercase UUIDv7 text form fits unchanged.
const IdentifierMaxLength = 63

// identifierPattern is the normative identifier grammar and the only regular
// expression in this module. Every other component - the configuration loader,
// the subject builder, the envelope validator - reaches the grammar through
// ParseIdentifier rather than restating it. The character class excludes ".",
// "*", ">", and whitespace by construction, which is what makes subject
// authorisation sound: a customer-supplied tenant identifier cannot contain a
// NATS wildcard.
var identifierPattern = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// Identifier is a validated, NATS-subject-safe token. The zero value is not a
// valid identifier; construct one only through ParseIdentifier.
type Identifier string

// ParseIdentifier is the single validation point for every identifier in the
// system. It returns ErrBadIdentifier for anything that does not match
// ^[a-z0-9-]{1,63}$ - including the empty string, uppercase, dots, NATS
// wildcards, whitespace, and anything longer than 63 bytes.
func ParseIdentifier(s string) (Identifier, error) {
	if !identifierPattern.MatchString(s) {
		return "", fmt.Errorf("%w: %q", ErrBadIdentifier, s)
	}
	return Identifier(s), nil
}

// String returns the token. It exists so an Identifier can be used where a
// fmt.Stringer is expected without an explicit conversion.
func (i Identifier) String() string { return string(i) }
