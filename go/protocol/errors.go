package protocol

import "errors"

// The sentinel errors a caller must be able to branch on. Every failure this
// package reports wraps exactly one of them, so `errors.Is` is sufficient and
// no caller ever needs to match an error string.
var (
	// ErrBadIdentifier is returned when a token does not satisfy the identifier
	// grammar, or when a subject template requires a token that is empty.
	ErrBadIdentifier = errors.New("protocol: identifier does not satisfy the grammar")

	// ErrUnknownEventType is returned when a type token is in no registry entry,
	// and when a subject matches no event type's template.
	ErrUnknownEventType = errors.New("protocol: unknown event type")

	// ErrSubjectTooLong is returned when a built subject would exceed the
	// 255-byte NATS limit. The subject builder never truncates.
	ErrSubjectTooLong = errors.New("protocol: subject exceeds the 255-byte limit")

	// ErrSchemaViolation is returned when an envelope or its payload fails the
	// schema registered for it.
	ErrSchemaViolation = errors.New("protocol: schema violation")

	// ErrUnsupportedMajor is returned for an unknown protocol MAJOR version. An
	// unknown MINOR is accepted, never reported.
	ErrUnsupportedMajor = errors.New("protocol: unsupported protocol major version")
)
