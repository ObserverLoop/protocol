// Package conformance holds the suite that a protocol binding must pass. It
// exports nothing: the contract lives in the fixtures at the repository root,
// and this package is the Go runner over them. A binding in another language
// consumes the same files and must produce the same canonical bytes and the
// same signatures.
package conformance
