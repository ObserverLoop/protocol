package protocol

import (
	"fmt"

	"github.com/gowebpki/jcs"
)

// Canonicalize returns the RFC 8785 JSON Canonicalization Scheme form of raw.
//
// This is the only place canonicalisation happens. Signing, verification, and
// digesting all route through it, so there is no way for two components to
// disagree about which bytes were signed.
func Canonicalize(raw []byte) ([]byte, error) {
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing: %w", err)
	}
	return canonical, nil
}
