// Package conformance carries the suite a protocol binding must pass, and the
// corpus it is defined over.
//
// The corpus — the manifest, the valid and invalid envelope fixtures, and the
// Ed25519 signing vectors — is authored at the repository root and mirrored
// into this package by cmd/protoc-registry so that embed can reach it. It is
// part of the contract rather than scaffolding for this repository's own tests:
// a consumer that has the module but cannot run the vectors has half of what
// the module is for. Embedding it means a consumer needs no checkout of this
// repository, needs no knowledge of where the module cache put it, and cannot
// be broken by a relative path that was correct on one machine and wrong on the
// next.
//
// FS returns the corpus. Signing returns the key and the vectors already
// decoded, so that no consumer has to rediscover where they live or how they
// are encoded. Everything else here is the Go runner over them, and a binding
// in another language consumes the same files and must produce the same
// canonical bytes and the same signatures.
//
// The corpus lives here rather than in go/protocol because go/protocol is
// linked into every consumer's production binary and the corpus is only ever
// needed by tests.
package conformance
