// Package protocol is the ObserverLoop wire contract: the signed envelope, the
// identifier grammar, the NATS subject grammar, the JetStream topology, and the
// JSON Schema payload set.
//
// It has no dependency on any ObserverLoop implementation repository. Every
// enumeration in this package is generated from registry.yaml at the root of
// the containing repository; the only hand-written enumeration is that file.
package protocol
