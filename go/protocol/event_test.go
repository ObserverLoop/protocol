package protocol

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// subjectMatches applies NATS subject matching: "*" spans one token, ">" spans
// the remainder. It exists only to prove stream bindings cover the subjects the
// grammar produces.
func subjectMatches(binding, subject string) bool {
	pattern := strings.Split(binding, ".")
	tokens := strings.Split(subject, ".")

	for i, want := range pattern {
		if want == ">" {
			return i < len(tokens)
		}
		if i >= len(tokens) {
			return false
		}
		if want != "*" && want != tokens[i] {
			return false
		}
	}
	return len(pattern) == len(tokens)
}

func TestAllEventTypes(t *testing.T) {
	types := AllEventTypes()
	require.Len(t, types, 17, "the MVP registry defines seventeen event types")

	for i := 1; i < len(types); i++ {
		require.Less(t, types[i-1], types[i], "AllEventTypes must be sorted")
	}

	// The caller gets a copy; mutating it must not corrupt the table.
	types[0] = "mutated"
	require.NotEqual(t, EventType("mutated"), AllEventTypes()[0])
}

func TestParseEventType(t *testing.T) {
	got, ok := ParseEventType("permission.requested")
	require.True(t, ok)
	require.Equal(t, EventPermissionRequested, got)

	_, ok = ParseEventType("permission.granted")
	require.False(t, ok)

	_, ok = ParseEventType("")
	require.False(t, ok)
}

func TestAuthorizationTables(t *testing.T) {
	require.Equal(t, []TrustDomain{TrustDomainTenant, TrustDomainSaaSAttested}, TrustDomainsFor(EventChatMessage))
	require.Equal(t, []TrustDomain{TrustDomainTenant}, TrustDomainsFor(EventDecisionRecord))
	require.Nil(t, TrustDomainsFor("chat.whisper"))

	require.Equal(t, []Capability{CapabilityInteractionRequest}, CapabilitiesFor(EventPermissionRequested))
	require.Equal(t, []Capability{CapabilityInteractionResolve}, CapabilitiesFor(EventPermissionResolved))
	require.Nil(t, CapabilitiesFor("chat.whisper"))

	require.Equal(t, DurabilityJetStream, DurabilityFor(EventChatMessage))
	// Command results are durable: they carry the reason a command was rejected,
	// which is an audit record, and a core-NATS result published while the
	// issuing CLI has already exited would be lost with no way to recover it.
	require.Equal(t, DurabilityJetStream, DurabilityFor(EventCommandResult))
	require.Equal(t, Durability(""), DurabilityFor("chat.whisper"))
}

// TestEveryEventTypeIsFullyDescribed guards against a registry entry that
// generates constants but no authorisation, which would fail open.
func TestEveryEventTypeIsFullyDescribed(t *testing.T) {
	for _, eventType := range AllEventTypes() {
		require.NotEmpty(t, TrustDomainsFor(eventType), eventType)
		require.NotEmpty(t, CapabilitiesFor(eventType), eventType)
		require.Contains(t, []Durability{DurabilityJetStream, DurabilityCore}, DurabilityFor(eventType), eventType)
	}
}

func TestAuthorizationTablesReturnCopies(t *testing.T) {
	domains := TrustDomainsFor(EventChatMessage)
	domains[0] = "tampered"
	require.NotEqual(t, TrustDomain("tampered"), TrustDomainsFor(EventChatMessage)[0])

	capabilities := CapabilitiesFor(EventChatMessage)
	capabilities[0] = "tampered"
	require.NotEqual(t, Capability("tampered"), CapabilitiesFor(EventChatMessage)[0])
}

func TestCheckProtocolVersion(t *testing.T) {
	require.NoError(t, CheckProtocolVersion("1.0"))
	require.NoError(t, CheckProtocolVersion("1.7"))
	require.ErrorIs(t, CheckProtocolVersion("2.0"), ErrUnsupportedMajor)
	require.ErrorIs(t, CheckProtocolVersion("1"), ErrUnsupportedMajor)

	major, minor, err := ParseProtocolVersion(ProtocolVersion)
	require.NoError(t, err)
	require.Equal(t, ProtocolMajor, major)
	require.Equal(t, ProtocolMinor, minor)
}

func TestStreamsFor(t *testing.T) {
	streams := StreamsFor("acme", "platform", 3)
	require.Len(t, streams, 2)

	byName := map[string]StreamSpec{}
	for _, s := range streams {
		byName[s.Name] = s
		require.Equal(t, 3, s.Replicas)
		for _, subject := range s.Subjects {
			require.NotContains(t, subject, "{", subject)
			require.True(t, len(subject) > 0)
		}
	}

	events, ok := byName["OL_EVENTS_platform"]
	require.True(t, ok)
	require.Equal(t, RetentionLimits, events.Retention)
	require.Equal(t, 90*24*time.Hour, events.MaxAge)
	require.Equal(t, DiscardOld, events.Discard)
	require.Equal(t, 2*time.Hour, events.DuplicateWindow)
	// conductor_result is bound to OL_EVENTS rather than OL_COMMANDS: command
	// results carry rejection reasons (quota exhaustion, capability shortfall,
	// policy denial) that belong in the audit record, and they may have several
	// observers. OL_COMMANDS uses workqueue retention, which deletes a message
	// once any one consumer acks it, so it is the wrong home for them.
	require.Equal(t, []string{
		"ol.v1.tenant.acme.workspace.platform.audit.>",
		"ol.v1.tenant.acme.workspace.platform.conductor.*.result.*.>",
		"ol.v1.tenant.acme.workspace.platform.thread.*.event.>",
	}, events.Subjects)

	commands, ok := byName["OL_COMMANDS_platform"]
	require.True(t, ok)
	require.Equal(t, RetentionWorkQueue, commands.Retention)
	require.Equal(t, 24*time.Hour, commands.MaxAge)
	require.Equal(t, []string{"ol.v1.tenant.acme.workspace.platform.conductor.*.command.>"}, commands.Subjects)
}

// TestEveryJetStreamEventIsCoveredByAStream closes the loop between the
// authorisation table and the topology: a durable event whose subject no stream
// captures would be published and silently lost.
func TestEveryJetStreamEventIsCoveredByAStream(t *testing.T) {
	streams := StreamsFor("acme", "platform", 1)

	for _, eventType := range AllEventTypes() {
		subject, err := SubjectFor(eventType, fullParams())
		require.NoError(t, err)

		covered := false
		for _, stream := range streams {
			for _, binding := range stream.Subjects {
				if subjectMatches(binding, subject) {
					covered = true
				}
			}
		}
		require.Equal(t, DurabilityFor(eventType) == DurabilityJetStream, covered,
			"%s: durability %s but stream coverage %v", eventType, DurabilityFor(eventType), covered)
	}
}
