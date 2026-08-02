package protocol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fullParams supplies every token any template can ask for, so a single value
// set exercises every subject class.
func fullParams() SubjectParams {
	return SubjectParams{
		TenantID:    "acme",
		WorkspaceID: "platform",
		ThreadID:    "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e21",
		AgentID:     "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e22",
		ConductorID: "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e23",
		CommandID:   "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e24",
		QueryID:     "0191f7b4-3f2a-7c1d-9e88-2b6a5d4c3e25",
	}
}

func TestSubjectForEveryEventType(t *testing.T) {
	for _, eventType := range AllEventTypes() {
		t.Run(eventType.String(), func(t *testing.T) {
			subject, err := SubjectFor(eventType, fullParams())
			require.NoError(t, err)

			require.True(t, strings.HasPrefix(subject, "ol.v1.tenant.acme.workspace.platform."), subject)
			require.True(t, strings.HasSuffix(subject, "."+eventType.String()), subject)
			require.LessOrEqual(t, len(subject), SubjectMaxLength)
			require.NotContains(t, subject, "{")
		})
	}
}

// TestSubjectRoundTrip is the property the whole subject grammar rests on: a
// subject built from parameters parses back to the same type and the same
// parameters, for every event type, over a spread of token values.
func TestSubjectRoundTrip(t *testing.T) {
	tokenSets := []SubjectParams{
		fullParams(),
		{TenantID: "a", WorkspaceID: "b", ThreadID: "c", AgentID: "d", ConductorID: "e", CommandID: "f", QueryID: "g"},
		{
			TenantID:    Identifier(strings.Repeat("t", IdentifierMaxLength)),
			WorkspaceID: "0",
			ThreadID:    "-",
			AgentID:     "x-1",
			ConductorID: "9",
			CommandID:   "z",
			QueryID:     "y",
		},
		{TenantID: "acme-eu-west-1", WorkspaceID: "team-platform", ThreadID: "thread-1", AgentID: "agent-1", ConductorID: "conductor-1", CommandID: "command-1", QueryID: "query-1"},
	}

	for _, eventType := range AllEventTypes() {
		for i, params := range tokenSets {
			subject, err := SubjectFor(eventType, params)
			require.NoError(t, err, "%s set %d", eventType, i)

			gotType, gotParams, err := ParseSubject(subject)
			require.NoError(t, err, subject)
			require.Equal(t, eventType, gotType, subject)

			// Only the tokens this template interpolates are recovered; the
			// others stay zero, and rebuilding from what was recovered must
			// reproduce the same subject exactly.
			rebuilt, err := SubjectFor(gotType, gotParams)
			require.NoError(t, err, subject)
			require.Equal(t, subject, rebuilt)
		}
	}
}

func TestSubjectForRejectsEmptyToken(t *testing.T) {
	// thread events interpolate thread_id; leaving it empty must fail rather
	// than produce a subject with an empty token.
	_, err := SubjectFor(EventChatMessage, SubjectParams{TenantID: "acme", WorkspaceID: "platform"})
	require.ErrorIs(t, err, ErrBadIdentifier)

	_, err = SubjectFor(EventChatMessage, SubjectParams{WorkspaceID: "platform", ThreadID: "t"})
	require.ErrorIs(t, err, ErrBadIdentifier)
}

func TestSubjectForRejectsMalformedToken(t *testing.T) {
	// An Identifier can be produced by conversion, bypassing ParseIdentifier.
	// The builder must not trust it: a wildcard here would break subject
	// authorisation for every consumer downstream.
	params := fullParams()
	params.TenantID = Identifier("acme.*")

	_, err := SubjectFor(EventChatMessage, params)
	require.ErrorIs(t, err, ErrBadIdentifier)
}

func TestSubjectForRejectsUnknownEventType(t *testing.T) {
	_, err := SubjectFor(EventType("not.a.registry.entry"), fullParams())
	require.ErrorIs(t, err, ErrUnknownEventType)
}

func TestSubjectForRejectsOversizeSubject(t *testing.T) {
	// Four maximum-length identifiers plus the literal segments exceed 255
	// bytes. The builder must refuse, never truncate.
	long := Identifier(strings.Repeat("x", IdentifierMaxLength))
	params := SubjectParams{TenantID: long, WorkspaceID: long, ThreadID: long, ConductorID: long, CommandID: long, AgentID: long, QueryID: long}

	_, err := SubjectFor(EventCommandResult, params)
	require.ErrorIs(t, err, ErrSubjectTooLong)
}

func TestParseSubjectRejects(t *testing.T) {
	rejected := map[string]string{
		"empty":               "",
		"wrong root":          "ol.v2.tenant.acme.workspace.platform.thread.t.event.chat.message",
		"unknown type":        "ol.v1.tenant.acme.workspace.platform.thread.t.event.chat.whisper",
		"missing type":        "ol.v1.tenant.acme.workspace.platform.thread.t.event",
		"trailing token":      "ol.v1.tenant.acme.workspace.platform.thread.t.event.chat.message.extra",
		"wildcard token":      "ol.v1.tenant.*.workspace.platform.thread.t.event.chat.message",
		"uppercase token":     "ol.v1.tenant.ACME.workspace.platform.thread.t.event.chat.message",
		"wrong literal":       "ol.v1.tenant.acme.workspaces.platform.thread.t.event.chat.message",
		"class does not hold": "ol.v1.tenant.acme.workspace.platform.audit.chat.message",
	}
	for name, subject := range rejected {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseSubject(subject)
			require.ErrorIs(t, err, ErrUnknownEventType)
		})
	}
}

func TestParseSubjectRecoversTokens(t *testing.T) {
	subject, err := SubjectFor(EventCommandResult, fullParams())
	require.NoError(t, err)

	gotType, params, err := ParseSubject(subject)
	require.NoError(t, err)
	require.Equal(t, EventCommandResult, gotType)
	require.Equal(t, Identifier("acme"), params.TenantID)
	require.Equal(t, Identifier("platform"), params.WorkspaceID)
	require.Equal(t, fullParams().ConductorID, params.ConductorID)
	require.Equal(t, fullParams().CommandID, params.CommandID)
	// command.result is not a thread subject, so no thread token is recovered.
	require.Equal(t, Identifier(""), params.ThreadID)
}
