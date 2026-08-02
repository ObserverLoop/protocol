package protocol

import (
	"fmt"
	"strings"
)

// SubjectMaxLength is the NATS subject limit. The builder enforces it and
// returns an error rather than publishing a truncated subject.
const SubjectMaxLength = 255

// The interpolated tokens a subject template may contain. {type} is the only
// one that may itself contain a dot, and it is always the final token.
const (
	tokenTenantID    = "{tenant_id}"
	tokenWorkspaceID = "{workspace_id}"
	tokenThreadID    = "{thread_id}"
	tokenAgentID     = "{agent_id}"
	tokenConductorID = "{conductor_id}"
	tokenCommandID   = "{command_id}"
	tokenQueryID     = "{query_id}"
	tokenType        = "{type}"
)

// SubjectParams carries every token a subject template can interpolate.
// Templates ignore the fields they do not use.
type SubjectParams struct {
	TenantID    Identifier
	WorkspaceID Identifier
	ThreadID    Identifier
	AgentID     Identifier
	ConductorID Identifier
	CommandID   Identifier
	// QueryID keys a query result to the request it answers, as CommandID keys
	// a command result to its command. A reader subscribes to the reply before
	// it publishes the question, which is what lets a read use the subject
	// grammar rather than an inbox convention of its own.
	QueryID Identifier
}

// field returns a pointer to the parameter a template token names, so that the
// builder and the parser share one mapping and cannot disagree about it.
func (p *SubjectParams) field(token string) *Identifier {
	switch token {
	case tokenTenantID:
		return &p.TenantID
	case tokenWorkspaceID:
		return &p.WorkspaceID
	case tokenThreadID:
		return &p.ThreadID
	case tokenAgentID:
		return &p.AgentID
	case tokenConductorID:
		return &p.ConductorID
	case tokenCommandID:
		return &p.CommandID
	case tokenQueryID:
		return &p.QueryID
	default:
		return nil
	}
}

// SubjectFor builds the subject for t. It returns an error when t is unknown,
// when a token the template requires is empty or malformed, or when the result
// would exceed SubjectMaxLength. It never truncates.
func SubjectFor(t EventType, p SubjectParams) (string, error) {
	template, err := templateFor(t)
	if err != nil {
		return "", err
	}

	tokens := strings.Split(template, ".")
	for i, token := range tokens {
		if token == tokenType {
			tokens[i] = string(t)
			continue
		}
		field := p.field(token)
		if field == nil {
			continue // a literal segment
		}
		// Re-validate rather than trust the type: an Identifier can be
		// conjured by conversion, and this is the subject that authorisation
		// will later be compared against.
		if _, err := ParseIdentifier(field.String()); err != nil {
			return "", fmt.Errorf("subject for %s: %s: %w", t, strings.Trim(token, "{}"), err)
		}
		tokens[i] = field.String()
	}

	subject := strings.Join(tokens, ".")
	if len(subject) > SubjectMaxLength {
		return "", fmt.Errorf("%w: %s is %d bytes", ErrSubjectTooLong, t, len(subject))
	}
	return subject, nil
}

// ParseSubject is the inverse of SubjectFor. Round-tripping is asserted by a
// table test over every event type.
//
// It returns ErrUnknownEventType when no template and type token combination
// matches, which is also the answer for a malformed subject: the protocol has
// no way to name what such a subject would be.
func ParseSubject(subject string) (EventType, SubjectParams, error) {
	tokens := strings.Split(subject, ".")

	for _, t := range eventTypes {
		template, err := templateFor(t)
		if err != nil {
			return "", SubjectParams{}, err
		}

		params, ok := matchTemplate(template, t, tokens)
		if !ok {
			continue
		}
		return t, params, nil
	}
	return "", SubjectParams{}, fmt.Errorf("%w: subject %q matches no template", ErrUnknownEventType, subject)
}

// matchTemplate attempts to bind tokens to template for one event type. The
// type token occupies as many trailing segments as it has dotted parts, which
// is why it must always be last.
func matchTemplate(template string, t EventType, tokens []string) (SubjectParams, bool) {
	templateTokens := strings.Split(template, ".")
	typeTokens := strings.Split(string(t), ".")

	// One template segment holds {type}; the type itself spans len(typeTokens).
	want := len(templateTokens) - 1 + len(typeTokens)
	if len(tokens) != want {
		return SubjectParams{}, false
	}

	var params SubjectParams
	for i, token := range templateTokens {
		if token == tokenType {
			if strings.Join(tokens[i:], ".") != string(t) {
				return SubjectParams{}, false
			}
			break
		}
		field := params.field(token)
		if field == nil {
			if tokens[i] != token {
				return SubjectParams{}, false
			}
			continue
		}
		value, err := ParseIdentifier(tokens[i])
		if err != nil {
			return SubjectParams{}, false
		}
		*field = value
	}
	return params, true
}

func templateFor(t EventType) (string, error) {
	class, ok := eventSubjectClasses[t]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownEventType, t)
	}
	template, ok := subjectTemplates[class]
	if !ok {
		return "", fmt.Errorf("%w: %q has no template for class %q", ErrUnknownEventType, t, class)
	}
	return template, nil
}
