package protocol

import (
	"strings"
	"time"
)

// StreamSpec is a JetStream stream, resolved for one tenant and workspace. It
// is deliberately a plain description rather than a broker call: this module
// must not depend on a NATS client.
type StreamSpec struct {
	Name            string
	Subjects        []string
	Retention       Retention
	MaxAge          time.Duration
	Discard         Discard
	Replicas        int
	DuplicateWindow time.Duration
}

// StreamsFor resolves every stream template for one workspace. The subject
// bindings are generated from the subject grammar, so a stream can never
// listen on a subject the grammar does not produce.
//
// The identifiers are substituted as given: they are already validated by the
// time a caller holds an Identifier, and this function has no error to return
// per the published surface.
func StreamsFor(tenant, workspace Identifier, replicas int) []StreamSpec {
	replace := strings.NewReplacer(
		tokenTenantID, tenant.String(),
		tokenWorkspaceID, workspace.String(),
	)

	out := make([]StreamSpec, 0, len(streamTemplates))
	for _, template := range streamTemplates {
		subjects := make([]string, len(template.subjects))
		for i, subject := range template.subjects {
			subjects[i] = replace.Replace(subject)
		}
		out = append(out, StreamSpec{
			Name:            replace.Replace(template.name),
			Subjects:        subjects,
			Retention:       template.retention,
			MaxAge:          template.maxAge,
			Discard:         template.discard,
			Replicas:        replicas,
			DuplicateWindow: template.duplicateWindow,
		})
	}
	return out
}
