package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Tokens the stream subject binding resolves at runtime rather than replacing
// with a wildcard: a stream is always scoped to one tenant and one workspace.
const (
	tenantToken    = "{tenant_id}"
	workspaceToken = "{workspace_id}"
)

// genStreams emits the JetStream stream templates. Subject bindings are derived
// from the subject grammar, never written by hand, so a change to a template
// cannot leave a stream listening on a subject that no longer exists.
func genStreams(root string, reg *registry) error {
	var b bytes.Buffer
	b.WriteString(`
import "time"

// Retention is a JetStream retention policy.
type Retention string

const (
`)
	for _, v := range enumValues(reg.Streams, func(s streamEntry) string { return s.Retention }) {
		fmt.Fprintf(&b, "\tRetention%s Retention = %s\n", goName(v), quote(v))
	}
	b.WriteString(`)

// Discard is a JetStream discard policy: which message is dropped when a limit
// is reached.
type Discard string

const (
`)
	for _, v := range enumValues(reg.Streams, func(s streamEntry) string { return s.Discard }) {
		fmt.Fprintf(&b, "\tDiscard%s Discard = %s\n", goName(v), quote(v))
	}
	b.WriteString(`)

// streamTemplate is a stream specification with the tenant and workspace tokens
// still unresolved. StreamsFor substitutes them.
type streamTemplate struct {
	name            string
	subjects        []string
	retention       Retention
	maxAge          time.Duration
	discard         Discard
	duplicateWindow time.Duration
}

var streamTemplates = []streamTemplate{
`)

	for _, s := range reg.Streams {
		maxAge, err := time.ParseDuration(s.MaxAge)
		if err != nil {
			return fmt.Errorf("stream %q max_age: %w", s.Name, err)
		}
		window, err := time.ParseDuration(s.DuplicateWindow)
		if err != nil {
			return fmt.Errorf("stream %q duplicate_window: %w", s.Name, err)
		}

		subjects, err := streamSubjects(reg, s)
		if err != nil {
			return err
		}

		b.WriteString("\t{\n")
		fmt.Fprintf(&b, "\t\tname: %s,\n", quote(s.Name+"_"+workspaceToken))
		b.WriteString("\t\tsubjects: []string{\n")
		for _, subject := range subjects {
			fmt.Fprintf(&b, "\t\t\t%s,\n", quote(subject))
		}
		b.WriteString("\t\t},\n")
		fmt.Fprintf(&b, "\t\tretention: Retention%s,\n", goName(s.Retention))
		fmt.Fprintf(&b, "\t\tmaxAge: %s,\n", goDuration(maxAge))
		fmt.Fprintf(&b, "\t\tdiscard: Discard%s,\n", goName(s.Discard))
		fmt.Fprintf(&b, "\t\tduplicateWindow: %s,\n", goDuration(window))
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")

	return writeGo(root, "streams_gen.go", &b)
}

// streamSubjects derives one subject binding per subject class the stream binds.
// Every interpolated token other than tenant and workspace becomes a single-
// token wildcard, and the trailing {type} becomes a multi-token wildcard.
func streamSubjects(reg *registry, s streamEntry) ([]string, error) {
	classes := append([]string(nil), s.SubjectClasses...)
	sort.Strings(classes)

	out := make([]string, 0, len(classes))
	for _, class := range classes {
		template, ok := reg.SubjectClasses[class]
		if !ok {
			return nil, fmt.Errorf("stream %q names undefined subject class %q", s.Name, class)
		}

		tokens := strings.Split(template, ".")
		for i, token := range tokens {
			switch {
			case token == typeToken:
				tokens[i] = ">"
			case token == tenantToken || token == workspaceToken:
				// Resolved by StreamsFor.
			case strings.HasPrefix(token, "{") && strings.HasSuffix(token, "}"):
				tokens[i] = "*"
			}
		}
		out = append(out, strings.Join(tokens, "."))
	}
	return out, nil
}

// enumValues collects the distinct values a stream field takes, sorted.
func enumValues(streams []streamEntry, pick func(streamEntry) string) []string {
	seen := map[string]struct{}{}
	for _, s := range streams {
		seen[pick(s)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// goDuration renders a duration as a readable Go expression rather than a
// nanosecond count, so a reviewer can check it against the topology table.
func goDuration(d time.Duration) string {
	for _, unit := range []struct {
		size time.Duration
		name string
	}{
		{time.Hour, "time.Hour"},
		{time.Minute, "time.Minute"},
		{time.Second, "time.Second"},
	} {
		if d%unit.size == 0 {
			return fmt.Sprintf("%d * %s", d/unit.size, unit.name)
		}
	}
	return fmt.Sprintf("time.Duration(%d)", int64(d))
}
