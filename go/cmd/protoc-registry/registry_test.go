package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// repoRoot returns the repository root from the package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(root, registryFile))
	return root
}

func TestLoadRegistry(t *testing.T) {
	reg, err := loadRegistry(repoRoot(t))
	require.NoError(t, err)

	require.Equal(t, "1.1", reg.Version)
	require.Len(t, reg.Events, 15, "the MVP registry defines fifteen event types")

	// Sorted by token, so generated output is deterministic.
	for i := 1; i < len(reg.Events); i++ {
		require.Less(t, reg.Events[i-1].Type, reg.Events[i].Type)
	}

	// Every class is reachable and every event resolves to one.
	for _, e := range reg.Events {
		require.Contains(t, reg.SubjectClasses, e.SubjectClass, e.Type)
		require.NotEmpty(t, e.TrustDomains, e.Type)
		require.NotEmpty(t, e.Capabilities, e.Type)
	}
}

// TestLoadRegistryRejects covers the cross-field rules. Each case mutates the
// real registry text minimally, so a passing case cannot pass by accident.
func TestLoadRegistryRejects(t *testing.T) {
	root := repoRoot(t)
	original, err := os.ReadFile(filepath.Join(root, registryFile))
	require.NoError(t, err)
	schema, err := os.ReadFile(filepath.Join(root, registrySchema))
	require.NoError(t, err)

	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{
			name: "undefined subject class",
			old:  "subject_class: audit\n    durability: jetstream\n    trust_domains: [tenant]\n    capabilities: [audit.write]\n\n  - type: audit.schema",
			new:  "subject_class: nowhere\n    durability: jetstream\n    trust_domains: [tenant]\n    capabilities: [audit.write]\n\n  - type: audit.schema",
			want: "undefined subject class",
		},
		{
			name: "schema path does not match type",
			old:  "schema: schemas/payload/chat.message.json",
			new:  "schema: schemas/payload/chat.msg.json",
			want: "must use schema",
		},
		{
			name: "duplicate type",
			old:  "  - type: decision.record",
			new:  "  - type: chat.message",
			want: "declared twice",
		},
		// Every subject class is currently bound to exactly one stream and every
		// event is jetstream, so both directions of the durability invariant have
		// to be provoked synthetically. Anchors include the type line because
		// "durability: jetstream" alone is not unique.
		{
			name: "core event bound to a stream",
			old:  "  - type: chat.message\n    schema: schemas/payload/chat.message.json\n    subject_class: thread\n    durability: jetstream",
			new:  "  - type: chat.message\n    schema: schemas/payload/chat.message.json\n    subject_class: thread\n    durability: core",
			want: "bound to stream",
		},
		{
			name: "jetstream event on an unbound class",
			old:  "    subject_classes: [thread, audit, conductor_result]",
			new:  "    subject_classes: [thread, conductor_result]",
			want: "bound to no stream",
		},
		{
			name: "unknown trust domain",
			old:  "trust_domains: [tenant, saas-attested]\n    capabilities: [thread.write]",
			new:  "trust_domains: [tenant, browser]\n    capabilities: [thread.write]",
			want: registrySchema,
		},
		{
			name: "template without a type token",
			old:  "  audit: ol.v1.tenant.{tenant_id}.workspace.{workspace_id}.audit.{type}",
			new:  "  audit: ol.v1.tenant.{tenant_id}.workspace.{workspace_id}.audit.fixed",
			want: registrySchema,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Contains(t, string(original), tc.old, "fixture anchor no longer present in registry.yaml")
			mutated := strings.Replace(string(original), tc.old, tc.new, 1)

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, registryFile), []byte(mutated), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, registrySchema), schema, 0o600))

			_, err := loadRegistry(dir)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestGoName(t *testing.T) {
	tests := map[string]string{
		"chat.message":         "ChatMessage",
		"permission.requested": "PermissionRequested",
		"saas-attested":        "SaaSAttested",
		"workqueue":            "WorkQueue",
		"conductor_result":     "ConductorResult",
		"thread.write":         "ThreadWrite",
	}
	for in, want := range tests {
		require.Equal(t, want, goName(in), in)
	}
}
