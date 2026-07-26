// Command protoc-registry generates every artifact that derives from
// registry.yaml: the Go event constants, the subject templates, the JetStream
// stream templates, and the trust-domain and capability authorisation tables.
//
// It is deterministic. Running it twice against an unchanged registry produces
// byte-identical output, which is what makes `make generate && git diff
// --exit-code` a usable drift gate.
//
// Usage:
//
//	protoc-registry -root <repository root>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "repository root containing registry.yaml")
	flag.Parse()

	if err := run(*root); err != nil {
		fmt.Fprintf(os.Stderr, "protoc-registry: %v\n", err)
		os.Exit(1)
	}
}

func run(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolving root: %w", err)
	}

	reg, err := loadRegistry(abs)
	if err != nil {
		return fmt.Errorf("loading registry: %w", err)
	}

	for _, step := range generators() {
		if err := step.fn(abs, reg); err != nil {
			return fmt.Errorf("generating %s: %w", step.name, err)
		}
	}
	return nil
}

type generator struct {
	name string
	fn   func(root string, reg *registry) error
}

// generators lists every generation step in a fixed order so that a failure
// always reports the same first offender.
func generators() []generator {
	return []generator{
		{"events", genEvents},
		{"authz", genAuthz},
		{"subjects", genSubjects},
		{"streams", genStreams},
		{"schemas", genSchemas},
	}
}
