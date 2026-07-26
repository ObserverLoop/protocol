.DEFAULT_GOAL := check

GO ?= go
ROOT := $(CURDIR)
GOMOD := $(ROOT)/go
DEV_BIN := $(ROOT)/.dev/bin

# golangci-lint refuses a module whose Go version exceeds the one it was built
# with, so a host binary built by an older toolchain cannot lint this module.
# Pin it here and build it with our own toolchain into .dev/bin.
GOLANGCI_VERSION := v2.7.2
LINT := $(DEV_BIN)/golangci-lint

.PHONY: build generate test test-race lint check tools verify-generate

tools: $(LINT)

$(LINT):
	cd $(GOMOD) && GOBIN=$(DEV_BIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

build:
	cd $(GOMOD) && $(GO) build ./...

# Everything derived from registry.yaml. Deterministic: re-running with an
# unchanged registry produces byte-identical output.
generate:
	cd $(GOMOD) && $(GO) run ./cmd/protoc-registry -root $(ROOT)
	cd $(GOMOD) && $(GO) fmt ./... >/dev/null

test:
	cd $(GOMOD) && $(GO) test ./...

test-race:
	cd $(GOMOD) && $(GO) test ./... -race

lint: $(LINT)
	cd $(GOMOD) && $(LINT) run

# The DRY gate: generated artifacts must already match the registry.
verify-generate: generate
	git diff --exit-code

check: build lint
	cd $(GOMOD) && $(GO) vet ./...
	cd $(GOMOD) && $(GO) test ./... -race
	$(MAKE) verify-generate
