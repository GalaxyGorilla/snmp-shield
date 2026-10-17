# snmp-proxy — minimal build/test automation.
# The project is plain Go: `go build ./...` works without make.
# This file exists for appliance packaging convenience.

BINARY := snmp-proxy
GO     ?= go

.PHONY: all build test vet staticcheck govulncheck race clean release

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/snmp-proxy

test:
	$(GO) test ./... -race -timeout 180s

vet:
	$(GO) vet ./...

staticcheck:
	~/go/bin/staticcheck ./...

govulncheck:
	~/go/bin/govulncheck ./...

race: test

# release builds a stripped static binary for appliance deployment.
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/$(BINARY) ./cmd/snmp-proxy

clean:
	rm -f bin/$(BINARY)
