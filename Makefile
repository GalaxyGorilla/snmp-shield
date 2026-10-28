# snmp-shield — minimal build/test automation.
# The project is plain Go: `go build ./...` works without make.
# This file exists for appliance packaging convenience.

BINARY := snmp-shield
GO     ?= go

.PHONY: all build test fmt-check vet staticcheck govulncheck race peers conformance interop release release-all sbom vulnscan clean

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/snmp-shield

# test gates on formatting: an unformatted file used to slip into a green
# suite because nothing checked (matches modbus-shield).
test: fmt-check
	$(GO) test ./... -race -timeout 180s

fmt-check:
	@unformatted=$$(gofmt -l . | grep -v '^vendor/' || true); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	$(GO) vet ./...

staticcheck:
	~/go/bin/staticcheck ./...

govulncheck:
	~/go/bin/govulncheck ./...

race: test

# peers provisions the independent SNMP stacks used by the conformance
# suite (net-snmp CLI, pysnmp in a venv, node net-snmp in node_modules, and
# a net-snmp 5.9 container for the RFC 6353 TSM client). Exit 77 when no
# third-party stack is available — the in-process gosnmp peer always runs,
# so the suite itself is never skipped.
peers:
	sh scripts/peers-setup.sh

# conformance runs the cross-vendor matrix against the built binary. This
# is the slow, high-signal suite: four independent implementations drive the
# real CLI through the real wire. Requires `make peers` for the full matrix.
conformance:
	$(GO) test ./internal/conformance -count=1 -timeout 900s

# release builds a stripped static binary for appliance deployment.
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/$(BINARY) ./cmd/snmp-shield

# release-all cross-builds stripped static binaries for the appliance
# platforms (amd64 + arm64 + armv7) into dist/. The project is pure Go
# with CGO disabled, so cross-compiling is exact — no ports, no ifdef.
release-all:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 ./cmd/snmp-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-arm64 ./cmd/snmp-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-armv7 ./cmd/snmp-shield
	@echo "release binaries written to dist/ ($(BINARY)-linux-{amd64,arm64,armv7})"

# interop drives the built binary with the real net-snmp CLI against the
# two-proxy chain (snmpget/snmpset/snmptrap ...). Exit 77 when net-snmp
# is missing. The other interop scripts (gateway/tsm/manager-gateway)
# run standalone: sh scripts/interop-<name>.sh
interop: build
	sh scripts/interop-snmp.sh

# sbom generates SPDX + CycloneDX SBOMs for the release binary into dist/.
# Requires syft (https://github.com/anchore/syft); exits 77 when missing.
sbom: release
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/syft/cmd/syft@latest)"; exit 77; }
	@mkdir -p dist
	syft bin/$(BINARY) -o spdx-json=dist/$(BINARY).spdx.json -o cyclonedx-json=dist/$(BINARY).cdx.json
	@echo "SBOMs written to dist/$(BINARY).spdx.json + dist/$(BINARY).cdx.json"

# vulnscan matches the SBOM against vulnerability databases (NVD/GHSA/OSV)
# via grype and fails on findings at severity HIGH or above.
# Requires grype (https://github.com/anchore/grype); exits 77 when missing.
vulnscan: sbom
	@command -v grype >/dev/null 2>&1 || { echo "grype not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/grype/cmd/grype@latest)"; exit 77; }
	grype db update
	grype dist/$(BINARY).spdx.json --fail-on high

clean:
	rm -f bin/$(BINARY)
	rm -rf dist/
