# snmp-shield — minimal build/test automation.
# The project is plain Go: `go build ./...` works without make.
# This file exists for appliance packaging convenience.

BINARY := snmp-shield
GO     ?= go

.PHONY: all build test vet staticcheck govulncheck race release sbom vulnscan clean

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/snmp-shield

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
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/$(BINARY) ./cmd/snmp-shield

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
