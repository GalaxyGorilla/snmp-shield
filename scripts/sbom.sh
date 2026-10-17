#!/usr/bin/env bash
# Generate an SBOM for the snmp-shield release binary and scan it against
# vulnerability databases (NVD/GHSA/OSV) via grype.
#
#   scripts/sbom.sh            build release + generate SBOM + vuln scan
#   scripts/sbom.sh --sbom-only   build release + generate SBOM, no scan
#
# Requires syft + grype (https://github.com/anchore/syft, .../grype);
# exits 77 (skip) when either tool is missing. Exit 0 = no findings at
# --fail-on high.
set -euo pipefail

cd "$(dirname "$0")/.."

SBOM_ONLY=0
[ "${1:-}" = "--sbom-only" ] && SBOM_ONLY=1

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "skip: $1 not installed ($1: GOBIN=\$HOME/go/bin go install ...)" >&2
        exit 77
    }
}
need syft
need grype

# Release binary (stripped static ELF; syft reads Go buildinfo from it).
make release >/dev/null
mkdir -p dist
syft bin/snmp-shield -o spdx-json=dist/snmp-shield.spdx.json -o cyclonedx-json=dist/snmp-shield.cdx.json
echo "SBOMs written to dist/snmp-shield.spdx.json + dist/snmp-shield.cdx.json"

[ "$SBOM_ONLY" = "1" ] && exit 0

# Fresh vuln DB (grype refuses to scan with a DB older than 5 days).
grype db update
grype dist/snmp-shield.spdx.json --fail-on high
echo "vulnscan: no findings at severity >= high"
