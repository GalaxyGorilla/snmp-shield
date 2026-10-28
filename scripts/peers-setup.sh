#!/bin/sh
# peers-setup.sh — prepare the managed external-SNMP toolchains used by the
# conformance tests. Idempotent; safe to re-run.
#
#   python venv + pysnmp + cryptography   -> test/peers/.venv
#   node net-snmp                         -> test/peers/node_modules
#   net-snmp in Docker                    -> docker image snmp-shield-net-snmp:peer
#       (current-release clear-leg peer + RFC 6353 TSM client + snmptrapd as
#        a v3 notification receiver; needs python3 for the shared adapter)
#
# net-snmp on the host is NOT installed here: it is a system package
# (apt-get install snmp / brew install net-snmp), and the adapter simply
# reports itself unavailable when the binaries are missing. The Docker image
# exists because a host net-snmp may be built without TLS, and RFC 6353
# cannot be exercised without `dtls:`.
#
# Exit codes: 0 = ready (possibly partially: see the summary),
#             77 = no usable toolchain on this host (tests skip).
set -u

here=$(cd "$(dirname "$0")" && pwd)/../test/peers
cd "$here" || exit 1
ready=0
missing=""

# --- Python: pysnmp 7.x needs cryptography for AES/DES privacy ---------------
if command -v python3 >/dev/null 2>&1; then
    if [ ! -x .venv/bin/python ]; then
        echo "== creating python venv (test/peers/.venv)"
        python3 -m venv .venv || echo "   venv creation failed"
    fi
    if [ -x .venv/bin/python ]; then
        if .venv/bin/python -c "import pysnmp, cryptography" >/dev/null 2>&1; then
            echo "== pysnmp: already installed"
        else
            echo "== installing pysnmp + cryptography"
            .venv/bin/pip install --quiet --upgrade pip >/dev/null 2>&1
            .venv/bin/pip install --quiet pysnmp cryptography || echo "   pip install failed"
        fi
        if .venv/bin/python -c "import pysnmp, cryptography" >/dev/null 2>&1; then
            echo "== pysnmp: $(.venv/bin/python -c 'import pysnmp; print(pysnmp.__version__)') ready"
            ready=1
        else
            missing="$missing pysnmp"
        fi
    else
        missing="$missing python-venv"
    fi
else
    missing="$missing python3"
fi

# --- Node: net-snmp ----------------------------------------------------------
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    if [ -d node_modules/net-snmp ] && node -e "require('net-snmp')" >/dev/null 2>&1; then
        echo "== node net-snmp: already installed"
    else
        echo "== installing node net-snmp"
        [ -f package.json ] || npm init -y >/dev/null 2>&1
        npm install --silent net-snmp || echo "   npm install failed"
    fi
    if node -e "require('net-snmp')" >/dev/null 2>&1; then
        echo "== node net-snmp: $(node -e "console.log(require('net-snmp/package.json').version)") ready"
        ready=1
    else
        missing="$missing node-net-snmp"
    fi
else
    missing="$missing node/npm"
fi

# --- net-snmp CLI (system) ---------------------------------------------------
if command -v snmpget >/dev/null 2>&1; then
    echo "== net-snmp CLI: $(snmpget --version 2>&1 | head -1) ready"
    ready=1
else
    missing="$missing net-snmp(snmpget)"
fi

# --- net-snmp in Docker: the only TSM/DTLS-capable peer ----------------------
# The host's net-snmp may be built without TLS (Apple's is), and RFC 6353
# cannot be exercised without a `dtls:` transport. A small Debian image with
# a current net-snmp gives the TSM scenarios a real third-party client.
#
# Three capabilities are required, and an image left over from an earlier
# revision can be missing two of them (snmptrapd for the receiver scenarios,
# python3 for the net-snmp adapter that runs INSIDE the container). Checking
# `docker image inspect` alone is not enough: a stale image then surfaces as a
# failing test instead of a rebuild.
image_ok() {
    docker image inspect "$1" >/dev/null 2>&1 || return 1
    docker run --rm --entrypoint sh "$1" -c \
        'command -v snmpget && command -v snmptrapd && command -v python3' >/dev/null 2>&1
}
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if image_ok snmp-shield-net-snmp:peer; then
        echo "== net-snmp docker peer: already built"
    else
        echo "== building net-snmp docker peer image (test/peers/netsnmp-docker)"
        docker build --quiet -t snmp-shield-net-snmp:peer "$here/netsnmp-docker" >/dev/null 2>&1 \
            || echo "   docker build failed"
    fi
    if image_ok snmp-shield-net-snmp:peer; then
        echo "== net-snmp docker peer: $(docker run --rm --entrypoint snmpget snmp-shield-net-snmp:peer --version 2>&1 | head -1) ready"
        ready=1
    else
        missing="$missing docker-netsnmp"
    fi
else
    missing="$missing docker(netsnmp-tsm)"
fi

if [ -n "$missing" ]; then
    echo "== unavailable:$missing (those peers will be skipped)"
fi
[ "$ready" -eq 1 ] || exit 77
exit 0
