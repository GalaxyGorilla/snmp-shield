#!/usr/bin/env bash
# net-snmp CLI interop test for the TSM gateway (single box):
#
#   [net-snmp TSM client] --SNMP-over-DTLS (RFC 6353)--> [gateway] --clear v2c--> [fake agent]
#
# Drives the raw (no-frame) DTLS front leg with real net-snmp v3 clients
# (snmpget, snmpgetnext, snmpbulkwalk, snmpset), verifies rejection of
# untrusted clients (the protection), and the trap direction (clear v2c
# trap at the gateway's trap listener -> TSM notification at a raw DTLS
# sink). The trap sink is a tiny Go helper (scripts/tsm-sink); the
# notification's crypto validation is covered by internal/tsm/gateway_test.go
# (a gosnmp TrapListener cannot do raw DTLS).
#
# Requires: net-snmp CLI tools (apt-get install snmp) and openssl, AND a
# net-snmp built with TLS. Apple's 5.6.2.1 has no `dtls:` transport at all
# ("Unknown host (dtls:...)"), so this exits 77 there — the RFC 6353 coverage
# then comes from the Docker-based scenarios in internal/conformance
# (net-snmp 5.9.3), which is the only vendor TSM client that exists here.
# Exit 0 = green; exit 77 = prerequisite missing (skip).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$PATH:/usr/local/go/bin"

for tool in snmpget snmpgetnext snmpbulkwalk snmpset snmptrap openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: $tool not found (apt-get install snmp openssl)"
        exit 77
    fi
done

# A TLS-enabled build exposes the tlsAlgorithms/tlsCipher config directives.
# Feature-probing beats version numbers: distro builds of 5.9 exist without TLS.
if ! snmpget -H 2>/dev/null | grep -q "tlsAlgorithms"; then
    echo "SKIP: this net-snmp has no TLS/DTLS transport ($(snmpget --version 2>&1 | head -1))"
    echo "      RFC 6353 is covered by internal/conformance with net-snmp 5.9 in Docker"
    exit 77
fi

fail=0
BIN=./bin/snmp-shield
go build -o "$BIN" ./cmd/snmp-shield
go build -o bin/tsm-sink ./scripts/tsm-sink

# ---------------------------------------------------------------- throwaway PKI
CERTDIR=$(mktemp -d)
trap 'kill "$GW_PID" "$AGENT_PID" "$SINK_PID" 2>/dev/null || true; rm -rf "$CERTDIR" "$SNMPHOME"' EXIT INT TERM

CA_CN="snmp-shield test CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERTDIR/ca.key" -out "$CERTDIR/ca.crt" -days 2 -nodes \
    -subj "/CN=${CA_CN}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.csr" -nodes \
    -subj "/CN=snmp-shield-agent" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERTDIR/client.key" -out "$CERTDIR/client.csr" -nodes \
    -subj "/CN=snmp-shield-manager" >/dev/null 2>&1
openssl x509 -req -in "$CERTDIR/server.csr" -CA "$CERTDIR/ca.crt" -CAkey "$CERTDIR/ca.key" \
    -CAcreateserial -out "$CERTDIR/server.crt" -days 2 \
    -extfile <(printf '%s\n' \
        "subjectAltName=DNS:snmp-shield-agent,DNS:localhost,IP:127.0.0.1" \
        "extendedKeyUsage=serverAuth") >/dev/null 2>&1
openssl x509 -req -in "$CERTDIR/client.csr" -CA "$CERTDIR/ca.crt" -CAkey "$CERTDIR/ca.key" \
    -CAcreateserial -out "$CERTDIR/client.crt" -days 2 \
    -extfile <(printf '%s\n' \
        "subjectAltName=DNS:snmp-shield-manager" \
        "extendedKeyUsage=clientAuth") >/dev/null 2>&1

ca_fp=$(openssl x509 -in "$CERTDIR/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)
cli_fp=$(openssl x509 -in "$CERTDIR/client.crt" -noout -fingerprint -sha256 | cut -d= -f2)

# ------------------------------------------------- net-snmp client environment
# net-snmp TSM clients need certs under $HOME/.snmp/tls (NOT tls/ca):
#   tls/ca-certs/  trust anchors
#   tls/certs/     identity cert + key
# plus snmp.conf tokens clientCert/trustCert with SHA-256 fingerprints
# (net-snmp stores fingerprints using the cert's own signature hash).
SNMPHOME=$(mktemp -d)
mkdir -p "$SNMPHOME/.snmp/tls/ca-certs" "$SNMPHOME/.snmp/tls/certs" "$SNMPHOME/.snmp/tls/private"
cp "$CERTDIR/ca.crt" "$SNMPHOME/.snmp/tls/ca-certs/"
cp "$CERTDIR/client.crt" "$CERTDIR/client.key" "$SNMPHOME/.snmp/tls/certs/"
cat > "$SNMPHOME/.snmp/snmp.conf" <<EOF
defVersion 3
defSecurityModel tsm
defSecurityName snmp-shield-manager
defAuthType SHA
defAuthPassphrase authpassphrase
defPrivType AES
defPrivPassphrase privpassphrase
defSecurityLevel authPriv
clientCert ${cli_fp}
trustCert ${ca_fp}
EOF

export HOME="$SNMPHOME"
export SNMPCONFPATH="$SNMPHOME/.snmp"

# MIB loading noise is harmless.
unnoisy() { grep -vE "Cannot find module|Cannot adopt|Undefined identifier|Did not find|Unlinked OID|MIB search|LINKED|Using 1 |currently unknown|deprecat|was requested with" || true; }

# GNU timeout is a coreutils binary; macOS only has it as gtimeout (brew), and
# plain sh hosts have neither. Every bounded call below needs SOME bound — a
# wedged net-snmp DTLS call would otherwise hang the suite — so fall back to
# perl's alarm (present on any POSIX host) instead of dropping the guard.
if command -v timeout >/dev/null 2>&1; then
    run_bounded() { timeout "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
    run_bounded() { gtimeout "$@"; }
else
    run_bounded() { _secs=$1; shift; perl -e 'alarm shift; exec @ARGV' "$_secs" "$@"; }
fi

# TSM client: OIDs come BEFORE the -v3 flags (net-snmp arg-order quirk).

# ------------------------------------------------------------------ free ports
free_port() {
    python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
PY
}
GW_PORT=$(free_port)
AGENT_PORT=$(free_port)
TRAP_PORT=$(free_port)
SINK_PORT=$(free_port)
D="localhost:$GW_PORT"   # net-snmp's name check only matches DNS names, not IPs

# ------------------------------------------------------------- fake v2c agent
AGENT_PORT="$AGENT_PORT" python3 - <<'PY' &
import os, socket, sys

def tlv(t, v):
    if len(v) < 128:
        return bytes([t, len(v)]) + v
    b = len(v)
    out = b''
    while b:
        out = bytes([b & 0xFF]) + out
        b >>= 8
    return bytes([t, 0x80 | len(out)]) + out + v

def enc_int(n):
    if n == 0:
        return tlv(0x02, b'\x00')
    v = b''
    while n:
        v = bytes([n & 0xFF]) + v
        n >>= 8
    if v[0] & 0x80:
        v = b'\x00' + v
    return tlv(0x02, v)

def dec_int(b, i):
    l = b[i+1]; i += 2
    n = 0
    for _ in range(l):
        n = (n << 8) | b[i]; i += 1
    return n, i

def dec_len(b, i):
    l = b[i]
    if l < 128:
        return l, i+1
    n = l & 0x7f; i += 1
    v = 0
    for _ in range(n):
        v = (v << 8) | b[i]; i += 1
    return v, i

OID_DESCR = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0
OID_OBJID = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00])  # 1.3.6.1.2.1.1.2.0

def next_oid(oid):
    if oid == OID_DESCR:
        return OID_OBJID
    # walk start: a strict prefix of a known OID (e.g. .1.3.6.1.2.1.1)
    if len(oid) < len(OID_DESCR) and OID_DESCR[:len(oid)] == oid:
        return OID_DESCR
    if len(oid) < len(OID_OBJID) and OID_OBJID[:len(oid)] == oid:
        return OID_OBJID
    return None

def value_for(oid):
    if oid == OID_DESCR:
        return (0x04, b"tsm-gateway interop agent")
    if oid == OID_OBJID:
        return (0x06, b"\x2b\x06\x01\x02\x01\x01\x01\x00")  # sysDescr OID as value
    return None

def build_resp(data):
    i = 1
    _, i = dec_len(data, i)          # outer length
    ver, i = dec_int(data, i)
    assert data[i] == 0x04
    cl, i = dec_len(data, i+1)
    comm = data[i:i+cl]
    i += cl
    ptag = data[i]
    i += 1
    plen, i = dec_len(data, i)
    reqid, i = dec_int(data, i)
    _, i = dec_int(data, i)           # errStatus (non-repeaters for BULK)
    _, i = dec_int(data, i)           # errIndex (max-repetitions for BULK)
    assert data[i] == 0x30
    vlen, i = dec_len(data, i+1)
    end = i + vlen
    parts = []
    while i < end:
        assert data[i] == 0x30
        l2, j = dec_len(data, i+1)
        j2 = j + l2
        assert data[j] == 0x06
        ol, k = dec_len(data, j+1)
        oid = data[k:k+ol]
        i = j2
        if ptag == 0xA0:              # GET
            val = value_for(oid) or (0x81, b"")   # noSuchInstance
            parts.append(tlv(0x30, tlv(0x06, oid) + tlv(val[0], val[1])))
        elif ptag == 0xA1:            # GETNEXT
            nxt = next_oid(oid)
            if nxt is None:
                parts.append(tlv(0x30, tlv(0x06, oid) + tlv(0x82, b"")))  # endOfMibView
            else:
                v = value_for(nxt) or (0x04, b"tsm-gateway interop agent")
                parts.append(tlv(0x30, tlv(0x06, nxt) + tlv(v[0], v[1])))
        elif ptag == 0xA5:            # GETBULK: walk like GETNEXT (net-snmp
            # retries; endOfMibView on the next OID terminates the walk)
            nxt = next_oid(oid)
            if nxt is None:
                parts.append(tlv(0x30, tlv(0x06, oid) + tlv(0x82, b"")))  # endOfMibView
            else:
                v = value_for(nxt) or (0x04, b"tsm-gateway interop agent")
                parts.append(tlv(0x30, tlv(0x06, nxt) + tlv(v[0], v[1])))
        else:                         # SET etc: echo null value
            parts.append(tlv(0x30, tlv(0x06, oid) + tlv(0x05, b"\x00")))
    vbl = tlv(0x30, b''.join(parts))
    inner = enc_int(reqid) + enc_int(0) + enc_int(0) + vbl
    pdu = bytes([0xA2]) + tlv(0x30, inner)[1:]
    msg = tlv(0x30, enc_int(1) + tlv(0x04, comm) + pdu)
    return msg

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(os.environ["AGENT_PORT"])))
sys.stderr.write("agent up\n")
while True:
    data, addr = s.recvfrom(65536)
    try:
        s.sendto(build_resp(data), addr)
    except Exception as e:
        sys.stderr.write("agent err: %s\n" % e)
PY
AGENT_PID=$!
sleep 0.5

# ---------------------------------------------------------------- trap sink
SINK_FILE=$(mktemp)
SINK_PORT="$SINK_PORT" SINK_FILE="$SINK_FILE" CERTDIR="$CERTDIR" ./bin/tsm-sink \
    "$SINK_PORT" "$CERTDIR/server.crt" "$CERTDIR/server.key" \
    "$SINK_FILE" > /dev/null 2>&1 &
SINK_PID=$!
sleep 0.5

# ------------------------------------------------------------------- gateway
./bin/snmp-shield gateway \
    --listen "127.0.0.1:$GW_PORT" --agent "127.0.0.1:$AGENT_PORT" \
    --security tsm-gateway \
    --ca-file "$CERTDIR/ca.crt" --cert-file "$CERTDIR/server.crt" --key-file "$CERTDIR/server.key" \
    --trap-listen "127.0.0.1:$TRAP_PORT" --trap-sink "127.0.0.1:$SINK_PORT" &
GW_PID=$!
sleep 1

echo "== TSM gateway interop (dtls:$D) =="

V3T="-v3 -On -t 3 -r 2 --defSecurityModel=tsm"

# 1. GET
out=$(run_bounded 20 snmpget "dtls:$D" .1.3.6.1.2.1.1.1.0 $V3T 2>&1 | unnoisy) \
    && echo "$out" | grep -q "tsm-gateway interop agent" \
    && echo "PASS: snmpget" || { echo "FAIL: snmpget: $out"; fail=1; }

# 2. GETNEXT
out=$(run_bounded 20 snmpgetnext "dtls:$D" .1.3.6.1.2.1.1.1.0 $V3T 2>&1 | unnoisy) \
    && echo "$out" | grep -q "1.3.6.1.2.1.1.2.0" \
    && echo "PASS: snmpgetnext" || { echo "FAIL: snmpgetnext: $out"; fail=1; }

# 3. GETBULK walk
out=$(run_bounded 25 snmpbulkwalk -v3 -On -t 3 -r 2 --defSecurityModel=tsm "dtls:$D" .1.3.6.1.2.1.1 2>&1 | unnoisy) \
    && echo "$out" | grep -q "tsm-gateway interop agent" \
    && echo "PASS: snmpbulkwalk" || { echo "FAIL: snmpbulkwalk: $out"; fail=1; }

# 4. SET (relayed as clear v2c SET)
out=$(run_bounded 20 snmpset -v 3 "dtls:$D" .1.3.6.1.2.1.1.6.0 i 42 2>&1 | unnoisy) \
    && echo "PASS: snmpset" || { echo "FAIL: snmpset: $out"; fail=1; }

# 5. untrusted client (cert from another CA) must be rejected
REJDIR=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$REJDIR/other.key" -out "$REJDIR/other.crt" -days 2 -nodes \
    -subj "/CN=other-manager" \
    -addext "subjectAltName=DNS:other-manager" >/dev/null 2>&1
REJHOME="$SNMPHOME-rej"
mkdir -p "$REJHOME/.snmp/tls/ca-certs" "$REJHOME/.snmp/tls/certs"
cp "$REJDIR/other.crt" "$REJDIR/other.key" "$REJHOME/.snmp/tls/certs/"
cp "$REJDIR/other.crt" "$REJHOME/.snmp/tls/ca-certs/"   # self-signed: its own anchor
rej_fp=$(openssl x509 -in "$REJDIR/other.crt" -noout -fingerprint -sha256 | cut -d= -f2)
sed "s|clientCert .*|clientCert ${rej_fp}|" "$SNMPHOME/.snmp/snmp.conf" > "$REJHOME/.snmp/snmp.conf"

out=$(HOME="$REJHOME" SNMPCONFPATH="$REJHOME/.snmp" run_bounded 20 snmpget "dtls:$D" .1.3.6.1.2.1.1.1.0 $V3T 2>&1 | unnoisy) \
    && { echo "FAIL: untrusted client was NOT rejected: $out"; fail=1; } \
    || echo "PASS: untrusted client rejected"

# 6. trap direction: clear v2c trap at the gateway -> TSM notification at the sink
trap_pdu=$(python3 - <<'PY'
def tlv(t, v):
    if len(v) < 128:
        return bytes([t, len(v)]) + v
    b = len(v)
    out = b''
    while b:
        out = bytes([b & 0xFF]) + out
        b >>= 8
    return bytes([t, 0x80 | len(out)]) + out + v

ent = tlv(0x06, b'\x2b\x06\x01\x04\x01\x87\x2f')      # 1.3.6.1.4.1.9999
agent = tlv(0x40, bytes([10, 0, 0, 1]))               # NetworkAddress
ts = tlv(0x43, bytes([0x30, 0x39]))                   # TimeTicks 12345
inner = ent + agent + tlv(0x02, b'\x00') + tlv(0x02, b'\x00') + ts + tlv(0x30, b'')
pdu = bytes([0xA4]) + tlv(0x30, inner)[1:]
msg = tlv(0x30, b'\x02\x01\x00' + tlv(0x04, b'devicecomm') + pdu)
print(msg.hex())
PY
)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(bytes.fromhex('$trap_pdu'), ('127.0.0.1', $TRAP_PORT))
"
sleep 2
if [ -s "$SINK_FILE" ]; then
    echo "PASS: trap direction (TSM notification delivered to sink)"
else
    echo "FAIL: no TSM notification at the sink"
    fail=1
fi

# 7. chain alive after trap
out=$(run_bounded 20 snmpget "dtls:$D" .1.3.6.1.2.1.1.1.0 $V3T 2>&1 | unnoisy) \
    && echo "$out" | grep -q "tsm-gateway interop agent" \
    && echo "PASS: chain alive after trap" || { echo "FAIL: chain dead after trap: $out"; fail=1; }

if [ "$fail" -eq 0 ]; then
    echo "ALL PASS"
    exit 0
fi
exit 1
