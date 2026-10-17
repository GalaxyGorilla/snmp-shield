#!/bin/sh
# scripts/interop-manager-gateway.sh — net-snmp interop test for the
# manager-gateway mode (the reverse direction of the usm-gateway):
# a legacy v2c manager talks clear SNMP to the proxy's front leg; the
# proxy re-issues every request as SNMPv3 USM authPriv toward a REAL
# snmpd (engine discovery, signed + encrypted requests), verifies and
# decrypts the responses and strips them back to clear v2c.
#
# Chain: snmpget -v2c --> gateway proxy --> v3 USM authPriv --> real snmpd
# Trap:  v3 snmptrap (agent user) --> gateway --trap-listen --> clear v2c --> sink
#
# Requires net-snmp tools + the snmpd binary (apt-get install snmp snmpd).
# Exit 0 = all green. Skips (rc 77) when tools are missing.
set -e
cd "$(dirname "$0")/.."

# non-login shells may lack go on PATH
PATH="$PATH:/usr/local/go/bin"

for tool in snmpget snmpgetnext snmpbulkwalk snmpset; do
  command -v "$tool" >/dev/null 2>&1 || { echo "== $tool not found; apt-get install snmp; SKIP"; exit 77; }
done
command -v /usr/sbin/snmpd >/dev/null 2>&1 || { echo "== snmpd not found; apt-get install snmpd; SKIP"; exit 77; }

BIN=./bin/snmp-shield
go build -o "$BIN" ./cmd/snmp-shield

# The REAL AGENT's v3 credentials (the gateway authenticates as this user
# toward snmpd; the v2c manager never sees them).
AUTH=authpass123
PRIV=privpass123

# free ports (UDP)
free_port() {
  python3 - <<EOF
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
EOF
}

GW_PORT=$(free_port)
AGENT_PORT=$(free_port)
TRAPLISTEN_PORT=$(free_port)
SINK_PORT=$(free_port)
SINK_FILE=$(mktemp)
SNMPD_CONF=$(mktemp)
SNMPD_LOG=$(mktemp)

cat > "$SNMPD_CONF" <<EOF
createUser authPrivUser SHA "$AUTH" AES "$PRIV"
rouser authPrivUser authpriv
agentaddress 127.0.0.1:$AGENT_PORT
EOF

# start the gateway FIRST so its trap listener is bound before snmpd's
# startup coldStart trap fires (snmpd does not retry traps)
"$BIN" gateway \
  --security usm-manager-gateway \
  --listen "127.0.0.1:$GW_PORT" \
  --agent "127.0.0.1:$AGENT_PORT" \
  --user authPrivUser \
  --auth-pass "$AUTH" --priv-pass "$PRIV" \
  --trap-listen "127.0.0.1:$TRAPLISTEN_PORT" \
  --trap-sink "127.0.0.1:$SINK_PORT" \
  --log-level warn &
GW_PID=$!
trap 'kill $GW_PID $SNMPD_PID $SINK_PID 2>/dev/null || true' EXIT INT TERM
sleep 0.5

# clear v2c trap sink: captures the clear notifications the gateway relays
# toward the legacy manager's trap receiver.
python3 - "$SINK_PORT" "$SINK_FILE" <<'EOF' &
import socket, sys
port=int(sys.argv[1]); path=sys.argv[2]
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1",port))
while True:
    data,addr=s.recvfrom(65536)
    with open(path,"ab") as f:
        f.write(data)
EOF
SINK_PID=$!

# REAL snmpd (v3 USM authPriv, user authPrivUser) — the gateway performs
# RFC 3414 engine discovery against it, then signs+encrypts every request.
/usr/sbin/snmpd -f -Le -C -c "$SNMPD_CONF" > "$SNMPD_LOG" 2>&1 &
SNMPD_PID=$!
sleep 1

if ! kill -0 "$SNMPD_PID" 2>/dev/null; then
  echo "== snmpd failed to start:"; cat "$SNMPD_LOG"; exit 1
fi

D="127.0.0.1:$GW_PORT"
V2C="-v2c -c public -On -t 2 -r 2"
V3V2C="-v3 -l authPriv -u authPrivUser -a SHA -A $AUTH -x AES -X $PRIV -On -t 2 -r 2"
fail=0

echo "== snmpget sysDescr.0 (clear v2c manager leg, v3 authPriv toward real snmpd)"
out=$(snmpget $V2C "$D" 1.3.6.1.2.1.1.1.0 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "STRING" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== snmpget sysUpTime.0 (second request exercises the 60s engine cache)"
out=$(snmpget $V2C "$D" 1.3.6.1.2.1.1.3.0 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "Timeticks\|STRING" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== snmpgetnext from sysDescr.0"
out=$(snmpgetnext $V2C "$D" 1.3.6.1.2.1.1.1.0 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "1.3.6.1.2.1.1.2.0" || { echo "FAIL: expected next OID sysObjectID.0: $out"; fail=1; }

echo "== snmpbulkwalk system subtree"
out=$(snmpbulkwalk $V2C "$D" 1.3.6.1.2.1.1 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "STRING" || { echo "FAIL: walk missed values: $out"; fail=1; }

echo "== snmpset (relayed as v3 SET; read-only rouser -> real snmpd error response, NOT a timeout)"
out=$(snmpset $V2C "$D" 1.3.6.1.2.1.1.1.0 s "nope" 2>&1) || true
echo "$out" | grep -q "Timeout" && { echo "FAIL: SET timed out (no round trip): $out"; fail=1; }
echo "$out" | grep -q "Error in packet" || echo "   note: snmpset returned: $out"

echo "== v3 on the manager front leg is ignored (v2c-only by design)"
if snmpget $V3V2C "$D" 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
  echo "FAIL: v3 was accepted on the clear front leg"; fail=1
else
  echo "   v3 ignored on the clear front leg (protection works)"
fi

echo "== v3 authPriv trap -> gateway --trap-listen -> clear v2c -> sink"
# trap direction: a real agent's v3 USM authPriv notification is verified,
# decrypted and relayed as a clear v2c trap toward the legacy manager.
# A bare snmpd sends no traps without a sink configured, so fire one the
# way a real device would (snmptrap with the agent's v3 user); the
# engineID is arbitrary — the gateway localizes keys to the wire engineID.
snmptrap -v3 -l authPriv -u authPrivUser -a SHA -A "$AUTH" -x AES -X "$PRIV" \
  -e 80001f8880deadbeef00000001 -On -t 2 -r 1 \
  "127.0.0.1:$TRAPLISTEN_PORT" '' 1.3.6.1.6.3.1.1.5.1 1.3.6.1.6.3.1.1.5.1 s "mgw-interop-coldstart" >/dev/null 2>&1 || { echo "FAIL: snmptrap errored"; fail=1; }
sleep 1
if [ -s "$SINK_FILE" ]; then
  echo "   trap delivered ($(wc -c < "$SINK_FILE") bytes)"
else
  echo "FAIL: trap never reached the sink"; fail=1
fi

echo "== chain alive after trap"
out=$(snmpget $V2C "$D" 1.3.6.1.2.1.1.1.0 2>&1) || { echo "FAIL: chain dead after trap: $out"; fail=1; }
echo "$out" | grep -q "STRING" || { echo "FAIL: chain broken after trap"; fail=1; }

if [ "$fail" = 0 ]; then
  echo "== manager-gateway interop: PASS"
  exit 0
else
  echo "== manager-gateway interop: FAIL" >&2
  exit 1
fi
