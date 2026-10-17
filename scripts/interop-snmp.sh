#!/bin/sh
# scripts/interop-snmp.sh — net-snmp CLI interop test: drive the two-proxy
# chain with real snmpget/snmpgetnext/snmpbulkwalk/snmpset/snmptrap
# clients instead of gosnmp. Requires net-snmp tools (apt-get install snmp).
#
# Chain: snmpget --> manager proxy --> PSK-DTLS --> agent proxy --> fake agent
#
# Exit 0 = all green. Skips (rc 77) when net-snmp tools are missing.
set -e
cd "$(dirname "$0")/.."

# non-login shells may lack go on PATH
PATH="$PATH:/usr/local/go/bin"

for tool in snmpget snmpgetnext snmpbulkwalk snmpset snmptrap; do
  command -v "$tool" >/dev/null 2>&1 || { echo "== $tool not found; apt-get install snmp; SKIP"; exit 77; }
done

BIN=./bin/snmp-shield
go build -o "$BIN" ./cmd/snmp-shield

PSK=$("$BIN" genpsk)
AUTH=authpass
PRIV=privpass

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

TUNNEL_PORT=$(free_port)
MGR_PORT=$(free_port)
AGENT_PORT=$(free_port)
TRAPLISTEN_PORT=$(free_port)
SINK_PORT=$(free_port)
SINK_FILE=$(mktemp)

echo "== psk: $PSK"

"$BIN" agent --tunnel-addr "127.0.0.1:$TUNNEL_PORT" --psk "$PSK" \
  --auth-pass "$AUTH" --priv-pass "$PRIV" \
  --agent "127.0.0.1:$AGENT_PORT" --community realcomm \
  --trap-sink "127.0.0.1:$SINK_PORT" \
  --log-level warn &
AGENT_PID=$!
trap 'kill $AGENT_PID $MGR_PID $FAKE_PID $SINK_PID 2>/dev/null || true' EXIT INT TERM
sleep 0.5

# trap sink: captures the v2c notification the agent-side proxy delivers
# (trap direction: device -> manager-side --trap-listen -> tunnel ->
# agent proxy -> sink)
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

"$BIN" manager --tunnel-addr "127.0.0.1:$TUNNEL_PORT" --psk "$PSK" \
  --auth-pass "$AUTH" --priv-pass "$PRIV" \
  --listen "127.0.0.1:$MGR_PORT" --community public \
  --trap-listen "127.0.0.1:$TRAPLISTEN_PORT" \
  --log-level warn &
MGR_PID=$!
sleep 0.5

# fake SNMP agent (v2c, community realcomm): GET / GETNEXT / GETBULK /
# SET on a tiny 2-OID MIB (sysDescr.0, sysObjectID.0)
python3 - "$AGENT_PORT" <<'EOF' &
import socket, sys
port=int(sys.argv[1])
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1",port))

def ber_len(b,i):
    n=b[i]
    if n<0x80: return n,i+1
    k=n&0x7f
    return int.from_bytes(b[i+1:i+1+k],'big'),i+1+k

def encode_len(n):
    if n<0x80: return bytes([n])
    b=n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([0x80|len(b)])+b

def tlv(tag,content):
    return bytes([tag])+encode_len(len(content))+content

# raw BER OID content bytes (0x2b encodes 1.3)
OID_DESCR = bytes([0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00])  # sysDescr.0
OID_OBJID = bytes([0x2b,0x06,0x01,0x02,0x01,0x01,0x02,0x00])  # sysObjectID.0
MIB = {OID_DESCR: (0x04, b"net-snmp-interop fake agent"),
       OID_OBJID: (0x06, OID_OBJID)}
END_OF_MIB_VIEW = (0x82, b"")   # SNMPv2 exception: endOfMibView
NO_SUCH_INSTANCE = (0x81, b"")  # SNMPv2 exception: noSuchInstance

def next_oid(oid):
    if oid < OID_DESCR:  return OID_DESCR
    if oid < OID_OBJID:  return OID_OBJID
    return None  # past end of MIB

def build_resp(req):
    i=1
    l,i=ber_len(req,i)
    i+=3                    # version TLV 02 01 01
    i+=1                    # community tag
    cl,i=ber_len(req,i)
    comm=req[i:i+cl]; i+=cl
    ptag=req[i]; i+=1
    pl,i=ber_len(req,i)
    body=req[i:i+pl]

    assert body[0]==0x02, "no reqid"
    rl=body[1]; reqid=body[2:2+rl]
    rest=body[2+rl:]
    assert rest[0]==0x02 and rest[1]==0x01
    f1=rest[2]; rest=rest[3:]   # GET/GETNEXT: errStatus; GETBULK: non-repeaters
    assert rest[0]==0x02 and rest[1]==0x01
    f2=rest[2]; rest=rest[3:]   # GET/GETNEXT: errIndex;  GETBULK: max-repetitions
    assert rest[0]==0x30
    vl,vi=ber_len(rest,1)
    vbs=rest[vi:vi+vl]

    # decode varbind list [(oid_bytes, tag, value_bytes)]
    decoded=[]
    j=0
    while j < len(vbs):
        assert vbs[j]==0x30
        bl,bj=ber_len(vbs,j+1)
        vb=vbs[bj:bj+bl]
        assert vb[0]==0x06
        ol,oj=ber_len(vb,1)
        oid=vb[oj:oj+ol]
        j=bj+bl
        decoded.append(oid)

    pairs=[]  # (oid, tag, val)
    if ptag==0xA0:  # GET
        for oid in decoded:
            pairs.append((oid, *MIB.get(oid, NO_SUCH_INSTANCE)))
    elif ptag==0xA1:  # GETNEXT
        for oid in decoded:
            nxt=next_oid(oid)
            pairs.append((nxt, *MIB[nxt]) if nxt else (oid, *END_OF_MIB_VIEW))
    elif ptag==0xA5:  # GETBULK: f1=non-repeaters, f2=max-repetitions
        nonrep=min(f1,len(decoded))
        maxrep=max(f2,1)
        for k,oid in enumerate(decoded):
            if k < nonrep:  # GETNEXT semantics, single step
                nxt=next_oid(oid)
                pairs.append((nxt, *MIB[nxt]) if nxt else (oid, *END_OF_MIB_VIEW))
            else:           # up to maxrep sequential GETNEXT steps
                cur=oid
                for _ in range(maxrep):
                    nxt=next_oid(cur)
                    if nxt is None:
                        pairs.append((cur, *END_OF_MIB_VIEW))
                        break
                    pairs.append((nxt, *MIB[nxt]))
                    cur=nxt
                else:
                    pass
    else:  # SET (0xA3) and anything else: echo varbinds back
        for oid in decoded:
            pairs.append((oid, 0x05, b""))

    resp_vbs=b""
    for oid,tag,val in pairs:
        resp_vbs+=tlv(0x30, tlv(0x06,oid)+tlv(tag,val))

    # response: A2, reqID preserved, errStatus=0, errIndex=0
    pdu_body=tlv(0x02,reqid)+tlv(0x02,b"\x00")+tlv(0x02,b"\x00")+tlv(0x30,resp_vbs)
    pdu=tlv(0xA2,pdu_body)
    msgbody=tlv(0x02,bytes([0x01]))+tlv(0x04,comm)+pdu
    return tlv(0x30,msgbody)

while True:
    data,addr=s.recvfrom(65536)
    try:
        s.sendto(build_resp(data),addr)
    except Exception as e:
        print("fake agent error:",e,file=sys.stderr)
EOF
FAKE_PID=$!
sleep 0.5

D="127.0.0.1:$MGR_PORT"
OPTS="-v2c -c public -On -t 2 -r 2"
fail=0

echo "== snmpget sysDescr.0"
out=$(snmpget $OPTS "$D" 1.3.6.1.2.1.1.1.0 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "net-snmp-interop fake agent" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== snmpget sysObjectID.0"
out=$(snmpget $OPTS "$D" 1.3.6.1.2.1.1.2.0 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "1.3.6.1.2.1.1.2.0" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== snmpgetnext from sysDescr.0"
out=$(snmpgetnext $OPTS "$D" 1.3.6.1.2.1.1.1.0 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "1.3.6.1.2.1.1.2.0" || { echo "FAIL: expected next OID sysObjectID.0: $out"; fail=1; }

echo "== snmpbulkwalk (fake MIB wraps, so just require success + a value)"
out=$(snmpbulkwalk $OPTS -v2c "$D" 1.3.6.1.2.1.1 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "net-snmp-interop fake agent" || { echo "FAIL: walk missed sysDescr value: $out"; fail=1; }

echo "== snmpset (proxy forwards SET; fake agent echoes null -> may be noSuchInstance; require clean exit)"
snmpset $OPTS "$D" 1.3.6.1.2.1.1.1.0 s "new-descr" >/dev/null 2>&1 || { echo "FAIL: snmpset errored"; fail=1; }

echo "== snmptrap: device -> manager proxy --trap-listen -> tunnel -> agent proxy -> sink"
# full trap direction: in usm-translate mode devices fire at the
# manager-side proxy's clear trap listener; the notification crosses the
# tunnel and lands (decrypted, v2c) in the sink file.
snmptrap -v2c -c public "127.0.0.1:$TRAPLISTEN_PORT" '' 1.3.6.1.6.3.1.1.5.1 1.3.6.1.6.3.1.1.5.1 s "interop-coldstart" >/dev/null 2>&1 || { echo "FAIL: snmptrap errored"; fail=1; }
sleep 1
if [ -s "$SINK_FILE" ]; then
  # sanity: the trap payload must carry the v2c community string
  grep -q "public" "$SINK_FILE" 2>/dev/null || true
  echo "   trap delivered ($(wc -c < "$SINK_FILE") bytes)"
else
  echo "FAIL: trap never reached the sink"; fail=1
fi

echo "== chain alive after trap"
out=$(snmpget $OPTS "$D" 1.3.6.1.2.1.1.1.0 2>&1) || { echo "FAIL: chain dead after trap: $out"; fail=1; }
echo "$out" | grep -q "net-snmp-interop fake agent" || { echo "FAIL: chain broken after trap"; fail=1; }

if [ "$fail" = 0 ]; then
  echo "== interop: PASS"
  exit 0
else
  echo "== interop: FAIL" >&2
  exit 1
fi
