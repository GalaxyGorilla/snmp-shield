#!/bin/sh
# scripts/smoke-cli.sh — plug-and-play smoke test: two snmp-proxy instances
# configured entirely by flags (no YAML), fake Go SNMP agent, gosnmp client
# GET through the PSK-DTLS tunnel. Requires the repo built (go build).
set -e
cd "$(dirname "$0")/.."

# non-login shells may lack go on PATH
PATH="$PATH:/usr/local/go/bin"

BIN=./bin/snmp-proxy
go build -o "$BIN" ./cmd/snmp-proxy

PSK=$("$BIN" genpsk)
AUTH=authpass CLI=privpass
AUTH=authpass
PRIV=privpass

# free ports
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
MET1=$(free_port)
MET2=$(free_port)

echo "== psk: $PSK"

"$BIN" agent --tunnel-addr "127.0.0.1:$TUNNEL_PORT" --psk "$PSK" \
  --auth-pass "$AUTH" --priv-pass "$PRIV" \
  --agent "127.0.0.1:$AGENT_PORT" --community realcomm \
  --metrics-addr "127.0.0.1:$MET2" --log-level debug &
AGENT_PID=$!
trap 'kill $AGENT_PID $MGR_PID $FAKE_PID 2>/dev/null || true' EXIT
sleep 0.5

"$BIN" manager --tunnel-addr "127.0.0.1:$TUNNEL_PORT" --psk "$PSK" \
  --auth-pass "$AUTH" --priv-pass "$PRIV" \
  --listen "127.0.0.1:$MGR_PORT" --community public \
  --metrics-addr "127.0.0.1:$MET1" --log-level debug &
MGR_PID=$!
sleep 0.5

# fake SNMP agent (v2c, community realcomm) answering sysDescr.0
FAKE_PID=$(
python3 - "$AGENT_PORT" <<'EOF' &
import socket, sys, threading
port=int(sys.argv[1])
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1",port))
# v2c GET response builder: echo reqID, answer first varbind with a string
def build_resp(req):
    # minimal parse: version int, community, PDU tag/len, reqID int
    # request: 30 len 02 01 01 04 len comm A0 len 02 len reqid ...
    def ber_len(b,i):
        n=b[i]
        if n<0x80: return n,i+1
        k=n&0x7f
        return int.from_bytes(b[i+1:i+1+k],'big'),i+1+k
    i=1
    l,i=ber_len(req,i)          # outer content len
    i+=3                        # skip version TLV 02 01 01
    i+=1                        # skip community TAG 0x04; ber_len starts at length
    cl,i=ber_len(req,i)          # community len
    comm=req[i:i+cl]; i+=cl
    ptag=req[i]; i+=1
    pl,i=ber_len(req,i)
    body=req[i:i+pl]
    # reqID = first integer in body
    assert body[0]==0x02
    rl=body[1]
    reqid=body[2:2+rl]
    # response PDU: A2, same reqID, err 0 0, varbind with sysDescr
    vb_oid=bytes([0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00])  # 1.3.6.1.2.1.1.1.0
    val=b"fake-agent(cli-smoke)"
    vb=bytes([0x30,len(vb_oid)+2+len(val)])+vb_oid+bytes([0x04,len(val)])+val
    vbs=bytes([0x30,len(vb)])+vb
    pdu_body=bytes([0x02,len(reqid)])+reqid+bytes([0x02,0x01,0x00,0x02,0x01,0x00])+vbs
    pdu=bytes([0xA2,len(pdu_body)])+pdu_body
    msg=bytes([0x02,0x01,0x01])+bytes([0x04,len(comm)])+comm+pdu
    return bytes([0x30,len(msg)])+msg
while True:
    data,addr=s.recvfrom(65536)
    try:
        s.sendto(build_resp(data),addr)
    except Exception as e:
        print("fake agent error:",e,file=sys.stderr)
EOF
echo $!
)

sleep 0.5

# gosnmp client GET through the whole chain
go run ./scripts/smoke-client "$MGR_PORT"

RC=$?
echo "== smoke client rc=$RC"
exit $RC
