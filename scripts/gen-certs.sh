#!/usr/bin/env bash
# Generate a throwaway PKI for TLS/DTLS tunnel testing:
#   certs/ca.{crt,key}, certs/{server,client}.{crt,key}
# Server SANs: snmp-proxy-agent, localhost, 127.0.0.1
# Client SANs: snmp-proxy-manager
#
# Output lands in certs/ (gitignored). For testing only.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p certs

DAYS=825
CA_CN="snmp-proxy test CA"
SRV_CN="snmp-proxy-agent"
CLI_CN="snmp-proxy-manager"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/ca.key -out certs/ca.crt -days "$DAYS" -nodes \
  -subj "/CN=${CA_CN}" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/server.key -out certs/server.csr -nodes \
  -subj "/CN=${SRV_CN}"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/client.key -out certs/client.csr -nodes \
  -subj "/CN=${CLI_CN}"

openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days "$DAYS" \
  -extfile <(printf '%s\n' \
    "subjectAltName=DNS:snmp-proxy-agent,DNS:localhost,IP:127.0.0.1" \
    "extendedKeyUsage=serverAuth")

openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/client.crt -days "$DAYS" \
  -extfile <(printf '%s\n' \
    "subjectAltName=DNS:snmp-proxy-manager" \
    "extendedKeyUsage=clientAuth")

rm -f certs/server.csr certs/client.csr
chmod 600 certs/*.key

echo "wrote certs/ca.{crt,key} certs/server.{crt,key} certs/client.{crt,key}"
