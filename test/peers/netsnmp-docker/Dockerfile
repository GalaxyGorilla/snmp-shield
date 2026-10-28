# Modern net-snmp for the conformance matrix.
#
# The host's net-snmp is whatever the OS ships (Apple ships 5.6.2.1, built
# without TLS), so it cannot act as an RFC 6353 TSM peer and cannot show how
# a current release reacts to our messages. This image is deliberately tiny
# and unpinned-in-spirit: it exists to run `snmpget`/`snmpwalk`/`snmpset`
# over `dtls:` as an independent TSM client, and to run the same adapter a
# native net-snmp peer would (hence python3) against a current release.
#
# The TSM client needs a writable HOME: net-snmp keeps its certificate index
# under $HOME/.snmp/tls and refuses to start when it cannot create it.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      snmp snmptrapd ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*

ENV HOME=/home/peer \
    SNMPCONFPATH=/home/peer/.snmp

RUN mkdir -p /home/peer/.snmp/tls/ca-certs \
             /home/peer/.snmp/tls/certs \
             /home/peer/.snmp/tls/private

WORKDIR /home/peer
