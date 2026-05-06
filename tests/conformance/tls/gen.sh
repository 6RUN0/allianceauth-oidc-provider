#!/usr/bin/env sh
# Generate a self-signed CA + server cert for the conformance provider.
#
# The CA cert is mounted into the suite container's trust store so the
# suite's HTTPS client (Spring HttpClient) accepts our provider's
# self-signed cert. Re-run after editing SAN list; the existing files
# are intentionally NOT committed (see .gitignore).
#
# Usage:
#   sh tests/conformance/tls/gen.sh

set -eu
cd "$(dirname "$0")"

# 1) Root CA — long-lived, signs provider cert.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
    -days 3650 -subj "/CN=allianceauth-oidc-conformance-CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# 2) Provider key + CSR.
openssl req -newkey rsa:2048 -nodes -keyout provider.key -out provider.csr \
    -subj "/CN=provider" 2>/dev/null

# 3) Sign provider cert with CA. SAN covers the docker-DNS hostname
#    plus localhost forms so a developer can also curl from the host.
cat > provider.ext <<EXT
subjectAltName = DNS:provider, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EXT

openssl x509 -req -in provider.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out provider.crt -days 825 \
    -extfile provider.ext 2>/dev/null

rm -f provider.csr provider.ext ca.srl

echo "Generated:"
ls -1 ca.crt provider.crt provider.key
