#!/usr/bin/env bash
#
# Generates the self-signed TLS material the production-like stack serves:
# a small lab CA and one leaf certificate for auth.lab.easyoidc.local.
#
#   ./deploy/make-lab-cert.sh          # idempotent: does nothing if valid
#   ./deploy/make-lab-cert.sh --force  # throw it away and start again
#
# Output (deploy/tls/, gitignored — this is key material):
#   ca.crt / ca.key     the lab certification authority
#   auth.crt / auth.key what nginx serves
#
# LABORATORY ONLY. In production the certificate comes from the customer's PKI
# and nothing in this repository generates it. What the lab must reproduce
# faithfully is the *shape*: the certificate names the public FQDN, which is
# also the name inside the Kerberos SPN and the host of ISSUER_URL. Those three
# names are one name; a certificate for a different one is a deployment that
# fails in three places at once.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLS_DIR="${HERE}/tls"
FQDN="${AUTH_PUBLIC_FQDN:-auth.lab.easyoidc.local}"
# The address nginx holds on the lab network, so `curl https://172.28.10.40`
# is diagnosable too. It is a Subject Alternative Name, never the CN.
NGINX_IP="${AUTH_PUBLIC_IP:-172.28.10.40}"
DAYS="${CERT_DAYS:-825}"

force=false
[ "${1:-}" = "--force" ] && force=true

mkdir -p "$TLS_DIR"
chmod 700 "$TLS_DIR"

if ! $force && [ -f "$TLS_DIR/auth.crt" ] && [ -f "$TLS_DIR/auth.key" ]; then
    if openssl x509 -in "$TLS_DIR/auth.crt" -noout -checkend 86400 >/dev/null 2>&1; then
        echo "already present: $TLS_DIR/auth.crt"
        openssl x509 -in "$TLS_DIR/auth.crt" -noout -subject -dates -ext subjectAltName
        exit 0
    fi
    echo "existing certificate is expired or expiring: regenerating"
fi

echo "generating a lab CA and a certificate for ${FQDN} in ${TLS_DIR}"

# --- the CA -----------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" \
    -subj "/CN=the platform auth-server lab CA/O=the platform/C=IT" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# --- the leaf ---------------------------------------------------------------
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$TLS_DIR/auth.key" -out "$TLS_DIR/auth.csr" \
    -subj "/CN=${FQDN}/O=the platform/C=IT" 2>/dev/null

cat >"$TLS_DIR/auth.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${FQDN},IP:${NGINX_IP}
EXT

openssl x509 -req -in "$TLS_DIR/auth.csr" -sha256 -days "$DAYS" \
    -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -extfile "$TLS_DIR/auth.ext" -out "$TLS_DIR/auth.crt" 2>/dev/null

rm -f "$TLS_DIR/auth.csr" "$TLS_DIR/auth.ext" "$TLS_DIR/ca.srl"

# nginx runs as a non-root user inside its container after dropping privileges,
# but the master process reads the key as root, so 0600 is enough and correct.
chmod 600 "$TLS_DIR/ca.key" "$TLS_DIR/auth.key"
chmod 644 "$TLS_DIR/ca.crt" "$TLS_DIR/auth.crt"

openssl x509 -in "$TLS_DIR/auth.crt" -noout -subject -issuer -dates -ext subjectAltName
echo "done: $TLS_DIR"
