#!/usr/bin/env bash
#
# Phase 5 acceptance: the production image, behind nginx over TLS, against the
# real laboratory domain. Everything below goes THROUGH the proxy — there is no
# request in this script that talks to the application directly.
#
#   cd applications/auth-server
#   ./deploy/make-lab-cert.sh
#   docker compose -f docker-compose.prod-like.yml up -d --build
#   docker compose -f docker-compose.prod-like.yml --profile test up -d
#   ./deploy/test-prod-like.sh
#
# Where things run:
#   - the client is auth-prod-like-client on the lab network (kinit, curl);
#   - the name auth.lab.easyoidc.local is pinned to nginx with curl's
#     --resolve. Kerberos builds the SPN from the URL's hostname, not from the
#     address it connects to, so SSO works exactly as it would with a DNS record
#     pointing here — and the laboratory's own DNS record is left alone;
#   - the certificate is verified against the lab CA (--cacert), never skipped.
#
# What it touches and restores: luigi.verdi is disabled and re-enabled on the
# domain controller (samba-tool), and this stack is taken down and brought back
# up once, on purpose. The domain controller itself is never stopped.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMPOSE=(docker compose -f docker-compose.prod-like.yml)
REALM=LAB.EASYOIDC.LOCAL
USER_PASSWORD="${LAB_USER_PASSWORD:-Lab.Passw0rd!}"
AUTH_FQDN=auth.lab.easyoidc.local
NGINX_IP=172.28.10.40
AUTH_BASE="https://${AUTH_FQDN}"
CURL_OPTS="--resolve ${AUTH_FQDN}:443:${NGINX_IP} --cacert /lab/ca.crt"
CURL_OPTS_HTTP="--resolve ${AUTH_FQDN}:80:${NGINX_IP}"

SERVER=auth-prod-like-auth-server
NGINX=auth-prod-like-nginx
MONGO=auth-prod-like-mongo
CLIENT=auth-prod-like-client
DC=auth-lab-dc
FLOW=./lab/sso-flow.sh

failures=0

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
step()    { printf '\033[0;36m--- %s\033[0m\n' "$*"; }
pass()    { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail()    { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }

# Reads one `KEY value` line out of a flow transcript; the LAST occurrence wins.
field() {
    printf '%s\n' "$1" \
        | awk -v k="$2" '$1 == k { $1=""; sub(/^ /,""); v=$0 } END { print v }'
}

check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "${label}: ${actual}"
    else
        fail "${label}: expected ${expected}, got ${actual:-<empty>}"
    fi
}

contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        pass "${label}"
    else
        fail "${label}: ${needle@Q} not found"
    fi
}

# One OAuth2 exchange, driven from inside the client container, over TLS.
flow() {
    docker exec -i \
        -e "AUTH_BASE=${AUTH_BASE}" \
        -e "CURL_OPTS=${CURL_OPTS}" \
        "$@" "$CLIENT" bash -s <"$FLOW"
}

# curl through the proxy, from inside the client container.
proxied() { docker exec "$CLIENT" curl -sS $CURL_OPTS "$@"; }

log_mark() { LOG_MARK="$(docker logs "$SERVER" 2>&1 | wc -l)"; }
log_since() { docker logs "$SERVER" 2>&1 | tail -n "+$((LOG_MARK + 1))"; }

restore() {
    printf '\n\033[1;36m=== restoring the laboratory ===\033[0m\n'
    docker exec "$DC" samba-tool user enable luigi.verdi 2>&1 | sed 's/^/  /'
}
trap restore EXIT

# ---------------------------------------------------------------------------
section "0. preconditions"
# ---------------------------------------------------------------------------
for container in "$DC" "$CLIENT" "$SERVER" "$NGINX" "$MONGO"; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = true ]; then
        pass "${container} is running"
    else
        fail "${container} is not running"
    fi
done
if [ "$failures" -ne 0 ]; then
    printf '\nBring the stack up first (see the header of this script).\n'
    exit 1
fi

step "the application container's healthcheck"
printf '  %s\n' "$(docker inspect -f '{{.State.Health.Status}}' "$SERVER")"
check "healthcheck" healthy "$(docker inspect -f '{{.State.Health.Status}}' "$SERVER")"

step "docker exec ${SERVER} id"
whoami_line="$(docker exec "$SERVER" id)"
printf '  %s\n' "$whoami_line"
if [[ "$whoami_line" == uid=0* ]]; then
    fail "the application runs as root"
else
    pass "the application does not run as root: ${whoami_line}"
fi

docker exec "$DC" samba-tool user enable luigi.verdi >/dev/null 2>&1

# ---------------------------------------------------------------------------
section "1. TLS: discovery and JWKS through nginx, and the HTTP redirect"
# ---------------------------------------------------------------------------
step "GET https://${AUTH_FQDN}/.well-known/openid-configuration"
discovery="$(proxied "${AUTH_BASE}/.well-known/openid-configuration")"
printf '  %s\n' "$(printf '%s' "$discovery" | head -c 300)…"
contains "the issuer is the https public name" "\"issuer\":\"${AUTH_BASE}\"" "$discovery"
contains "the authorization endpoint is https" "\"authorization_endpoint\":\"${AUTH_BASE}/auth\"" "$discovery"
contains "the token endpoint is https" "\"token_endpoint\":\"${AUTH_BASE}/token\"" "$discovery"
contains "the jwks uri is https" "\"jwks_uri\":\"${AUTH_BASE}/jwks\"" "$discovery"

step "GET https://${AUTH_FQDN}/jwks"
jwks="$(proxied "${AUTH_BASE}/jwks")"
printf '  %s\n' "$(printf '%s' "$jwks" | head -c 300)…"
contains "the signing key is published" '"kty":"RSA"' "$jwks"
contains "the algorithm is RS256" '"alg":"RS256"' "$jwks"

step "GET http://${AUTH_FQDN}/health (plain HTTP)"
redirect="$(docker exec "$CLIENT" curl -sS -i $CURL_OPTS_HTTP "http://${AUTH_FQDN}/health")"
printf '%s\n' "$redirect" | head -4 | sed 's/^/  /'
contains "plain HTTP is redirected" '301 Moved Permanently' "$redirect"
contains "…to the https public name" "Location: ${AUTH_BASE}/health" "$redirect"

step "GET ${AUTH_BASE}/health"
health="$(proxied "${AUTH_BASE}/health")"
printf '  %s\n' "$health"
contains "the server is healthy through the proxy" '"status":"ok"' "$health"
contains "…and it speaks spnego" '"identityProvider":"spnego"' "$health"
contains "…against mongodb" '"mongo":"ok"' "$health"

# ---------------------------------------------------------------------------
section "2. silent SSO through nginx: kinit + curl --negotiate"
# ---------------------------------------------------------------------------
step "kinit mario.rossi@${REALM} inside ${CLIENT}"
docker exec -i "$CLIENT" bash -c \
    "kdestroy -A 2>/dev/null; printf '%s\n' '${USER_PASSWORD}' | kinit mario.rossi@${REALM} && klist" \
    | sed 's/^/  /'

log_mark
out="$(flow -e MODE=sso)"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
check "sub claim" mario.rossi "$(field "$out" ID_SUB)"
check "realm claim" "$REALM" "$(field "$out" ID_REALM)"
MARIO_REFRESH="$(field "$out" REFRESH_TOKEN)"
if [ -n "$MARIO_REFRESH" ]; then
    pass "a refresh token was issued"
else
    fail "no refresh token was issued"
fi
step "server log"
log_since | grep -E 'SPNEGO handshake|login accepted' | sed 's/^/  /'
contains "the server completed the Kerberos handshake" 'SPNEGO handshake completed' "$(log_since)"

# ---------------------------------------------------------------------------
section "3. no ticket: the fallback form, through the proxy"
# ---------------------------------------------------------------------------
step "kdestroy -A"
docker exec "$CLIENT" kdestroy -A
out="$(flow -e MODE=sso)"
check "challenge status" 401 "$(field "$out" CHALLENGE_STATUS)"
check "WWW-Authenticate: Negotiate survived the proxy" yes "$(field "$out" CHALLENGE_NEGOTIATE)"
check "the fallback form is in the body" yes "$(field "$out" CHALLENGE_BODY_HAS_FORM)"

step "the same form, with the domain password"
out="$(flow -e MODE=form -e FORM_USERNAME=mario.rossi -e "FORM_PASSWORD=${USER_PASSWORD}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
check "sub claim" mario.rossi "$(field "$out" ID_SUB)"

step "and with the wrong one"
out="$(flow -e MODE=form -e FORM_USERNAME=mario.rossi -e FORM_PASSWORD=password-sbagliata)"
check "challenge status" 401 "$(field "$out" CHALLENGE_STATUS)"
check "no authorization code" "-" "$(field "$out" AUTH_CODE)"
contains "the form says so in Italian" 'Nome utente o password non corretti' "$(field "$out" CHALLENGE_ALERT)"

# ---------------------------------------------------------------------------
section "4. refresh through the proxy, and a disabled account"
# ---------------------------------------------------------------------------
step "refresh mario.rossi's token"
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${MARIO_REFRESH}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
MARIO_REFRESH="$(field "$out" REFRESH_TOKEN)"
if [ -n "$MARIO_REFRESH" ]; then
    pass "the refresh token rotated"
else
    fail "no rotated refresh token came back"
fi

step "log luigi.verdi in while the account is still enabled"
out="$(flow -e MODE=form -e FORM_USERNAME=luigi.verdi -e "FORM_PASSWORD=${USER_PASSWORD}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
LUIGI_REFRESH="$(field "$out" REFRESH_TOKEN)"

step "docker exec ${DC} samba-tool user disable luigi.verdi"
docker exec "$DC" samba-tool user disable luigi.verdi | sed 's/^/  /'

step "his refresh token, through the proxy"
log_mark
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${LUIGI_REFRESH}")"
check "token endpoint status" 400 "$(field "$out" TOKEN_STATUS)"
check "error" invalid_grant "$(field "$out" TOKEN_ERROR)"
step "server log"
log_since | grep -E 'account_disabled|refresh rejected' | sed 's/^/  /'
logs="$(log_since)"
contains "the log names account_disabled" '"reason":"account_disabled"' "$logs"
contains "the grant chain was revoked" '"revoked":true' "$logs"

step "docker exec ${DC} samba-tool user enable luigi.verdi"
docker exec "$DC" samba-tool user enable luigi.verdi | sed 's/^/  /'

# ---------------------------------------------------------------------------
section "5. a 12 KB Authorization header must reach the application"
# ---------------------------------------------------------------------------
# The point is nginx, not the token: a made-up bearer that the application
# rejects with 401 invalid_token proves the header crossed the proxy intact.
# A 400 or a 431 here would mean nginx cut it, which is exactly what happens to
# a domain user with many group memberships when the buffers are left at their
# defaults.
step "GET ${AUTH_BASE}/me with a ~12 KB bearer token"
big="$(docker exec "$CLIENT" bash -c \
    'printf "Authorization: Bearer %s" "$(head -c 9000 /dev/urandom | base64 -w0)" > /tmp/bighdr; wc -c </tmp/bighdr')"
printf '  header line: %s bytes\n' "$big"
bigout="$(docker exec "$CLIENT" bash -c \
    "curl -sS -o /dev/null -D - $CURL_OPTS -H \"\$(cat /tmp/bighdr)\" '${AUTH_BASE}/me'")"
printf '%s\n' "$bigout" | head -6 | sed 's/^/  /'
status="$(printf '%s' "$bigout" | head -1 | awk '{print $2}' | tr -d '\r')"
case "$status" in
    400|431) fail "nginx rejected the big header with ${status}" ;;
    401)     pass "the header crossed the proxy: the application answered 401" ;;
    *)       fail "unexpected status ${status}" ;;
esac
contains "and it answered as the resource server, not as a proxy" 'invalid_token' "$bigout"

# ---------------------------------------------------------------------------
section "6. down + up: the tokens already issued survive"
# ---------------------------------------------------------------------------
# The RS256 signing key and the whole grant chain live in MongoDB, in a named
# volume. `down` destroys the containers and keeps the volume; if the key were
# regenerated at boot, every token in circulation would die with the restart.
step "signing key id before the restart"
kid_before="$(printf '%s' "$jwks" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')"
printf '  %s\n' "$kid_before"

step "docker compose down"
"${COMPOSE[@]}" --profile test down 2>&1 | tail -5 | sed 's/^/  /'

step "docker compose up -d"
"${COMPOSE[@]}" up -d 2>&1 | tail -3 | sed 's/^/  /'
"${COMPOSE[@]}" --profile test up -d 2>&1 | tail -3 | sed 's/^/  /'
for _ in $(seq 1 30); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$SERVER" 2>/dev/null)" = healthy ] && break
    sleep 2
done
printf '  %s: %s\n' "$SERVER" "$(docker inspect -f '{{.State.Health.Status}}' "$SERVER")"
check "healthcheck after the restart" healthy "$(docker inspect -f '{{.State.Health.Status}}' "$SERVER")"

step "signing key id after the restart"
jwks_after="$(proxied "${AUTH_BASE}/jwks")"
kid_after="$(printf '%s' "$jwks_after" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')"
printf '  %s\n' "$kid_after"
check "the signing key is the same one" "$kid_before" "$kid_after"

step "the refresh token issued before the restart"
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${MARIO_REFRESH}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
if [ -n "$(field "$out" REFRESH_TOKEN)" ]; then
    pass "it still refreshes, and rotated again"
else
    fail "no rotated refresh token came back"
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "$failures" -eq 0 ]; then
    printf '\033[1;32mALL SCENARIOS PASSED\033[0m\n'
    exit 0
fi
printf '\033[1;31m%d CHECK(S) FAILED\033[0m\n' "$failures"
exit 1
