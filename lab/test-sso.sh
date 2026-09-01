#!/usr/bin/env bash
#
# Acceptance: the five SSO scenarios,
# plus the directory-outage policy, run on the wire against the laboratory.
#
#   cd applications/auth-server/lab
#   ./provision.sh                                          # the domain
#   docker compose -f dev-server-compose.yml up -d --build   # the auth-server
#   ./test-sso.sh
#
# Where everything runs, and why:
#   - the auth-server under test lives in a container at 172.28.10.20, because
#     the Kerberos SPN is HTTP/auth.lab.easyoidc.local and that name only
#     resolves inside the lab network — rootless Docker keeps the host out;
#   - every HTTP request is made from auth-lab-client (kinit, curl --negotiate);
#   - every directory change is made with samba-tool inside auth-lab-dc.
#
# The script restores what it changes: luigi.verdi is re-enabled and the domain
# controller is brought back up, even if a check fails half way.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REALM=LAB.EASYOIDC.LOCAL
USER_PASSWORD="${LAB_USER_PASSWORD:-Lab.Passw0rd!}"
AUTH_FQDN=auth.lab.easyoidc.local
AUTH_IP=172.28.10.20
AUTH_BASE="http://${AUTH_FQDN}:3000"
# Used while the DC is down: with the lab DNS server stopped, no name resolves.
AUTH_BASE_IP="http://${AUTH_IP}:3000"
SERVER=auth-lab-auth-server
CLIENT=auth-lab-client
DC=auth-lab-dc
FLOW=./sso-flow.sh

failures=0

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
step()    { printf '\033[0;36m--- %s\033[0m\n' "$*"; }
pass()    { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail()    { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }

# Reads one `KEY value` line out of a flow transcript. The LAST occurrence wins:
# a form flow reports the challenge twice — once when it is first offered, once
# when the submitted credentials come back — and it is the second that is under
# test.
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
        fail "${label}: ${needle@Q} not found in ${haystack@Q}"
    fi
}

# Runs one OAuth2 flow inside the client container and echoes its stdout.
# The human-readable transcript goes straight to this script's stderr.
flow() {
    docker exec -i "$@" "$CLIENT" bash -s <"$FLOW"
}

# Everything the server logged since the marker set by log_mark.
log_mark() { LOG_MARK="$(docker logs "$SERVER" 2>&1 | wc -l)"; }
log_since() { docker logs "$SERVER" 2>&1 | tail -n "+$((LOG_MARK + 1))"; }

restore() {
    printf '\n\033[1;36m=== restoring the laboratory ===\033[0m\n'
    docker start "$DC" >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' "$DC" 2>/dev/null)" = healthy ] && break
        sleep 2
    done
    docker exec "$DC" samba-tool user enable luigi.verdi 2>&1 | sed 's/^/  /'
    docker exec "$DC" samba-tool user list 2>&1 | sed 's/^/  /'
}
trap restore EXIT

# ---------------------------------------------------------------------------
section "0. preconditions"
# ---------------------------------------------------------------------------
for container in "$DC" "$CLIENT" "$SERVER"; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = true ]; then
        pass "${container} is running"
    else
        fail "${container} is not running"
    fi
done
if [ "$failures" -ne 0 ]; then
    printf '\nStart the lab (./provision.sh) and the server '
    printf '(docker compose -f dev-server-compose.yml up -d --build) first.\n'
    exit 1
fi

health="$(docker exec "$CLIENT" curl -sS "${AUTH_BASE}/health")"
printf '%s\n' "$health"
contains "the server under test speaks spnego" '"identityProvider":"spnego"' "$health"

docker exec "$DC" samba-tool user enable luigi.verdi >/dev/null 2>&1

# ---------------------------------------------------------------------------
section "1. silent SSO: kinit mario.rossi + curl --negotiate through the whole flow"
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
if [ -n "$(field "$out" REFRESH_TOKEN)" ]; then
    pass "a refresh token was issued"
else
    fail "no refresh token was issued"
fi
step "server log"
log_since | grep -E 'SPNEGO handshake|login accepted' | sed 's/^/  /'
contains "the server logged the completed handshake" 'SPNEGO handshake completed' "$(log_since)"

MARIO_REFRESH="$(field "$out" REFRESH_TOKEN)"

# ---------------------------------------------------------------------------
section "2. no ticket: kdestroy, then the same request"
# ---------------------------------------------------------------------------
step "kdestroy -A"
docker exec "$CLIENT" kdestroy -A
out="$(flow -e MODE=sso)"
check "challenge status" 401 "$(field "$out" CHALLENGE_STATUS)"
check "WWW-Authenticate: Negotiate offered" yes "$(field "$out" CHALLENGE_NEGOTIATE)"
check "the fallback form is in the body" yes "$(field "$out" CHALLENGE_BODY_HAS_FORM)"
check "no authorization code" "-" "$(field "$out" AUTH_CODE)"

# ---------------------------------------------------------------------------
section "2b. NTLM is refused outright, and the handshake is not continued"
# ---------------------------------------------------------------------------
log_mark
out="$(flow -e MODE=ntlm)"
check "challenge status" 401 "$(field "$out" CHALLENGE_STATUS)"
check "no WWW-Authenticate continuation" no "$(field "$out" CHALLENGE_NEGOTIATE)"
contains "the form explains NTLM in Italian" 'NTLM' "$(field "$out" CHALLENGE_ALERT)"
step "server log"
log_since | grep -E 'ntlm_not_supported' | sed 's/^/  /'
contains "the log names ntlm_not_supported" '"reason":"ntlm_not_supported"' "$(log_since)"

# ---------------------------------------------------------------------------
section "3. password form: the domain password, right and wrong"
# ---------------------------------------------------------------------------
step "correct password"
out="$(flow -e MODE=form -e FORM_USERNAME=mario.rossi -e "FORM_PASSWORD=${USER_PASSWORD}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
check "sub claim" mario.rossi "$(field "$out" ID_SUB)"

step "wrong password"
log_mark
out="$(flow -e MODE=form -e FORM_USERNAME=mario.rossi -e FORM_PASSWORD=password-sbagliata)"
check "challenge status" 401 "$(field "$out" CHALLENGE_STATUS)"
check "no authorization code" "-" "$(field "$out" AUTH_CODE)"
contains "the form says so in Italian" 'Nome utente o password non corretti' "$(field "$out" CHALLENGE_ALERT)"
step "server log"
log_since | grep -E 'reason":"invalid_credentials' | sed 's/^/  /'
contains "the log names the reason" '"reason":"invalid_credentials"' "$(log_since)"

# ---------------------------------------------------------------------------
section "4. samba-tool user disable luigi.verdi"
# ---------------------------------------------------------------------------
step "log luigi.verdi in while the account is still enabled"
out="$(flow -e MODE=form -e FORM_USERNAME=luigi.verdi -e "FORM_PASSWORD=${USER_PASSWORD}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
check "sub claim" luigi.verdi "$(field "$out" ID_SUB)"
LUIGI_REFRESH="$(field "$out" REFRESH_TOKEN)"

step "docker exec ${DC} samba-tool user disable luigi.verdi"
docker exec "$DC" samba-tool user disable luigi.verdi | sed 's/^/  /'

step "the refresh token issued a moment ago"
log_mark
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${LUIGI_REFRESH}")"
check "token endpoint status" 400 "$(field "$out" TOKEN_STATUS)"
check "error" invalid_grant "$(field "$out" TOKEN_ERROR)"
step "server log"
log_since | grep -E 'account_disabled|refresh rejected' | sed 's/^/  /'
logs="$(log_since)"
contains "the log names account_disabled" '"reason":"account_disabled"' "$logs"
contains "the grant chain was revoked" '"revoked":true' "$logs"

step "a fresh login is refused too"
log_mark
out="$(flow -e MODE=form -e FORM_USERNAME=luigi.verdi -e "FORM_PASSWORD=${USER_PASSWORD}")"
check "challenge status" 401 "$(field "$out" CHALLENGE_STATUS)"
check "no authorization code" "-" "$(field "$out" AUTH_CODE)"
contains "the form says the account is not active" "non è più attivo sul dominio" "$(field "$out" CHALLENGE_ALERT)"
contains "the log names account_disabled" '"reason":"account_disabled"' "$(log_since)"

# ---------------------------------------------------------------------------
section "5. samba-tool user enable luigi.verdi"
# ---------------------------------------------------------------------------
step "docker exec ${DC} samba-tool user enable luigi.verdi"
docker exec "$DC" samba-tool user enable luigi.verdi | sed 's/^/  /'

step "a fresh login works again"
out="$(flow -e MODE=form -e FORM_USERNAME=luigi.verdi -e "FORM_PASSWORD=${USER_PASSWORD}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
check "sub claim" luigi.verdi "$(field "$out" ID_SUB)"

step "the refresh token revoked in step 4 must stay dead"
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${LUIGI_REFRESH}")"
check "token endpoint status" 400 "$(field "$out" TOKEN_STATUS)"
check "error" invalid_grant "$(field "$out" TOKEN_ERROR)"

# ---------------------------------------------------------------------------
section "6. domain controller down: reject, but do not revoke"
# ---------------------------------------------------------------------------
step "docker stop ${DC}"
docker stop "$DC" >/dev/null
printf '  %s\n' "$(docker inspect -f '{{.State.Status}}' "$DC")"

step "refresh while the directory is unreachable"
log_mark
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${MARIO_REFRESH}" -e "AUTH_BASE=${AUTH_BASE_IP}")"
check "token endpoint status" 400 "$(field "$out" TOKEN_STATUS)"
check "error" temporarily_unavailable "$(field "$out" TOKEN_ERROR)"
step "server log"
log_since | grep -E 'gate_unavailable|fail closed|refresh rejected' | sed 's/^/  /'
logs="$(log_since)"
contains "the log is loud about the outage" 'fail closed' "$logs"
contains "the grant chain was NOT revoked" '"revoked":false' "$logs"

step "docker start ${DC}, then wait for it to be healthy"
docker start "$DC" >/dev/null
for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$DC")" = healthy ] && break
    sleep 2
done
printf '  %s\n' "$(docker inspect -f '{{.State.Health.Status}}' "$DC")"

step "the same refresh token still works"
out="$(flow -e MODE=refresh -e "REFRESH_TOKEN=${MARIO_REFRESH}" -e "AUTH_BASE=${AUTH_BASE_IP}")"
check "token endpoint status" 200 "$(field "$out" TOKEN_STATUS)"
if [ -n "$(field "$out" REFRESH_TOKEN)" ]; then
    pass "a rotated refresh token came back"
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
