#!/usr/bin/env bash
#
# One complete OAuth2 exchange against the lab auth-server, run INSIDE the
# krb-client container (the host cannot reach 172.28.10.0/24 under rootless
# Docker). It is fed to the container on stdin by test-sso.sh:
#
#   docker exec -i -e MODE=sso auth-lab-client bash -s < sso-flow.sh
#
# Environment:
#   MODE           sso | form | ntlm | refresh   how the login is answered
#   FORM_USERNAME  user name for MODE=form
#   FORM_PASSWORD  password for MODE=form
#   AUTH_BASE      base URL of the auth-server   (default http://auth.lab.easyoidc.local:3000)
#   CLIENT_ID      OAuth2 client                 (default desktop-app)
#   REDIRECT_URI   registered redirect           (default http://127.0.0.1/callback)
#   REFRESH_TOKEN  set (with MODE=refresh) to exchange a refresh token instead
#   CURL_OPTS      extra curl arguments, split on whitespace. Phase 5 uses it to
#                  reach the same server through nginx over TLS:
#                    CURL_OPTS='--resolve auth.lab.easyoidc.local:443:172.28.10.40 --cacert /lab/ca.crt'
#
# It prints a transcript on stderr and machine-readable lines on stdout:
#
#   CHALLENGE_STATUS <http status of the first interaction response>
#   CHALLENGE_NEGOTIATE <yes|no>
#   CHALLENGE_BODY_HAS_FORM <yes|no>
#   CHALLENGE_ALERT <the Italian alert text, if any>
#   AUTH_CODE <code|->
#   TOKEN_STATUS <http status of the token endpoint>
#   TOKEN_ERROR <error code|->
#   ACCESS_TOKEN / REFRESH_TOKEN / ID_SUB / ID_REALM
#
# The redirect chain always ends at the loopback redirect URI, which nothing is
# listening on: curl's "connection refused" there is the expected end of a
# successful flow, and the code is read out of the Location header.
set -uo pipefail

AUTH_BASE="${AUTH_BASE:-http://auth.lab.easyoidc.local:3000}"
CLIENT_ID="${CLIENT_ID:-desktop-app}"
REDIRECT_URI="${REDIRECT_URI:-http://127.0.0.1/callback}"
MODE="${MODE:-sso}"
# Extra curl arguments, word-split on purpose: the caller passes whole options.
read -r -a CURL_EXTRA <<<"${CURL_OPTS:-}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/cookies"
HDR="$WORK/headers"
BODY="$WORK/body"
# A flow that runs to completion ends on the loopback redirect URI, where
# nothing is listening: curl then writes no body file at all. Pre-creating them
# keeps the inspection below reading an empty file instead of erroring.
: >"$HDR"
: >"$BODY"

say() { printf '%s\n' "$*" >&2; }
emit() { printf '%s %s\n' "$1" "${2:--}"; }

b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

urlencode() {
    local s="$1" out='' c
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) out+="$(printf '%%%02X' "'$c")" ;;
        esac
    done
    printf '%s' "$out"
}

# Reads one header out of the dump of the LAST response that carried it.
last_header() { grep -i "^$1:" "$HDR" | tail -1 | sed "s/^[^:]*: *//" | tr -d '\r'; }

# ---------------------------------------------------------------------------
# The refresh-only mode: no browser interaction at all.
# ---------------------------------------------------------------------------
if [ "$MODE" = refresh ]; then
    say "\$ POST ${AUTH_BASE}/token   grant_type=refresh_token"
    status="$(curl -sS "${CURL_EXTRA[@]}" -o "$BODY" -w '%{http_code}' \
        -X POST "${AUTH_BASE}/token" \
        -d grant_type=refresh_token \
        -d "refresh_token=${REFRESH_TOKEN}" \
        -d "client_id=${CLIENT_ID}")"
    say "  -> HTTP ${status}"
    say "  -> $(head -c 400 "$BODY")"
    emit TOKEN_STATUS "$status"
    emit TOKEN_ERROR "$(sed -n 's/.*"error":"\([^"]*\)".*/\1/p' "$BODY")"
    emit ACCESS_TOKEN "$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$BODY")"
    emit REFRESH_TOKEN "$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$BODY")"
    exit 0
fi

# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------
VERIFIER="$(head -c 48 /dev/urandom | b64url)"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | b64url)"

AUTHORIZE="${AUTH_BASE}/auth?client_id=$(urlencode "$CLIENT_ID")&response_type=code&scope=openid"
AUTHORIZE+="&redirect_uri=$(urlencode "$REDIRECT_URI")"
AUTHORIZE+="&code_challenge=${CHALLENGE}&code_challenge_method=S256&state=lab-$RANDOM"

# ---------------------------------------------------------------------------
# Step 1: the authorization request, up to the login interaction.
# ---------------------------------------------------------------------------
negotiate=()
[ "$MODE" = sso ] && negotiate=(--negotiate -u :)

say "\$ GET /auth  (MODE=${MODE}${negotiate:+, curl --negotiate})"
effective="$(curl -sS "${CURL_EXTRA[@]}" -L -c "$JAR" -b "$JAR" -D "$HDR" -o "$BODY" \
    "${negotiate[@]}" -w '%{url_effective}' "$AUTHORIZE" 2>/dev/null)"
say "  -> ended at ${effective}"
say "  -> statuses: $(grep -c '^HTTP/' "$HDR") response(s): $(grep '^HTTP/' "$HDR" | tr -d '\r' | paste -sd' | ')"

emit CHALLENGE_STATUS "$(grep '^HTTP/' "$HDR" | tail -1 | awk '{print $2}' | tr -d '\r')"
if tr -d '\r' <"$HDR" | grep -qi '^www-authenticate: *Negotiate *$'; then
    emit CHALLENGE_NEGOTIATE yes
else
    emit CHALLENGE_NEGOTIATE no
fi
if grep -q 'name="password"' "$BODY"; then
    emit CHALLENGE_BODY_HAS_FORM yes
else
    emit CHALLENGE_BODY_HAS_FORM no
fi
emit CHALLENGE_ALERT "$(sed -n 's/.*<p class="alert" role="alert">\(.*\)<\/p>.*/\1/p' "$BODY" | head -1)"

code="$(last_header location | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"

# ---------------------------------------------------------------------------
# Step 2 (MODE=ntlm only): re-offer the challenge with an NTLM type-1 message
# inside the Negotiate header, which is what a Windows client falls back to when
# it holds no Kerberos ticket for the service. curl will not do this by itself —
# the server only ever advertises Negotiate — so the header is set by hand.
# ---------------------------------------------------------------------------
if [ "$MODE" = ntlm ]; then
    NTLM_TYPE1='TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=='
    say "\$ GET ${effective}   Authorization: Negotiate <NTLM type 1>"
    curl -sS "${CURL_EXTRA[@]}" -c "$JAR" -b "$JAR" -D "$HDR" -o "$BODY" \
        -H "Authorization: Negotiate ${NTLM_TYPE1}" "$effective" >/dev/null 2>&1
    say "  -> statuses: $(grep '^HTTP/' "$HDR" | tr -d '\r' | paste -sd' | ')"
    emit CHALLENGE_STATUS "$(grep '^HTTP/' "$HDR" | tail -1 | awk '{print $2}' | tr -d '\r')"
    if tr -d '\r' <"$HDR" | grep -qi '^www-authenticate:'; then
        emit CHALLENGE_NEGOTIATE yes
    else
        emit CHALLENGE_NEGOTIATE no
    fi
    emit CHALLENGE_ALERT "$(sed -n 's/.*<p class="alert" role="alert">\(.*\)<\/p>.*/\1/p' "$BODY" | head -1)"
    emit AUTH_CODE
    emit TOKEN_STATUS 0
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 3 (MODE=form only): post the credentials back to the interaction.
# ---------------------------------------------------------------------------
if [ "$MODE" = form ] && [ -z "$code" ]; then
    action="$(sed -n 's/.*<form method="post" action="\([^"]*\)".*/\1/p' "$BODY" | head -1)"
    if [ -z "$action" ]; then
        say '  !! the challenge carried no login form'
        emit AUTH_CODE
        emit TOKEN_STATUS 0
        exit 0
    fi
    say "\$ POST ${action}   username=${FORM_USERNAME:-}"
    effective="$(curl -sS "${CURL_EXTRA[@]}" -L -c "$JAR" -b "$JAR" -D "$HDR" -o "$BODY" \
        -w '%{url_effective}' \
        --data-urlencode "username=${FORM_USERNAME:-}" \
        --data-urlencode "password=${FORM_PASSWORD:-}" \
        "${AUTH_BASE}${action}" 2>/dev/null)"
    say "  -> ended at ${effective}"
    say "  -> statuses: $(grep '^HTTP/' "$HDR" | tr -d '\r' | paste -sd' | ')"
    emit CHALLENGE_STATUS "$(grep '^HTTP/' "$HDR" | tail -1 | awk '{print $2}' | tr -d '\r')"
    emit CHALLENGE_ALERT "$(sed -n 's/.*<p class="alert" role="alert">\(.*\)<\/p>.*/\1/p' "$BODY" | head -1)"
    code="$(last_header location | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
fi

emit AUTH_CODE "${code:-}"

if [ -z "$code" ]; then
    say '  !! no authorization code was issued'
    emit TOKEN_STATUS 0
    exit 0
fi
say "  -> authorization code ${code:0:12}…"

# ---------------------------------------------------------------------------
# Step 4: code -> tokens, with the PKCE verifier.
# ---------------------------------------------------------------------------
say "\$ POST ${AUTH_BASE}/token   grant_type=authorization_code"
status="$(curl -sS "${CURL_EXTRA[@]}" -o "$BODY" -w '%{http_code}' \
    -X POST "${AUTH_BASE}/token" \
    -d grant_type=authorization_code \
    -d "code=${code}" \
    --data-urlencode "redirect_uri=${REDIRECT_URI}" \
    -d "client_id=${CLIENT_ID}" \
    -d "code_verifier=${VERIFIER}")"
say "  -> HTTP ${status}"
say "  -> $(sed 's/\("\(access\|refresh\|id\)_token":"[^"]\{12\}\)[^"]*/\1…/g' "$BODY" | head -c 500)"

emit TOKEN_STATUS "$status"
emit TOKEN_ERROR "$(sed -n 's/.*"error":"\([^"]*\)".*/\1/p' "$BODY")"

access="$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$BODY")"
refresh="$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$BODY")"
idtoken="$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$BODY")"

emit ACCESS_TOKEN "$access"
emit REFRESH_TOKEN "$refresh"

if [ -n "$idtoken" ]; then
    payload="$(printf '%s' "$idtoken" | cut -d. -f2 | tr '_-' '/+')"
    # base64 needs its padding back before it will decode.
    while [ $((${#payload} % 4)) -ne 0 ]; do payload="${payload}="; done
    claims="$(printf '%s' "$payload" | base64 -d 2>/dev/null)"
    say "  -> id_token claims: ${claims}"
    emit ID_SUB "$(printf '%s' "$claims" | sed -n 's/.*"sub":"\([^"]*\)".*/\1/p')"
    emit ID_REALM "$(printf '%s' "$claims" | sed -n 's/.*"realm":"\([^"]*\)".*/\1/p')"
fi
