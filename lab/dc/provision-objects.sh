#!/bin/bash
#
# Directory objects of the laboratory domain: test users, the auth-server service
# account with its HTTP SPN, the exported keytab, the group used by the LDAP group
# check and the DNS record of the future auth-server container.
#
# Runs INSIDE the samba-dc container (mounted at /lab/dc by docker-compose.yml)
# and is driven from the host by ../provision.sh. Every step is idempotent: a
# second run reports "already ..." for everything and changes nothing.
#
set -euo pipefail

REALM="${SAMBA_REALM:-LAB.EASYOIDC.LOCAL}"
ADMIN_PASSWORD="${SAMBA_ADMIN_PASSWORD:?SAMBA_ADMIN_PASSWORD must be set}"
USER_PASSWORD="${LAB_USER_PASSWORD:?LAB_USER_PASSWORD must be set}"
SVC_PASSWORD="${LAB_SVC_PASSWORD:?LAB_SVC_PASSWORD must be set}"
AUTH_HOSTNAME="${LAB_AUTH_HOSTNAME:-auth}"
AUTH_IP="${LAB_AUTH_IP:-172.28.10.20}"
GROUP_NAME="${LAB_GROUP_NAME:-easyoidc-users}"
SVC_ACCOUNT="${LAB_SVC_ACCOUNT:-svc-auth}"
KEYTAB="${LAB_KEYTAB_PATH:-/lab/secrets/auth.keytab}"

DNS_ZONE="$(printf '%s' "$REALM" | tr '[:upper:]' '[:lower:]')"
BASE_DN="DC=$(printf '%s' "$DNS_ZONE" | sed 's/\./,DC=/g')"
SPN="HTTP/${AUTH_HOSTNAME}.${DNS_ZONE}"
DNS_SERVER=127.0.0.1
ADMIN_CREDS="Administrator%${ADMIN_PASSWORD}"
SAM_LDB=/var/lib/samba/private/sam.ldb
# 0x18 = AES128-CTS-HMAC-SHA1-96 | AES256-CTS-HMAC-SHA1-96. Without this the
# keytab export for the SPN falls back to RC4 (arcfour-hmac) only.
SUPPORTED_ENCTYPES=24

log() { printf '[provision] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 0. password policy: lab passwords must never expire and must not be forced
#    through the default AD complexity rules.
# ---------------------------------------------------------------------------
log "relaxing the domain password policy (no complexity, no expiry)"
samba-tool domain passwordsettings set \
    --complexity=off \
    --history-length=0 \
    --min-pwd-age=0 \
    --max-pwd-age=0 \
    --min-pwd-length=7 >/dev/null

# ---------------------------------------------------------------------------
# 1. users
# ---------------------------------------------------------------------------
user_exists() { samba-tool user list | grep -Fxq -- "$1"; }

ensure_user() {
    local name="$1" password="$2" description="$3"
    if user_exists "$name"; then
        log "user ${name}: already present"
    else
        samba-tool user create "$name" "$password" --description="$description" >/dev/null
        log "user ${name}: created"
    fi
    samba-tool user setexpiry "$name" --noexpiry >/dev/null
}

ensure_user mario.rossi   "$USER_PASSWORD" "Lab test user, stays enabled"
ensure_user luigi.verdi   "$USER_PASSWORD" "Lab test user, disabled and re-enabled by the SSO tests"
ensure_user "$SVC_ACCOUNT" "$SVC_PASSWORD" "auth-server service account (HTTP SPN holder)"

# A user disabled by an earlier test run must come back enabled on re-provision:
# present in the full list but absent from the enabled-only list means disabled.
if ! samba-tool user list --hide-disabled | grep -Fxq -- luigi.verdi; then
    samba-tool user enable luigi.verdi >/dev/null
    log "user luigi.verdi: was disabled, re-enabled"
fi

# ---------------------------------------------------------------------------
# 2. service principal name on the service account
# ---------------------------------------------------------------------------
if samba-tool spn list "$SVC_ACCOUNT" | grep -Fq -- "$SPN"; then
    log "spn ${SPN}: already on ${SVC_ACCOUNT}"
else
    samba-tool spn add "$SPN" "$SVC_ACCOUNT" >/dev/null
    log "spn ${SPN}: added to ${SVC_ACCOUNT}"
fi

# ---------------------------------------------------------------------------
# 3. group used by the (optional) LDAP group check
# ---------------------------------------------------------------------------
if samba-tool group list | grep -Fxq -- "$GROUP_NAME"; then
    log "group ${GROUP_NAME}: already present"
else
    samba-tool group add "$GROUP_NAME" >/dev/null
    log "group ${GROUP_NAME}: created"
fi

if samba-tool group listmembers "$GROUP_NAME" 2>/dev/null | grep -Fxq -- mario.rossi; then
    log "group ${GROUP_NAME}: mario.rossi already a member"
else
    samba-tool group addmembers "$GROUP_NAME" mario.rossi >/dev/null
    log "group ${GROUP_NAME}: mario.rossi added"
fi

# ---------------------------------------------------------------------------
# 4. DNS A record for the future auth-server container
# ---------------------------------------------------------------------------
if samba-tool dns query "$DNS_SERVER" "$DNS_ZONE" "$AUTH_HOSTNAME" A -U "$ADMIN_CREDS" >/dev/null 2>&1; then
    log "dns ${AUTH_HOSTNAME}.${DNS_ZONE}: record already present"
else
    samba-tool dns add "$DNS_SERVER" "$DNS_ZONE" "$AUTH_HOSTNAME" A "$AUTH_IP" -U "$ADMIN_CREDS" >/dev/null
    log "dns ${AUTH_HOSTNAME}.${DNS_ZONE}: A ${AUTH_IP} created"
fi

# ---------------------------------------------------------------------------
# 5. encryption types on the service account
#
# Phase 8 of the plan demands an AES256 keytab. Samba stores AES keys for every
# account, but `samba-tool domain exportkeytab --principal=<SPN>` only emits the
# enctypes msDS-SupportedEncryptionTypes allows, and that attribute is unset on a
# freshly created account, which leaves RC4 as the only exported key. `replace`
# makes this step idempotent.
# ---------------------------------------------------------------------------
ldbmodify -H "$SAM_LDB" >/dev/null <<LDIF
dn: CN=${SVC_ACCOUNT},CN=Users,${BASE_DN}
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: ${SUPPORTED_ENCTYPES}
LDIF
log "account ${SVC_ACCOUNT}: msDS-SupportedEncryptionTypes = ${SUPPORTED_ENCTYPES} (AES128 + AES256)"

# ---------------------------------------------------------------------------
# 6. keytab export (host side, gitignored)
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$KEYTAB")"
if [ -f "$KEYTAB" ] && klist -k -e "$KEYTAB" 2>/dev/null | grep -Fq -- "$SPN@${REALM} (aes256-cts-hmac-sha1-96)"; then
    log "keytab ${KEYTAB}: already holds ${SPN}@${REALM} with AES256"
else
    # exportkeytab appends, so start from a clean file to avoid duplicate entries.
    rm -f "$KEYTAB"
    samba-tool domain exportkeytab "$KEYTAB" --principal="$SPN" >/dev/null
    chmod 0640 "$KEYTAB"
    log "keytab ${KEYTAB}: exported for ${SPN}"
fi

log "done"
