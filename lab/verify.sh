#!/usr/bin/env bash
#
# Acceptance checks of the Active Directory laboratory.
#
# Everything that talks Kerberos or LDAP runs inside the krb-client container:
# the host needs no krb5 or LDAP tooling at all.
#
#   ./verify.sh
#
# Exit code 0 = every check passed.
#
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REALM=LAB.EASYOIDC.LOCAL
BASE_DN='DC=lab,DC=easyoidc,DC=local'
DC_FQDN=dc1.lab.easyoidc.local
AUTH_FQDN=auth.lab.easyoidc.local
AUTH_IP=172.28.10.20
NETWORK=auth-lab

failures=0

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
pass()    { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail()    { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
section "1. lab network sits inside 172.28.0.0/16 and clears the PBX range"
# ---------------------------------------------------------------------------
subnet="$(docker network inspect "$NETWORK" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr -d ' ')"
printf 'lab subnet: %s\n' "$subnet"
if [[ "$subnet" == 172.28.* ]]; then
    pass "lab subnet ${subnet} is inside 172.28.0.0/16"
else
    fail "lab subnet ${subnet} is NOT inside 172.28.0.0/16"
fi

printf '\nall docker networks:\n'
docker network inspect $(docker network ls -q) \
    --format '  {{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null
if docker network inspect $(docker network ls -q) \
        --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -q '172\.19\.'; then
    fail "a docker network overlaps the production PBX range 172.19.0.0/16"
else
    pass "no docker network touches 172.19.0.0/16"
fi

# ---------------------------------------------------------------------------
section "2. exported keytab holds the HTTP SPN"
# ---------------------------------------------------------------------------
if [ ! -f secrets/auth.keytab ]; then
    fail "secrets/auth.keytab is missing (run ./provision.sh)"
else
    ktout="$(docker compose exec -T krb-client klist -k -e /lab/secrets/auth.keytab 2>&1)"
    printf '%s\n' "$ktout"
    if grep -Fq "HTTP/${AUTH_FQDN}@${REALM}" <<<"$ktout"; then
        pass "keytab contains HTTP/${AUTH_FQDN}@${REALM}"
    else
        fail "keytab does not contain HTTP/${AUTH_FQDN}@${REALM}"
    fi
    # The plan (phase 8) insists on AES256; RC4-only keytabs are what we must not ship.
    if grep -Fq "aes256-cts-hmac-sha1-96" <<<"$ktout"; then
        pass "keytab holds an aes256-cts-hmac-sha1-96 key"
    else
        fail "keytab holds no AES256 key"
    fi
fi

# ---------------------------------------------------------------------------
section "3. DNS: the lab zone resolves the DC and the auth-server placeholder"
# ---------------------------------------------------------------------------
dnsout="$(docker compose exec -T krb-client bash -c \
    "host ${DC_FQDN}; host ${AUTH_FQDN}; host -t SRV _kerberos._tcp.lab.easyoidc.local" 2>&1)"
printf '%s\n' "$dnsout"
if grep -Fq "${AUTH_FQDN} has address ${AUTH_IP}" <<<"$dnsout"; then
    pass "${AUTH_FQDN} resolves to ${AUTH_IP}"
else
    fail "${AUTH_FQDN} does not resolve to ${AUTH_IP}"
fi

# ---------------------------------------------------------------------------
section "4. Kerberos: kinit + kvno on the service principal"
# ---------------------------------------------------------------------------
krbout="$(docker compose exec -T krb-client bash -s <<EOS 2>&1
kdestroy -A 2>/dev/null || true
echo '\$ kinit mario.rossi@${REALM}   (password on stdin)'
printf '%s\n' "\$LAB_USER_PASSWORD" | kinit mario.rossi@${REALM}
echo '\$ klist'
klist
echo '\$ kvno HTTP/${AUTH_FQDN}'
kvno HTTP/${AUTH_FQDN}
echo '\$ klist'
klist
EOS
)"
printf '%s\n' "$krbout"
if grep -Fq "mario.rossi@${REALM}" <<<"$krbout"; then
    pass "kinit mario.rossi@${REALM} obtained a TGT"
else
    fail "kinit mario.rossi@${REALM} did not obtain a TGT"
fi
if grep -Fq "HTTP/${AUTH_FQDN}@${REALM}: kvno = " <<<"$krbout"; then
    pass "kvno obtained a service ticket for HTTP/${AUTH_FQDN}"
else
    fail "kvno did not obtain a service ticket for HTTP/${AUTH_FQDN}"
fi

# ---------------------------------------------------------------------------
section "5. LDAP: read userAccountControl of mario.rossi"
# ---------------------------------------------------------------------------
ldapout="$(docker compose exec -T krb-client bash -s <<EOS 2>&1
ldapsearch -x -LLL \
  -H ldaps://${DC_FQDN} \
  -D "svc-auth@${REALM}" -w "\$LAB_SVC_PASSWORD" \
  -b "${BASE_DN}" \
  "(sAMAccountName=mario.rossi)" \
  sAMAccountName userPrincipalName userAccountControl accountExpires memberOf
EOS
)"
printf '%s\n' "$ldapout"
if grep -q '^userAccountControl: ' <<<"$ldapout"; then
    pass "simple bind as svc-auth over LDAPS read userAccountControl"
else
    fail "could not read userAccountControl over LDAPS"
fi
if grep -q 'memberOf: CN=easyoidc-users' <<<"$ldapout"; then
    pass "mario.rossi is a member of easyoidc-users"
else
    fail "mario.rossi is not a member of easyoidc-users"
fi

# ---------------------------------------------------------------------------
section "6. the group holds mario.rossi only"
# ---------------------------------------------------------------------------
members="$(docker compose exec -T samba-dc samba-tool group listmembers easyoidc-users 2>&1 | tr -d '\r')"
printf '%s\n' "$members"
if [ "$(printf '%s\n' "$members" | grep -c .)" = 1 ] && grep -Fxq mario.rossi <<<"$members"; then
    pass "easyoidc-users contains exactly mario.rossi"
else
    fail "easyoidc-users does not contain exactly mario.rossi"
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "$failures" -eq 0 ]; then
    printf '\033[1;32mALL CHECKS PASSED\033[0m\n'
    exit 0
fi
printf '\033[1;31m%d CHECK(S) FAILED\033[0m\n' "$failures"
exit 1
