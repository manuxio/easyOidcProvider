#!/bin/bash
#
# Entrypoint of the laboratory Samba AD DC.
#
# First boot: provisions the domain into /var/lib/samba + /etc/samba, which are
# named volumes, so the domain survives `docker compose down` and `up`.
# Every boot: re-applies the small smb.conf tweaks the container needs and then
# runs samba in the foreground as PID 1.
#
set -euo pipefail

REALM="${SAMBA_REALM:-LAB.EASYOIDC.LOCAL}"
NETBIOS_DOMAIN="${SAMBA_NETBIOS_DOMAIN:-LAB}"
ADMIN_PASSWORD="${SAMBA_ADMIN_PASSWORD:?SAMBA_ADMIN_PASSWORD must be set}"
DEBUG_LEVEL="${SAMBA_DEBUG_LEVEL:-1}"
# Docker's embedded resolver: lets the lab resolve names outside the AD zone.
DNS_FORWARDER="${SAMBA_DNS_FORWARDER:-127.0.0.11}"

SAM_LDB=/var/lib/samba/private/sam.ldb
SMB_CONF=/etc/samba/smb.conf

log() { printf '[entrypoint] %s\n' "$*"; }

if [ ! -f "$SAM_LDB" ]; then
    log "no domain database at ${SAM_LDB}: provisioning realm ${REALM} (NetBIOS ${NETBIOS_DOMAIN})"
    # A leftover smb.conf from the Debian package would confuse the provisioner.
    rm -f "$SMB_CONF"
    # samba-tool-ntvfs is samba-tool with the sysvol ACL backend forced away from
    # the in-process smbd, which panics under rootless Docker. See the wrapper's
    # own docstring for the full explanation.
    samba-tool-ntvfs domain provision \
        --server-role=dc \
        --use-rfc2307 \
        --dns-backend=SAMBA_INTERNAL \
        --realm="$REALM" \
        --domain="$NETBIOS_DOMAIN" \
        --adminpass="$ADMIN_PASSWORD" \
        --host-name="$(hostname -s)"
    log "domain provisioned"
else
    log "existing domain database found at ${SAM_LDB}: skipping provision"
fi

# Two fix-ups, applied on every boot so a re-created container repairs itself.
#
# 1. `server services` and `dcerpc endpoint servers`: because we provision with
#    use_ntvfs (see samba-tool-ntvfs), provision writes the old NTVFS-era lists.
#    Neither survives on Samba 4.22:
#      - the NTVFS file server is called `smb`, and only `s3fs` exists now, so
#        samba dies with
#        server_service_startup: Failed to start service 'smb' - NT_STATUS_INVALID_SYSTEM_SERVICE
#      - the endpoint list names `winreg` and `srvsvc`, which are no longer s4
#        endpoint servers, so the whole `rpc` service fails to initialise with
#        dcesrv_init_ep_server: Failed to find endpoint server 'winreg'
#        and with it go epmapper/135 and `samba-tool dns`.
#    Dropping both lines puts samba back on its own AD DC defaults, which are
#    correct.
#
# 2. `dns forwarder`: send names outside the AD zone to Docker's embedded
#    resolver, so the lab client can still resolve ordinary hosts through the DC.
#
# Do NOT add `interfaces` / `bind interfaces only` here: they break the file
# server the same way. Samba binds 0.0.0.0:53 happily next to Docker's
# 127.0.0.11:53 — the more specific bind still wins for local lookups.
python3 - "$SMB_CONF" "$DNS_FORWARDER" <<'PY'
import sys

path, forwarder = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    lines = handle.readlines()

changed = False

STALE = ("server services", "dcerpc endpoint servers")
kept = [line for line in lines if not line.strip().startswith(STALE)]
if len(kept) != len(lines):
    lines, changed = kept, True
    print("[entrypoint] smb.conf: dropped the NTVFS-era service lists")

if not any(line.strip().startswith("dns forwarder") for line in lines):
    for index, line in enumerate(lines):
        if line.strip() == "[global]":
            lines.insert(index + 1, "\tdns forwarder = %s\n" % forwarder)
            changed = True
            print("[entrypoint] smb.conf: dns forwarder set to %s" % forwarder)
            break

if changed:
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)
else:
    print("[entrypoint] smb.conf: already adjusted")
PY

# Samba writes a realm-ready krb5.conf while provisioning; make it the system one
# so samba-tool and kinit inside this container talk to the right KDC.
if [ -f /var/lib/samba/private/krb5.conf ]; then
    cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf
fi

log "starting samba (debuglevel ${DEBUG_LEVEL})"
exec samba --foreground --no-process-group --debuglevel="$DEBUG_LEVEL"
