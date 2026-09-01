#!/usr/bin/env bash
#
# Populate the laboratory domain with the objects the auth-server needs.
#
# Idempotent: run it as many times as you like. It brings the lab up if it is
# down, waits for the DC to be healthy, then runs dc/provision-objects.sh inside
# the container.
#
#   ./provision.sh
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

DC_SERVICE=samba-dc
WAIT_SECONDS="${LAB_WAIT_SECONDS:-300}"

log() { printf '\033[1;34m[lab]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[lab]\033[0m %s\n' "$*" >&2; exit 1; }

mkdir -p secrets

log "bringing the lab up (build if needed)"
docker compose up -d --build

log "waiting up to ${WAIT_SECONDS}s for ${DC_SERVICE} to become healthy"
deadline=$(( $(date +%s) + WAIT_SECONDS ))
while :; do
    status="$(docker inspect -f '{{.State.Health.Status}}' auth-lab-dc 2>/dev/null || echo missing)"
    [ "$status" = healthy ] && break
    if [ "$(date +%s)" -ge "$deadline" ]; then
        docker compose logs --tail=80 "$DC_SERVICE" || true
        die "the domain controller never became healthy (last status: ${status})"
    fi
    sleep 3
done
log "domain controller healthy"

log "provisioning directory objects"
docker compose exec -T "$DC_SERVICE" /lab/dc/provision-objects.sh

log "keytab on the host:"
ls -l secrets/auth.keytab

log "provisioning complete. Run ./verify.sh for the acceptance checks."
