#!/usr/bin/env bash
#
# Destroy the laboratory domain and everything it produced, then rebuild it from
# scratch. Use it when the directory is in a state you no longer trust; the
# normal stop/start cycle is `docker compose down` / `docker compose up -d`,
# which keeps the domain.
#
#   ./reset.sh          # asks for confirmation
#   ./reset.sh --yes    # no questions
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ "${1:-}" != "--yes" ]; then
    printf 'This deletes the lab domain database and the exported keytab. Continue? [y/N] '
    read -r answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) printf 'aborted\n'; exit 1 ;;
    esac
fi

printf '[lab] removing containers and volumes\n'
docker compose down -v --remove-orphans

printf '[lab] removing exported secrets\n'
rm -f secrets/auth.keytab

printf '[lab] re-provisioning from scratch\n'
exec ./provision.sh
