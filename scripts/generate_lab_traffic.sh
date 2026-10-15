#!/usr/bin/env bash

set -euo pipefail

PC1="clab-step2-switch-pc1"
PC2="clab-step2-switch-pc2"
ROUNDS="${TRAFFIC_ROUNDS:-3}"

if ! [[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "TRAFFIC_ROUNDS must be a positive integer" >&2
    exit 2
fi

run_in_client() {
    local client="$1"
    local command="$2"
    docker exec "$client" sh -c "$command"
}

http_get() {
    local client="$1"
    local url="$2"
    run_in_client "$client" "wget -qO- --timeout=5 '$url' >/dev/null"
}

dns_lookup() {
    local client="$1"
    local hostname="$2"
    run_in_client "$client" "nslookup '$hostname' >/dev/null"
}

ssh_handshake() {
    run_in_client "$PC2" \
        "ssh -o BatchMode=yes -o ConnectTimeout=3 \
         -o StrictHostKeyChecking=no labuser@10.10.35.10 true \
         >/dev/null 2>&1 || true"
}

smb_read() {
    run_in_client "$PC1" \
        "smbclient -N //10.10.35.40/shared \
         -c 'ls; get README.txt /tmp/notline-readme.txt' \
         >/dev/null"
}

for ((round = 1; round <= ROUNDS; round++)); do
    echo "Traffic round $round/$ROUNDS"

    dns_lookup "$PC1" "frontend.enterprise.local"
    dns_lookup "$PC2" "app.enterprise.local"
    dns_lookup "$PC1" "db.enterprise.local"

    http_get "$PC1" "http://10.10.20.20/"
    http_get "$PC1" "http://10.10.20.20/api/health"
    http_get "$PC1" "http://10.10.20.20/api/users"
    http_get "$PC1" "http://10.10.20.20/api/users/search?name=postgres"
    http_get "$PC2" "http://10.10.20.20/api/health"
    http_get "$PC2" "http://10.10.20.20/api/users/search?name=appuser"

    ssh_handshake
    smb_read
    sleep 1
done

echo "Lab traffic generation complete"
