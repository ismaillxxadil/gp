#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== NOTLINE First-Time Setup ==="

echo "=== Checking prerequisites ==="
missing=0

for cmd in git docker containerlab ovs-vsctl python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "[OK] $cmd"
    else
        echo "[MISSING] $cmd"
        missing=1
    fi
done

if [ "$missing" -ne 0 ]; then
    echo "Install the missing tools using the README instructions."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not accessible."
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose is not available."
    exit 1
fi

echo "=== Setting up Python backend ==="
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -e "./backend[dev]"

echo "=== Preparing runtime directories ==="
mkdir -p db1/data probe-logs probe2-logs

echo "=== Configuring Neo4j ==="

if [ ! -f infrastructure/.env ]; then
    echo "Generating a new local Neo4j password..."
    password="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"

    (
        umask 077
        printf 'NEO4J_PASSWORD=%s\n' "$password" > infrastructure/.env
    )
else
    echo "Existing Neo4j configuration preserved."
fi

chmod 600 infrastructure/.env

echo "=== Initializing OVS bridges ==="
sudo ovs-vsctl --may-exist add-br sw1
sudo ovs-vsctl --may-exist add-br sw2

echo ""
echo "=== Setup complete ==="
echo "Start NOTLINE with: ./scripts/start.sh"
