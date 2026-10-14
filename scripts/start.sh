#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Starting NOTLINE ==="

if [ ! -f infrastructure/.env ]; then
    echo "ERROR: Missing infrastructure/.env"
    exit 1
fi

echo "=== Starting Neo4j ==="
docker compose \
    --env-file infrastructure/.env \
    -f infrastructure/compose.yaml \
    up -d

echo "=== Building application images ==="
docker build -t enterprise-web:2.0 ./web1
docker build -t enterprise-app:1.0 ./app1

echo "=== Preparing directories and OVS bridges ==="
mkdir -p db1/data probe-logs probe2-logs
sudo ovs-vsctl --may-exist add-br sw1
sudo ovs-vsctl --may-exist add-br sw2

echo "=== Rebuilding Containerlab ==="
bash start-lab.sh

echo "=== NOTLINE Started ==="
echo "Neo4j: http://localhost:7474"
