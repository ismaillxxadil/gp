# Graph pipeline guide

This is the repeatable operational path for turning current lab traffic into a
security-enriched graph. Run commands from the repository root. The lab and
Neo4j must already be running.

The shorter root-level [GRAPH_PIPELINE.md](../../GRAPH_PIPELINE.md) remains a
quick reference. This page explains the stages and their contracts.

## 1. Start or verify the lab

For a fresh deployment:

```bash
./scripts/start.sh
```

Verify the containers and pinned runtime versions before enrichment:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' | grep clab-step2-switch
docker exec clab-step2-switch-web1 nginx -v 2>&1
docker exec clab-step2-switch-app1 node --version
```

The version declarations used by enrichment are in
[security/enrichment.py](../../backend/src/notline/security/enrichment.py) and
[security/components.py](../../backend/src/notline/security/components.py).
If a Dockerfile changes, rebuild and recreate the lab before trusting the
security graph.

## 2. Generate benign traffic

```bash
TRAFFIC_ROUNDS=3 ./scripts/generate_lab_traffic.sh
```

The script exercises DNS, the NGINX frontend and proxied API, SSH, and SMB.
It is intended to generate passive evidence, not adversary activity.

## 3. Import Zeek evidence

```bash
backend/.venv/bin/python backend/scripts/import_zeek.py
```

The importer:

1. reads each configured `conn.log` source;
2. parses and validates records;
3. adds conservative service hints;
4. groups mirrored observations and assigns canonical flow IDs;
5. writes raw observations and IPs;
6. imports confirmed DHCP ACK assignments;
7. classifies current versus historical DHCP identities;
8. refreshes IP, service, and asset communication relationships.

If the capture cadence differs from the default 15-minute activity window:

```bash
NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS=3600 \
  backend/.venv/bin/python backend/scripts/import_zeek.py
```

## 4. Enrich security identities

```bash
backend/.venv/bin/python backend/scripts/enrich_vulnerabilities.py
```

This stage initializes the graph constraints, then:

- resolves the configured PostgreSQL, Samba, OpenSSH, and NGINX targets to
  exact active NVD CPEs;
- fetches and evaluates NVD CVE applicability;
- enriches the pinned Node.js component when its exact CPE is verified;
- records unresolved Express/node-postgres CPE identities without guessing;
- records all exact npm package identities from `app1/package-lock.json`;
- scans each npm package version through OSV;
- refreshes asset-to-CVE and asset-to-advisory exposures.

NVD and OSV responses are cached under `backend/.cache/`. These are runtime
artifacts, not source documentation.

## 5. Audit readiness

```bash
backend/.venv/bin/python backend/scripts/audit_graph.py
```

The audit prints three separate decisions:

- **Verified-path simulation readiness** checks current graph evidence and
  derived exposure prerequisites.
- **Security coverage** checks unresolved services, unresolved components
  without OSV coverage, incomplete package scans, and OSV errors.
- **Full security simulation readiness** requires both decisions to pass.

Do not replace an audit warning with a manual claim that the graph is complete.
An unresolved CPE may be acceptable when an alternative advisory source is
complete, but it must remain visible.

## 6. Tests and static checks

```bash
cd backend
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
```

The code-level behavior behind each stage is mapped in the
[code map](../reference/code-map.md), and the graph objects and relationships
are described in the [graph model](../reference/graph-model.md).
