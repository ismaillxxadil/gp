# NOTLINE graph pipeline

Run these commands from the repository root after the lab and Neo4j are
running.

The lab images are pinned to the runtime versions used by the verified
security targets. After changing either Dockerfile, rebuild and recreate the
lab before enrichment:

```bash
./scripts/start.sh
```

## 1. Generate benign application traffic

```bash
./scripts/generate_lab_traffic.sh
```

The script exercises DNS, HTTP, the application-to-database path, SSH, and
SMB without performing adversary activity.

## 2. Import passive Zeek evidence

```bash
backend/.venv/bin/python backend/scripts/import_zeek.py
```

This imports connections and confirmed DHCP assignments, derives IP/service
and asset communication edges, and classifies DHCP identities using the most
recent capture window.

The default DHCP activity window is 15 minutes. Override it for a different
network or capture cadence:

```bash
NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS=3600 \
  backend/.venv/bin/python backend/scripts/import_zeek.py
```

Historical identities are retained for evidence but excluded from current
simulation edges.

## 3. Enrich verified security relationships

```bash
backend/.venv/bin/python backend/scripts/enrich_vulnerabilities.py
```

This verifies exact active NVD CPEs before writing CPE-to-CVE relationships.
It also scans exact npm package versions through OSV and records package
advisories separately. A missing CPE is recorded as unresolved; it is never
replaced with an approximate product or version.

## 4. Audit the graph

```bash
backend/.venv/bin/python backend/scripts/audit_graph.py
```

The audit reports three states:

- verified-path simulation readiness;
- security coverage completeness;
- full security simulation readiness.

Full security readiness requires every security identity to have either a
verified CPE/CVE path or a completed ecosystem advisory scan, with no scan
errors. Exact CPE gaps remain visible as warnings.

## 5. Run automated checks

```bash
cd backend
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
```
