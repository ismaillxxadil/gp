# NOTLINE — Self-Healing Cybersecurity Digital Twin

NOTLINE is a research prototype for building a security-enriched digital twin
of an isolated enterprise network. It passively observes traffic with Zeek,
preserves the evidence in Neo4j, derives infrastructure relationships, and
maps verified software identities to vulnerability and advisory data.

The project is inspired by the NOTLINE research direction. The current
implementation stops at the trusted graph and readiness boundary. Autonomous
agents, LLM reasoning, adversary simulation, and automatic self-healing are
planned extensions, not operational features yet.

## Current status

The following foundation is implemented and tested:

- An isolated Containerlab enterprise network with VLANs, Open vSwitch
  mirroring, FRRouting, application services, database services, DHCP/DNS,
  IoT devices, and two Zeek probes.
- Repeatable benign traffic generation for DNS, HTTP, the application path,
  SSH, and SMB.
- Passive JSON `conn.log` and `dhcp.log` ingestion from both probes.
- Typed observation parsing, malformed-record rejection, discoverable-IP
  filtering, service-label normalization, conservative port inference, and
  cross-probe flow deduplication.
- A Neo4j evidence graph containing observations, IP addresses, DHCP leases,
  assets, services, and software components.
- Derived IP communication, service, asset communication, and current-exposure
  relationships.
- DHCP-aware current, historical, and retired identity handling.
- Exact NVD CPE resolution for verified services and runtime components.
- NVD CVE applicability evaluation using CPE attributes, configuration
  boolean logic, and version bounds.
- Exact npm package inventory and OSV advisory scanning for package versions
  that do not have a trusted CPE path.
- Explicit unresolved-identity and scan-error states instead of guessed
  security relationships.
- Graph audit output for verified-path readiness, security coverage, and full
  security simulation readiness.
- Focused unit/contract tests and Ruff lint/format checks.

The current lab profile verifies these service identities:

| Service | Runtime evidence | Security identity |
| --- | --- | --- |
| PostgreSQL | 18.0 | Exact NVD CPE/CVE path |
| Samba | 4.20.6 | Exact NVD CPE/CVE path |
| OpenSSH | 9.9p2 | Exact NVD CPE/CVE path |
| NGINX Open Source | 1.30.3 | Exact NVD CPE/CVE path |
| Node.js | 22.22.3 | Exact NVD CPE/CVE path when verified |
| Express and node-postgres | Exact npm lockfile versions | Exact OSV package path |

A keyword search is never treated as proof of identity. An approximate CPE is
not written into the graph.

## Architecture at a glance

```text
  Containerlab + Docker + OVS + FRRouting
                  |
                  v
          Mirrored network traffic
                  |
                  v
             Zeek probes
                  |
                  v
        JSON conn.log / dhcp.log
                  |
                  v
       Python parsing and normalization
                  |
                  v
       Neo4j evidence and derived graph
                  |
                  v
       NVD CPE/CVE + OSV enrichment
                  |
                  v
          Graph audit and readiness
                  |
                  v
    Future: simulation, agents, LLMs, response
```

The main operational path is:

```text
traffic -> Zeek logs -> import_zeek.py -> Neo4j graph
                                      |
                                      v
                         enrich_vulnerabilities.py
                                      |
                                      v
                              audit_graph.py
```

## Quick start

Run these commands from the repository root.

### Prerequisites

The host must provide:

- Docker Engine and Docker Compose;
- Containerlab;
- Open vSwitch;
- Python 3;
- Git;
- permission to run the required Containerlab and OVS commands with
  `sudo`.

### First-time setup

```bash
./scripts/setup.sh
```

This creates `backend/.venv`, installs the backend and development
dependencies, creates runtime directories, generates a local Neo4j password in
`infrastructure/.env` when needed, and prepares the OVS bridges.

The environment file is local and ignored by Git. Do not commit it.

### Start the lab

```bash
./scripts/start.sh
```

This starts Neo4j, rebuilds the pinned web and application images, deploys the
Containerlab topology, applies VLAN configuration, and recreates the OVS SPAN
mirrors.

Startup destroys and recreates the ephemeral Containerlab deployment. Persist
any intended change in the repository before running it again.

Verify the deployment:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' | grep clab-step2-switch
docker ps --filter name=notline-neo4j
curl -fsS http://localhost:7474 >/dev/null && echo 'Neo4j HTTP is ready'
```

Neo4j Browser is available at <http://localhost:7474>.

## Build the graph from current traffic

Neo4j and the lab must be running before these commands.

### 1. Initialize a fresh graph

The schema command is idempotent. Run it for a new database:

```bash
backend/.venv/bin/python scripts/init_graph.py
backend/.venv/bin/python backend/scripts/seed_inventory.py
```

`seed_inventory.py` writes the stable topology assets and their configured
addresses. The security enrichment stage also ensures the schema exists, but
explicit initialization makes a fresh deployment easier to understand.

### 2. Generate benign traffic

```bash
TRAFFIC_ROUNDS=3 ./scripts/generate_lab_traffic.sh
```

This produces passive evidence for DNS, the NGINX frontend and proxied API,
SSH, and SMB. It does not perform adversary activity.

### 3. Import Zeek evidence

```bash
backend/.venv/bin/python backend/scripts/import_zeek.py
```

The importer parses both configured probes, normalizes service evidence, groups
mirrored records into canonical flows, writes observations and DHCP assignments,
classifies current versus historical identities, and refreshes derived
communication relationships.

For a different capture cadence:

```bash
NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS=3600 \
  backend/.venv/bin/python backend/scripts/import_zeek.py
```

### 4. Enrich security relationships

```bash
backend/.venv/bin/python backend/scripts/enrich_vulnerabilities.py
```

This stage:

- resolves configured service/runtime identities to exact active NVD CPEs;
- fetches CVE records and writes only applicable CPE-to-CVE relationships;
- records unresolved CPE evidence without guessing;
- inventories exact npm packages from `app1/package-lock.json`;
- queries OSV for exact package versions;
- refreshes asset-to-CVE and asset-to-advisory exposure edges.

NVD and OSV responses are cached under `backend/.cache/`, which is ignored
runtime data.

### 5. Audit readiness

```bash
backend/.venv/bin/python backend/scripts/audit_graph.py
```

Read the three decisions separately:

- **Verified-path simulation readiness**: the graph has the evidence and derived
  relationships required for a verified simulation path.
- **Security coverage**: security identities have either verified CPE/CVE
  evidence or a completed alternative advisory scan.
- **Full security simulation readiness**: both conditions pass.

A passing audit means the graph prerequisites are satisfied. It does not mean
the adversary-simulation engine or self-healing agent has been implemented.

## Configuration boundary

Network-specific inputs are isolated in
[`backend/src/notline/network_profile.py`](backend/src/notline/network_profile.py).

The current profile contains the lab topology, probe log paths, trusted service
targets, software-component declarations, npm lockfile sources, and DHCP
activity-window policy.

Select a configured profile with:

```bash
NOTLINE_NETWORK_PROFILE=notline-lab \
  backend/.venv/bin/python backend/scripts/import_zeek.py
```

The reusable pipeline code is designed to support additional profiles, but a
new network still needs its own inventory, evidence sources, runtime identity
declarations, and validation. It is not automatically generic for every
network yet.

## Repository map

| Area | Purpose |
| --- | --- |
| [`step2.clab.yml`](step2.clab.yml) | Containerlab topology, services, addresses, and probe mounts |
| [`scripts/`](scripts/) | Setup, startup, graph initialization, and traffic generation |
| [`backend/scripts/`](backend/scripts/) | Inventory, Zeek import, enrichment, and audit entry points |
| [`backend/src/notline/discovery/`](backend/src/notline/discovery/) | Typed Zeek observations, service enrichment, inventory, and deduplication |
| [`backend/src/notline/graph/`](backend/src/notline/graph/) | Neo4j connection, schema, evidence writers, derived edges, and audit |
| [`backend/src/notline/security/`](backend/src/notline/security/) | NVD/OSV clients, CPE resolution, applicability, and security targets |
| [`backend/tests/`](backend/tests/) | Unit and graph-writer contract tests |
| [`docs/`](docs/) | Maintained architecture, operational, graph, security, and testing documentation |
| [`infrastructure/compose.yaml`](infrastructure/compose.yaml) | Neo4j service definition |
| [`app1/`](app1/) and [`web1/`](web1/) | Application and frontend container definitions |

## How to learn the project

Read the documentation in this order:

1. [`docs/README.md`](docs/README.md) — documentation map, scope, and source-of-truth rules.
2. [`docs/architecture/overview.md`](docs/architecture/overview.md) — system
   boundaries, components, runtime data flow, and current limitations.
3. [`docs/guides/deployment.md`](docs/guides/deployment.md) — prerequisites,
   startup, verification, mirrors, probes, and troubleshooting.
4. [`docs/guides/pipeline.md`](docs/guides/pipeline.md) — the repeatable
   traffic-to-graph workflow and its stage contracts.
5. [`docs/reference/graph-model.md`](docs/reference/graph-model.md) — node
   labels, evidence relationships, derived relationships, freshness, and
   exposure paths.
6. [`docs/reference/discovery.md`](docs/reference/discovery.md) — how Zeek
   records become observations, canonical flows, services, and assets.
7. [`docs/reference/security-enrichment.md`](docs/reference/security-enrichment.md)
   — exact CPE/CVE verification, applicability, NVD caching, npm inventory,
   OSV, and exposure derivation.
8. [`docs/reference/graph-writers.md`](docs/reference/graph-writers.md) — how
   Neo4j writes and refreshes evidence and derived edges.
9. [`docs/reference/code-map.md`](docs/reference/code-map.md) — executable
   entry points, module responsibilities, dependency direction, and test map.
10. [`docs/development/testing.md`](docs/development/testing.md) — test
    boundaries, quality gates, live smoke checks, and change checklist.

[`GRAPH_PIPELINE.md`](GRAPH_PIPELINE.md) is a short root-level command
reference. The detailed and maintained explanation is
[`docs/guides/pipeline.md`](docs/guides/pipeline.md).

When documentation and behavior disagree, use this order:

1. executable code and tests;
2. deployment configuration and live verification;
3. the maintained pages in [`docs/`](docs/);
4. older handoff notes or copied narrative material.

## Development roadmap

### Next: stabilize and reproduce the trusted graph

- Keep the fresh-deployment path reproducible from an empty Neo4j database.
- Add a live smoke check that verifies traffic, Zeek capture, import, enrichment,
  and audit in sequence.
- Keep runtime versions, security target declarations, and graph evidence
  synchronized.
- Review and improve the public repository documentation and lab credential
  handling before upload.

### Then: simulation over the audited graph

- Define a small, explicit scenario model for attacker entry points,
  capabilities, actions, and observable effects.
- Run read-only path analysis against the verified graph first.
- Preserve scenario evidence and outcomes in a separate simulation layer.
- Reject scenarios when the graph audit reports missing prerequisites.

### Later: agents and LLM reasoning

- Add agents only around trusted graph queries and explicit tools.
- Make LLM output advisory and explainable, with source paths back to graph
  evidence.
- Evaluate hallucination, uncertainty, and unsafe action proposals.
- Keep authorization, policy, and approval outside the model.

### Last: controlled self-healing

- Define a small allowlisted set of defensive actions.
- Require policy checks, approval gates, rollback, and post-action validation.
- Test only inside the isolated lab before considering broader deployment.

## Testing and quality checks

From the repository root:

```bash
cd backend
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
```

The test suite uses mocked request functions and recording Neo4j drivers for
fast, deterministic contract tests. Live Docker/OVS/Zeek/Neo4j behavior still
requires the deployment and pipeline checks described in
[`docs/development/testing.md`](docs/development/testing.md).

## Research and safety boundaries

This is an isolated research lab. Keep its services and credentials away from
production networks. Do not commit:

- `infrastructure/.env`;
- Neo4j data directories;
- Zeek logs and packet captures;
- Containerlab generated state or TLS material;
- virtual environments and API caches.

The lab credentials are disposable test credentials, not a security design.
Treat all automated or LLM-generated recommendations as untrusted until
validated by explicit policy and human-approved controls.
