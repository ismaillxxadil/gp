# Code map

This page is a navigation reference, not a second copy of the source. Read it
before opening a module so that each file is understood in the context of the
pipeline it serves.

## Executable entry points

| Entry point | Role | Main dependencies |
| --- | --- | --- |
| [scripts/setup.sh](../../scripts/setup.sh) | First-time host/backend setup, runtime directories, local Neo4j password, OVS bridge creation | Docker, Containerlab, OVS, Python |
| [scripts/start.sh](../../scripts/start.sh) | Starts Neo4j, rebuilds local images, prepares bridges, and rebuilds the lab | Docker Compose, Docker, `start-lab.sh` |
| [start-lab.sh](../../start-lab.sh) | Deploys Containerlab and configures OVS SPAN mirrors | Containerlab, OVS |
| [scripts/generate_lab_traffic.sh](../../scripts/generate_lab_traffic.sh) | Produces repeatable benign application traffic | `pc1`, `pc2`, HTTP, SSH, SMB, DNS |
| [scripts/init_graph.py](../../scripts/init_graph.py) | Initializes Neo4j uniqueness constraints | `graph.connection`, `graph.schema` |
| [backend/scripts/seed_inventory.py](../../backend/scripts/seed_inventory.py) | Writes stable topology assets and refreshes asset edges | `network_profile`, `graph.writer` |
| [backend/scripts/import_zeek.py](../../backend/scripts/import_zeek.py) | Parses Zeek logs, groups flows, writes evidence, and refreshes derived graph | discovery package, `graph.writer` |
| [backend/scripts/enrich_vulnerabilities.py](../../backend/scripts/enrich_vulnerabilities.py) | Resolves security identities, writes NVD/OSV evidence, and refreshes exposures | security package, `graph.security_writer` |
| [backend/scripts/audit_graph.py](../../backend/scripts/audit_graph.py) | Prints graph metrics and simulation readiness | `graph.audit` |

## Python package map

### `notline.discovery`

| Module | Responsibility |
| --- | --- |
| [models.py](../../backend/src/notline/discovery/models.py) | Pydantic models for connection and DHCP evidence; discoverable-IP validation |
| [zeek_parser.py](../../backend/src/notline/discovery/zeek_parser.py) | Converts one JSON record into a typed observation or rejects it |
| [service_enrichment.py](../../backend/src/notline/discovery/service_enrichment.py) | Normalizes Zeek service labels and applies conservative port hints |
| [deduplication.py](../../backend/src/notline/discovery/deduplication.py) | Groups same-flow records from mirrored probes and generates canonical IDs |
| [inventory.py](../../backend/src/notline/discovery/inventory.py) | Stable lab topology asset definitions |

### `notline.graph`

| Module | Responsibility |
| --- | --- |
| [connection.py](../../backend/src/notline/graph/connection.py) | Loads local Neo4j settings and owns the driver lifecycle |
| [schema.py](../../backend/src/notline/graph/schema.py) | Idempotent uniqueness constraints for graph identities |
| [writer.py](../../backend/src/notline/graph/writer.py) | Observation, IP, DHCP, inventory, service, and communication writes/derivations |
| [security_writer.py](../../backend/src/notline/graph/security_writer.py) | Verified CPE/CVE writes, unresolved identities, components, OSV advisories, exposures |
| [audit.py](../../backend/src/notline/graph/audit.py) | Metric queries and readiness predicates |

### `notline.security`

| Module | Responsibility |
| --- | --- |
| [models.py](../../backend/src/notline/security/models.py) | Typed NVD CPE, match criteria, configuration tree, and CVE records |
| [nvd_client.py](../../backend/src/notline/security/nvd_client.py) | Cached, paginated, rate-aware NVD API client |
| [applicability.py](../../backend/src/notline/security/applicability.py) | CPE 2.3 parsing and NVD boolean/version applicability evaluation |
| [cpe_resolution.py](../../backend/src/notline/security/cpe_resolution.py) | Filters candidate CPEs by active status, product alias, and exact version |
| [enrichment.py](../../backend/src/notline/security/enrichment.py) | Declares verified service targets and orchestrates service enrichment |
| [components.py](../../backend/src/notline/security/components.py) | Declares software component targets attached to assets |
| [package_inventory.py](../../backend/src/notline/security/package_inventory.py) | Reads exact npm package identities from lockfile v3 |
| [osv_models.py](../../backend/src/notline/security/osv_models.py) | Normalized OSV advisory model |
| [osv_client.py](../../backend/src/notline/security/osv_client.py) | Cached exact-version OSV API client |

### `notline.network_profile`

[network_profile.py](../../backend/src/notline/network_profile.py) is the
configuration boundary between reusable pipeline logic and a particular
network. It selects log sources, static inventory, trusted security targets,
software components, package lockfiles, and the DHCP activity window.

## Dependency direction

The intended dependency direction is:

```text
entry-point scripts
        |
        +--> network_profile
        +--> discovery -----> graph.writer
        +--> security -----> graph.security_writer
        +--> graph.connection / graph.schema / graph.audit
```

Discovery models do not import Neo4j. Security models and API clients do not
write to Neo4j directly. Graph writers are the persistence boundary. This
separation keeps parsing, security decisions, and database mutation testable
independently.

## Tests as executable contracts

The tests are grouped by behavior rather than by a single end-to-end fixture:

- [test_zeek_parser.py](../../backend/tests/test_zeek_parser.py): validation,
  filtering, and DHCP status rules;
- [test_deduplication.py](../../backend/tests/test_deduplication.py): mirrored
  flow grouping and canonical IDs;
- [test_service_enrichment.py](../../backend/tests/test_service_enrichment.py):
  service normalization and port inference;
- [test_graph_writer.py](../../backend/tests/test_graph_writer.py): evidence,
  inventory, DHCP freshness, and derived asset edges;
- [test_enrichment.py](../../backend/tests/test_enrichment.py),
  [test_cpe_resolution.py](../../backend/tests/test_cpe_resolution.py), and
  [test_cpe_applicability.py](../../backend/tests/test_cpe_applicability.py):
  trusted CPE selection and CVE applicability;
- [test_security_writer.py](../../backend/tests/test_security_writer.py) and
  [test_exposure_writer.py](../../backend/tests/test_exposure_writer.py):
  security graph persistence and exposure cleanup;
- [test_graph_audit.py](../../backend/tests/test_graph_audit.py): readiness
  metrics and blockers.

Run the complete backend contract suite with:

```bash
cd backend
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
```
