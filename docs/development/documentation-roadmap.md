# Documentation roadmap

This roadmap keeps the documentation work incremental. Each part should be
written from the current source and tests, then checked against a real pipeline
run when the behavior depends on Neo4j, Zeek, Docker, or external security
feeds.

## Completed in this increment

- documentation hub and writing rules;
- system context and implemented/planned boundary;
- executable entry points and package map;
- Neo4j labels, relationships, evidence, and freshness semantics;
- reproducible passive-import and security-enrichment guide.

## Next module-by-module parts

### Part 2 — Discovery reference

Started in [discovery.md](../reference/discovery.md). The remaining work is to
add more concrete input/output examples if the Zeek schema or supported
service inference table expands.

Document the contracts and examples for:

- `ConnectionObservation` and `DHCPObservation`;
- discoverable-IP filtering;
- Zeek parsing and rejection behavior;
- layered service normalization;
- cross-probe flow grouping and canonical IDs.

Primary sources: [discovery/models.py](../../backend/src/notline/discovery/models.py),
[discovery/zeek_parser.py](../../backend/src/notline/discovery/zeek_parser.py),
[discovery/service_enrichment.py](../../backend/src/notline/discovery/service_enrichment.py),
[discovery/deduplication.py](../../backend/src/notline/discovery/deduplication.py),
and their focused tests.

### Part 3 — Graph writer reference

Started in [graph-writers.md](../reference/graph-writers.md). The remaining
work is to add query-by-query examples if the graph schema changes or new
derived relationship types are introduced.

Document each write/refresh operation, its input evidence, its Cypher effect,
and its stale-data behavior. Include a small lifecycle example from an
observation to `ASSET_COMMUNICATES_WITH`.

Primary sources: [graph/writer.py](../../backend/src/notline/graph/writer.py),
[graph/schema.py](../../backend/src/notline/graph/schema.py), and
[test_graph_writer.py](../../backend/tests/test_graph_writer.py).

### Part 4 — Security reference

Started in [security-enrichment.md](../reference/security-enrichment.md). The
remaining work is to add examples for new security data sources when the
project expands beyond NVD and OSV.

Document the NVD data model, exact CPE selection, recursive applicability
evaluation, NVD caching, OSV package scanning, and security writer contracts.
Include a clear distinction between candidate data, verified identities, and
derived exposure.

Primary sources: [security/models.py](../../backend/src/notline/security/models.py),
[security/applicability.py](../../backend/src/notline/security/applicability.py),
[security/nvd_client.py](../../backend/src/notline/security/nvd_client.py),
[security/osv_client.py](../../backend/src/notline/security/osv_client.py), and
[graph/security_writer.py](../../backend/src/notline/graph/security_writer.py).

### Part 5 — Lab and deployment runbooks

Started in [lab-topology.md](../reference/lab-topology.md) and
[deployment.md](../guides/deployment.md). The remaining work is to reconcile
the repeated legacy material in the root README and keep these runbooks aligned
with any topology changes.

Split the existing topology notes into setup, deployment, verification, mirror
troubleshooting, service troubleshooting, and graph troubleshooting. Reconcile
the older root [README.md](../../README.md) with the current implemented
pipeline so readers do not encounter stale claims.

### Part 6 — Testing and quality

Documented in [testing.md](./testing.md). Update it when the test strategy,
external-feed boundaries, or required quality gates change.

Document test fixtures, fake Neo4j drivers, external API mocking, the meaning
of the full test suite, and which checks are required before graph changes are
accepted.

### Part 7 — Simulation boundary

When simulation code exists, document its inputs, safety gates, dry-run mode,
action audit trail, and rollback behavior. Do not describe future agent or LLM
behavior as implemented before those contracts exist.

## Maintenance checklist

For every code change:

1. update the relevant reference or guide;
2. link to the owning source file and focused tests;
3. distinguish observed behavior from design intent;
4. record new assumptions, unresolved identities, or safety gates;
5. run the smallest relevant tests, then the complete backend checks when the
   change crosses package boundaries.
