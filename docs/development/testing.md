# Testing and quality reference

The backend tests are primarily fast unit/contract tests. They protect parsing,
identity decisions, Cypher construction, security applicability, and audit
rules without requiring a running Neo4j instance or live NVD/OSV requests.

## Test stack

The test and lint dependencies are declared in
[backend/pyproject.toml](../../backend/pyproject.toml):

- pytest for automated tests;
- Ruff for linting and formatting;
- injected request functions for NVD and OSV client tests;
- small recording drivers for graph-writer tests.

## Test boundaries

### Pure discovery behavior

[test_zeek_parser.py](../../backend/tests/test_zeek_parser.py) verifies required
fields, malformed-record rejection, discoverable-IP filtering, and DHCP message
classification.

[test_service_enrichment.py](../../backend/tests/test_service_enrichment.py)
verifies service normalization, layered Zeek labels, and the deliberately small
port-inference table.

[test_deduplication.py](../../backend/tests/test_deduplication.py) verifies
same-probe identity, cross-probe timestamp tolerance, different-flow
separation, and deterministic canonical IDs.

### Graph writer contracts

Graph tests use a RecordingDriver with an execute_query method. They inspect
the generated Cypher and parameters rather than connecting to Neo4j. This
keeps tests fast and makes important persistence contracts visible:

- observation IDs and metadata are updated with MERGE/SET;
- inventory assets and addresses use topology evidence;
- retired/history cleanup happens before provisional asset-edge refresh;
- DHCP activity windows produce current versus historical states;
- security writers require existing service/component evidence;
- stale exposure edges are removed before current exposure derivation.

Relevant tests are [test_graph_writer.py](../../backend/tests/test_graph_writer.py),
[test_security_writer.py](../../backend/tests/test_security_writer.py), and
[test_exposure_writer.py](../../backend/tests/test_exposure_writer.py).

### Security and external-feed behavior

[test_cpe_resolution.py](../../backend/tests/test_cpe_resolution.py) verifies
that product aliases, exact versions, malformed entries, and deprecated
entries are handled conservatively.

[test_cpe_applicability.py](../../backend/tests/test_cpe_applicability.py)
verifies CPE parsing, escaped fields, NVD AND/OR/negation behavior, and version
bounds.

[test_nvd_client.py](../../backend/tests/test_nvd_client.py) injects response
functions to test pagination, cache reuse, deprecated filtering, active match
criteria, and OSV request normalization without live network calls.

[test_package_inventory.py](../../backend/tests/test_package_inventory.py)
verifies exact direct/transitive npm identities and invalid lockfile rejection.

### Readiness behavior

[test_graph_audit.py](../../backend/tests/test_graph_audit.py) verifies metric
collection, readiness blockers, full security coverage, and failure when an
audit query returns no result.

[test_network_profile.py](../../backend/tests/test_network_profile.py)
verifies profile selection and the configurable DHCP activity window.

## Required local checks

Run these from the backend directory:

~~~bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
~~~

The first command validates behavior. The second catches lint and import
problems. The third prevents formatting drift from obscuring code changes.

## Live integration smoke check

Unit tests do not prove that Docker, OVS, Containerlab, Zeek, Neo4j, and the
external security feeds work together. For a live graph change, also run:

1. [deployment verification](../guides/deployment.md);
2. [benign traffic generation](../guides/pipeline.md);
3. Zeek import;
4. NVD/OSV enrichment;
5. graph audit.

The final command must be interpreted from its separate states:

- verified-path readiness;
- security coverage;
- full security simulation readiness.

A passing unit suite does not justify skipping the live audit. A passing live
audit does not justify skipping unit tests for a changed rule.

## Change checklist

Before accepting a change:

1. add or update the smallest focused test for the changed rule;
2. preserve unresolved/error states instead of converting them into false
   positive evidence;
3. run pytest, Ruff check, and Ruff format check;
4. run the live pipeline when the change affects Docker versions, Zeek input,
   Neo4j queries, external feeds, or readiness;
5. update the relevant reference page and the
   [documentation roadmap](./documentation-roadmap.md) if scope changes.
