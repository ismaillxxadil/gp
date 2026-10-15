# Graph writers and audit reference

The graph package is the persistence boundary of the backend. Discovery and
security code decide what evidence means; the graph writers translate those
decisions into idempotent Neo4j mutations and derived relationships.

## Responsibilities

| Module | Responsibility |
| --- | --- |
| [connection.py](../../backend/src/notline/graph/connection.py) | Load local Neo4j settings, create a driver, verify connectivity, and close it |
| [schema.py](../../backend/src/notline/graph/schema.py) | Create idempotent uniqueness constraints |
| [writer.py](../../backend/src/notline/graph/writer.py) | Store observations, topology identities, DHCP leases, and communication/service edges |
| [security_writer.py](../../backend/src/notline/graph/security_writer.py) | Store CPE/CVE/component/advisory evidence and derived exposures |
| [audit.py](../../backend/src/notline/graph/audit.py) | Measure graph state and decide readiness |

The graph package deliberately does not read Zeek files or call NVD/OSV. The
entry-point scripts coordinate those activities and pass typed values to the
writers.

## Two graph layers

### Evidence layer

Evidence writes preserve what was observed or configured:

- `Observation` nodes retain one probe-specific Zeek record;
- `IPAddress` nodes retain addresses seen in records or inventory;
- `Asset` nodes represent topology identities or observed DHCP/MAC identities;
- `HAS_IP` relationships preserve topology and lease evidence;
- `Service` nodes summarize service observations;
- `SoftwareComponent` nodes preserve runtime and package identities.

Evidence writes use `MERGE` with stable identifiers and then update mutable
metadata. Re-running an import therefore does not create a second node for the
same observation, address, asset, or service identity.

### Derived layer

Derived relationships summarize evidence:

- `COMMUNICATES_WITH` aggregates observation counts between IP addresses;
- `RUNS_SERVICE` connects destination IPs to observed services;
- `ASSET_COMMUNICATES_WITH` maps IP communication to current asset identities;
- `EXPOSED_TO` connects current assets to verified CVEs or exact-version
  advisories.

The first three are maintained by [writer.py](../../backend/src/notline/graph/writer.py);
security exposures are maintained by
[security_writer.py](../../backend/src/notline/graph/security_writer.py).

## Schema constraints

[schema.py](../../backend/src/notline/graph/schema.py) creates these Neo4j
constraints with `IF NOT EXISTS`:

| Label | Unique property |
| --- | --- |
| `Asset` | `asset_id` |
| `IPAddress` | `address` |
| `Service` | `service_id` |
| `Observation` | `observation_id` |
| `CPE` | `cpe_name` |
| `CVE` | `cve_id` |
| `SoftwareComponent` | `component_id` |
| `Advisory` | `advisory_id` |

The constraints protect `MERGE` operations from creating duplicate identities.
They do not validate semantic correctness; parser validation, exact identity
checks, and tests provide that layer.

## Observation write path

`write_connection` receives one validated `ConnectionObservation` and a
canonical flow ID. It:

1. merges the source and destination `IPAddress` nodes;
2. merges an `Observation` using `probe:uid`;
3. updates timestamp, transport, service, provenance, ports, state, byte and
   packet counters, and canonical flow metadata;
4. creates `SOURCE_IP` and `DESTINATION_IP` relationships.

The observation is the durable evidence unit. It is not replaced by the
aggregated communication relationship.

## IP communication derivation

`update_communication_graph` matches observation endpoints and groups them by
source and destination IP. For each directed pair it stores:

- raw observation count;
- distinct canonical flow count;
- protocols;
- first-seen timestamp;
- last-seen timestamp.

The result is an `IPAddress -[:COMMUNICATES_WITH]-> IPAddress` relationship.
It is an upsert over the accumulated observation set, so historical evidence
remains visible. This relationship is not an authorization or reachability
proof; it is an observed communication summary.

## Service derivation

`update_service_graph` considers observations with a non-empty service and a
destination port. Its service identity is deterministic:

```text
service:<destination-ip>|<protocol>|<destination-port>|<service-name>
```

The service node stores the normalized name, protocol, port, discovery status,
observation counts, flow counts, first-seen, and last-seen timestamps. The
`IPAddress -[:RUNS_SERVICE]-> Service` relationship stores the evidence source
(`zeek_conn`, `port_inference`, or `mixed`) and the same aggregate counts.

Direct Zeek labels produce `passive`; the supported port hint produces
`passive_inferred`. The provenance is retained so later discovery improvements
can distinguish measured service identity from inference.

## Topology inventory writes

`write_inventory_asset` writes stable identities declared by the selected
[network profile](../../backend/src/notline/network_profile.py). Each inventory
asset receives:

- `identity_source = "containerlab_topology"`;
- `discovery_status = "inventory"`;
- its configured name, type, zone, and addresses;
- `HAS_IP` relationships with topology evidence.

`retire_unlisted_inventory_assets` marks older topology identities as
`retired` rather than deleting them. It requires a non-empty current inventory
ID list as a safety check. A later inventory write clears a previous
`retired_reason` for an identity that becomes current again.

## DHCP identity and freshness

`write_dhcp_assignment` accepts only confirmed ACK observations with an
assigned IP. It creates or updates an asset whose ID is `mac:<lowercase-mac>`
and writes a `HAS_IP` lease with:

- `evidence = "dhcp_ack"`;
- source `zeek`;
- lease timestamp;
- lease duration;
- calculated expiry when a duration exists.

`reconcile_dhcp_asset_status` evaluates every Zeek DHCP identity after the
import. The latest confirmed lease timestamp is compared to:

```text
active_since = capture_end - activity_window_seconds
```

The default activity window is 900 seconds. A current identity becomes
`passive_current`; an older identity becomes `historical`. The capture ID,
capture end, last observed timestamp, and window are recorded on the asset.
This is why the graph can retain historical clients without treating their old
addresses as current simulation participants.

## Asset communication derivation

`update_asset_communication_graph` maps:

```text
Asset -> HAS_IP -> IPAddress
      -> COMMUNICATES_WITH -> IPAddress
      <- HAS_IP <- Asset
```

It applies four important guards:

1. self-communication is excluded;
2. retired and historical endpoints are excluded;
3. DHCP-backed endpoints must have communication timestamps compatible with
   their lease interval;
4. old provisional edges involving retired or historical assets are deleted
   before current mappings are rebuilt.

The resulting relationship is marked `mapping_status = "provisional"`. That
word is intentional: it is a current evidence-based identity mapping, not an
absolute claim that the asset identity can never be ambiguous.

## Security writer contract

Security writers enforce the boundary between candidate metadata and verified
security relationships:

- `write_verified_service_vulnerabilities` requires an existing service and an
  exact observed/resolved CPE match;
- `write_verified_component_vulnerabilities` requires an existing asset-to-
  component relationship and applies the same exact-match rule;
- both evaluate NVD applicability before creating `CPE -[:AFFECTED_BY]-> CVE`;
- unresolved service/component writers keep reasons and candidates without
  creating an unverified CPE;
- npm inventory writers preserve exact package identity from the lockfile;
- OSV writers replace stale OSV advisory edges for the scanned component;
- exposure writers derive and remove stale `EXPOSED_TO` edges from current
  evidence.

Detailed source relationships and security paths are in the
[graph model](./graph-model.md). The focused contracts are tested in
[test_graph_writer.py](../../backend/tests/test_graph_writer.py),
[test_security_writer.py](../../backend/tests/test_security_writer.py), and
[test_exposure_writer.py](../../backend/tests/test_exposure_writer.py).

## Audit contract

[audit.py](../../backend/src/notline/graph/audit.py) runs one query per metric
and fails if any query returns no value. Important metrics include:

- total, active, historical, and retired assets;
- IP addresses, observations, IP communication, and asset communication;
- services and services resolved to CPEs;
- CPEs, CVEs, verified CPE-to-CVE relationships, and CVE exposures;
- advisory nodes and advisory exposures;
- software/package components and OSV scan status;
- unresolved services/components and unresolved components without OSV.

`GraphAudit.ready_for_simulation` requires:

1. at least one active asset;
2. passive observations;
3. asset communication edges;
4. discovered services;
5. at least one service mapped to a verified CPE;
6. at least one verified CPE-to-CVE relationship;
7. at least one derived asset-to-CVE exposure.

`security_coverage_complete` additionally requires:

- zero unresolved services;
- zero unresolved components without an alternative OSV result;
- zero unscanned npm components;
- zero OSV scan errors.

`ready_for_full_security_simulation` is true only when both predicates pass.
The command-line presentation is in
[audit_graph.py](../../backend/scripts/audit_graph.py).

## Change checklist

When changing a graph writer:

1. identify whether the change affects evidence or derived data;
2. preserve stable identity keys and uniqueness constraints;
3. define whether old relationships are retained, refreshed, or deleted;
4. keep provenance and timestamps on derived relationships;
5. add or update a focused fake-driver test;
6. update [graph-model.md](./graph-model.md) and this page;
7. run the graph writer, exposure, audit, and full backend tests.
