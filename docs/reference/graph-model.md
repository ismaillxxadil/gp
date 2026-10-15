# Neo4j graph model

The graph has two layers:

1. **evidence**, which records what the topology and passive sensors observed;
2. **derived security context**, which summarizes communications, service
   identity, vulnerability applicability, and exposure.

Derived relationships must remain explainable through the evidence paths that
produced them.

## Node labels

| Label | Identity key | Meaning |
| --- | --- | --- |
| `Asset` | `asset_id` | A stable topology identity or a passively observed DHCP/MAC identity |
| `IPAddress` | `address` | An observed or inventory IP address |
| `Observation` | `observation_id` | One probe-specific Zeek connection observation |
| `Service` | `service_id` | A service derived from destination IP, protocol, port, and normalized service name |
| `SoftwareComponent` | `component_id` | A runtime, framework, library, or exact package identity attached to an asset |
| `CPE` | `cpe_name` | An active, verified CPE 2.3 identity from NVD |
| `CVE` | `cve_id` | A normalized NVD vulnerability record |
| `Advisory` | `advisory_id` | An exact-version ecosystem advisory, currently from OSV |

The uniqueness constraints are declared in
[graph/schema.py](../../backend/src/notline/graph/schema.py).

## Evidence relationships

| Relationship | Direction | Purpose |
| --- | --- | --- |
| `SOURCE_IP` | `Observation -> IPAddress` | Source address in one Zeek record |
| `DESTINATION_IP` | `Observation -> IPAddress` | Destination address in one Zeek record |
| `HAS_IP` | `Asset -> IPAddress` | Topology or DHCP identity-to-address evidence |
| `HAS_COMPONENT` | `Asset -> SoftwareComponent` | Runtime, lockfile, or component evidence on an asset |
| `RUNS_SERVICE` | `IPAddress -> Service` | Passive service evidence derived from observations |

An observation stores its probe, timestamp, protocol, service, service source,
ports, state, byte counts, packet counts, and canonical flow ID. The original
probe-specific observation remains available even when two probes observe the
same physical flow.

## Derived relationships

| Relationship | Direction | Source path | Meaning |
| --- | --- | --- | --- |
| `COMMUNICATES_WITH` | `IPAddress -> IPAddress` | observations | Aggregated directed IP communication |
| `ASSET_COMMUNICATES_WITH` | `Asset -> Asset` | `HAS_IP` + `COMMUNICATES_WITH` | Provisional asset-level communication mapping |
| `IDENTIFIED_AS` | `Service -> CPE` or `SoftwareComponent -> CPE` | verified enrichment | Exact product identity backed by evidence |
| `AFFECTED_BY` | `CPE -> CVE` | NVD applicability | The CPE is vulnerable under an applicable NVD match |
| `AFFECTED_BY` | `SoftwareComponent -> Advisory` | OSV exact-version query | The package identity has an exact-version advisory |
| `EXPOSED_TO` | `Asset -> CVE` | service path | Current asset reaches a vulnerable observed service |
| `EXPOSED_TO` | `Asset -> Advisory` | component path | Current asset owns a component affected by an advisory |

The two `AFFECTED_BY` patterns are intentionally distinguished by the target
label and the relationship's `source` property (`nvd` or `osv`).

## Main security paths

### Service vulnerability path

```text
Asset -[:HAS_IP]-> IPAddress
      -[:RUNS_SERVICE]-> Service
      -[:IDENTIFIED_AS]-> CPE
      -[:AFFECTED_BY]-> CVE
```

The exposure writer derives:

```text
Asset -[:EXPOSED_TO]-> CVE
```

only when the `AFFECTED_BY` relationship is marked `vulnerable = true` and the
communication/service evidence is compatible with the asset's DHCP lease.

### Package advisory path

```text
Asset -[:HAS_COMPONENT]-> SoftwareComponent
      -[:AFFECTED_BY {source: 'osv'}]-> Advisory
```

The advisory exposure writer derives an asset-level `EXPOSED_TO` relationship
from that exact package path. It records the component IDs and package URLs on
the derived relationship.

## Identity and freshness states

### Asset discovery status

| Status | Meaning | Included in current derived edges? |
| --- | --- | --- |
| `inventory` | Stable identity from the configured topology profile | Yes |
| `passive` | DHCP identity created from a confirmed lease before current-window reconciliation | Temporarily, then classified |
| `passive_current` | DHCP identity observed inside the current activity window | Yes |
| `historical` | DHCP identity retained for evidence but outside the current window | No |
| `retired` | Topology identity no longer present in the current inventory | No |

The importer uses the latest confirmed DHCP timestamp as the capture end and a
default 900-second activity window. Override it with
`NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS`. The logic is implemented in
[graph/writer.py](../../backend/src/notline/graph/writer.py).

### Service evidence status

Services are marked `passive` when Zeek supplied the service label and
`passive_inferred` when the backend supplied the supported port hint. The
provenance is also kept on the service relationship through
`evidence_sources`.

### Security identity status

Services and software components have `cpe_resolution_status` values such as
`resolved` or `unresolved`. Unresolved records keep the reason, candidate CPEs,
and optional active match criteria. They do not receive an approximate CPE.

Npm components additionally have `osv_scan_status`: `pending`, `complete`, or
`error`. Full security coverage accepts an unresolved CPE when an alternative
OSV scan completed successfully.

## Reproducible graph inspection

Open Neo4j Browser at `http://localhost:7474` and use focused queries rather
than rendering every node at once.

### Overview counts

```cypher
MATCH (n)
RETURN labels(n) AS labels, count(*) AS count
ORDER BY labels;
```

### Current service-to-CVE exposure

```cypher
MATCH (a:Asset)-[e:EXPOSED_TO]->(cve:CVE)
RETURN a.asset_id, e.service_ids, e.cpe_names, cve.cve_id,
       cve.cvss_base_score
ORDER BY a.asset_id, cve.cve_id;
```

### Package advisory exposure

```cypher
MATCH (a:Asset)-[e:EXPOSED_TO]->(advisory:Advisory)
RETURN a.asset_id, e.component_ids, e.package_purls,
       advisory.advisory_id, advisory.aliases
ORDER BY a.asset_id, advisory.advisory_id;
```

### Explain one observed flow

```cypher
MATCH (o:Observation)-[:SOURCE_IP]->(src:IPAddress),
      (o)-[:DESTINATION_IP]->(dst:IPAddress)
RETURN o, src, dst
ORDER BY o.timestamp DESC
LIMIT 25;
```
