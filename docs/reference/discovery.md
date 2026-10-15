# Passive discovery reference

The discovery package turns Zeek JSON into trusted, typed evidence. It does
not perform active probing and it does not decide whether a host is
vulnerable. Its job ends when normalized observations and conservative service
hints are ready for the graph writer.

## Module responsibilities

```text
Zeek JSON
   |
   v
zeek_parser.py -----> ConnectionObservation / DHCPObservation
   |                                      |
   v                                      v
service_enrichment.py              deduplication.py
   |                                      |
   +------------------------------> import_zeek.py
                                          |
                                          v
                                    graph/writer.py
```

| Module | Contract |
| --- | --- |
| [models.py](../../backend/src/notline/discovery/models.py) | Defines typed observation objects and IP eligibility |
| [zeek_parser.py](../../backend/src/notline/discovery/zeek_parser.py) | Converts one record at a time, returning `None` for invalid input |
| [service_enrichment.py](../../backend/src/notline/discovery/service_enrichment.py) | Normalizes service labels and adds explicitly labeled port inference |
| [deduplication.py](../../backend/src/notline/discovery/deduplication.py) | Groups mirrored records without discarding the raw records |
| [import_zeek.py](../../backend/scripts/import_zeek.py) | Orchestrates file reading, grouping, writing, DHCP freshness, and graph refresh |

## Connection observations

`parse_connection(record, probe)` requires these Zeek fields:

- `id.orig_h` and `id.resp_h` as source and destination IP strings;
- `uid` as the Zeek connection identity;
- `ts` as the timestamp;
- `proto` as the transport protocol.

The following values are copied when present:

| Zeek field | Model field |
| --- | --- |
| `id.orig_p` | `source_port` |
| `id.resp_p` | `destination_port` |
| `service` | normalized `service` and `service_components` |
| `conn_state` | `connection_state` |
| `duration` | `duration` |
| `orig_bytes`, `resp_bytes` | `source_bytes`, `destination_bytes` |
| `orig_ip_bytes`, `resp_ip_bytes` | `source_ip_bytes`, `destination_ip_bytes` |
| `orig_pkts`, `resp_pkts` | `source_packets`, `destination_packets` |

The observation ID written to Neo4j is `probe:uid`. This preserves the
individual sensor record even when it belongs to a cross-probe canonical flow.

## IP filtering

`is_discoverable_ip` rejects:

- unspecified addresses such as `0.0.0.0`;
- multicast addresses;
- loopback addresses;
- link-local addresses.

Private RFC1918 addresses are accepted because they are the normal addresses
of this lab. The parser returns `None` when either endpoint is absent,
unusable, or fails Pydantic validation. The importer counts such records as
skipped rather than stopping the whole log import.

## DHCP observations

`parse_dhcp` derives an assignment status from `msg_types`:

| Message evidence | Status |
| --- | --- |
| contains `ACK` | `confirmed` |
| contains `REQUEST` but no `ACK` | `requested` |
| anything else | `unknown` |

The importer persists only `confirmed` records that contain an assigned IP.
The asset identity becomes `mac:<lowercase-mac>`, and the `HAS_IP` lease
relationship stores the observation timestamp, lease duration, and calculated
expiry when available. See the [graph model](./graph-model.md) for the
current/historical classification that happens after import.

## Service normalization

Zeek can report layered values such as `http,ssl`. The normalizer:

1. splits on commas;
2. trims and case-folds each component;
3. keeps the complete component list;
4. chooses a graph-facing service using this priority:
   `http`, `postgresql`, `smb`, `ssh`, `dhcp`;
5. uses the single remaining component when there is only one;
6. otherwise preserves the original value as the service name.

If Zeek supplies no service, the current explicit inference table contains only
`tcp/5432 -> postgresql`. The resulting observation records
`service_source = "port_inference"`, so inferred evidence cannot be confused
with a direct Zeek label. Unknown ports are left unresolved.

## Mirrored-flow grouping

`flow_signature` uses the directed transport identity:

```text
(protocol, source_ip, destination_ip, source_port, destination_port)
```

`group_connection_observations` then applies these rules:

- records from the same probe match only when their Zeek UIDs are equal;
- records from different probes match when their signatures are equal and
  their timestamps differ by at most `0.1` seconds;
- a negative timestamp tolerance is rejected;
- groups are processed deterministically by signature, timestamp, probe, and
  UID.

`canonical_flow_id` uses the earliest deterministic representative and embeds
the transport identity plus the timestamp rounded to milliseconds. The ID is
stored on every raw observation in the group. This gives aggregate graph
relationships a stable flow count while preserving sensor provenance.

## Import sequence

[import_zeek.py](../../backend/scripts/import_zeek.py) performs the following
sequence:

1. load the connection sources from the selected network profile;
2. parse valid records and add service hints;
3. group them and assign each `(probe, uid)` a canonical flow ID;
4. write every observation;
5. read and write confirmed DHCP assignments;
6. classify DHCP identities using the latest confirmed timestamp and the
   configured activity window;
7. refresh IP communication, service, and asset communication edges.

The importer is intentionally not responsible for CPE/CVE or OSV work. That
boundary belongs to [enrich_vulnerabilities.py](../../backend/scripts/enrich_vulnerabilities.py).

## Test contracts

The behavior is covered by:

- [test_zeek_parser.py](../../backend/tests/test_zeek_parser.py) for accepted
  fields, invalid records, IP filters, and DHCP message classification;
- [test_service_enrichment.py](../../backend/tests/test_service_enrichment.py)
  for layered labels and the PostgreSQL port hint;
- [test_deduplication.py](../../backend/tests/test_deduplication.py) for
  same-probe identity, cross-probe tolerance, and deterministic IDs;
- [test_network_profile.py](../../backend/tests/test_network_profile.py) for
  configured log sources and the DHCP window override.

When changing discovery behavior, update the corresponding test and this page
together. A parser change can alter graph counts, service identity, exposure
paths, and simulation readiness even when the graph writer itself is unchanged.
