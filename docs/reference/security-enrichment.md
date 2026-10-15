# Security enrichment reference

Security enrichment adds vulnerability context to identities that were already
observed or inventoried. It does not discover arbitrary products by guessing
and it does not create a service or component that the evidence graph does not
already contain.

## Trust boundary

The security pipeline has four evidence levels:

```text
runtime/topology evidence
        |
        v
NVD/OSV candidate lookup
        |
        v
exact identity verification
        |
        v
applicability evaluation
        |
        v
verified vulnerability/advisory relationship
        |
        v
derived current asset exposure
```

A keyword search is not proof of identity. A CPE is written only when the
configured product aliases and exact version match, the CPE is active, and the
expected identity is unambiguous. A CVE relationship is written only when the
NVD configuration and version rules say that the observed CPE is vulnerable.

The orchestration entry point is
[enrich_vulnerabilities.py](../../backend/scripts/enrich_vulnerabilities.py).
The lower-level graph mutations live in
[graph/security_writer.py](../../backend/src/notline/graph/security_writer.py).

## Security target declarations

### Verified service targets

The current lab profile declares these exact runtime identities in
[security/enrichment.py](../../backend/src/notline/security/enrichment.py):

| Service | Evidence source | Expected CPE |
| --- | --- | --- |
| PostgreSQL 18.0 | `db1_runtime_version` | `cpe:2.3:a:postgresql:postgresql:18.0:*:*:*:*:*:*:*` |
| Samba 4.20.6 | `files1_runtime_version` | `cpe:2.3:a:samba:samba:4.20.6:*:*:*:*:*:*:*` |
| OpenSSH 9.9p2 | `srv1_runtime_version` | `cpe:2.3:a:openbsd:openssh:9.9:p2:*:*:*:*:*:*` |
| NGINX Open Source 1.30.3 | `web1_runtime_version` | `cpe:2.3:a:f5:nginx_open_source:1.30.3:*:*:*:*:*:*:*` |

These targets are tied to service IDs derived from passive service discovery.
The writer must match an existing `Service`; enrichment cannot create an
unobserved service just because a target is configured.

### Application components

[security/components.py](../../backend/src/notline/security/components.py)
declares software evidence attached to `app1`:

| Component | Version | Identity path |
| --- | --- | --- |
| Node.js runtime | 22.22.3 | Exact NVD CPE, when verified |
| Express | 5.2.1 | Exact npm package plus OSV; no expected CPE currently configured |
| node-postgres (`pg`) | 8.23.1 | Exact npm package plus OSV; no expected CPE currently configured |

The Dockerfile pins the Node.js runtime so the configured exact CPE remains
reproducible. Package versions come from the lockfile and are not inferred from
the service name.

## NVD data model

[security/models.py](../../backend/src/notline/security/models.py) normalizes
the NVD response into small typed models:

- `NvdCpeName`: one CPE dictionary entry, including deprecation and metadata;
- `NvdCpeMatchCriterion`: an active version-range match-string result;
- `NvdCpeMatch`: one CVE configuration criterion, including vulnerability and
  version bounds;
- `NvdConfigurationNode`: recursive `AND`/`OR`/`negate` structure;
- `NvdCveRecord`: CVE metadata, selected CVSS score, and configuration tree.

The models preserve the fields needed for later applicability decisions rather
than flattening a CVE into a product/version label.

## CPE resolution

[security/cpe_resolution.py](../../backend/src/notline/security/cpe_resolution.py)
contains the reusable candidate filter. It rejects candidates that are:

- deprecated;
- malformed CPE 2.3 bindings;
- not one of the configured product aliases;
- not the exact observed product version.

[security/enrichment.py](../../backend/src/notline/security/enrichment.py)
then applies a stricter service-target check: the resolved CPE name must equal
the target's expected CPE exactly, and exactly one active match must remain.

For software components, the same exact expected-CPE check is applied before
`write_verified_component_vulnerabilities` is called. When no exact CPE is
verified, the component is recorded as unresolved with candidate names,
optional active match criteria, and a reason. No approximate CPE node is
created.

## NVD client behavior

[security/nvd_client.py](../../backend/src/notline/security/nvd_client.py)
provides three operations:

| Method | NVD endpoint | Use |
| --- | --- | --- |
| `search_cpes` | `/cpes/2.0` | Candidate dictionary lookup by keyword |
| `fetch_cves_for_cpe` | `/cves/2.0` | All CVE records associated with one exact CPE |
| `search_cpe_match_criteria` | `/cpematch/2.0` | Active version-range criteria for unresolved evidence |

The client:

- paginates responses;
- filters deprecated CPE dictionary entries in `search_cpes`;
- rate-limits requests with a default six-second minimum interval;
- retries retryable network/server failures;
- accepts an optional NVD API key;
- caches JSON responses by endpoint and sorted request parameters;
- uses a default cache lifetime of 24 hours.

`NvdClient` accepts an injected requester, clock, and sleeper so the API
behavior can be tested without live network calls. A failed request raises
`NvdClientError`; it is not silently converted into a verified result.

## CVE applicability evaluation

[security/applicability.py](../../backend/src/notline/security/applicability.py)
is the gate between fetched CVEs and graph relationships.

### CPE parsing

`parse_cpe23` parses the formatted CPE 2.3 binding into its eleven attributes:

```text
part, vendor, product, version, update, edition, language,
sw_edition, target_sw, target_hw, other
```

Escaped separators are handled before fields are compared. Malformed or
unsupported values do not become a match.

### Configuration logic

`find_applicable_matches` recursively evaluates each NVD configuration node:

- `AND` requires every child condition;
- `OR` requires at least one child condition;
- `negate` inverts the condition and contributes no vulnerable match;
- non-vulnerable CPE matches can satisfy a condition but are never returned as
  vulnerability evidence.

For each candidate, non-version CPE attributes must match. Versions are then
checked using exact criteria or inclusive/exclusive lower and upper bounds.
Numeric dotted versions are compared after trailing zero normalization. If a
version cannot be safely compared, the match is rejected.

The resulting match metadata is stored on `CPE -[:AFFECTED_BY]-> CVE`, including
criteria, match-criteria ID, vulnerability flag, and version bounds.

## Verified NVD graph writes

`write_verified_service_vulnerabilities` and
`write_verified_component_vulnerabilities` both:

1. validate that the observed CPE equals the resolved CPE;
2. evaluate every CVE with `find_applicable_matches`;
3. match the existing service or asset/component evidence path;
4. merge the CPE and CVE nodes;
5. create or update only applicable `AFFECTED_BY` relationships;
6. preserve source, confidence, and match metadata.

The component writer additionally requires:

```text
Asset -[:HAS_COMPONENT]-> SoftwareComponent
```

This prevents a valid CPE from being attached to the wrong asset or to a
component identity that was never inventoried.

## Npm inventory and OSV

### Lockfile identity

[security/package_inventory.py](../../backend/src/notline/security/package_inventory.py)
reads npm lockfile v3 entries under `node_modules/`. Each package retains:

- package name and exact version;
- package URL (`pkg:npm/...`);
- lockfile path;
- direct/transitive status;
- resolved URL and integrity when present.

[graph/security_writer.py](../../backend/src/notline/graph/security_writer.py)
stores these as `SoftwareComponent` nodes. Direct packages can reuse the stable
component IDs declared in `components.py`; transitive packages receive a
path-based component ID so multiple copies can remain distinct.

### Exact-version advisory query

[security/osv_client.py](../../backend/src/notline/security/osv_client.py)
queries OSV with the exact tuple:

```text
ecosystem = npm
name      = package name
version   = exact lockfile version
```

Responses are normalized by [osv_models.py](../../backend/src/notline/security/osv_models.py)
and cached by the complete request payload. The client retries transient
request failures and raises `OsvClientError` after the retry budget is
exhausted.

### OSV graph lifecycle

For each package component:

1. inventory writes mark `osv_scan_status = pending` unless a prior status
   exists;
2. a successful exact-version query writes/updates `Advisory` nodes and
   `SoftwareComponent -[:AFFECTED_BY {source: 'osv'}]-> Advisory` edges;
3. stale OSV edges for that component are removed when they are not in the
   current result;
4. the component becomes `osv_scan_status = complete`;
5. a failed query sets `osv_scan_status = error` and preserves prior findings.

The asset advisory exposure writer then derives current asset-level
`EXPOSED_TO` relationships from the component/advisory path.

## Exposure derivation

There are two separate exposure paths:

### Service/CVE exposure

```text
Asset -> IP -> Service -> CPE -> CVE
```

The CVE exposure writer requires `vulnerable = true` and checks that DHCP lease
timing is compatible with the observed service activity. It stores the service
IDs, IP addresses, CPE names, match criteria IDs, confidence, and observation
window on the derived edge.

### Component/advisory exposure

```text
Asset -> SoftwareComponent -> Advisory
```

The advisory exposure writer stores the affected component IDs and package URLs
on the derived edge. Historical and retired assets are excluded from current
exposure metrics.

## Failure and unresolved behavior

Security enrichment is intentionally conservative:

- a missing or ambiguous CPE becomes an unresolved identity;
- a non-applicable CVE produces no `AFFECTED_BY` relationship;
- an NVD/OSV request failure raises or records an error rather than fabricating
  coverage;
- an OSV error keeps previous advisory findings but makes the component
  incomplete for readiness purposes;
- exact npm/OSV coverage can satisfy security coverage even when a package has
  no CPE.

The audit therefore distinguishes `unresolved_components` from
`unresolved_components_without_osv`. The former is a visible warning; the
latter is a coverage blocker.

## Tests and maintenance

The security behavior is covered by:

- [test_security_models.py](../../backend/tests/test_security_models.py) for
  NVD model normalization;
- [test_cpe_resolution.py](../../backend/tests/test_cpe_resolution.py) for
  exact candidate filtering;
- [test_cpe_applicability.py](../../backend/tests/test_cpe_applicability.py)
  for CPE parsing, boolean configuration, and version ranges;
- [test_enrichment.py](../../backend/tests/test_enrichment.py) for exact target
  resolution;
- [test_nvd_client.py](../../backend/tests/test_nvd_client.py) for pagination,
  cache behavior, and injected requests;
- [test_package_inventory.py](../../backend/tests/test_package_inventory.py)
  for exact lockfile identities;
- [test_security_writer.py](../../backend/tests/test_security_writer.py) and
  [test_exposure_writer.py](../../backend/tests/test_exposure_writer.py) for
  graph persistence and exposure cleanup.

When adding a new product or ecosystem, document the evidence source, exact
identity rule, fallback advisory source, cache behavior, and readiness effect
before adding it to the profile.
