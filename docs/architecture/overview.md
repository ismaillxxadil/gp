# Architecture overview

## 1. Purpose and goals

NOTLINE builds a security-enriched digital twin of an isolated enterprise lab.
It observes network activity without actively scanning the network, preserves
the raw evidence in Neo4j, derives useful relationships, and attaches
security metadata only when the identity and applicability evidence is strong
enough.

The current engineering goals are:

- represent stable infrastructure identities and passively observed clients;
- retain raw observations so derived relationships can be explained;
- discover services from Zeek evidence and conservative port inference;
- map verified software identities to exact CPEs and applicable CVEs;
- scan package ecosystems such as npm when a CPE is not the right identity;
- distinguish current, historical, and retired assets instead of deleting
  evidence;
- expose explicit audit signals before simulation is allowed.

The future research goals are autonomous adversary reasoning, defensive
planning, and controlled self-healing. Those layers are outside the current
implemented boundary.

## 2. System context

The system runs an isolated enterprise network lab. Containerlab creates the
nodes and links, Open vSwitch provides VLAN switching and SPAN mirrors,
FRRouting provides routing, and Zeek observes mirrored traffic through two
passive probes. Neo4j stores the digital twin.

```text
                          isolated enterprise lab
  PC1 / PC2 ---- SW1 ---- R1 ---- SW2 ---- WEB1 ---- APP1 ---- DB1
       |           |       |       |         |        |         |
     DHCP/DNS   PROBE2   VLANs   PROBE1    NGINX    Node.js   PostgreSQL
                                  |          |
                              SRV1/FILES1  HTTP traffic
                              IOT1/IOT2

  OVS SPAN mirrors -> Zeek JSON logs -> Python backend -> Neo4j graph
```

The topology and static address inventory are defined in
[step2.clab.yml](../../step2.clab.yml),
[context.md](../../context.md), and
[discovery/inventory.py](../../backend/src/notline/discovery/inventory.py).

## 3. Building blocks

### 3.1 Lab and traffic sources

- [step2.clab.yml](../../step2.clab.yml) defines the Containerlab nodes,
  links, addresses, service startup commands, and Zeek log mounts.
- [config/vlan-config.sh](../../config/vlan-config.sh) applies VLAN behavior
  to the OVS bridges.
- [scripts/start.sh](../../scripts/start.sh) starts Neo4j, builds the local
  web/application images, and invokes the lab rebuild.
- [scripts/generate_lab_traffic.sh](../../scripts/generate_lab_traffic.sh)
  creates deterministic benign DNS, HTTP, SSH, and SMB activity for the
  passive sensors.

### 3.2 Passive observation

The two Zeek probes write JSON `conn.log` and `dhcp.log` files into
`probe-logs/` and `probe2-logs/`. The backend does not treat every line as
truth: [zeek_parser.py](../../backend/src/notline/discovery/zeek_parser.py)
validates the records, rejects unusable IPs and malformed values, and turns
valid records into typed Pydantic models.

### 3.3 Discovery and normalization

The discovery package has four distinct responsibilities:

1. [models.py](../../backend/src/notline/discovery/models.py) defines typed
   connection and DHCP observations.
2. [service_enrichment.py](../../backend/src/notline/discovery/service_enrichment.py)
   normalizes layered Zeek service labels and adds only the currently
   supported port inference (`tcp/5432 -> postgresql`).
3. [deduplication.py](../../backend/src/notline/discovery/deduplication.py)
   groups mirrored records into canonical physical flows while retaining the
   original sensor observations.
4. [inventory.py](../../backend/src/notline/discovery/inventory.py) supplies
   stable topology identities. DHCP clients are deliberately not hard-coded;
   their identity is derived from observed MAC addresses.

### 3.4 Graph persistence and derivation

[graph/writer.py](../../backend/src/notline/graph/writer.py) writes raw
observations and topology/DHCP evidence, then derives IP communication, service,
and asset communication relationships. The raw-to-derived separation is
important: derived edges can be refreshed without losing the evidence that
produced them.

[graph/schema.py](../../backend/src/notline/graph/schema.py) creates uniqueness
constraints for graph identities. [graph/audit.py](../../backend/src/notline/graph/audit.py)
checks whether the graph contains the minimum evidence and security coverage
needed for simulation.

### 3.5 Security enrichment

The security path has separate sources and separate identity rules:

- [security/enrichment.py](../../backend/src/notline/security/enrichment.py)
  declares verified service targets and exact expected CPE identities.
- [security/nvd_client.py](../../backend/src/notline/security/nvd_client.py)
  retrieves and caches NVD CPE and CVE data with pagination, rate limiting,
  and retries.
- [security/applicability.py](../../backend/src/notline/security/applicability.py)
  evaluates NVD configuration trees, CPE fields, and version bounds before a
  CVE relationship is written.
- [security/package_inventory.py](../../backend/src/notline/security/package_inventory.py)
  extracts exact npm runtime identities from `package-lock.json`.
- [security/osv_client.py](../../backend/src/notline/security/osv_client.py)
  queries exact npm package versions through OSV and caches responses.
- [graph/security_writer.py](../../backend/src/notline/graph/security_writer.py)
  persists verified relationships, unresolved identities, package components,
  advisories, and derived exposure edges.

The key safety rule is that a keyword search is only a candidate-discovery
step. A candidate becomes a CPE identity only after product, version,
deprecation, and expected-identity checks succeed.

## 4. Runtime data flow

```text
1. Lab traffic
   clients -> services -> mirrored packets

2. Zeek evidence
   packets -> conn.log / dhcp.log JSON

3. Import
   JSON -> parse -> validate -> normalize service -> group mirrored flows

4. Evidence graph
   observations + IPs + DHCP leases + topology assets -> Neo4j

5. Derived graph
   IP communications -> services -> asset communications

6. Security enrichment
   service/runtime identity -> exact CPE -> applicable CVEs
   package-lock identity -> exact OSV advisory results

7. Audit
   graph metrics + identity coverage -> readiness status
```

The executable orchestration is in
[backend/scripts/import_zeek.py](../../backend/scripts/import_zeek.py),
[backend/scripts/enrich_vulnerabilities.py](../../backend/scripts/enrich_vulnerabilities.py),
and [backend/scripts/audit_graph.py](../../backend/scripts/audit_graph.py).

## 5. Important invariants

### Evidence is append/update oriented

Observations, IPs, assets, services, CPEs, CVEs, and components are merged by
stable identifiers. Re-running the pipeline updates aggregate metadata rather
than creating a duplicate node for each run.

### Derived relationships are refreshable

Communication, service, asset communication, and exposure edges are derived
from evidence. The writer removes stale provisional or exposure relationships
before rebuilding them where the current graph semantics require it.

### Historical identities are retained

DHCP identities outside the configured activity window become `historical`.
Topology identities that are no longer in the configured inventory become
`retired`. These identities remain queryable for forensic history but are not
used to create current simulation edges.

### Security relationships must be explainable

Every verified CPE/CVE relationship carries source and applicability metadata.
Unresolved identities are recorded with reasons and candidate information; an
approximate CPE is never substituted silently.

### Readiness is explicit

The graph is not considered ready merely because Neo4j contains nodes. The
audit requires current assets, observations, asset communication, discovered
services, at least one resolved service, verified CPE-to-CVE evidence, derived
exposures, and complete alternative advisory coverage where CPE resolution is
not available.

## 6. Current boundary and risks

Implemented now:

- passive Zeek import;
- flow grouping across two sensors;
- topology and DHCP identity handling;
- service and asset communication derivation;
- NVD CPE/CVE enrichment;
- exact npm/OSV coverage;
- graph audit and readiness reporting.

Not implemented yet:

- autonomous agents and LLM reasoning;
- adversary simulation orchestration;
- defensive action planning or automatic remediation;
- a generic runtime discovery adapter for arbitrary networks.

The network-specific inputs are isolated in
[network_profile.py](../../backend/src/notline/network_profile.py). Supporting
another network should add a profile and evidence sources rather than copy the
graph writer logic, but the current profile still contains lab-specific static
inventory and security evidence declarations.
