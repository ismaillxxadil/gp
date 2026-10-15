# NOTLINE documentation

This directory is the maintained technical documentation for the NOTLINE
self-healing cybersecurity digital twin project.

The project is large enough that one README cannot explain it well. These
documents therefore separate architecture, operational procedures, and code
reference. The structure is intentionally lightweight:

- [Architecture](./architecture/overview.md) explains what the system is,
  where its boundaries are, and how its major building blocks interact.
- [Code map](./reference/code-map.md) explains where behavior lives in the
  repository and which executable entry points call it.
- [Graph model](./reference/graph-model.md) describes the Neo4j labels,
  relationships, evidence, and freshness rules.
- [Discovery reference](./reference/discovery.md) explains how Zeek records
  become normalized observations and canonical flows.
- [Graph writers reference](./reference/graph-writers.md) explains persistence,
  derived relationships, freshness, and readiness checks.
- [Security enrichment reference](./reference/security-enrichment.md) explains
  exact CPE/CVE verification, applicability, NVD, and OSV processing.
- [Lab topology reference](./reference/lab-topology.md) describes nodes, VLANs,
  services, passive probes, mirrors, and persistence.
- [Pipeline guide](./guides/pipeline.md) gives the repeatable commands for
  collecting passive evidence, importing it, enriching it, and auditing the
  result.
- [Deployment guide](./guides/deployment.md) explains startup, verification,
  and troubleshooting.
- [Testing reference](./development/testing.md) explains unit contracts,
  mocked boundaries, live checks, and quality gates.
- [Documentation roadmap](./development/documentation-roadmap.md) tracks the
  remaining module-by-module documentation work.

## Documentation principles

The documentation follows two complementary ideas:

1. **Architecture is organized by system concern.** The architecture overview
   follows the useful parts of the arc42 template: goals, constraints,
   building blocks, runtime behavior, deployment, and risks.
2. **Reader intent is kept separate.** Operational procedures are written as
   task-oriented guides, conceptual behavior as explanations, and source-level
   facts as reference. This follows the four-way distinction used by
   [Diátaxis](https://diataxis.fr/).

The documentation must describe the code that exists. Planned agents, LLM
reasoning, self-healing actions, and adversary simulation are clearly marked as
planned until their implementation and tests exist.

## Source of truth

Use the following order when information disagrees:

1. executable code and tests;
2. deployment configuration and runtime verification;
3. these documents;
4. older narrative notes or copied handoff material.

If a behavior changes, update the relevant document in the same change. Link to
the implementation instead of copying large code blocks into documentation.
For Python modules and public functions, keep docstrings aligned with
[PEP 257](https://peps.python.org/pep-0257/): state behavior, inputs, outputs,
side effects, and important failure conditions.

## Current implementation boundary

The implemented path is:

```text
Containerlab + OVS + Zeek
            -> JSON passive observations
            -> Python normalization and deduplication
            -> Neo4j evidence and derived graph
            -> NVD CPE/CVE verification + OSV package scanning
            -> graph audit and simulation readiness
```

The autonomous agent, LLM reasoning, response planning, and self-healing
execution layers are not documented as operational features yet. They are
future extensions over the trusted graph and audit contract.
