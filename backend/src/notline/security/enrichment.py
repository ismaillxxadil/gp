from __future__ import annotations

from dataclasses import dataclass

from neo4j import Driver

from notline.graph.security_writer import write_verified_service_vulnerabilities
from notline.security.models import NvdCpeName
from notline.security.nvd_client import NvdClient


class SecurityEnrichmentError(RuntimeError):
    """Raised when a security target cannot be resolved unambiguously."""


@dataclass(frozen=True)
class SecurityTarget:
    service_id: str
    product_name: str
    product_version: str
    evidence_source: str
    cpe_keyword: str
    cpe_product_aliases: tuple[str, ...] = ()
    expected_cpe_name: str | None = None
    cpe_match_string: str | None = None


@dataclass(frozen=True)
class EnrichmentResult:
    cpe: NvdCpeName
    fetched_cve_count: int
    verified_relationship_count: int


POSTGRESQL_TARGET = SecurityTarget(
    service_id="service:10.10.30.10|tcp|5432|postgresql",
    product_name="PostgreSQL",
    product_version="18.0",
    evidence_source="db1_runtime_version",
    cpe_keyword="PostgreSQL 18.0",
    cpe_product_aliases=("postgresql",),
    expected_cpe_name="cpe:2.3:a:postgresql:postgresql:18.0:*:*:*:*:*:*:*",
)
SAMBA_TARGET = SecurityTarget(
    service_id="service:10.10.35.40|tcp|445|smb",
    product_name="Samba",
    product_version="4.20.6",
    evidence_source="files1_runtime_version",
    cpe_keyword="Samba 4.20.6",
    cpe_product_aliases=("samba",),
    expected_cpe_name="cpe:2.3:a:samba:samba:4.20.6:*:*:*:*:*:*:*",
)
OPENSSH_TARGET = SecurityTarget(
    service_id="service:10.10.35.10|tcp|22|ssh",
    product_name="OpenSSH",
    product_version="9.9p2",
    evidence_source="srv1_runtime_version",
    cpe_keyword="openssh",
    cpe_product_aliases=("openssh",),
    expected_cpe_name="cpe:2.3:a:openbsd:openssh:9.9:p2:*:*:*:*:*:*",
)

NGINX_TARGET = SecurityTarget(
    service_id="service:10.10.20.20|tcp|80|http",
    product_name="NGINX Open Source",
    product_version="1.30.3",
    evidence_source="web1_runtime_version",
    cpe_keyword="nginx 1.30.3",
    cpe_product_aliases=("nginx_open_source",),
    expected_cpe_name="cpe:2.3:a:f5:nginx_open_source:1.30.3:*:*:*:*:*:*:*",
)

VERIFIED_SECURITY_TARGETS = (
    POSTGRESQL_TARGET,
    SAMBA_TARGET,
    OPENSSH_TARGET,
    NGINX_TARGET,
)

UNRESOLVED_SECURITY_TARGETS: tuple[SecurityTarget, ...] = ()


def resolve_target_cpe(client: NvdClient, target: SecurityTarget) -> NvdCpeName:
    if target.expected_cpe_name is None:
        raise SecurityEnrichmentError(
            f"No expected exact CPE configured for {target.product_name}"
        )

    candidates = client.search_cpes(target.cpe_keyword, max_results=2_000)
    matches = [
        candidate
        for candidate in candidates
        if candidate.cpe_name == target.expected_cpe_name and not candidate.deprecated
    ]

    if len(matches) != 1:
        raise SecurityEnrichmentError(
            f"Expected one active CPE for {target.expected_cpe_name!r}, "
            f"found {len(matches)}"
        )
    return matches[0]


def enrich_target(
    driver: Driver,
    client: NvdClient,
    target: SecurityTarget,
) -> EnrichmentResult:
    cpe = resolve_target_cpe(client, target)
    records = client.fetch_cves_for_cpe(cpe.cpe_name)
    verified_relationship_count = write_verified_service_vulnerabilities(
        driver,
        service_id=target.service_id,
        cpe=cpe,
        records=records,
        observed_cpe=target.expected_cpe_name,
        product_name=target.product_name,
        product_version=target.product_version,
        product_evidence_source=target.evidence_source,
    )
    return EnrichmentResult(
        cpe=cpe,
        fetched_cve_count=len(records),
        verified_relationship_count=verified_relationship_count,
    )
