from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from neo4j import Driver

from notline.security.applicability import find_applicable_matches
from notline.security.models import (
    NvdCpeMatch,
    NvdCpeName,
    NvdCveRecord,
)
from notline.security.osv_models import OsvAdvisory
from notline.security.package_inventory import NpmPackage


@dataclass(frozen=True)
class _VerifiedTarget:
    """Graph target details that differ between services and components."""

    match_clause: str
    variable: str
    identifier_parameters: Mapping[str, object]
    evidence_property: str


@dataclass(frozen=True)
class _VerifiedCpeEvidence:
    """Normalized evidence shared by the service and component writers."""

    cpe: NvdCpeName
    vulnerabilities: list[dict[str, object]]
    observed_cpe: str
    source: str
    confidence: float
    product_name: str | None
    product_version: str | None
    product_evidence_source: str | None


_VERIFIED_VULNERABILITY_QUERY = """
__TARGET_MATCH__
MERGE (cpe:CPE {cpe_name: $cpe_name})
SET cpe.cpe_name_id = $cpe_name_id,
    cpe.title = $cpe_title,
    cpe.deprecated = $cpe_deprecated,
    cpe.created = $cpe_created,
    cpe.last_modified = $cpe_last_modified,
    cpe.source = $source

SET __TARGET__.product_name = coalesce($product_name, __TARGET__.product_name),
    __TARGET__.product_version = coalesce(
        $product_version,
        __TARGET__.product_version
    ),
    __TARGET__.__EVIDENCE_PROPERTY__ = coalesce(
        $product_evidence_source,
        __TARGET__.__EVIDENCE_PROPERTY__
    ),
    __TARGET__.cpe_resolution_status = 'resolved',
    __TARGET__.cpe_resolution_reason = null,
    __TARGET__.cpe_resolution_candidates = []

MERGE (__TARGET__)-[identified:IDENTIFIED_AS]->(cpe)
SET identified.source = $source,
    identified.confidence = $confidence,
    identified.observed_cpe = $observed_cpe,
    identified.evidence = 'verified_cpe_resolution'

WITH cpe
UNWIND $vulnerabilities AS vulnerability
MERGE (cve:CVE {cve_id: vulnerability.cve_id})
SET cve.description = vulnerability.description,
    cve.published = vulnerability.published,
    cve.last_modified = vulnerability.last_modified,
    cve.cvss_base_score = vulnerability.cvss_base_score,
    cve.source = $source

MERGE (cpe)-[affected:AFFECTED_BY {
    match_key: vulnerability.match_key
}]->(cve)
SET affected.vulnerable = vulnerability.vulnerable,
    affected.criteria = vulnerability.criteria,
    affected.match_criteria_id = vulnerability.match_criteria_id,
    affected.version_start_including = vulnerability.version_start_including,
    affected.version_start_excluding = vulnerability.version_start_excluding,
    affected.version_end_including = vulnerability.version_end_including,
    affected.version_end_excluding = vulnerability.version_end_excluding,
    affected.source = $source
"""


def write_verified_service_vulnerabilities(
    driver: Driver,
    *,
    service_id: str,
    cpe: NvdCpeName,
    records: Iterable[NvdCveRecord],
    observed_cpe: str,
    source: str = "nvd",
    confidence: float = 1.0,
    product_name: str | None = None,
    product_version: str | None = None,
    product_evidence_source: str | None = None,
) -> int:
    """Write verified CPE/CVE evidence for an existing passive service.

    Applicability is evaluated here before any graph write. The service must
    already exist, so security enrichment cannot create an unobserved service.
    """

    _validate_verified_cpe(cpe, observed_cpe, confidence)
    return _write_verified_vulnerabilities(
        driver,
        target=_VerifiedTarget(
            match_clause="MATCH (service:Service {service_id: $service_id})",
            variable="service",
            identifier_parameters={"service_id": service_id},
            evidence_property="product_evidence_source",
        ),
        evidence=_VerifiedCpeEvidence(
            cpe=cpe,
            vulnerabilities=_vulnerability_rows(records, observed_cpe),
            observed_cpe=observed_cpe,
            source=source,
            confidence=confidence,
            product_name=product_name,
            product_version=product_version,
            product_evidence_source=product_evidence_source,
        ),
    )


def write_verified_component_vulnerabilities(
    driver: Driver,
    *,
    asset_id: str,
    component_id: str,
    cpe: NvdCpeName,
    records: Iterable[NvdCveRecord],
    observed_cpe: str,
    source: str = "nvd",
    confidence: float = 1.0,
    product_name: str | None = None,
    product_version: str | None = None,
    product_evidence_source: str | None = None,
) -> int:
    """Write verified CPE/CVE evidence for an inventoried component."""

    _validate_verified_cpe(cpe, observed_cpe, confidence)
    return _write_verified_vulnerabilities(
        driver,
        target=_VerifiedTarget(
            match_clause="""MATCH (asset:Asset {asset_id: $asset_id})
      -[:HAS_COMPONENT]->
      (component:SoftwareComponent {component_id: $component_id})""",
            variable="component",
            identifier_parameters={
                "asset_id": asset_id,
                "component_id": component_id,
            },
            evidence_property="evidence_source",
        ),
        evidence=_VerifiedCpeEvidence(
            cpe=cpe,
            vulnerabilities=_vulnerability_rows(records, observed_cpe),
            observed_cpe=observed_cpe,
            source=source,
            confidence=confidence,
            product_name=product_name,
            product_version=product_version,
            product_evidence_source=product_evidence_source,
        ),
    )


def _validate_verified_cpe(
    cpe: NvdCpeName,
    observed_cpe: str,
    confidence: float,
) -> None:
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    if cpe.cpe_name != observed_cpe:
        raise ValueError("observed_cpe must equal the resolved CPE name")


def _vulnerability_rows(
    records: Iterable[NvdCveRecord],
    observed_cpe: str,
) -> list[dict[str, object]]:
    return [
        _vulnerability_row(record, match)
        for record in records
        for match in find_applicable_matches(record, observed_cpe)
    ]


def _write_verified_vulnerabilities(
    driver: Driver,
    *,
    target: _VerifiedTarget,
    evidence: _VerifiedCpeEvidence,
) -> int:
    query = (
        _VERIFIED_VULNERABILITY_QUERY.replace("__TARGET_MATCH__", target.match_clause)
        .replace("__TARGET__", target.variable)
        .replace("__EVIDENCE_PROPERTY__", target.evidence_property)
    )
    parameters = {
        **target.identifier_parameters,
        "cpe_name": evidence.cpe.cpe_name,
        "cpe_name_id": evidence.cpe.cpe_name_id,
        "cpe_title": evidence.cpe.title,
        "cpe_deprecated": evidence.cpe.deprecated,
        "cpe_created": evidence.cpe.created,
        "cpe_last_modified": evidence.cpe.last_modified,
        "product_name": evidence.product_name,
        "product_version": evidence.product_version,
        "product_evidence_source": evidence.product_evidence_source,
        "observed_cpe": evidence.observed_cpe,
        "source": evidence.source,
        "confidence": evidence.confidence,
        "vulnerabilities": evidence.vulnerabilities,
        "database_": "neo4j",
    }
    driver.execute_query(query, **parameters)
    return len(evidence.vulnerabilities)


def write_unresolved_service_identity(
    driver: Driver,
    *,
    service_id: str,
    product_name: str,
    product_version: str,
    evidence_source: str,
    reason: str,
    candidate_cpes: list[str],
    cpe_match_criteria_ids: list[str] | None = None,
    cpe_match_search_string: str | None = None,
) -> None:
    """Record product evidence when no exact active CPE can be trusted."""

    query = """
    MATCH (service:Service {service_id: $service_id})
    SET service.product_name = $product_name,
        service.product_version = $product_version,
        service.product_evidence_source = $evidence_source,
        service.cpe_resolution_status = 'unresolved',
        service.cpe_resolution_reason = $reason,
        service.cpe_resolution_candidates = $candidate_cpes,
        service.cpe_match_criteria_ids = $cpe_match_criteria_ids,
        service.cpe_match_search_string = $cpe_match_search_string
    """

    driver.execute_query(
        query,
        service_id=service_id,
        product_name=product_name,
        product_version=product_version,
        evidence_source=evidence_source,
        reason=reason,
        candidate_cpes=candidate_cpes,
        cpe_match_criteria_ids=cpe_match_criteria_ids or [],
        cpe_match_search_string=cpe_match_search_string,
        database_="neo4j",
    )


def write_unresolved_software_component(
    driver: Driver,
    *,
    asset_id: str,
    component_id: str,
    product_name: str,
    product_version: str,
    component_type: str,
    evidence_source: str,
    reason: str,
    candidate_cpes: list[str],
    cpe_match_criteria_ids: list[str] | None = None,
    cpe_match_search_string: str | None = None,
) -> None:
    """Record software evidence without creating an unverified CPE node."""

    query = """
    MATCH (asset:Asset {asset_id: $asset_id})
    MERGE (component:SoftwareComponent {component_id: $component_id})
    SET component.product_name = $product_name,
        component.product_version = $product_version,
        component.component_type = $component_type,
        component.evidence_source = $evidence_source,
        component.cpe_resolution_status = 'unresolved',
        component.cpe_resolution_reason = $reason,
        component.cpe_resolution_candidates = $candidate_cpes,
        component.cpe_match_criteria_ids = $cpe_match_criteria_ids,
        component.cpe_match_search_string = $cpe_match_search_string

    MERGE (asset)-[has_component:HAS_COMPONENT]->(component)
    SET has_component.evidence = $evidence_source,
        has_component.discovery_status = 'runtime_evidence'
    """

    driver.execute_query(
        query,
        asset_id=asset_id,
        component_id=component_id,
        product_name=product_name,
        product_version=product_version,
        component_type=component_type,
        evidence_source=evidence_source,
        reason=reason,
        candidate_cpes=candidate_cpes,
        cpe_match_criteria_ids=cpe_match_criteria_ids or [],
        cpe_match_search_string=cpe_match_search_string,
        database_="neo4j",
    )


def write_npm_package_inventory(
    driver: Driver,
    *,
    asset_id: str,
    packages: Iterable[NpmPackage],
    direct_component_ids: Mapping[str, str] | None = None,
) -> int:
    """Persist exact npm package identities without inventing CPEs."""

    direct_component_ids = direct_component_ids or {}
    package_rows = [
        {
            "component_id": package_component_id(
                asset_id,
                package,
                direct_component_ids,
            ),
            "name": package.name,
            "version": package.version,
            "purl": package.purl,
            "path": package.package_path,
            "direct_dependency": package.direct_dependency,
            "resolved": package.resolved,
            "integrity": package.integrity,
        }
        for package in packages
    ]
    if not package_rows:
        return 0

    query = """
    MATCH (asset:Asset {asset_id: $asset_id})
    UNWIND $packages AS package
    MERGE (component:SoftwareComponent {
        component_id: package.component_id
    })
    ON CREATE SET
        component.product_name = package.name,
        component.product_version = package.version,
        component.component_type = 'npm_dependency',
        component.evidence_source = 'npm_package_lock'
    SET component.package_ecosystem = 'npm',
        component.package_name = package.name,
        component.package_version = package.version,
        component.package_purl = package.purl,
        component.package_path = package.path,
        component.direct_dependency = package.direct_dependency,
        component.package_resolved = package.resolved,
        component.package_integrity = package.integrity,
        component.package_identity_source = 'npm_package_lock',
        component.osv_scan_status = coalesce(component.osv_scan_status, 'pending')

    MERGE (asset)-[has_component:HAS_COMPONENT]->(component)
    SET has_component.package_evidence = 'npm_package_lock',
        has_component.package_path = package.path,
        has_component.discovery_status = 'inventory'
    """

    driver.execute_query(
        query,
        asset_id=asset_id,
        packages=package_rows,
        database_="neo4j",
    )
    return len(package_rows)


def write_osv_advisories(
    driver: Driver,
    *,
    component_id: str,
    ecosystem: str,
    package_name: str,
    package_version: str,
    advisories: Iterable[OsvAdvisory],
    scanned_at: float,
) -> int:
    """Persist exact-version OSV results and replace stale advisory edges."""

    advisory_rows = [
        {
            "advisory_id": advisory.osv_id,
            "aliases": advisory.aliases,
            "summary": advisory.summary,
            "details": advisory.details,
            "published": advisory.published,
            "modified": advisory.modified,
            "withdrawn": advisory.withdrawn,
            "severity": advisory.severity,
            "references": advisory.reference_urls,
        }
        for advisory in advisories
    ]
    advisory_ids = [row["advisory_id"] for row in advisory_rows]

    query = """
    MATCH (component:SoftwareComponent {component_id: $component_id})
    OPTIONAL MATCH (component)-[stale:AFFECTED_BY]->(old:Advisory)
    WHERE stale.source = 'osv'
      AND NOT (old.advisory_id IN $advisory_ids)
    DELETE stale
    WITH component
    SET component.osv_scan_status = 'complete',
        component.osv_last_scanned_at = $scanned_at,
        component.osv_scan_error = null
    WITH component
    UNWIND $advisories AS advisory
    MERGE (node:Advisory {advisory_id: advisory.advisory_id})
    SET node.aliases = advisory.aliases,
        node.summary = advisory.summary,
        node.details = advisory.details,
        node.published = advisory.published,
        node.modified = advisory.modified,
        node.withdrawn = advisory.withdrawn,
        node.severity = advisory.severity,
        node.references = advisory.references,
        node.source = 'osv'
    MERGE (component)-[affected:AFFECTED_BY {
        source: 'osv',
        advisory_id: advisory.advisory_id
    }]->(node)
    SET affected.ecosystem = $ecosystem,
        affected.package_name = $package_name,
        affected.package_version = $package_version,
        affected.source = 'osv',
        affected.discovery_status = 'verified_exact_version'
    """

    driver.execute_query(
        query,
        component_id=component_id,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        advisories=advisory_rows,
        advisory_ids=advisory_ids,
        scanned_at=scanned_at,
        database_="neo4j",
    )
    return len(advisory_rows)


def write_osv_scan_error(
    driver: Driver,
    *,
    component_id: str,
    error: str,
    scanned_at: float,
) -> None:
    """Record an advisory-source failure without deleting prior findings."""

    query = """
    MATCH (component:SoftwareComponent {component_id: $component_id})
    SET component.osv_scan_status = 'error',
        component.osv_last_scanned_at = $scanned_at,
        component.osv_scan_error = $error
    """

    driver.execute_query(
        query,
        component_id=component_id,
        error=error,
        scanned_at=scanned_at,
        database_="neo4j",
    )


def update_asset_advisory_exposure(driver: Driver) -> None:
    """Derive current asset exposure to exact-version package advisories."""

    delete_stale_query = """
    MATCH (asset:Asset)-[exposure:EXPOSED_TO]->(advisory:Advisory)
    WHERE NOT EXISTS {
        MATCH (asset)-[:HAS_COMPONENT]->(:SoftwareComponent)
              -[:AFFECTED_BY {source: 'osv'}]->(advisory)
    }
    DELETE exposure
    """
    driver.execute_query(delete_stale_query, database_="neo4j")

    update_query = """
    MATCH (asset:Asset)-[:HAS_COMPONENT]->(component:SoftwareComponent)
          -[affected:AFFECTED_BY {source: 'osv'}]->(advisory:Advisory)
    WHERE NOT (
        coalesce(asset.discovery_status, 'active') IN ['retired', 'historical']
    )
    WITH asset, advisory,
         collect(DISTINCT component.component_id) AS component_ids,
         collect(DISTINCT component.package_purl) AS package_purls
    MERGE (asset)-[exposure:EXPOSED_TO]->(advisory)
    SET exposure.source = 'derived',
        exposure.derived_from = 'asset_component_osv_advisory',
        exposure.discovery_status = 'derived',
        exposure.component_ids = component_ids,
        exposure.package_purls = package_purls
    """
    driver.execute_query(update_query, database_="neo4j")


def update_asset_vulnerability_exposure(driver: Driver) -> None:
    """Derive asset-to-CVE exposure from current verified graph evidence."""

    delete_stale_query = """
    MATCH (asset:Asset)-[exposure:EXPOSED_TO]->(cve:CVE)
    WHERE NOT EXISTS {
        MATCH (asset)-[has_ip:HAS_IP]->(ip:IPAddress)
              -[runs:RUNS_SERVICE]->(service:Service)
              -[:IDENTIFIED_AS]->(:CPE)
              -[affected:AFFECTED_BY]->(cve)
        WHERE affected.vulnerable = true
          AND (
              NOT EXISTS {
                  MATCH (asset)-[lease:HAS_IP]->(ip)
                  WHERE lease.evidence = 'dhcp_ack'
              }
              OR EXISTS {
                  MATCH (asset)-[lease:HAS_IP]->(ip)
                  WHERE lease.evidence = 'dhcp_ack'
                    AND runs.first_seen >= lease.last_seen
                    AND (
                        lease.lease_expires_at IS NULL
                        OR runs.last_seen <= lease.lease_expires_at
                    )
              }
          )
    }
    DELETE exposure
    """

    driver.execute_query(delete_stale_query, database_="neo4j")

    update_query = """
    MATCH (asset:Asset)-[has_ip:HAS_IP]->(ip:IPAddress)
          -[runs:RUNS_SERVICE]->(service:Service)
          -[identified:IDENTIFIED_AS]->(cpe:CPE)
          -[affected:AFFECTED_BY]->(cve:CVE)
    WHERE affected.vulnerable = true
      AND (
          NOT EXISTS {
              MATCH (asset)-[lease:HAS_IP]->(ip)
              WHERE lease.evidence = 'dhcp_ack'
          }
          OR EXISTS {
              MATCH (asset)-[lease:HAS_IP]->(ip)
              WHERE lease.evidence = 'dhcp_ack'
                AND runs.first_seen >= lease.last_seen
                AND (
                    lease.lease_expires_at IS NULL
                    OR runs.last_seen <= lease.lease_expires_at
                )
          }
      )
    WITH asset, cve,
         collect(DISTINCT service.service_id) AS service_ids,
         collect(DISTINCT ip.address) AS ip_addresses,
         collect(DISTINCT cpe.cpe_name) AS cpe_names,
         collect(DISTINCT affected.match_criteria_id) AS raw_match_ids,
         max(coalesce(identified.confidence, 0.0)) AS confidence,
         min(runs.first_seen) AS first_seen,
         max(runs.last_seen) AS last_seen
    WITH asset, cve, service_ids, ip_addresses, cpe_names,
         [match_id IN raw_match_ids WHERE match_id IS NOT NULL]
             AS match_criteria_ids,
         confidence, first_seen, last_seen
    MERGE (asset)-[exposure:EXPOSED_TO]->(cve)
    SET exposure.source = 'derived',
        exposure.derived_from = 'asset_ip_service_cpe_cve',
        exposure.discovery_status = 'derived',
        exposure.service_ids = service_ids,
        exposure.ip_addresses = ip_addresses,
        exposure.cpe_names = cpe_names,
        exposure.match_criteria_ids = match_criteria_ids,
        exposure.confidence = confidence,
        exposure.first_seen = first_seen,
        exposure.last_seen = last_seen
    """

    driver.execute_query(update_query, database_="neo4j")


def _vulnerability_row(
    record: NvdCveRecord,
    match: NvdCpeMatch,
) -> dict[str, object]:
    return {
        "cve_id": record.cve_id,
        "description": record.description,
        "published": record.published,
        "last_modified": record.last_modified,
        "cvss_base_score": record.cvss_base_score,
        "match_key": _match_key(match),
        "criteria": match.criteria,
        "match_criteria_id": match.match_criteria_id,
        "vulnerable": match.vulnerable,
        "version_start_including": match.version_start_including,
        "version_start_excluding": match.version_start_excluding,
        "version_end_including": match.version_end_including,
        "version_end_excluding": match.version_end_excluding,
    }


def _match_key(match: NvdCpeMatch) -> str:
    if match.match_criteria_id:
        return match.match_criteria_id

    criteria = "|".join(
        str(value)
        for value in (
            match.criteria,
            match.vulnerable,
            match.version_start_including,
            match.version_start_excluding,
            match.version_end_including,
            match.version_end_excluding,
        )
    )
    return hashlib.sha256(criteria.encode()).hexdigest()


def package_component_id(
    asset_id: str,
    package: NpmPackage,
    direct_component_ids: Mapping[str, str],
) -> str:
    if package.direct_dependency and package.name in direct_component_ids:
        return direct_component_ids[package.name]
    return f"component:{asset_id}|npm|{package.package_path}"
