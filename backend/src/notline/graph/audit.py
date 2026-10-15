from __future__ import annotations

from dataclasses import dataclass

from neo4j import Driver

AUDIT_QUERIES = {
    "assets": "MATCH (n:Asset) RETURN count(n) AS value",
    "active_assets": (
        "MATCH (n:Asset) WHERE NOT (coalesce(n.discovery_status, 'active') "
        "IN ['retired', 'historical']) "
        "RETURN count(n) AS value"
    ),
    "retired_assets": (
        "MATCH (n:Asset) WHERE n.discovery_status = 'retired' RETURN count(n) AS value"
    ),
    "historical_assets": (
        "MATCH (n:Asset) WHERE n.discovery_status = 'historical' "
        "RETURN count(n) AS value"
    ),
    "ip_addresses": "MATCH (n:IPAddress) RETURN count(n) AS value",
    "observations": "MATCH (n:Observation) RETURN count(n) AS value",
    "ip_communications": (
        "MATCH ()-[r:COMMUNICATES_WITH]->() RETURN count(r) AS value"
    ),
    "asset_communications": (
        "MATCH (src:Asset)-[r:ASSET_COMMUNICATES_WITH]->(dst:Asset) "
        "WHERE NOT (coalesce(src.discovery_status, 'active') "
        "IN ['retired', 'historical']) "
        "AND NOT (coalesce(dst.discovery_status, 'active') "
        "IN ['retired', 'historical']) "
        "RETURN count(r) AS value"
    ),
    "services": "MATCH (n:Service) RETURN count(n) AS value",
    "resolved_services": (
        "MATCH (n:Service)-[:IDENTIFIED_AS]->(:CPE) RETURN count(DISTINCT n) AS value"
    ),
    "cpes": "MATCH (n:CPE) RETURN count(n) AS value",
    "cves": "MATCH (n:CVE) RETURN count(n) AS value",
    "cpe_vulnerabilities": (
        "MATCH (:CPE)-[r:AFFECTED_BY]->(:CVE) RETURN count(r) AS value"
    ),
    "advisories": "MATCH (n:Advisory) RETURN count(n) AS value",
    "exposed_cves": (
        "MATCH (a:Asset)-[r:EXPOSED_TO]->(:CVE) "
        "WHERE NOT (coalesce(a.discovery_status, 'active') "
        "IN ['retired', 'historical']) "
        "RETURN count(r) AS value"
    ),
    "advisory_exposures": (
        "MATCH (a:Asset)-[r:EXPOSED_TO]->(:Advisory) "
        "WHERE NOT (coalesce(a.discovery_status, 'active') "
        "IN ['retired', 'historical']) "
        "RETURN count(r) AS value"
    ),
    "software_components": ("MATCH (n:SoftwareComponent) RETURN count(n) AS value"),
    "package_components": (
        "MATCH (n:SoftwareComponent) "
        "WHERE n.package_ecosystem = 'npm' RETURN count(n) AS value"
    ),
    "scanned_package_components": (
        "MATCH (n:SoftwareComponent) "
        "WHERE n.package_ecosystem = 'npm' "
        "AND n.osv_scan_status = 'complete' RETURN count(n) AS value"
    ),
    "unscanned_package_components": (
        "MATCH (n:SoftwareComponent) "
        "WHERE n.package_ecosystem = 'npm' "
        "AND coalesce(n.osv_scan_status, 'unscanned') <> 'complete' "
        "RETURN count(n) AS value"
    ),
    "osv_scan_errors": (
        "MATCH (n:SoftwareComponent) "
        "WHERE n.package_ecosystem = 'npm' "
        "AND n.osv_scan_status = 'error' RETURN count(n) AS value"
    ),
    "unresolved_services": (
        "MATCH (n:Service) WHERE n.cpe_resolution_status = 'unresolved' "
        "RETURN count(n) AS value"
    ),
    "unresolved_components": (
        "MATCH (n:SoftwareComponent) "
        "WHERE n.cpe_resolution_status = 'unresolved' RETURN count(n) AS value"
    ),
    "unresolved_components_without_osv": (
        "MATCH (n:SoftwareComponent) "
        "WHERE n.cpe_resolution_status = 'unresolved' "
        "AND (n.package_ecosystem IS NULL "
        "OR coalesce(n.osv_scan_status, 'unscanned') <> 'complete') "
        "RETURN count(n) AS value"
    ),
}


@dataclass(frozen=True)
class GraphAudit:
    assets: int
    active_assets: int
    retired_assets: int
    historical_assets: int
    ip_addresses: int
    observations: int
    ip_communications: int
    asset_communications: int
    services: int
    resolved_services: int
    cpes: int
    cves: int
    cpe_vulnerabilities: int
    advisories: int
    exposed_cves: int
    advisory_exposures: int
    software_components: int
    package_components: int
    scanned_package_components: int
    unscanned_package_components: int
    osv_scan_errors: int
    unresolved_services: int
    unresolved_components: int
    unresolved_components_without_osv: int

    @property
    def readiness_blockers(self) -> tuple[str, ...]:
        checks = (
            (self.active_assets > 0, "no active assets"),
            (self.observations > 0, "no passive observations"),
            (self.asset_communications > 0, "no asset communication edges"),
            (self.services > 0, "no discovered services"),
            (self.resolved_services > 0, "no services mapped to verified CPEs"),
            (self.cpe_vulnerabilities > 0, "no verified CPE-to-CVE relationships"),
            (self.exposed_cves > 0, "no derived asset-to-CVE exposures"),
        )
        return tuple(message for passed, message in checks if not passed)

    @property
    def ready_for_simulation(self) -> bool:
        return not self.readiness_blockers

    @property
    def security_coverage_complete(self) -> bool:
        """Whether every discovered security identity has a trusted source."""

        return (
            self.unresolved_services == 0
            and self.unresolved_components_without_osv == 0
            and self.unscanned_package_components == 0
            and self.osv_scan_errors == 0
        )

    @property
    def ready_for_full_security_simulation(self) -> bool:
        return self.ready_for_simulation and self.security_coverage_complete


def collect_graph_audit(driver: Driver) -> GraphAudit:
    values: dict[str, int] = {}
    for metric, query in AUDIT_QUERIES.items():
        result = driver.execute_query(query, database_="neo4j")
        if not result.records:
            raise RuntimeError(f"Audit query returned no value: {metric}")
        values[metric] = int(result.records[0]["value"])
    return GraphAudit(**values)
