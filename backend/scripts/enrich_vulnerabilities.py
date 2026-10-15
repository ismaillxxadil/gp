import os
import time
from collections.abc import Iterable
from pathlib import Path

from dotenv import load_dotenv
from neo4j import Driver

from notline.graph.connection import Neo4jConnection
from notline.graph.schema import initialize_schema
from notline.graph.security_writer import (
    package_component_id,
    update_asset_advisory_exposure,
    update_asset_vulnerability_exposure,
    write_npm_package_inventory,
    write_osv_advisories,
    write_osv_scan_error,
    write_unresolved_service_identity,
    write_unresolved_software_component,
    write_verified_component_vulnerabilities,
)
from notline.network_profile import NetworkProfile, get_configured_network_profile
from notline.security.components import SoftwareComponentTarget
from notline.security.cpe_resolution import select_exact_product_version_cpes
from notline.security.enrichment import SecurityTarget, enrich_target
from notline.security.models import NvdCpeName
from notline.security.nvd_client import NvdClient
from notline.security.osv_client import OsvClient, OsvClientError
from notline.security.package_inventory import load_npm_runtime_packages

NVD_CACHE_DIR = Path("backend/.cache/nvd")
OSV_CACHE_DIR = Path("backend/.cache/osv")


def main() -> None:
    load_dotenv("infrastructure/.env")
    profile = get_configured_network_profile()
    client = NvdClient(
        api_key=os.getenv("NVD_API_KEY"),
        cache_dir=NVD_CACHE_DIR,
    )
    osv_client = OsvClient(cache_dir=OSV_CACHE_DIR)
    db = Neo4jConnection()

    try:
        db.verify()
        initialize_schema(db.driver)
        _enrich_verified_services(db.driver, client, profile)
        _record_unresolved_services(db.driver, client, profile)
        _enrich_software_components(db.driver, client, profile)

        _write_package_inventories(db.driver, profile, osv_client)
        _refresh_exposure_graph(db.driver)
        print("Asset vulnerability exposure graph updated.")
    finally:
        db.close()


def _enrich_verified_services(
    driver: Driver,
    client: NvdClient,
    profile: NetworkProfile,
) -> None:
    for target in profile.verified_security_targets:
        result = enrich_target(driver, client, target)
        print(f"Resolved CPE: {result.cpe.cpe_name}")
        print(f"Fetched CVE records: {result.fetched_cve_count}")
        print(
            "Verified vulnerability relationships prepared: "
            f"{result.verified_relationship_count}"
        )


def _record_unresolved_services(
    driver: Driver,
    client: NvdClient,
    profile: NetworkProfile,
) -> None:
    for target in profile.unresolved_security_targets:
        candidates = _find_exact_candidates(client, target)
        candidate_cpes = [candidate.cpe_name for candidate in candidates]
        match_criteria_ids = _active_match_criteria_ids(
            client,
            target.cpe_match_string,
        )

        write_unresolved_service_identity(
            driver,
            service_id=target.service_id,
            product_name=target.product_name,
            product_version=target.product_version,
            evidence_source=target.evidence_source,
            reason=_service_resolution_reason(target.expected_cpe_name, candidate_cpes),
            candidate_cpes=candidate_cpes,
            cpe_match_criteria_ids=match_criteria_ids,
            cpe_match_search_string=target.cpe_match_string,
        )
        print(
            f"Unresolved CPE: {target.product_name} {target.product_version} "
            f"({len(candidate_cpes)} candidates, "
            f"{len(match_criteria_ids)} active match criteria)"
        )


def _enrich_software_components(
    driver: Driver,
    client: NvdClient,
    profile: NetworkProfile,
) -> None:
    for target in profile.software_components:
        candidates = _find_exact_candidates(client, target)
        exact_candidates = [
            candidate
            for candidate in candidates
            if candidate.cpe_name == target.expected_cpe_name
        ]
        if target.expected_cpe_name and len(exact_candidates) == 1:
            cpe = exact_candidates[0]
            records = client.fetch_cves_for_cpe(cpe.cpe_name)
            relationship_count = write_verified_component_vulnerabilities(
                driver,
                asset_id=target.asset_id,
                component_id=target.component_id,
                cpe=cpe,
                records=records,
                observed_cpe=target.expected_cpe_name,
                product_name=target.product_name,
                product_version=target.product_version,
                product_evidence_source=target.evidence_source,
            )
            print(
                f"Resolved component CPE: {target.product_name} "
                f"({len(records)} CVEs, {relationship_count} verified relationships)"
            )
            continue

        candidate_cpes = [candidate.cpe_name for candidate in candidates]
        match_criteria_ids = _active_match_criteria_ids(
            client,
            target.cpe_match_string,
        )
        write_unresolved_software_component(
            driver,
            asset_id=target.asset_id,
            component_id=target.component_id,
            product_name=target.product_name,
            product_version=target.product_version,
            component_type=target.component_type,
            evidence_source=target.evidence_source,
            reason="No exact active CPE was verified for this software component",
            candidate_cpes=candidate_cpes,
            cpe_match_criteria_ids=match_criteria_ids,
            cpe_match_search_string=target.cpe_match_string,
        )
        print(
            f"Unresolved component CPE: {target.product_name} "
            f"{target.product_version} ({len(candidate_cpes)} candidates, "
            f"{len(match_criteria_ids)} active match criteria)"
        )


def _find_exact_candidates(
    client: NvdClient,
    target: SecurityTarget | SoftwareComponentTarget,
) -> list[NvdCpeName]:
    return select_exact_product_version_cpes(
        client.search_cpes(target.cpe_keyword, max_results=2_000),
        product_aliases=target.cpe_product_aliases,
        product_version=target.product_version,
    )


def _service_resolution_reason(
    expected_cpe: str | None,
    candidate_cpes: Iterable[str],
) -> str:
    if expected_cpe and expected_cpe not in candidate_cpes:
        return "Exact observed version is not present in the NVD CPE dictionary"
    return "No exact active CPE was found in the NVD CPE dictionary"


def _refresh_exposure_graph(driver: Driver) -> None:
    update_asset_vulnerability_exposure(driver)
    update_asset_advisory_exposure(driver)


def _active_match_criteria_ids(
    client: NvdClient,
    match_string: str | None,
) -> list[str]:
    if not match_string:
        return []
    return [
        criterion.match_criteria_id
        for criterion in client.search_cpe_match_criteria(match_string)
    ]


def _write_package_inventories(
    driver: Driver,
    profile: NetworkProfile,
    client: OsvClient,
) -> None:
    for source in profile.npm_package_lockfiles:
        packages = load_npm_runtime_packages(source.path)
        direct_component_ids = {
            target.package_name: target.component_id
            for target in profile.software_components
            if target.asset_id == source.asset_id and target.package_name
        }
        count = write_npm_package_inventory(
            driver,
            asset_id=source.asset_id,
            packages=packages,
            direct_component_ids=direct_component_ids,
        )
        print(
            f"{source.asset_id}: recorded {count} npm package identities "
            f"from {source.path}"
        )

        scanned = 0
        findings = 0
        for package in packages:
            component_id = package_component_id(
                source.asset_id,
                package,
                direct_component_ids,
            )
            scanned_at = time.time()
            try:
                advisories = client.query_package(
                    ecosystem="npm",
                    name=package.name,
                    version=package.version,
                )
            except OsvClientError as error:
                write_osv_scan_error(
                    driver,
                    component_id=component_id,
                    error=str(error),
                    scanned_at=scanned_at,
                )
                print(f"OSV scan failed for {package.name}@{package.version}")
                continue

            findings += write_osv_advisories(
                driver,
                component_id=component_id,
                ecosystem="npm",
                package_name=package.name,
                package_version=package.version,
                advisories=advisories,
                scanned_at=scanned_at,
            )
            scanned += 1

        print(
            f"{source.asset_id}: OSV scanned {scanned}/{len(packages)} packages, "
            f"found {findings} advisories"
        )


if __name__ == "__main__":
    main()
