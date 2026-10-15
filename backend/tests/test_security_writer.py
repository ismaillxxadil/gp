from typing import Any

import pytest

from notline.graph.security_writer import (
    write_npm_package_inventory,
    write_osv_advisories,
    write_verified_component_vulnerabilities,
    write_verified_service_vulnerabilities,
)
from notline.security.models import NvdCpeName, NvdCveRecord
from notline.security.osv_models import OsvAdvisory
from notline.security.package_inventory import NpmPackage


class RecordingDriver:
    def __init__(self) -> None:
        self.query = None
        self.parameters: dict[str, Any] | None = None

    def execute_query(self, query: str, **parameters: Any) -> None:
        self.query = query
        self.parameters = parameters


POSTGRESQL_18_CPE = "cpe:2.3:a:postgresql:postgresql:18.0:*:*:*:*:*:*:*"


def test_writer_persists_only_verified_vulnerabilities() -> None:
    driver = RecordingDriver()
    count = write_verified_service_vulnerabilities(
        driver,
        service_id="service:10.10.30.10|tcp|5432|postgresql",
        cpe=_postgresql_cpe(),
        records=[_postgresql_cve(), _irrelevant_cve()],
        observed_cpe=POSTGRESQL_18_CPE,
    )

    assert count == 1
    assert driver.query is not None
    assert "MATCH (service:Service {service_id: $service_id})" in driver.query
    assert "MERGE (cpe:CPE {cpe_name: $cpe_name})" in driver.query
    assert "MERGE (service)-[identified:IDENTIFIED_AS]->(cpe)" in driver.query
    assert "MERGE (cve:CVE {cve_id: vulnerability.cve_id})" in driver.query
    assert "MERGE (cpe)-[affected:AFFECTED_BY" in driver.query
    assert driver.parameters is not None
    assert driver.parameters["service_id"] == (
        "service:10.10.30.10|tcp|5432|postgresql"
    )
    assert driver.parameters["vulnerabilities"][0]["cve_id"] == "CVE-2026-2003"


def test_writer_keeps_verified_cpe_when_no_cve_applies() -> None:
    driver = RecordingDriver()

    count = write_verified_service_vulnerabilities(
        driver,
        service_id="service:10.10.30.10|tcp|5432|postgresql",
        cpe=_postgresql_cpe(),
        records=[_irrelevant_cve()],
        observed_cpe=POSTGRESQL_18_CPE,
    )

    assert count == 0
    assert driver.query is not None
    assert "MERGE (service)-[identified:IDENTIFIED_AS]->(cpe)" in driver.query


def test_writer_rejects_mismatched_observed_cpe() -> None:
    with pytest.raises(ValueError, match="observed_cpe"):
        write_verified_service_vulnerabilities(
            RecordingDriver(),
            service_id="service:10.10.30.10|tcp|5432|postgresql",
            cpe=_postgresql_cpe(),
            records=[],
            observed_cpe="cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*",
        )


def test_npm_inventory_enriches_direct_components_and_adds_transitive_ones() -> None:
    driver = RecordingDriver()

    count = write_npm_package_inventory(
        driver,
        asset_id="app1",
        packages=[
            NpmPackage(
                name="express",
                version="5.2.1",
                purl="pkg:npm/express@5.2.1",
                package_path="node_modules/express",
                direct_dependency=True,
            ),
            NpmPackage(
                name="content-type",
                version="2.1.0",
                purl="pkg:npm/content-type@2.1.0",
                package_path="node_modules/express/node_modules/content-type",
                direct_dependency=False,
            ),
        ],
        direct_component_ids={"express": "component:app1|express"},
    )

    assert count == 2
    assert driver.query is not None
    assert "MATCH (asset:Asset {asset_id: $asset_id})" in driver.query
    assert "UNWIND $packages AS package" in driver.query
    assert "MERGE (component:SoftwareComponent" in driver.query
    assert "package_identity_source = 'npm_package_lock'" in driver.query
    assert driver.parameters is not None
    assert driver.parameters["packages"][0]["component_id"] == "component:app1|express"
    assert driver.parameters["packages"][1]["component_id"] == (
        "component:app1|npm|node_modules/express/node_modules/content-type"
    )


def test_writer_records_exact_version_osv_advisories():
    driver = RecordingDriver()

    count = write_osv_advisories(
        driver,
        component_id="component:app1|express",
        ecosystem="npm",
        package_name="express",
        package_version="5.2.1",
        advisories=[
            OsvAdvisory(
                osv_id="GHSA-test",
                aliases=["CVE-2026-1234"],
                summary="Test issue",
                reference_urls=["https://example.test/advisory"],
            )
        ],
        scanned_at=1000.0,
    )

    assert count == 1
    assert driver.query is not None
    assert "MERGE (node:Advisory" in driver.query
    assert "source: 'osv'" in driver.query
    assert driver.parameters is not None
    assert driver.parameters["advisories"][0]["advisory_id"] == "GHSA-test"


def test_writer_records_verified_component_cpe_and_cves():
    driver = RecordingDriver()

    count = write_verified_component_vulnerabilities(
        driver,
        asset_id="app1",
        component_id="component:app1|nodejs",
        cpe=_nodejs_cpe(),
        records=[_postgresql_cve()],
        observed_cpe=_nodejs_cpe().cpe_name,
        product_name="Node.js",
        product_version="22.22.3",
        product_evidence_source="app1_runtime_version",
    )

    assert count == 0
    assert driver.query is not None
    assert "-[:HAS_COMPONENT]->" in driver.query
    assert "(component:SoftwareComponent" in driver.query
    assert "MERGE (component)-[identified:IDENTIFIED_AS]->(cpe)" in driver.query
    assert "component.cpe_resolution_status = 'resolved'" in driver.query


def _postgresql_cpe() -> NvdCpeName:
    return NvdCpeName(
        cpe_name_id="postgresql-18-id",
        cpe_name=POSTGRESQL_18_CPE,
        title="PostgreSQL 18.0",
    )


def _nodejs_cpe() -> NvdCpeName:
    return NvdCpeName(
        cpe_name_id="nodejs-22.22.3-id",
        cpe_name="cpe:2.3:a:nodejs:node.js:22.22.3:*:*:*:-:*:*:*",
        title="Node.js 22.22.3",
    )


def _postgresql_cve() -> NvdCveRecord:
    return NvdCveRecord.from_nvd(
        {
            "cve": {
                "id": "CVE-2026-2003",
                "published": "2026-02-12T14:16:02.067",
                "lastModified": "2026-06-16T23:10:32.860",
                "descriptions": [{"lang": "en", "value": "PostgreSQL issue."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 4.3}},
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": (
                                            "cpe:2.3:a:postgresql:postgresql:"
                                            "*:*:*:*:*:*:*:*"
                                        ),
                                        "matchCriteriaId": "match-18",
                                        "versionStartIncluding": "18.0",
                                        "versionEndExcluding": "18.2",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    )


def _irrelevant_cve() -> NvdCveRecord:
    return NvdCveRecord.from_nvd(
        {
            "cve": {
                "id": "CVE-2009-2943",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": (
                                            "cpe:2.3:a:ocaml:postgresql-ocaml:"
                                            "1.5.4:*:*:*:*:*:*:*"
                                        ),
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": (
                                            "cpe:2.3:a:postgresql:postgresql:"
                                            "*:*:*:*:*:*:*:*"
                                        ),
                                    },
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    )
