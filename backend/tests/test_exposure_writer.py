from typing import Any

from notline.graph.security_writer import (
    update_asset_advisory_exposure,
    update_asset_vulnerability_exposure,
)


class RecordingDriver:
    def __init__(self) -> None:
        self.queries: list[str] = []
        self.parameters: list[dict[str, Any]] = []

    def execute_query(self, query: str, **parameters: Any) -> None:
        self.queries.append(query)
        self.parameters.append(parameters)


def test_exposure_refresh_removes_stale_edges_and_derives_current_paths() -> None:
    driver = RecordingDriver()

    update_asset_vulnerability_exposure(driver)

    assert len(driver.queries) == 2
    assert "MATCH (asset:Asset)-[exposure:EXPOSED_TO]->(cve:CVE)" in driver.queries[0]
    assert "DELETE exposure" in driver.queries[0]
    assert "MERGE (asset)-[exposure:EXPOSED_TO]->(cve)" in driver.queries[1]
    assert "affected.vulnerable = true" in driver.queries[1]
    assert "lease.evidence = 'dhcp_ack'" in driver.queries[1]
    assert "exposure.match_criteria_ids" in driver.queries[1]


def test_advisory_exposure_refresh_uses_current_package_components() -> None:
    driver = RecordingDriver()

    update_asset_advisory_exposure(driver)

    assert len(driver.queries) == 2
    assert "(advisory:Advisory)" in driver.queries[0]
    assert "DELETE exposure" in driver.queries[0]
    assert "component.package_purl" in driver.queries[1]
    assert "asset_component_osv_advisory" in driver.queries[1]
