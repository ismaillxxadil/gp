from typing import Any

from notline.graph.security_writer import write_unresolved_software_component


class RecordingDriver:
    def __init__(self) -> None:
        self.query = None
        self.parameters: dict[str, Any] | None = None

    def execute_query(self, query: str, **parameters: Any) -> None:
        self.query = query
        self.parameters = parameters


def test_unresolved_component_is_attached_to_existing_asset() -> None:
    driver = RecordingDriver()

    write_unresolved_software_component(
        driver,
        asset_id="app1",
        component_id="component:app1|express",
        product_name="Express",
        product_version="5.3.0",
        component_type="framework",
        evidence_source="app1_runtime_version",
        reason="No exact active CPE was verified for this software component",
        candidate_cpes=["cpe:2.3:a:example:express:5.3.0:*:*:*:*:*:*:*"],
        cpe_match_criteria_ids=["criterion-1"],
        cpe_match_search_string="cpe:2.3:a:example:express:5.3.0",
    )

    assert driver.query is not None
    assert "MATCH (asset:Asset {asset_id: $asset_id})" in driver.query
    assert "MERGE (component:SoftwareComponent" in driver.query
    assert "MERGE (asset)-[has_component:HAS_COMPONENT]->(component)" in driver.query
    assert "MERGE (cpe:CPE" not in driver.query
    assert "MERGE (cve:CVE" not in driver.query
    assert "cpe_match_criteria_ids = $cpe_match_criteria_ids" in driver.query
    assert driver.parameters is not None
    assert driver.parameters["component_id"] == "component:app1|express"
    assert driver.parameters["cpe_match_criteria_ids"] == ["criterion-1"]
