from typing import Any

from notline.graph.security_writer import write_unresolved_service_identity


class RecordingDriver:
    def __init__(self) -> None:
        self.query = None
        self.parameters: dict[str, Any] | None = None

    def execute_query(self, query: str, **parameters: Any) -> None:
        self.query = query
        self.parameters = parameters


def test_unresolved_identity_is_recorded_without_cpe_nodes() -> None:
    driver = RecordingDriver()

    write_unresolved_service_identity(
        driver,
        service_id="service:10.10.20.20|tcp|80|http",
        product_name="NGINX Open Source",
        product_version="1.30.6",
        evidence_source="web1_runtime_version",
        reason="Exact observed version is not present in the NVD CPE dictionary",
        candidate_cpes=["cpe:2.3:a:f5:nginx_open_source:1.30.3:*:*:*:*:*:*:*"],
        cpe_match_criteria_ids=["criterion-1"],
        cpe_match_search_string="cpe:2.3:a:f5:nginx_open_source:1.30.6",
    )

    assert driver.query is not None
    assert "MATCH (service:Service {service_id: $service_id})" in driver.query
    assert "cpe_resolution_status = 'unresolved'" in driver.query
    assert "MERGE (cpe:CPE" not in driver.query
    assert "cpe_match_criteria_ids = $cpe_match_criteria_ids" in driver.query
    assert driver.parameters is not None
    assert driver.parameters["candidate_cpes"] == [
        "cpe:2.3:a:f5:nginx_open_source:1.30.3:*:*:*:*:*:*:*"
    ]
    assert driver.parameters["cpe_match_criteria_ids"] == ["criterion-1"]
