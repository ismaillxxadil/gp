from notline.discovery.inventory import InventoryAsset
from notline.discovery.models import ConnectionObservation
from notline.graph.writer import (
    reconcile_dhcp_asset_status,
    retire_unlisted_inventory_assets,
    update_asset_communication_graph,
    update_service_graph,
    write_connection,
    write_inventory_asset,
)


class RecordingDriver:
    def __init__(self):
        self.query = None
        self.parameters = None
        self.queries = []

    def execute_query(self, query, **parameters):
        self.query = query
        self.parameters = parameters
        self.queries.append(query)


def test_write_connection_updates_existing_observation_metadata():
    driver = RecordingDriver()
    observation = ConnectionObservation(
        probe="probe1",
        uid="Cwriter-test",
        timestamp=1000.0,
        source_ip="10.10.10.140",
        destination_ip="10.10.20.20",
        source_port=39472,
        destination_port=80,
        protocol="tcp",
        service="http",
        connection_state="SF",
        duration=0.25,
        source_bytes=87,
        destination_bytes=431,
        source_ip_bytes=459,
        destination_ip_bytes=699,
        source_packets=7,
        destination_packets=5,
    )

    write_connection(driver, observation, canonical_flow_id="flow:test")

    assert driver.query is not None
    assert "MERGE (obs:Observation" in driver.query
    assert "ON CREATE SET" not in driver.query
    assert "SET" in driver.query
    assert driver.parameters["observation_id"] == "probe1:Cwriter-test"
    assert driver.parameters["canonical_flow_id"] == "flow:test"
    assert driver.parameters["service"] == "http"
    assert driver.parameters["service_source"] is None
    assert driver.parameters["service_components"] == []
    assert driver.parameters["duration"] == 0.25
    assert driver.parameters["source_bytes"] == 87
    assert driver.parameters["destination_bytes"] == 431
    assert driver.parameters["source_ip_bytes"] == 459
    assert driver.parameters["destination_ip_bytes"] == 699


def test_update_service_graph_uses_passive_observations():
    driver = RecordingDriver()

    update_service_graph(driver)

    assert driver.query is not None
    assert "MATCH (obs:Observation)-[:DESTINATION_IP]->(ip:IPAddress)" in driver.query
    assert "MERGE (service:Service {service_id: service_id})" in driver.query
    assert "MERGE (ip)-[r:RUNS_SERVICE]->(service)" in driver.query
    assert "count(DISTINCT coalesce" in driver.query
    assert "evidence_sources" in driver.query


def test_write_inventory_asset_records_topology_identity():
    driver = RecordingDriver()
    asset = InventoryAsset(
        asset_id="web1",
        name="web1",
        asset_type="web_server",
        network_zone="web",
        addresses=("10.10.20.20",),
    )

    write_inventory_asset(driver, asset)

    assert driver.query is not None
    assert "MERGE (asset:Asset {asset_id: $asset_id})" in driver.query
    assert "UNWIND $addresses AS address" in driver.query
    assert "topology_inventory" in driver.query
    assert driver.parameters["asset_id"] == "web1"
    assert driver.parameters["addresses"] == ["10.10.20.20"]


def test_retire_unlisted_inventory_assets_preserves_history():
    driver = RecordingDriver()

    retire_unlisted_inventory_assets(driver, ["web1", "app1"])

    assert "NOT asset.asset_id IN $active_asset_ids" in driver.query
    assert "asset.discovery_status = 'retired'" in driver.query
    assert driver.parameters["active_asset_ids"] == ["web1", "app1"]


def test_asset_communication_refresh_removes_retired_edges_first():
    driver = RecordingDriver()

    update_asset_communication_graph(driver)

    assert len(driver.queries) == 2
    assert "DELETE r" in driver.queries[0]
    assert "mapping_status = 'provisional'" in driver.queries[0]
    assert "src.discovery_status IN ['retired', 'historical']" in driver.queries[0]
    assert "IN ['retired', 'historical']" in driver.queries[1]


def test_reconcile_dhcp_asset_status_uses_capture_window():
    driver = RecordingDriver()

    reconcile_dhcp_asset_status(
        driver,
        capture_end=1000.0,
        activity_window_seconds=60.0,
        capture_id="lab:1000",
    )

    assert "identity_source: 'zeek_dhcp'" in driver.query
    assert "'passive_current'" in driver.query
    assert "'historical'" in driver.query
    assert driver.parameters["active_since"] == 940.0
    assert driver.parameters["capture_id"] == "lab:1000"
