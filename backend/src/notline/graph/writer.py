from collections.abc import Iterable

from neo4j import Driver

from notline.discovery.inventory import InventoryAsset
from notline.discovery.models import ConnectionObservation, DHCPObservation


def write_connection(
    driver: Driver,
    observation: ConnectionObservation,
    canonical_flow_id: str | None = None,
) -> None:
    """Store one Zeek connection observation in Neo4j."""

    query = """
    MERGE (src:IPAddress {address: $source_ip})
    MERGE (dst:IPAddress {address: $destination_ip})

    MERGE (obs:Observation {observation_id: $observation_id})
    SET
        obs.timestamp = $timestamp,
        obs.protocol = $protocol,
        obs.service = $service,
        obs.service_source = $service_source,
        obs.service_components = $service_components,
        obs.canonical_flow_id = $canonical_flow_id,
        obs.source_port = $source_port,
        obs.destination_port = $destination_port,
        obs.connection_state = $connection_state,
        obs.duration = $duration,
        obs.source_bytes = $source_bytes,
        obs.destination_bytes = $destination_bytes,
        obs.source_ip_bytes = $source_ip_bytes,
        obs.destination_ip_bytes = $destination_ip_bytes,
        obs.source_packets = $source_packets,
        obs.destination_packets = $destination_packets,
        obs.probe = $probe

    MERGE (obs)-[:SOURCE_IP]->(src)
    MERGE (obs)-[:DESTINATION_IP]->(dst)
    """

    driver.execute_query(
        query,
        source_ip=observation.source_ip,
        destination_ip=observation.destination_ip,
        observation_id=f"{observation.probe}:{observation.uid}",
        timestamp=observation.timestamp,
        protocol=observation.protocol,
        service=observation.service,
        service_source=observation.service_source,
        service_components=observation.service_components,
        canonical_flow_id=canonical_flow_id,
        source_port=observation.source_port,
        destination_port=observation.destination_port,
        connection_state=observation.connection_state,
        duration=observation.duration,
        source_bytes=observation.source_bytes,
        destination_bytes=observation.destination_bytes,
        source_ip_bytes=observation.source_ip_bytes,
        destination_ip_bytes=observation.destination_ip_bytes,
        source_packets=observation.source_packets,
        destination_packets=observation.destination_packets,
        probe=observation.probe,
        database_="neo4j",
    )


def update_communication_graph(driver: Driver) -> None:
    query = """
    MATCH (src:IPAddress)<-[:SOURCE_IP]-(obs:Observation)-[:DESTINATION_IP]->(dst:IPAddress)
    WITH src, dst,
         count(obs) AS raw_observation_count,
         count(DISTINCT coalesce(obs.canonical_flow_id, obs.observation_id)) AS flow_count,
         collect(DISTINCT obs.protocol) AS protocols,
         min(obs.timestamp) AS first_seen,
         max(obs.timestamp) AS last_seen
    MERGE (src)-[r:COMMUNICATES_WITH]->(dst)
    SET r.observation_count = raw_observation_count,
        r.flow_count = flow_count,
        r.protocols = protocols,
        r.first_seen = first_seen,
        r.last_seen = last_seen
    """

    driver.execute_query(query, database_="neo4j")


def update_service_graph(driver: Driver) -> None:
    """Derive passive service evidence from normalized observations."""

    query = """
    MATCH (obs:Observation)-[:DESTINATION_IP]->(ip:IPAddress)
    WHERE obs.service IS NOT NULL
      AND obs.service <> ''
      AND obs.destination_port IS NOT NULL
    WITH ip,
         obs.service AS service_name,
         obs.protocol AS protocol,
         obs.destination_port AS destination_port,
         count(obs) AS raw_observation_count,
         count(DISTINCT coalesce(obs.canonical_flow_id, obs.observation_id)) AS flow_count,
         min(obs.timestamp) AS first_seen,
         max(obs.timestamp) AS last_seen,
         collect(DISTINCT coalesce(obs.service_source, 'zeek_conn')) AS evidence_sources
    WITH ip,
         service_name,
         protocol,
         destination_port,
         raw_observation_count,
         flow_count,
         first_seen,
         last_seen,
         evidence_sources,
         'service:' + ip.address + '|' + protocol + '|' +
             toString(destination_port) + '|' + service_name AS service_id
    MERGE (service:Service {service_id: service_id})
    ON CREATE SET
        service.name = service_name,
        service.protocol = protocol,
        service.port = destination_port,
        service.discovery_status = CASE
            WHEN 'zeek_conn' IN evidence_sources THEN 'passive'
            ELSE 'passive_inferred'
        END,
        service.first_seen = first_seen
    SET service.last_seen = last_seen,
        service.observation_count = raw_observation_count,
        service.flow_count = flow_count,
        service.evidence_sources = evidence_sources
    MERGE (ip)-[r:RUNS_SERVICE]->(service)
    SET r.evidence = CASE
            WHEN size(evidence_sources) = 1 THEN evidence_sources[0]
            ELSE 'mixed'
        END,
        r.evidence_sources = evidence_sources,
        r.discovery_status = CASE
            WHEN 'zeek_conn' IN evidence_sources THEN 'passive'
            ELSE 'passive_inferred'
        END,
        r.observation_count = raw_observation_count,
        r.flow_count = flow_count,
        r.first_seen = first_seen,
        r.last_seen = last_seen
    """

    driver.execute_query(query, database_="neo4j")


def write_dhcp_assignment(driver: Driver, observation: DHCPObservation) -> None:
    """Store a confirmed DHCP assignment as an asset-to-IP relationship."""

    if observation.assignment_status != "confirmed":
        return

    if not observation.assigned_ip or not observation.mac:
        return

    query = """
    MERGE (asset:Asset {asset_id: $asset_id})
    ON CREATE SET
        asset.mac = $mac,
        asset.identity_source = 'zeek_dhcp',
        asset.discovery_status = 'passive'

    MERGE (ip:IPAddress {address: $assigned_ip})

    MERGE (asset)-[r:HAS_IP]->(ip)
    SET r.evidence = 'dhcp_ack',
        r.source = 'zeek',
        r.last_seen = $timestamp,
        r.lease_time = $lease_time,
        r.lease_expires_at = $lease_expires_at
    """

    lease_expires_at = (
        observation.timestamp + observation.lease_time
        if observation.lease_time is not None
        else None
    )

    driver.execute_query(
        query,
        asset_id=f"mac:{observation.mac.lower()}",
        mac=observation.mac.lower(),
        assigned_ip=observation.assigned_ip,
        timestamp=observation.timestamp,
        lease_time=observation.lease_time,
        lease_expires_at=lease_expires_at,
        database_="neo4j",
    )


def reconcile_dhcp_asset_status(
    driver: Driver,
    *,
    capture_end: float,
    activity_window_seconds: float,
    capture_id: str,
) -> None:
    """Classify DHCP identities for the current passive capture window."""

    if activity_window_seconds < 0:
        raise ValueError("activity_window_seconds cannot be negative")

    query = """
    MATCH (asset:Asset {identity_source: 'zeek_dhcp'})
    OPTIONAL MATCH (asset)-[lease:HAS_IP]->(:IPAddress)
    WITH asset, max(lease.last_seen) AS last_seen
    SET asset.discovery_status = CASE
            WHEN last_seen >= $active_since THEN 'passive_current'
            ELSE 'historical'
        END,
        asset.last_observed_at = last_seen,
        asset.capture_id = $capture_id,
        asset.capture_end = $capture_end,
        asset.activity_window_seconds = $activity_window_seconds
    """

    driver.execute_query(
        query,
        active_since=capture_end - activity_window_seconds,
        capture_id=capture_id,
        capture_end=capture_end,
        activity_window_seconds=activity_window_seconds,
        database_="neo4j",
    )


def write_inventory_asset(driver: Driver, asset: InventoryAsset) -> None:
    """Store stable device identities and addresses from the lab inventory."""

    query = """
    MERGE (asset:Asset {asset_id: $asset_id})
    SET asset.name = $name,
        asset.asset_type = $asset_type,
        asset.network_zone = $network_zone,
        asset.identity_source = 'containerlab_topology',
        asset.discovery_status = 'inventory',
        asset.retired_reason = null

    WITH asset
    UNWIND $addresses AS address
    MERGE (ip:IPAddress {address: address})
    MERGE (asset)-[r:HAS_IP]->(ip)
    SET r.evidence = 'topology_inventory',
        r.source = 'containerlab',
        r.discovery_status = 'inventory'
    """

    driver.execute_query(
        query,
        asset_id=asset.asset_id,
        name=asset.name,
        asset_type=asset.asset_type,
        network_zone=asset.network_zone,
        addresses=list(asset.addresses),
        database_="neo4j",
    )


def retire_unlisted_inventory_assets(
    driver: Driver,
    active_asset_ids: Iterable[str],
) -> None:
    """Mark old topology identities inactive without deleting their history."""

    active_ids = list(active_asset_ids)
    if not active_ids:
        raise ValueError("active_asset_ids must not be empty")

    query = """
    MATCH (asset:Asset)
    WHERE asset.identity_source IN ['containerlab', 'containerlab_topology']
      AND NOT asset.asset_id IN $active_asset_ids
    SET asset.discovery_status = 'retired',
        asset.retired_reason = 'not_in_current_inventory'
    """

    driver.execute_query(
        query,
        active_asset_ids=active_ids,
        database_="neo4j",
    )


def update_asset_communication_graph(driver: Driver) -> None:
    """Derive asset communications from identified IP relationships."""

    delete_retired_query = """
    MATCH (src:Asset)-[r:ASSET_COMMUNICATES_WITH]->(dst:Asset)
    WHERE r.mapping_status = 'provisional'
      AND (
          src.discovery_status IN ['retired', 'historical']
          OR dst.discovery_status IN ['retired', 'historical']
      )
    DELETE r
    """

    driver.execute_query(delete_retired_query, database_="neo4j")

    query = """
    MATCH (src:Asset)-[:HAS_IP]->(src_ip:IPAddress)
          -[c:COMMUNICATES_WITH]->(dst_ip:IPAddress)
          <-[:HAS_IP]-(dst:Asset)

    WHERE src <> dst
      AND NOT (
          coalesce(src.discovery_status, '') IN ['retired', 'historical']
      )
      AND NOT (
          coalesce(dst.discovery_status, '') IN ['retired', 'historical']
      )
      AND (
          NOT EXISTS {
              MATCH (src)-[src_lease:HAS_IP]->(src_ip)
              WHERE src_lease.evidence = 'dhcp_ack'
          }
          OR EXISTS {
              MATCH (src)-[src_lease:HAS_IP]->(src_ip)
              WHERE src_lease.evidence = 'dhcp_ack'
                AND c.first_seen >= src_lease.last_seen
                AND c.last_seen <= src_lease.lease_expires_at
          }
      )
      AND (
          NOT EXISTS {
              MATCH (dst)-[dst_lease:HAS_IP]->(dst_ip)
              WHERE dst_lease.evidence = 'dhcp_ack'
          }
          OR EXISTS {
              MATCH (dst)-[dst_lease:HAS_IP]->(dst_ip)
              WHERE dst_lease.evidence = 'dhcp_ack'
                AND c.first_seen >= dst_lease.last_seen
                AND c.last_seen <= dst_lease.lease_expires_at
          }
      )

    WITH src, dst,
         sum(c.observation_count) AS total_observations,
         sum(coalesce(c.flow_count, c.observation_count)) AS total_flows,
         reduce(protocols = [], p IN collect(c.protocols) |
             protocols + p
         ) AS all_protocols,
         min(c.first_seen) AS first_seen,
         max(c.last_seen) AS last_seen

    MERGE (src)-[r:ASSET_COMMUNICATES_WITH]->(dst)

    SET r.observation_count = total_observations,
        r.flow_count = total_flows,
        r.protocols = all_protocols,
        r.first_seen = first_seen,
        r.last_seen = last_seen,
        r.mapping_status = 'provisional'
    """

    driver.execute_query(query, database_="neo4j")
