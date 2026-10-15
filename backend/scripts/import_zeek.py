from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from neo4j import Driver

from notline.discovery.deduplication import (
    canonical_flow_id,
    group_connection_observations,
)
from notline.discovery.models import ConnectionObservation
from notline.discovery.service_enrichment import enrich_connection_service
from notline.discovery.zeek_parser import parse_connection, parse_dhcp
from notline.graph.connection import Neo4jConnection
from notline.graph.writer import (
    reconcile_dhcp_asset_status,
    update_asset_communication_graph,
    update_communication_graph,
    update_service_graph,
    write_connection,
    write_dhcp_assignment,
)
from notline.network_profile import (
    NetworkProfile,
    ZeekLogSource,
    get_configured_network_profile,
)


def _read_connection_log(
    source: ZeekLogSource,
) -> tuple[list[ConnectionObservation], int]:
    observations = []
    skipped = 0

    with source.path.open() as file:
        for line in file:
            try:
                record: Mapping[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            observation = parse_connection(record, source.probe)
            if observation is None:
                skipped += 1
                continue

            observations.append(enrich_connection_service(observation))

    return observations, skipped


def _load_connection_observations(
    profile: NetworkProfile,
) -> tuple[list[ConnectionObservation], list[tuple[str, int, int]]]:
    observations = []
    stats = []

    for source in profile.connection_logs:
        source_observations, skipped = _read_connection_log(source)
        observations.extend(source_observations)
        stats.append((source.probe, len(source_observations), skipped))

    return observations, stats


def _build_canonical_flow_ids(
    observations: list[ConnectionObservation],
) -> tuple[list[tuple[ConnectionObservation, ...]], dict[tuple[str, str], str]]:
    groups = group_connection_observations(observations)
    canonical_ids = {}

    for group in groups:
        flow_id = canonical_flow_id(group)
        for observation in group:
            canonical_ids[(observation.probe, observation.uid)] = flow_id

    return groups, canonical_ids


def _write_connection_observations(
    driver: Driver,
    observations: list[ConnectionObservation],
    canonical_ids: dict[tuple[str, str], str],
) -> None:
    for observation in observations:
        write_connection(
            driver,
            observation,
            canonical_flow_id=canonical_ids[(observation.probe, observation.uid)],
        )


def _import_dhcp_assignments(
    driver: Driver,
    profile: NetworkProfile,
) -> float | None:
    latest_timestamp: float | None = None
    for source in profile.dhcp_logs:
        imported = 0
        skipped = 0

        if not source.path.exists():
            print(f"{source.probe}: DHCP log not found: {source.path}")
            continue

        with source.path.open() as file:
            for line in file:
                try:
                    record: Mapping[str, Any] = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                observation = parse_dhcp(record, source.probe)
                if (
                    observation is None
                    or observation.assignment_status != "confirmed"
                    or not observation.assigned_ip
                ):
                    skipped += 1
                    continue

                write_dhcp_assignment(driver, observation)
                latest_timestamp = max(
                    latest_timestamp or observation.timestamp,
                    observation.timestamp,
                )
                imported += 1

        print(
            f"{source.probe}: imported {imported} DHCP assignments, skipped {skipped}"
        )

    return latest_timestamp


def _refresh_derived_graph(driver: Driver) -> None:
    update_communication_graph(driver)
    print("Communication graph updated!")

    update_service_graph(driver)
    print("Service graph updated!")

    update_asset_communication_graph(driver)
    print("Asset communication graph updated!")


def main() -> None:
    profile = get_configured_network_profile()
    db = Neo4jConnection()

    try:
        connection_observations, connection_stats = _load_connection_observations(
            profile
        )
        flow_groups, canonical_ids = _build_canonical_flow_ids(connection_observations)
        _write_connection_observations(
            db.driver,
            connection_observations,
            canonical_ids,
        )

        for probe, imported, skipped in connection_stats:
            print(
                f"{probe}: processed {imported} valid observations, skipped {skipped}"
            )
        print(
            f"Connection observations grouped into {len(flow_groups)} canonical flows"
        )

        latest_dhcp_timestamp = _import_dhcp_assignments(db.driver, profile)
        if latest_dhcp_timestamp is not None:
            reconcile_dhcp_asset_status(
                db.driver,
                capture_end=latest_dhcp_timestamp,
                activity_window_seconds=profile.dhcp_activity_window_seconds,
                capture_id=f"{profile.name}:{latest_dhcp_timestamp:.6f}",
            )
        _refresh_derived_graph(db.driver)

        print("Import complete!")
    finally:
        db.close()


if __name__ == "__main__":
    main()
