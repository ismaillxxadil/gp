import pytest

from notline.discovery.deduplication import (
    canonical_flow_id,
    group_connection_observations,
)
from notline.discovery.models import ConnectionObservation


def _http_observation(probe: str, uid: str, timestamp: float) -> ConnectionObservation:
    return ConnectionObservation(
        probe=probe,
        uid=uid,
        timestamp=timestamp,
        source_ip="10.10.10.140",
        destination_ip="10.10.20.20",
        source_port=39472,
        destination_port=80,
        protocol="tcp",
        service="http",
        duration=0.03,
        source_bytes=87,
        destination_bytes=431,
        source_ip_bytes=459,
        destination_ip_bytes=699,
        source_packets=7,
        destination_packets=5,
    )


def test_mirrored_http_observations_are_grouped():
    observations = [
        _http_observation("probe1", "Cstlfw43MTyVUhLBic", 1792040966.197872),
        _http_observation("probe2", "CiGHtA3T2QvhBwVC38", 1792040966.192761),
    ]

    groups = group_connection_observations(observations)

    assert len(groups) == 1
    assert {observation.probe for observation in groups[0]} == {
        "probe1",
        "probe2",
    }

    flow_id = canonical_flow_id(groups[0])

    assert flow_id == canonical_flow_id(tuple(reversed(groups[0])))
    assert flow_id.startswith("flow:tcp|10.10.10.140|39472|10.10.20.20|80|")


def test_different_connections_are_not_grouped():
    observations = [
        _http_observation("probe1", "C-first", 1000.0),
        _http_observation("probe2", "C-second", 1000.2),
    ]

    groups = group_connection_observations(observations)

    assert len(groups) == 2


def test_same_probe_connections_with_different_uids_are_not_grouped():
    observations = [
        _http_observation("probe1", "C-first", 1000.0),
        _http_observation("probe1", "C-second", 1000.01),
    ]

    groups = group_connection_observations(observations)

    assert len(groups) == 2


def test_negative_timestamp_tolerance_is_rejected():
    with pytest.raises(ValueError, match="timestamp_tolerance"):
        group_connection_observations([], timestamp_tolerance=-0.1)


def test_empty_group_cannot_have_a_canonical_id():
    with pytest.raises(ValueError, match="must not be empty"):
        canonical_flow_id(())
