from collections.abc import Iterable, Sequence

from notline.discovery.models import ConnectionObservation

type FlowSignature = tuple[
    str,
    str,
    str,
    int | None,
    int | None,
]

DEFAULT_SENSOR_TIME_TOLERANCE = 0.1


def flow_signature(observation: ConnectionObservation) -> FlowSignature:
    """Return the directed transport identity of a connection observation."""

    return (
        observation.protocol,
        observation.source_ip,
        observation.destination_ip,
        observation.source_port,
        observation.destination_port,
    )


def canonical_flow_id(observations: Sequence[ConnectionObservation]) -> str:
    """Build a deterministic ID for one already-grouped physical flow."""

    if not observations:
        raise ValueError("observations must not be empty")

    representative = min(
        observations,
        key=lambda observation: (
            observation.timestamp,
            observation.probe,
            observation.uid,
        ),
    )
    protocol, source_ip, destination_ip, source_port, destination_port = flow_signature(
        representative
    )
    timestamp_millis = round(representative.timestamp * 1000)

    return "flow:" + "|".join(
        (
            protocol,
            source_ip,
            str(source_port) if source_port is not None else "-",
            destination_ip,
            str(destination_port) if destination_port is not None else "-",
            str(timestamp_millis),
        )
    )


def group_connection_observations(
    observations: Iterable[ConnectionObservation],
    *,
    timestamp_tolerance: float = DEFAULT_SENSOR_TIME_TOLERANCE,
) -> list[tuple[ConnectionObservation, ...]]:
    """Group raw observations that likely describe one physical connection.

    Cross-probe matching uses the directed transport signature and start-time
    proximity. It is intentionally a heuristic: raw observations remain in
    their original groups so callers can preserve sensor evidence.
    """

    if timestamp_tolerance < 0:
        raise ValueError("timestamp_tolerance must be non-negative")

    ordered = sorted(
        observations,
        key=lambda observation: (
            flow_signature(observation),
            observation.timestamp,
            observation.probe,
            observation.uid,
        ),
    )
    groups: list[list[ConnectionObservation]] = []

    for observation in ordered:
        for group in groups:
            if _belongs_to_group(observation, group, timestamp_tolerance):
                group.append(observation)
                break
        else:
            groups.append([observation])

    return [tuple(group) for group in groups]


def _belongs_to_group(
    observation: ConnectionObservation,
    group: list[ConnectionObservation],
    timestamp_tolerance: float,
) -> bool:
    for candidate in group:
        if observation.probe == candidate.probe:
            if observation.uid == candidate.uid:
                return True
            continue

        if flow_signature(observation) != flow_signature(candidate):
            continue

        if abs(observation.timestamp - candidate.timestamp) <= timestamp_tolerance:
            return True

    return False
