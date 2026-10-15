from notline.discovery.models import ConnectionObservation

SERVICE_PORT_HINTS: dict[tuple[str, int], str] = {
    ("tcp", 5432): "postgresql",
}
SERVICE_COMPONENT_PRIORITY = (
    "http",
    "postgresql",
    "smb",
    "ssh",
    "dhcp",
)


def normalize_zeek_service(value: object) -> tuple[str | None, list[str]]:
    """Return one graph-friendly service name and preserve Zeek components."""

    if not isinstance(value, str) or not value.strip():
        return None, []

    components = [component.strip().casefold() for component in value.split(",")]
    components = [component for component in components if component]
    if not components:
        return None, []

    for preferred in SERVICE_COMPONENT_PRIORITY:
        if preferred in components:
            return preferred, components

    if len(components) == 1:
        return components[0], components

    return value, components


def enrich_connection_service(
    observation: ConnectionObservation,
) -> ConnectionObservation:
    """Add an explicit, provenance-tagged service hint when Zeek has none."""

    if observation.service or observation.destination_port is None:
        return observation

    service = SERVICE_PORT_HINTS.get(
        (observation.protocol.casefold(), observation.destination_port)
    )
    if service is None:
        return observation

    return observation.model_copy(
        update={
            "service": service,
            "service_source": "port_inference",
            "service_components": [service],
        }
    )
