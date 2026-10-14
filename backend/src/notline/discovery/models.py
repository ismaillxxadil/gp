from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, Field


class ConnectionObservation(BaseModel):
    probe: str
    uid: str
    timestamp: float

    source_ip: str
    destination_ip: str

    source_port: int | None = None
    destination_port: int | None = None

    protocol: str
    connection_state: str | None = None

    source_packets: int = Field(default=0, ge=0)
    destination_packets: int = Field(default=0, ge=0)


class DHCPObservation(BaseModel):
    probe: str
    timestamp: float
    mac: str

    requested_ip: str | None = None
    message_types: list[str] = Field(default_factory=list)

    assignment_status: Literal[
        "requested",
        "confirmed",
        "unknown",
    ] = "unknown"


def is_discoverable_ip(value: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False

    return not (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
    )
