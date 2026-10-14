from collections.abc import Mapping

from pydantic import ValidationError

from notline.discovery.models import (
    ConnectionObservation,
    DHCPObservation,
    is_discoverable_ip,
)


def parse_connection(
    record: Mapping,
    probe: str,
) -> ConnectionObservation | None:
    """Normalize one Zeek conn.log JSON record."""

    source_ip = record.get("id.orig_h")
    destination_ip = record.get("id.resp_h")

    if not isinstance(source_ip, str) or not isinstance(destination_ip, str):
        return None

    if not (
        is_discoverable_ip(source_ip)
        and is_discoverable_ip(destination_ip)
    ):
        return None

    try:
        return ConnectionObservation(
            probe=probe,
            uid=record["uid"],
            timestamp=record["ts"],
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=record.get("id.orig_p"),
            destination_port=record.get("id.resp_p"),
            protocol=record["proto"],
            connection_state=record.get("conn_state"),
            source_packets=record.get("orig_pkts", 0),
            destination_packets=record.get("resp_pkts", 0),
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None


def parse_dhcp(
    record: Mapping,
    probe: str,
) -> DHCPObservation | None:
    """Normalize one Zeek dhcp.log JSON record."""

    message_types = record.get("msg_types", [])

    if not isinstance(message_types, list):
        return None

    if "ACK" in message_types:
        status = "confirmed"
    elif "REQUEST" in message_types:
        status = "requested"
    else:
        status = "unknown"

    try:
        return DHCPObservation(
            probe=probe,
            timestamp=record["ts"],
            mac=record["mac"],
            requested_ip=record.get("requested_addr"),
            message_types=message_types,
            assignment_status=status,
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None
