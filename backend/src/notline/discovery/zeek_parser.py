from collections.abc import Mapping

from pydantic import ValidationError

from notline.discovery.models import (
    ConnectionObservation,
    DHCPObservation,
    is_discoverable_ip,
)
from notline.discovery.service_enrichment import normalize_zeek_service


def parse_connection(
    record: Mapping,
    probe: str,
) -> ConnectionObservation | None:
    """Normalize one Zeek conn.log JSON record."""

    source_ip = record.get("id.orig_h")
    destination_ip = record.get("id.resp_h")

    if not isinstance(source_ip, str) or not isinstance(destination_ip, str):
        return None

    if not (is_discoverable_ip(source_ip) and is_discoverable_ip(destination_ip)):
        return None

    try:
        service, service_components = normalize_zeek_service(record.get("service"))

        return ConnectionObservation(
            probe=probe,
            uid=record["uid"],
            timestamp=record["ts"],
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=record.get("id.orig_p"),
            destination_port=record.get("id.resp_p"),
            protocol=record["proto"],
            service=service,
            service_source=("zeek_conn" if service is not None else None),
            service_components=service_components,
            connection_state=record.get("conn_state"),
            duration=record.get("duration"),
            source_bytes=record.get("orig_bytes"),
            destination_bytes=record.get("resp_bytes"),
            source_ip_bytes=record.get("orig_ip_bytes"),
            destination_ip_bytes=record.get("resp_ip_bytes"),
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
            assigned_ip=record.get("assigned_addr"),
            server_ip=record.get("server_addr"),
            lease_time=record.get("lease_time"),
            message_types=message_types,
            assignment_status=status,
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None
