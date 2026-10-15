from notline.discovery.models import is_discoverable_ip
from notline.discovery.zeek_parser import parse_connection, parse_dhcp


def test_valid_connection():
    record = {
        "ts": 1000.0,
        "uid": "C123",
        "id.orig_h": "10.10.20.20",
        "id.orig_p": 45000,
        "id.resp_h": "10.10.25.30",
        "id.resp_p": 3000,
        "proto": "tcp",
        "conn_state": "SF",
        "orig_pkts": 5,
        "resp_pkts": 4,
    }

    result = parse_connection(record, "probe1")

    assert result is not None
    assert result.source_ip == "10.10.20.20"
    assert result.destination_ip == "10.10.25.30"
    assert result.destination_port == 3000
    assert result.source_packets == 5


def test_connection_normalizes_layered_smb_services():
    record = {
        "ts": 1000.0,
        "uid": "Csmb123",
        "id.orig_h": "10.10.10.107",
        "id.orig_p": 40000,
        "id.resp_h": "10.10.35.40",
        "id.resp_p": 445,
        "proto": "tcp",
        "service": "gssapi,dce_rpc,ntlm,smb",
    }

    result = parse_connection(record, "probe1")

    assert result is not None
    assert result.service == "smb"
    assert result.service_source == "zeek_conn"
    assert result.service_components == ["gssapi", "dce_rpc", "ntlm", "smb"]


def test_connection_preserves_http_metadata():
    record = {
        "ts": 1792040966.197872,
        "uid": "Cstlfw43PCAPTEST",
        "id.orig_h": "10.10.10.140",
        "id.orig_p": 39472,
        "id.resp_h": "10.10.20.20",
        "id.resp_p": 80,
        "proto": "tcp",
        "service": "http",
        "duration": 0.027773141860961914,
        "orig_bytes": 87,
        "resp_bytes": 431,
        "orig_pkts": 7,
        "resp_pkts": 5,
        "orig_ip_bytes": 459,
        "resp_ip_bytes": 699,
        "conn_state": "SF",
    }

    result = parse_connection(record, "probe1")

    assert result is not None
    assert result.service == "http"
    assert result.service_source == "zeek_conn"
    assert result.service_components == ["http"]
    assert result.duration == 0.027773141860961914
    assert result.source_bytes == 87
    assert result.destination_bytes == 431
    assert result.source_ip_bytes == 459
    assert result.destination_ip_bytes == 699


def test_reject_unspecified_source():
    record = {
        "ts": 1000.0,
        "uid": "C124",
        "id.orig_h": "::",
        "id.resp_h": "ff02::1",
        "proto": "icmp",
    }

    assert parse_connection(record, "probe1") is None


def test_reject_link_local_source():
    record = {
        "ts": 1000.0,
        "uid": "C125",
        "id.orig_h": "fe80::1234",
        "id.resp_h": "ff02::1",
        "proto": "icmp",
    }

    assert parse_connection(record, "probe1") is None


def test_dhcp_request_is_not_confirmed():
    record = {
        "ts": 1000.0,
        "mac": "aa:c1:ab:4a:65:7b",
        "requested_addr": "10.10.10.133",
        "msg_types": ["DISCOVER", "REQUEST"],
    }

    result = parse_dhcp(record, "probe2")

    assert result is not None
    assert result.requested_ip == "10.10.10.133"
    assert result.assignment_status == "requested"


def test_dhcp_discover_without_ip():
    record = {
        "ts": 1000.0,
        "mac": "aa:c1:ab:4a:65:7b",
        "msg_types": ["DISCOVER"],
    }

    result = parse_dhcp(record, "probe2")

    assert result is not None
    assert result.requested_ip is None
    assert result.assignment_status == "unknown"


def test_invalid_connection_is_skipped():
    assert parse_connection({"uid": "incomplete"}, "probe1") is None


def test_ip_filter():
    assert is_discoverable_ip("10.10.20.20")
    assert not is_discoverable_ip("::")
    assert not is_discoverable_ip("ff02::1")
    assert not is_discoverable_ip("fe80::1")
    assert not is_discoverable_ip("127.0.0.1")
