from notline.discovery.models import ConnectionObservation
from notline.discovery.service_enrichment import (
    enrich_connection_service,
    normalize_zeek_service,
)


def _observation(**updates) -> ConnectionObservation:
    values = {
        "probe": "probe1",
        "uid": "Cservice-test",
        "timestamp": 1000.0,
        "source_ip": "10.10.25.30",
        "destination_ip": "10.10.30.10",
        "source_port": 50000,
        "destination_port": 5432,
        "protocol": "tcp",
    }
    values.update(updates)
    return ConnectionObservation(**values)


def test_infers_postgresql_from_unlabelled_tcp_port():
    result = enrich_connection_service(_observation())

    assert result.service == "postgresql"
    assert result.service_source == "port_inference"
    assert result.service_components == ["postgresql"]


def test_normalizes_layered_zeek_service():
    result = normalize_zeek_service("gssapi,dce_rpc,ntlm,smb")

    assert result == (
        "smb",
        ["gssapi", "dce_rpc", "ntlm", "smb"],
    )


def test_preserves_direct_zeek_service_label():
    observation = _observation(service="postgresql", service_source="zeek_conn")

    result = enrich_connection_service(observation)

    assert result == observation


def test_does_not_infer_unknown_port():
    result = enrich_connection_service(_observation(destination_port=65000))

    assert result.service is None
    assert result.service_source is None
