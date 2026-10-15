from typing import Any

import pytest

from notline.security.enrichment import (
    NGINX_TARGET,
    OPENSSH_TARGET,
    POSTGRESQL_TARGET,
    SAMBA_TARGET,
    SecurityEnrichmentError,
    resolve_target_cpe,
)
from notline.security.models import NvdCpeName


class FakeNvdClient:
    def __init__(self, candidates: list[NvdCpeName]) -> None:
        self.candidates = candidates
        self.calls: list[dict[str, Any]] = []

    def search_cpes(self, keyword: str, *, max_results: int) -> list[NvdCpeName]:
        self.calls.append({"keyword": keyword, "max_results": max_results})
        return self.candidates


def test_resolve_target_cpe_requires_one_active_exact_match() -> None:
    client = FakeNvdClient(
        [
            NvdCpeName(
                cpe_name_id="postgresql-18-id",
                cpe_name=POSTGRESQL_TARGET.expected_cpe_name,
                deprecated=False,
            ),
            NvdCpeName(
                cpe_name_id="other-id",
                cpe_name="cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*",
                deprecated=False,
            ),
        ]
    )

    resolved = resolve_target_cpe(client, POSTGRESQL_TARGET)

    assert resolved.cpe_name_id == "postgresql-18-id"
    assert client.calls == [{"keyword": "PostgreSQL 18.0", "max_results": 2000}]


def test_resolve_target_cpe_rejects_ambiguous_results() -> None:
    client = FakeNvdClient(
        [
            NvdCpeName(
                cpe_name_id="first",
                cpe_name=POSTGRESQL_TARGET.expected_cpe_name,
            ),
            NvdCpeName(
                cpe_name_id="second",
                cpe_name=POSTGRESQL_TARGET.expected_cpe_name,
            ),
        ]
    )

    with pytest.raises(SecurityEnrichmentError, match="found 2"):
        resolve_target_cpe(client, POSTGRESQL_TARGET)


def test_samba_target_uses_verified_service_and_exact_cpe() -> None:
    assert SAMBA_TARGET.service_id == "service:10.10.35.40|tcp|445|smb"
    assert SAMBA_TARGET.expected_cpe_name == (
        "cpe:2.3:a:samba:samba:4.20.6:*:*:*:*:*:*:*"
    )


def test_openssh_target_uses_exact_dictionary_cpe() -> None:
    assert OPENSSH_TARGET.expected_cpe_name == (
        "cpe:2.3:a:openbsd:openssh:9.9:p2:*:*:*:*:*:*"
    )
    assert len(OPENSSH_TARGET.expected_cpe_name.split(":")) == 13
    assert OPENSSH_TARGET.cpe_keyword == "openssh"


def test_nginx_target_uses_pinned_exact_cpe() -> None:
    assert NGINX_TARGET.product_version == "1.30.3"
    assert NGINX_TARGET.expected_cpe_name == (
        "cpe:2.3:a:f5:nginx_open_source:1.30.3:*:*:*:*:*:*:*"
    )
