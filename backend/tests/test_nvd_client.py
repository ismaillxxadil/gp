from pathlib import Path
from typing import Any

from notline.security.nvd_client import NvdClient
from notline.security.osv_client import OsvClient


def test_fetch_cves_for_cpe_paginates_and_normalizes() -> None:
    calls: list[dict[str, str]] = []

    def request_json(endpoint: str, params: dict[str, str]) -> dict[str, Any]:
        calls.append(params)
        if params["startIndex"] == "0":
            return {
                "totalResults": 2,
                "vulnerabilities": [_cve_payload("CVE-1")],
            }
        return {
            "totalResults": 2,
            "vulnerabilities": [_cve_payload("CVE-2")],
        }

    client = NvdClient(
        request_json=request_json,
        min_interval_seconds=0,
        cache_dir=None,
    )

    records = client.fetch_cves_for_cpe(
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        page_size=1,
    )

    assert [record.cve_id for record in records] == ["CVE-1", "CVE-2"]
    assert [call["startIndex"] for call in calls] == ["0", "1"]


def test_search_cpes_uses_cache_and_filters_deprecated_entries(
    tmp_path: Path,
) -> None:
    calls = 0

    def request_json(endpoint: str, params: dict[str, str]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {
            "totalResults": 2,
            "products": [
                {
                    "cpe": {
                        "cpeNameId": "active-id",
                        "cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                        "deprecated": False,
                        "titles": [{"lang": "en", "title": "Product 1.0"}],
                    }
                },
                {
                    "cpe": {
                        "cpeNameId": "deprecated-id",
                        "cpeName": "cpe:2.3:a:vendor:product:0.1:*:*:*:*:*:*:*",
                        "deprecated": True,
                        "titles": [],
                    }
                },
            ],
        }

    client = NvdClient(
        request_json=request_json,
        min_interval_seconds=0,
        cache_dir=tmp_path,
        clock=lambda: 100.0,
    )

    first_result = client.search_cpes("Product", max_results=2, page_size=2)
    second_result = client.search_cpes("Product", max_results=2, page_size=2)

    assert calls == 1
    assert [entry.cpe_name_id for entry in first_result] == ["active-id"]
    assert [entry.cpe_name for entry in second_result] == [
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    ]


def test_search_cpe_match_criteria_normalizes_active_entries() -> None:
    def request_json(endpoint: str, params: dict[str, str]) -> dict[str, Any]:
        assert endpoint == "/cpematch/2.0"
        assert params["matchStringSearch"] == ("cpe:2.3:a:vendor:product:1.0")
        return {
            "totalResults": 2,
            "matchStrings": [
                {
                    "matchString": {
                        "matchCriteriaId": "active-match",
                        "criteria": ("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
                        "versionEndExcluding": "2.0",
                        "status": "Active",
                        "matches": [
                            {
                                "cpeNameId": "cpe-id",
                                "cpeName": (
                                    "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                                ),
                            }
                        ],
                    }
                },
                {
                    "matchString": {
                        "matchCriteriaId": "inactive-match",
                        "criteria": ("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
                        "status": "Inactive",
                    }
                },
            ],
        }

    client = NvdClient(
        request_json=request_json,
        min_interval_seconds=0,
        cache_dir=None,
    )

    criteria = client.search_cpe_match_criteria(
        "cpe:2.3:a:vendor:product:1.0",
        max_results=2,
        page_size=2,
    )

    assert [criterion.match_criteria_id for criterion in criteria] == ["active-match"]
    assert criteria[0].version_end_excluding == "2.0"
    assert criteria[0].matched_cpes[0].cpe_name_id == "cpe-id"


def test_osv_client_queries_exact_package_version_and_normalizes_advisory() -> None:
    calls: list[dict[str, Any]] = []

    def request_json(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return {
            "vulns": [
                {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2026-1234"],
                    "summary": "Test package issue",
                    "details": "Test details",
                    "published": "2026-01-01T00:00:00Z",
                    "modified": "2026-01-02T00:00:00Z",
                    "references": [
                        {"type": "ADVISORY", "url": "https://example.test/advisory"}
                    ],
                }
            ]
        }

    client = OsvClient(request_json=request_json, cache_dir=None)

    advisories = client.query_package(
        ecosystem="npm",
        name="express",
        version="5.2.1",
    )

    assert calls == [
        {
            "package": {"ecosystem": "npm", "name": "express"},
            "version": "5.2.1",
        }
    ]
    assert advisories[0].osv_id == "GHSA-test"
    assert advisories[0].aliases == ["CVE-2026-1234"]
    assert advisories[0].reference_urls == ["https://example.test/advisory"]


def _cve_payload(cve_id: str) -> dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": "Test CVE."}],
            "configurations": [],
        }
    }
