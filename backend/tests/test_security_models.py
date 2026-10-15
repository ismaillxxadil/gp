from notline.security.models import NvdCveRecord


def test_nvd_cve_record_preserves_version_bounds() -> None:
    record = NvdCveRecord.from_nvd(
        {
            "cve": {
                "id": "CVE-2026-2003",
                "published": "2026-02-12T14:16:02.067",
                "lastModified": "2026-06-16T23:10:32.860",
                "descriptions": [
                    {"lang": "es", "value": "Descripción no usada."},
                    {"lang": "en", "value": "PostgreSQL issue."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 4.3}},
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": (
                                            "cpe:2.3:a:postgresql:postgresql:"
                                            "*:*:*:*:*:*:*:*"
                                        ),
                                        "matchCriteriaId": "match-18",
                                        "versionStartIncluding": "18.0",
                                        "versionEndExcluding": "18.2",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    )

    assert record.cve_id == "CVE-2026-2003"
    assert record.description == "PostgreSQL issue."
    assert record.cvss_base_score == 4.3
    assert len(record.configurations) == 1
    match = record.configurations[0].matches[0]
    assert match.criteria == "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"
    assert match.version_start_including == "18.0"
    assert match.version_end_excluding == "18.2"


def test_nvd_cve_record_keeps_irrelevant_and_exclusion_matches() -> None:
    record = NvdCveRecord.from_nvd(
        {
            "cve": {
                "id": "CVE-2009-2943",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": (
                                            "cpe:2.3:a:ocaml:postgresql-ocaml:"
                                            "1.5.4:*:*:*:*:*:*:*"
                                        ),
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": (
                                            "cpe:2.3:a:postgresql:postgresql:"
                                            "*:*:*:*:*:*:*:*"
                                        ),
                                    },
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    )

    matches = record.configurations[0].matches
    assert matches[0].criteria.startswith("cpe:2.3:a:ocaml:")
    assert matches[0].vulnerable is True
    assert matches[1].vulnerable is False
