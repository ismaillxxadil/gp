from notline.security.applicability import (
    cve_applies_to_cpe,
    find_applicable_matches,
    parse_cpe23,
)
from notline.security.models import NvdCveRecord

POSTGRESQL_18_CPE = "cpe:2.3:a:postgresql:postgresql:18.0:*:*:*:*:*:*:*"


def test_postgresql_18_cve_matches_exact_version_range() -> None:
    record = _record_with_match(
        cve_id="CVE-2026-2003",
        criteria="cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
        match_criteria_id="match-18",
        version_start_including="18.0",
        version_end_excluding="18.2",
    )

    matches = find_applicable_matches(record, POSTGRESQL_18_CPE)

    assert cve_applies_to_cpe(record, POSTGRESQL_18_CPE)
    assert [match.match_criteria_id for match in matches] == ["match-18"]


def test_postgresql_version_outside_range_does_not_match() -> None:
    record = _record_with_match(
        cve_id="CVE-2026-2003",
        criteria="cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
        version_start_including="18.0",
        version_end_excluding="18.2",
    )

    assert not cve_applies_to_cpe(
        record,
        "cpe:2.3:a:postgresql:postgresql:18.2:*:*:*:*:*:*:*",
    )


def test_ocaml_binding_cve_does_not_match_postgresql_server() -> None:
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

    assert not cve_applies_to_cpe(record, POSTGRESQL_18_CPE)


def test_cpe_parser_handles_escaped_separator() -> None:
    parsed = parse_cpe23(r"cpe:2.3:a:vendor:product\:edition:1.0:*:*:*:*:*:*:*")

    assert parsed.product == "product:edition"


def _record_with_match(
    *,
    cve_id: str,
    criteria: str,
    match_criteria_id: str | None = None,
    version_start_including: str | None = None,
    version_end_excluding: str | None = None,
) -> NvdCveRecord:
    match = {
        "vulnerable": True,
        "criteria": criteria,
    }
    if match_criteria_id is not None:
        match["matchCriteriaId"] = match_criteria_id
    if version_start_including is not None:
        match["versionStartIncluding"] = version_start_including
    if version_end_excluding is not None:
        match["versionEndExcluding"] = version_end_excluding

    return NvdCveRecord.from_nvd(
        {
            "cve": {
                "id": cve_id,
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [match],
                            }
                        ]
                    }
                ],
            }
        }
    )
