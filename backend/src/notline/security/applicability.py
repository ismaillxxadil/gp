from __future__ import annotations

import re
from dataclasses import dataclass

from notline.security.models import NvdConfigurationNode, NvdCpeMatch, NvdCveRecord

_CPE_FIELD_NAMES = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_NUMERIC_VERSION = re.compile(r"\d+(?:\.\d+)*")


@dataclass(frozen=True)
class ParsedCpe:
    """The fields of a CPE 2.3 formatted binding."""

    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str


@dataclass(frozen=True)
class _NodeEvaluation:
    condition_matches: bool
    vulnerable_matches: tuple[NvdCpeMatch, ...]


def parse_cpe23(value: str) -> ParsedCpe:
    """Parse a CPE 2.3 formatted binding conservatively."""

    fields = _split_cpe_fields(value)
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        raise ValueError(f"Unsupported CPE 2.3 formatted binding: {value!r}")

    attributes = [_unescape(field) for field in fields[2:]]
    return ParsedCpe(**dict(zip(_CPE_FIELD_NAMES, attributes, strict=True)))


def find_applicable_matches(
    record: NvdCveRecord,
    observed_cpe: str,
) -> list[NvdCpeMatch]:
    """Return vulnerable NVD matches that apply to an observed CPE.

    A non-vulnerable CPE match still participates in the boolean configuration,
    but it is never returned as evidence for a vulnerability relationship.
    """

    parsed_observed_cpe = parse_cpe23(observed_cpe)
    applicable_matches: list[NvdCpeMatch] = []

    for configuration_node in record.configurations:
        evaluation = _evaluate_node(configuration_node, parsed_observed_cpe)
        if evaluation.condition_matches:
            applicable_matches.extend(evaluation.vulnerable_matches)

    return _unique_matches(applicable_matches)


def cve_applies_to_cpe(record: NvdCveRecord, observed_cpe: str) -> bool:
    """Return whether a CVE has at least one vulnerable match for a CPE."""

    return bool(find_applicable_matches(record, observed_cpe))


def _evaluate_node(
    node: NvdConfigurationNode,
    observed_cpe: ParsedCpe,
) -> _NodeEvaluation:
    evaluations = [_evaluate_match(match, observed_cpe) for match in node.matches]
    evaluations.extend(_evaluate_node(child, observed_cpe) for child in node.children)

    if not evaluations:
        return _NodeEvaluation(condition_matches=False, vulnerable_matches=())

    if node.operator == "AND":
        condition_matches = all(
            evaluation.condition_matches for evaluation in evaluations
        )
    else:
        condition_matches = any(
            evaluation.condition_matches for evaluation in evaluations
        )

    if node.negate:
        return _NodeEvaluation(
            condition_matches=not condition_matches, vulnerable_matches=()
        )

    vulnerable_matches = (
        tuple(
            match
            for evaluation in evaluations
            if evaluation.condition_matches
            for match in evaluation.vulnerable_matches
        )
        if condition_matches
        else ()
    )
    return _NodeEvaluation(
        condition_matches=condition_matches,
        vulnerable_matches=vulnerable_matches,
    )


def _evaluate_match(
    match: NvdCpeMatch,
    observed_cpe: ParsedCpe,
) -> _NodeEvaluation:
    condition_matches = _match_fields(match, observed_cpe)
    vulnerable_matches = (match,) if condition_matches and match.vulnerable else ()
    return _NodeEvaluation(
        condition_matches=condition_matches,
        vulnerable_matches=vulnerable_matches,
    )


def _match_fields(match: NvdCpeMatch, observed_cpe: ParsedCpe) -> bool:
    try:
        criteria = parse_cpe23(match.criteria)
    except ValueError:
        return False

    for field_name in _CPE_FIELD_NAMES:
        if field_name == "version":
            continue
        if not _field_matches(
            getattr(criteria, field_name),
            getattr(observed_cpe, field_name),
        ):
            return False

    return _version_matches(criteria.version, match, observed_cpe.version)


def _version_matches(
    criteria_version: str,
    match: NvdCpeMatch,
    observed_version: str,
) -> bool:
    if criteria_version not in ("*", "-"):
        return _compare_versions(criteria_version, observed_version) == 0

    if criteria_version == "-" and observed_version != "-":
        return False

    lower_bounds = (
        (match.version_start_including, True),
        (match.version_start_excluding, False),
    )
    for bound, inclusive in lower_bounds:
        if bound is None:
            continue
        comparison = _compare_versions(observed_version, bound)
        if comparison is None:
            return False
        if comparison < 0 or (not inclusive and comparison == 0):
            return False

    upper_bounds = (
        (match.version_end_including, True),
        (match.version_end_excluding, False),
    )
    for bound, inclusive in upper_bounds:
        if bound is None:
            continue
        comparison = _compare_versions(observed_version, bound)
        if comparison is None:
            return False
        if comparison > 0 or (not inclusive and comparison == 0):
            return False

    return True


def _compare_versions(left: str, right: str) -> int | None:
    if not _NUMERIC_VERSION.fullmatch(left) or not _NUMERIC_VERSION.fullmatch(right):
        return None

    left_parts = _trim_zeroes(tuple(int(part) for part in left.split(".")))
    right_parts = _trim_zeroes(tuple(int(part) for part in right.split(".")))
    return (left_parts > right_parts) - (left_parts < right_parts)


def _trim_zeroes(parts: tuple[int, ...]) -> tuple[int, ...]:
    trimmed = parts
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed = trimmed[:-1]
    return trimmed


def _field_matches(criteria: str, observed: str) -> bool:
    if criteria == "*":
        return True
    if criteria == "-":
        return observed == "-"
    return criteria.casefold() == observed.casefold()


def _split_cpe_fields(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False

    for character in value:
        if character == ":" and not escaped:
            fields.append("".join(current))
            current = []
            continue

        current.append(character)
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False

    fields.append("".join(current))
    return fields


def _unescape(value: str) -> str:
    unescaped: list[str] = []
    escaped = False

    for character in value:
        if escaped:
            unescaped.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            unescaped.append(character)

    if escaped:
        unescaped.append("\\")
    return "".join(unescaped)


def _unique_matches(matches: list[NvdCpeMatch]) -> list[NvdCpeMatch]:
    unique: list[NvdCpeMatch] = []
    seen: set[tuple[str, str | None]] = set()

    for match in matches:
        key = (match.criteria, match.match_criteria_id)
        if key not in seen:
            seen.add(key)
            unique.append(match)

    return unique
