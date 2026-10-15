from __future__ import annotations

from collections.abc import Iterable

from notline.security.applicability import parse_cpe23
from notline.security.models import NvdCpeName


def select_exact_product_version_cpes(
    candidates: Iterable[NvdCpeName],
    *,
    product_aliases: Iterable[str],
    product_version: str,
) -> list[NvdCpeName]:
    """Keep only active CPEs matching the observed product and version.

    Keyword searches are intentionally treated as discovery hints, not
    identity proof. A candidate must have an exact CPE product alias and an
    exact version before it can be used for security enrichment.
    """

    aliases = {alias.casefold() for alias in product_aliases}
    selected: list[NvdCpeName] = []

    for candidate in candidates:
        if candidate.deprecated:
            continue

        try:
            parsed = parse_cpe23(candidate.cpe_name)
        except ValueError:
            continue

        if parsed.product.casefold() not in aliases:
            continue
        if parsed.version != product_version:
            continue
        selected.append(candidate)

    return selected
