from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SoftwareComponentTarget:
    """Verified software evidence attached to an inventoried asset."""

    asset_id: str
    component_id: str
    product_name: str
    product_version: str
    component_type: str
    evidence_source: str
    cpe_keyword: str
    cpe_product_aliases: tuple[str, ...] = ()
    expected_cpe_name: str | None = None
    cpe_match_string: str | None = None
    package_name: str | None = None


# Runtime versions are pinned in app1/Dockerfile so their security identities
# remain reproducible across lab deployments.
APP_COMPONENT_TARGETS = (
    SoftwareComponentTarget(
        asset_id="app1",
        component_id="component:app1|nodejs",
        product_name="Node.js",
        product_version="22.22.3",
        component_type="runtime",
        evidence_source="app1_runtime_version",
        cpe_keyword="Node.js 22.22.3",
        cpe_product_aliases=("node.js", "nodejs"),
        expected_cpe_name=("cpe:2.3:a:nodejs:node.js:22.22.3:*:*:*:-:*:*:*"),
        cpe_match_string="cpe:2.3:a:nodejs:node.js:22.22.3",
    ),
    SoftwareComponentTarget(
        asset_id="app1",
        component_id="component:app1|express",
        product_name="Express",
        product_version="5.2.1",
        component_type="framework",
        evidence_source="app1_runtime_version",
        cpe_keyword="Express 5.2.1",
        cpe_product_aliases=("express",),
        package_name="express",
    ),
    SoftwareComponentTarget(
        asset_id="app1",
        component_id="component:app1|node-postgres",
        product_name="node-postgres",
        product_version="8.23.1",
        component_type="library",
        evidence_source="app1_runtime_version",
        cpe_keyword="node-postgres 8.23.1",
        cpe_product_aliases=("node_postgres", "node-postgres", "pg"),
        package_name="pg",
    ),
)
