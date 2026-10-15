from notline.security.cpe_resolution import select_exact_product_version_cpes
from notline.security.models import NvdCpeName


def test_keyword_candidates_must_match_product_and_version() -> None:
    selected = select_exact_product_version_cpes(
        [
            _cpe("cpe:2.3:a:auth0:express-jwt:5.3.0:*:*:*:*:node.js:*:*"),
            _cpe("cpe:2.3:a:express:express:5.2.0:*:*:*:*:node.js:*:*"),
            _cpe("cpe:2.3:a:express:express:5.3.0:*:*:*:*:node.js:*:*"),
        ],
        product_aliases=("express",),
        product_version="5.3.0",
    )

    assert [candidate.cpe_name for candidate in selected] == [
        "cpe:2.3:a:express:express:5.3.0:*:*:*:*:node.js:*:*"
    ]


def test_deprecated_and_malformed_candidates_are_rejected() -> None:
    selected = select_exact_product_version_cpes(
        [
            _cpe(
                "cpe:2.3:a:express:express:5.3.0:*:*:*:*:node.js:*:*",
                deprecated=True,
            ),
            _cpe("not-a-cpe"),
        ],
        product_aliases=("express",),
        product_version="5.3.0",
    )

    assert selected == []


def _cpe(name: str, *, deprecated: bool = False) -> NvdCpeName:
    return NvdCpeName(
        cpe_name_id=f"id:{name}",
        cpe_name=name,
        deprecated=deprecated,
    )
