from notline.security.components import APP_COMPONENT_TARGETS


def test_app_components_have_stable_ids_and_runtime_evidence() -> None:
    assert [target.component_id for target in APP_COMPONENT_TARGETS] == [
        "component:app1|nodejs",
        "component:app1|express",
        "component:app1|node-postgres",
    ]
    assert all(target.asset_id == "app1" for target in APP_COMPONENT_TARGETS)
    assert all(
        target.evidence_source == "app1_runtime_version"
        for target in APP_COMPONENT_TARGETS
    )
