from pathlib import Path

import pytest

from notline.network_profile import (
    LAB_PROFILE,
    get_configured_network_profile,
    get_network_profile,
)


def test_lab_profile_contains_all_network_specific_inputs() -> None:
    assert get_network_profile("notline-lab") is LAB_PROFILE
    assert len(LAB_PROFILE.inventory_assets) == 7
    assert [source.probe for source in LAB_PROFILE.connection_logs] == [
        "probe1",
        "probe2",
    ]
    assert all(isinstance(source.path, Path) for source in LAB_PROFILE.dhcp_logs)
    assert len(LAB_PROFILE.verified_security_targets) == 4
    assert len(LAB_PROFILE.unresolved_security_targets) == 0
    assert len(LAB_PROFILE.software_components) == 3
    assert len(LAB_PROFILE.npm_package_lockfiles) == 1
    assert LAB_PROFILE.npm_package_lockfiles[0].asset_id == "app1"
    assert LAB_PROFILE.npm_package_lockfiles[0].path.name == "package-lock.json"


def test_unknown_profile_names_fail_with_available_profiles() -> None:
    with pytest.raises(ValueError, match="notline-lab"):
        get_network_profile("other-network")


def test_profile_can_be_selected_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTLINE_NETWORK_PROFILE", "notline-lab")

    assert get_configured_network_profile() is LAB_PROFILE


def test_profile_can_override_dhcp_activity_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTLINE_NETWORK_PROFILE", "notline-lab")
    monkeypatch.setenv("NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS", "120")

    profile = get_configured_network_profile()

    assert profile.dhcp_activity_window_seconds == 120.0
