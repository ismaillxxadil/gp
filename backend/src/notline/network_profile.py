from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

from notline.discovery.inventory import STATIC_ASSETS, InventoryAsset
from notline.security.components import (
    APP_COMPONENT_TARGETS,
    SoftwareComponentTarget,
)
from notline.security.enrichment import (
    UNRESOLVED_SECURITY_TARGETS,
    VERIFIED_SECURITY_TARGETS,
    SecurityTarget,
)


@dataclass(frozen=True)
class ZeekLogSource:
    """One probe log consumed by the passive discovery importer."""

    probe: str
    path: Path


@dataclass(frozen=True)
class NpmPackageInventorySource:
    """One npm lockfile containing exact runtime package identities."""

    asset_id: str
    path: Path


@dataclass(frozen=True)
class NetworkProfile:
    """Network-specific inputs consumed by the reusable NOTLINE pipeline."""

    name: str
    inventory_assets: tuple[InventoryAsset, ...]
    connection_logs: tuple[ZeekLogSource, ...]
    dhcp_logs: tuple[ZeekLogSource, ...]
    verified_security_targets: tuple[SecurityTarget, ...]
    unresolved_security_targets: tuple[SecurityTarget, ...]
    software_components: tuple[SoftwareComponentTarget, ...]
    npm_package_lockfiles: tuple[NpmPackageInventorySource, ...]
    dhcp_activity_window_seconds: float = 900.0


LAB_PROFILE = NetworkProfile(
    name="notline-lab",
    inventory_assets=STATIC_ASSETS,
    connection_logs=(
        ZeekLogSource("probe1", Path("probe-logs/conn.log")),
        ZeekLogSource("probe2", Path("probe2-logs/conn.log")),
    ),
    dhcp_logs=(
        ZeekLogSource("probe1", Path("probe-logs/dhcp.log")),
        ZeekLogSource("probe2", Path("probe2-logs/dhcp.log")),
    ),
    verified_security_targets=VERIFIED_SECURITY_TARGETS,
    unresolved_security_targets=UNRESOLVED_SECURITY_TARGETS,
    software_components=APP_COMPONENT_TARGETS,
    npm_package_lockfiles=(
        NpmPackageInventorySource("app1", Path("app1/package-lock.json")),
    ),
)

PROFILES = {LAB_PROFILE.name: LAB_PROFILE}


def get_network_profile(name: str = LAB_PROFILE.name) -> NetworkProfile:
    """Return a configured profile by name."""

    try:
        return PROFILES[name]
    except KeyError as error:
        available = ", ".join(sorted(PROFILES))
        raise ValueError(
            f"Unknown network profile {name!r}; available profiles: {available}"
        ) from error


def get_configured_network_profile() -> NetworkProfile:
    """Select a profile from the environment, defaulting to the lab profile."""

    profile = get_network_profile(
        os.getenv("NOTLINE_NETWORK_PROFILE", LAB_PROFILE.name)
    )
    raw_window = os.getenv("NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS")
    if raw_window is None:
        return profile

    try:
        window = float(raw_window)
    except ValueError as error:
        raise ValueError(
            "NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS must be a number"
        ) from error
    if window < 0:
        raise ValueError("NOTLINE_DHCP_ACTIVITY_WINDOW_SECONDS cannot be negative")
    return replace(profile, dhcp_activity_window_seconds=window)
