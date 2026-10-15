from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote


@dataclass(frozen=True)
class NpmPackage:
    """One exact runtime package identity from an npm lockfile."""

    name: str
    version: str
    purl: str
    package_path: str
    direct_dependency: bool
    resolved: str | None = None
    integrity: str | None = None


def load_npm_runtime_packages(lockfile_path: Path) -> tuple[NpmPackage, ...]:
    """Read all versioned runtime packages from an npm lockfile v3."""

    try:
        payload = json.loads(lockfile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid npm lockfile: {lockfile_path}") from error

    packages = payload.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise ValueError("npm lockfile must contain a packages root entry")

    root = packages[""]
    if not isinstance(root, dict):
        raise TypeError("npm lockfile root entry must be an object")
    direct_dependencies = root.get("dependencies", {})
    if not isinstance(direct_dependencies, dict):
        raise TypeError("npm lockfile root dependencies must be an object")

    result: list[NpmPackage] = []
    for package_path, metadata in sorted(packages.items()):
        if not package_path or not package_path.startswith("node_modules/"):
            continue
        if not isinstance(metadata, dict):
            continue

        version = metadata.get("version")
        if not isinstance(version, str) or not version:
            continue

        name = _package_name(package_path, metadata)
        result.append(
            NpmPackage(
                name=name,
                version=version,
                purl=_npm_purl(name, version),
                package_path=package_path,
                direct_dependency=(
                    package_path == f"node_modules/{name}"
                    and name in direct_dependencies
                ),
                resolved=_optional_string(metadata, "resolved"),
                integrity=_optional_string(metadata, "integrity"),
            )
        )

    return tuple(result)


def _package_name(package_path: str, metadata: dict[str, Any]) -> str:
    declared_name = metadata.get("name")
    if isinstance(declared_name, str) and declared_name:
        return declared_name
    return package_path.rsplit("node_modules/", maxsplit=1)[-1]


def _npm_purl(name: str, version: str) -> str:
    encoded_name = quote(name, safe="")
    encoded_version = quote(version, safe=".+-")
    return f"pkg:npm/{encoded_name}@{encoded_version}"


def _optional_string(metadata: dict[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) else None
