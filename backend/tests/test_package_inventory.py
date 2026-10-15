import json

from notline.security.package_inventory import load_npm_runtime_packages


def test_load_npm_runtime_packages_keeps_exact_direct_and_transitive_identities(
    tmp_path,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"express": "^5.2.1"}},
                    "node_modules/express": {
                        "version": "5.2.1",
                        "resolved": "https://registry.npmjs.org/express/-/express-5.2.1.tgz",
                        "integrity": "sha512-express",
                    },
                    "node_modules/express/node_modules/content-type": {
                        "version": "2.1.0"
                    },
                    "node_modules/@example/client": {"version": "1.4.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    packages = load_npm_runtime_packages(lockfile)

    assert {(package.name, package.version) for package in packages} == {
        ("@example/client", "1.4.0"),
        ("content-type", "2.1.0"),
        ("express", "5.2.1"),
    }
    express = next(package for package in packages if package.name == "express")
    assert express.direct_dependency is True
    assert express.purl == "pkg:npm/express@5.2.1"
    assert express.integrity == "sha512-express"

    transitive = next(package for package in packages if package.version == "2.1.0")
    assert transitive.direct_dependency is False
    assert transitive.package_path == "node_modules/express/node_modules/content-type"


def test_load_npm_runtime_packages_rejects_missing_packages_root(tmp_path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")

    try:
        load_npm_runtime_packages(lockfile)
    except ValueError as error:
        assert "packages root entry" in str(error)
    else:
        raise AssertionError("expected invalid lockfile to be rejected")
