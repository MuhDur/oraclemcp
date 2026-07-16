#!/usr/bin/env python3
"""Generate or check the declarative current-release version surfaces.

The manifest deliberately covers only current-state release claims. Historical
release records are evidence, not generated surfaces, and must remain intact.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class SurfaceError(RuntimeError):
    """A release surface disagrees with the declared canonical source."""


def get_key(document: dict[str, Any], dotted_key: str) -> str:
    value: Any = document
    for component in dotted_key.split("."):
        if not isinstance(value, dict) or component not in value:
            raise SurfaceError(f"missing TOML key {dotted_key}")
        value = value[component]
    if not isinstance(value, str):
        raise SurfaceError(f"TOML key {dotted_key} is not a string")
    return value


def read_toml(root: Path, relative_path: str) -> dict[str, Any]:
    try:
        return tomllib.loads((root / relative_path).read_text())
    except FileNotFoundError as error:
        raise SurfaceError(f"missing {relative_path}") from error


def canonical_values(root: Path, manifest: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for entry in manifest.get("canonical", []):
        value = get_key(read_toml(root, entry["path"]), entry["toml_key"])
        prefix = entry.get("strip_prefix", "")
        if prefix:
            if not value.startswith(prefix):
                raise SurfaceError(
                    f"{entry['name']} at {entry['path']} must start with {prefix!r}"
                )
            value = value.removeprefix(prefix)
        if not SEMVER.fullmatch(value):
            raise SurfaceError(f"{entry['name']} is not a semantic version: {value!r}")
        values[entry["name"]] = value
    return values


def check_or_write_surface(
    root: Path, entry: dict[str, Any], values: dict[str, str], write: bool
) -> None:
    path = root / entry["path"]
    original = path.read_text()
    pattern = re.compile(entry["pattern"], re.MULTILINE)
    matches = list(pattern.finditer(original))
    expected_count = entry.get("match_count", 1)
    if len(matches) != expected_count:
        raise SurfaceError(
            f"{entry['name']} expected {expected_count} matching field(s) in {entry['path']}, "
            f"found {len(matches)}"
        )
    replacement = entry["replacement"].format(**values)
    rendered = pattern.sub(replacement, original)
    if write:
        if rendered != original:
            path.write_text(rendered)
        return
    if rendered != original:
        raise SurfaceError(
            f"{entry['name']} in {entry['path']} drifts from {entry['source']} "
            f"({values[entry['source']]})"
        )


def check_relationships(root: Path, manifest: dict[str, Any], values: dict[str, str]) -> None:
    for entry in manifest.get("relationship", []):
        kind = entry["kind"]
        if kind == "toml_workspace_version":
            for relative_path in entry["paths"]:
                package = read_toml(root, relative_path).get("package", {})
                if package.get("version", {}).get("workspace") is not True:
                    raise SurfaceError(
                        f"{entry['name']}: {relative_path} must inherit package.version from the workspace"
                    )
        elif kind == "toml_dependency_versions":
            dependencies = read_toml(root, entry["path"]).get("dependencies", {})
            expected = values[entry["source"]]
            for dependency in entry["dependencies"]:
                actual = dependencies.get(dependency, {}).get("version")
                if actual != expected:
                    raise SurfaceError(
                        f"{entry['name']}: {entry['path']} {dependency} version {actual!r} != {expected!r}"
                    )
        elif kind == "lock_package_versions":
            packages = read_toml(root, entry["path"]).get("package", [])
            expected = values[entry["source"]]
            for package_name in entry["packages"]:
                versions = {p["version"] for p in packages if p.get("name") == package_name}
                if versions != {expected}:
                    raise SurfaceError(
                        f"{entry['name']}: {package_name} versions {sorted(versions)} != {[expected]}"
                    )
        else:
            raise SurfaceError(f"unknown relationship kind: {kind}")


def check_numeric_scans(root: Path, manifest: dict[str, Any], values: dict[str, str]) -> None:
    for entry in manifest.get("numeric_scan", []):
        allowed = {version.format(**values) for version in entry["allowed_versions"]}
        found = set(SEMVER.findall((root / entry["path"]).read_text()))
        unexpected = sorted(found - allowed)
        if unexpected:
            raise SurfaceError(
                f"{entry['name']}: unlisted numeric release surface(s) in {entry['path']}: "
                + ", ".join(unexpected)
            )


def check_non_locksteps(manifest: dict[str, Any]) -> None:
    for entry in manifest.get("intentional_non_lockstep", []):
        if not entry.get("canonical_path") or not entry.get("independent_from") or not entry.get("rationale"):
            raise SurfaceError(f"intentional non-lockstep entry is incomplete: {entry.get('name', '<unnamed>')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail when a derived surface drifts")
    mode.add_argument("--write", action="store_true", help="regenerate derived version fields")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        manifest = read_toml(root, "release-surfaces.toml")
        if manifest.get("manifest", {}).get("version") != 1:
            raise SurfaceError("unsupported manifest version")
        values = canonical_values(root, manifest)
        for entry in manifest.get("surface", []):
            check_or_write_surface(root, entry, values, arguments.write)
        check_relationships(root, manifest, values)
        check_numeric_scans(root, manifest, values)
        check_non_locksteps(manifest)
    except (OSError, tomllib.TOMLDecodeError, SurfaceError) as error:
        print(f"release-surface-manifest: {error}", file=sys.stderr)
        return 1

    print(
        "release-surface-manifest: OK "
        f"(server={values['server_version']}, driver={values['driver_version']}, runtime={values['runtime_version']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
