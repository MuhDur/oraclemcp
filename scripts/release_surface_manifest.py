#!/usr/bin/env python3
"""Validate declarative release surfaces and machine-readable release facts.

The manifest deliberately covers only current-state release claims. Historical
release records are evidence, not generated surfaces, and must remain intact.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)


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


def read_json(path: str) -> dict[str, Any]:
    if path == "-":
        document = json.load(sys.stdin)
    else:
        with Path(path).open(encoding="utf-8") as stream:
            document = json.load(stream)
    if not isinstance(document, dict):
        raise SurfaceError("JSON document must be an object")
    return document


def workspace_publish_order(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    packages = metadata.get("packages")
    members = metadata.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(members, list) or not members:
        raise SurfaceError("cargo metadata has no workspace packages")

    packages_by_id: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise SurfaceError("cargo metadata contains a malformed package")
        if package["id"] in packages_by_id:
            raise SurfaceError(f"cargo metadata repeats package id {package['id']!r}")
        packages_by_id[package["id"]] = package

    try:
        workspace = [packages_by_id[member] for member in members]
    except KeyError as error:
        raise SurfaceError(f"workspace member is missing from cargo metadata: {error.args[0]}") from error

    names: set[str] = set()
    directories: dict[Path, str] = {}
    for package in workspace:
        name = package.get("name")
        manifest_path = package.get("manifest_path")
        if not isinstance(name, str) or not isinstance(manifest_path, str):
            raise SurfaceError("workspace package is missing name or manifest_path")
        if name in names:
            raise SurfaceError(f"workspace package name is not unique: {name}")
        names.add(name)
        directories[Path(manifest_path).parent.resolve()] = name

    def publishes_to_crates_io(package: dict[str, Any]) -> bool:
        registries = package.get("publish")
        if registries is None:
            return True
        if not isinstance(registries, list) or not all(isinstance(item, str) for item in registries):
            raise SurfaceError(f"{package['name']} has malformed cargo metadata publish policy")
        return "crates-io" in registries

    publishable = [package for package in workspace if publishes_to_crates_io(package)]
    if not publishable:
        raise SurfaceError("cargo metadata has no crates.io-publishable workspace packages")
    publishable_names = {package["name"] for package in publishable}
    dependencies: dict[str, set[str]] = {package["name"]: set() for package in publishable}

    for package in publishable:
        raw_dependencies = package.get("dependencies", [])
        if not isinstance(raw_dependencies, list):
            raise SurfaceError(f"{package['name']} has malformed dependency metadata")
        for dependency in raw_dependencies:
            if not isinstance(dependency, dict):
                raise SurfaceError(f"{package['name']} has malformed dependency metadata")
            dependency_path = dependency.get("path")
            if dependency_path is None:
                continue
            if not isinstance(dependency_path, str):
                raise SurfaceError(f"{package['name']} has a malformed path dependency")
            dependency_name = directories.get(Path(dependency_path).resolve())
            if dependency_name is None or dependency_name == package["name"]:
                continue
            if dependency_name not in publishable_names:
                raise SurfaceError(
                    f"publishable package {package['name']} depends on non-publishable workspace package "
                    f"{dependency_name}"
                )
            dependencies[package["name"]].add(dependency_name)

    ordered: list[dict[str, Any]] = []
    emitted: set[str] = set()
    while len(ordered) < len(publishable):
        ready = [
            package
            for package in publishable
            if package["name"] not in emitted
            and dependencies[package["name"]].issubset(emitted)
        ]
        if not ready:
            blocked = ", ".join(
                f"{name}<-{','.join(sorted(required - emitted))}"
                for name, required in dependencies.items()
                if name not in emitted
            )
            raise SurfaceError(f"workspace publish dependency cycle or unresolved edge: {blocked}")
        package = ready[0]
        ordered.append(package)
        emitted.add(package["name"])
    return ordered


def validate_registry_response(
    document: dict[str, Any], expected_crate: str, expected_version: str
) -> None:
    version = document.get("version")
    if not isinstance(version, dict):
        raise SurfaceError("crates.io response is missing a version object")
    actual_crate = version.get("crate")
    if actual_crate != expected_crate:
        raise SurfaceError(
            f"crates.io response crate {actual_crate!r} does not match {expected_crate!r}"
        )
    actual_version = version.get("num")
    if actual_version != expected_version:
        raise SurfaceError(
            f"crates.io response version {actual_version!r} does not match {expected_version!r}"
        )
    if version.get("yanked") is not False:
        raise SurfaceError(
            f"crates.io response for {expected_crate} {expected_version} is yanked or lacks yanked=false"
        )


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
    mode.add_argument("--value", metavar="NAME", help="print one canonical manifest value")
    mode.add_argument(
        "--publish-order",
        metavar="METADATA_JSON",
        help="print crates.io-publishable workspace packages in dependency order; use - for stdin",
    )
    mode.add_argument(
        "--validate-registry-response",
        metavar="RESPONSE_JSON",
        help="validate one crates.io exact-version response; use - for stdin",
    )
    parser.add_argument("--crate", help="expected crate for --validate-registry-response")
    parser.add_argument("--expected-version", help="expected version for --validate-registry-response")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        if arguments.publish_order:
            for package in workspace_publish_order(read_json(arguments.publish_order)):
                version = package.get("version")
                if not isinstance(version, str) or not version:
                    raise SurfaceError(f"{package['name']} has no package version")
                print(f"{package['name']}\t{version}")
            return 0
        if arguments.validate_registry_response:
            if not arguments.crate or not arguments.expected_version:
                raise SurfaceError(
                    "--validate-registry-response requires --crate and --expected-version"
                )
            validate_registry_response(
                read_json(arguments.validate_registry_response),
                arguments.crate,
                arguments.expected_version,
            )
            return 0

        manifest = read_toml(root, "release-surfaces.toml")
        if manifest.get("manifest", {}).get("version") != 1:
            raise SurfaceError("unsupported manifest version")
        values = canonical_values(root, manifest)
        if arguments.value:
            if arguments.value not in values:
                raise SurfaceError(f"unknown canonical value: {arguments.value}")
            print(values[arguments.value])
            return 0
        for entry in manifest.get("surface", []):
            check_or_write_surface(root, entry, values, arguments.write)
        check_relationships(root, manifest, values)
        check_numeric_scans(root, manifest, values)
        check_non_locksteps(manifest)
    except (json.JSONDecodeError, OSError, tomllib.TOMLDecodeError, SurfaceError) as error:
        print(f"release-surface-manifest: {error}", file=sys.stderr)
        return 1

    print(
        "release-surface-manifest: OK "
        f"(server={values['server_version']}, driver={values['driver_version']}, runtime={values['runtime_version']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
