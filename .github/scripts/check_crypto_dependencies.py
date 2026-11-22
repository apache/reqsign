# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Reject direct cryptographic implementation dependencies outside crypto/*.

The check walks every manifest so it sees declarations that Cargo metadata
would omit, including unused workspace entries, standalone workspace
inheritance, renamed packages, target-specific tables, and both Cargo
dependency table spellings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import tomllib

FORBIDDEN_PACKAGES = frozenset(
    {
        "sha1",
        "sha2",
        "hmac",
        "rsa",
        "p256",
        "aes-gcm",
        "md-5",
        "getrandom",
        "boring",
        "openssl",
        "ring",
        "aws-lc-rs",
    }
)
SKIPPED_DIRECTORIES = frozenset({"target", ".git"})
# Cargo 1.87 accepts both hyphenated and underscored table names.
DEPENDENCY_TABLES = (
    "dependencies",
    "dev-dependencies",
    "dev_dependencies",
    "build-dependencies",
    "build_dependencies",
)


@dataclass(frozen=True)
class Violation:
    manifest: str
    table: str
    key: str
    package: str

    def __str__(self) -> str:
        return (
            f"{self.manifest}: [{self.table}] {self.key} resolves to "
            f"cryptographic implementation crate {self.package!r}"
        )


def dependency_package(
    key: str,
    value: object,
    workspace_packages: dict[str, str],
) -> str:
    if isinstance(value, str):
        return key
    if isinstance(value, dict):
        if value.get("workspace") is True:
            return workspace_packages.get(key, key)
        package = value.get("package")
        if isinstance(package, str):
            return package
    return key


def dependency_tables(manifest: dict[str, object]) -> list[tuple[str, object]]:
    paths: list[tuple[str, object]] = []
    for table in DEPENDENCY_TABLES:
        if table in manifest:
            paths.append((table, manifest[table]))
    target = manifest.get("target")
    if isinstance(target, dict):
        for target_name, target_table in target.items():
            if not isinstance(target_table, dict):
                continue
            for table in DEPENDENCY_TABLES:
                if table in target_table:
                    paths.append((f"target.{target_name}.{table}", target_table[table]))
    return paths


def workspace_dependencies(manifest: dict[str, object]) -> dict[str, object]:
    workspace = manifest.get("workspace")
    if not isinstance(workspace, dict):
        return {}
    dependencies = workspace.get("dependencies", {})
    return dependencies if isinstance(dependencies, dict) else {}


def parse_manifests(root: Path) -> dict[Path, tuple[Path, dict[str, object]]]:
    manifests = {}
    for manifest_path in sorted(root.rglob("Cargo.toml")):
        relative = manifest_path.relative_to(root)
        if any(part in SKIPPED_DIRECTORIES for part in relative.parts):
            continue
        with manifest_path.open("rb") as file:
            manifests[manifest_path] = (relative, tomllib.load(file))
    return manifests


def owning_workspace(
    manifest_path: Path,
    root: Path,
    manifests: dict[Path, tuple[Path, dict[str, object]]],
) -> Path | None:
    directory = manifest_path.parent
    while True:
        candidate = directory / "Cargo.toml"
        if candidate in manifests and isinstance(manifests[candidate][1].get("workspace"), dict):
            return candidate
        if directory == root:
            return None
        directory = directory.parent


def check_repository(root: Path) -> list[Violation]:
    root = root.resolve()
    manifests = parse_manifests(root)
    workspace_packages = {
        path: {
            key: dependency_package(key, value, {})
            for key, value in workspace_dependencies(manifest).items()
        }
        for path, (_, manifest) in manifests.items()
        if isinstance(manifest.get("workspace"), dict)
    }
    violations: list[Violation] = []

    for manifest_path, (relative, manifest) in manifests.items():
        if relative.parts[0] == "crypto":
            continue
        workspace_path = owning_workspace(manifest_path, root, manifests)
        inherited_packages = workspace_packages.get(workspace_path, {})

        for key, value in workspace_dependencies(manifest).items():
            package = dependency_package(key, value, {})
            if package in FORBIDDEN_PACKAGES:
                violations.append(
                    Violation(relative.as_posix(), "workspace.dependencies", key, package)
                )

        for table, dependencies in dependency_tables(manifest):
            if not isinstance(dependencies, dict):
                continue
            for key, value in dependencies.items():
                package = dependency_package(key, value, inherited_packages)
                if package in FORBIDDEN_PACKAGES:
                    violations.append(
                        Violation(relative.as_posix(), table, key, package)
                    )

    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    violations = check_repository(root)
    if not violations:
        print("crypto dependency boundary is clean")
        return 0
    for violation in violations:
        print(violation, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
