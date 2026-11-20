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
would omit, including unused workspace entries, renamed packages, target
specific tables, and build/dev dependency kinds.
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
        "getrandom",
        "boring",
        "openssl",
        "ring",
        "aws-lc-rs",
    }
)
SKIPPED_DIRECTORIES = frozenset({"target", ".git"})
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


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
        package = value.get("package")
        if isinstance(package, str):
            return package
        if value.get("workspace") is True:
            return workspace_packages.get(key, key)
    return key


def table_paths(manifest: dict[str, object]) -> list[tuple[str, object]]:
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


def collect_workspace_packages(root: Path) -> tuple[dict[str, str], dict[str, object]]:
    manifest_path = root / "Cargo.toml"
    if not manifest_path.is_file():
        return {}, {}
    with manifest_path.open("rb") as file:
        manifest = tomllib.load(file)
    workspace = manifest.get("workspace")
    dependencies = workspace.get("dependencies", {}) if isinstance(workspace, dict) else {}
    if not isinstance(dependencies, dict):
        dependencies = {}
    packages = {
        key: dependency_package(key, value, {})
        for key, value in dependencies.items()
    }
    return packages, dependencies


def check_repository(root: Path) -> list[Violation]:
    workspace_packages, workspace_dependencies = collect_workspace_packages(root)
    violations: list[Violation] = []

    if workspace_dependencies:
        for key, value in workspace_dependencies.items():
            package = dependency_package(key, value, workspace_packages)
            if package in FORBIDDEN_PACKAGES:
                violations.append(
                    Violation("Cargo.toml", "workspace.dependencies", key, package)
                )

    for manifest_path in sorted(root.rglob("Cargo.toml")):
        relative = manifest_path.relative_to(root)
        if any(part in SKIPPED_DIRECTORIES for part in relative.parts):
            continue
        if relative.parts[0] == "crypto":
            continue
        with manifest_path.open("rb") as file:
            manifest = tomllib.load(file)
        for table, dependencies in table_paths(manifest):
            if not isinstance(dependencies, dict):
                continue
            for key, value in dependencies.items():
                package = dependency_package(key, value, workspace_packages)
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
