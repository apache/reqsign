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

import json
import subprocess
from dataclasses import asdict, dataclass
from graphlib import TopologicalSorter
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[3]

# Publish-plan entries that are not root workspace members. Keep this list
# explicit: a directory excluded from the workspace is not published merely
# because a package exists there. The release publisher addresses every
# standalone manifest by path because `cargo publish --workspace` never sees
# it.
STANDALONE_MANIFESTS = ("crypto/boring/Cargo.toml",)


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    # Manifest path relative to PROJECT_DIR for standalone packages. Workspace
    # members use None and are selected by package name.
    manifest: str | None = None


def cargo_metadata(manifest: Path | None = None) -> dict:
    """Read one metadata document without recursive dependency output."""
    command = ["cargo", "metadata", "--no-deps", "--format-version", "1"]
    if manifest is not None:
        command += ["--manifest-path", str(manifest)]
    return json.loads(subprocess.check_output(command, cwd=PROJECT_DIR, text=True))


def local_packages() -> dict[Path, dict]:
    """Map each local package directory in the release scope to its metadata.

    A standalone manifest is its own workspace, so it needs a separate metadata
    call. Its package directory is the manifest's directory.
    """
    metadata = cargo_metadata()
    local = {
        Path(package["manifest_path"]).parent: package
        for package in metadata["packages"]
    }
    for manifest in STANDALONE_MANIFESTS:
        manifest_path = PROJECT_DIR / manifest
        packages = cargo_metadata(manifest_path)["packages"]
        assert len(packages) == 1, (
            f"{manifest} must contain exactly one package, found {len(packages)}"
        )
        package = packages[0]
        path = Path(package["manifest_path"]).parent
        assert path == manifest_path.parent, (
            f"{manifest} resolved to unexpected manifest {package['manifest_path']}"
        )
        assert path not in local, f"{manifest} is already a workspace member"
        local[path] = package
    return local


def _publishable(package: dict) -> bool:
    return package["publish"] is None or "crates-io" in package["publish"]


def plan() -> list[Package]:
    local = local_packages()
    packages = {
        path: package for path, package in local.items() if _publishable(package)
    }
    standalone = {(PROJECT_DIR / manifest).parent for manifest in STANDALONE_MANIFESTS}
    graph = {}
    for path, package in packages.items():
        dependencies = set()
        for dependency in package["dependencies"]:
            # Workspace members are staged and published as one set, and their
            # dev-only edges can form cycles. A standalone manifest is packaged
            # on its own, and packaging resolves every local path dependency,
            # including dev-dependencies, so those crates must publish first.
            if dependency["kind"] == "dev" and path not in standalone:
                continue
            if "path" not in dependency:
                continue
            dependency_path = Path(dependency["path"])
            if dependency_path in local:
                assert dependency_path in packages, (
                    f"{package['name']} depends on unpublished local package "
                    f"{local[dependency_path]['name']}"
                )
                dependencies.add(dependency_path)
        graph[path] = dependencies
    return [
        Package(
            packages[path]["name"],
            packages[path]["version"],
            manifest=(
                str(Path(packages[path]["manifest_path"]).relative_to(PROJECT_DIR))
                if path in standalone
                else None
            ),
        )
        for path in TopologicalSorter(graph).static_order()
    ]


if __name__ == "__main__":
    print(json.dumps([asdict(package) for package in plan()], indent=2))
