#!/usr/bin/env python3
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

from graphlib import TopologicalSorter
import json
import subprocess
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve()
PROJECT_DIR = SCRIPT_PATH.parents[3]


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    path: str


def load_metadata(project_dir: Path = PROJECT_DIR) -> dict[str, object]:
    return json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=project_dir, text=True,
    ))


def plan_from_metadata(metadata: dict[str, object], project_dir: Path) -> list[Package]:
    # --no-deps returns workspace members; Cargo validates their identities.
    local = {
        Path(package["manifest_path"]).parent: package
        for package in metadata["packages"]
    }
    packages = {
        path: package
        for path, package in local.items()
        if package["publish"] is None or "crates-io" in package["publish"]
    }
    graph = {}
    for path, package in packages.items():
        dependencies = set()
        for dependency in package["dependencies"]:
            if dependency["kind"] == "dev" or "path" not in dependency:
                continue
            dependency_path = Path(dependency["path"])
            if dependency_path in local:
                assert dependency_path in packages, (
                    f"{package['name']} depends on unpublished workspace package "
                    f"{local[dependency_path]['name']}"
                )
                dependencies.add(dependency_path)
        graph[path] = dependencies
    return [
        Package(packages[path]["name"], packages[path]["version"], path.relative_to(project_dir).as_posix())
        for path in TopologicalSorter(graph).static_order()
    ]


def plan(project_dir: Path = PROJECT_DIR) -> list[Package]:
    project_dir = project_dir.resolve()
    return plan_from_metadata(load_metadata(project_dir), project_dir)


def main() -> int:
    print(json.dumps([asdict(package) for package in plan()], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
