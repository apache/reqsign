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


@dataclass(frozen=True)
class Package:
    name: str
    version: str


def plan() -> list[Package]:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=PROJECT_DIR,
            text=True,
        )
    )
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
        Package(packages[path]["name"], packages[path]["version"])
        for path in TopologicalSorter(graph).static_order()
    ]


if __name__ == "__main__":
    print(json.dumps([asdict(package) for package in plan()], indent=2))
