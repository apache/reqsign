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

import tempfile
import unittest
from pathlib import Path

from plan import PROJECT_DIR
from plan import Package
from plan import plan
from plan import plan_from_metadata


def package(
    root: Path,
    name: str,
    *,
    dependencies: list[dict[str, object]] | None = None,
    publish: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": f"path+file://{root / name}#{name}@1.0.0",
        "name": name,
        "version": "1.0.0",
        "manifest_path": str(root / name / "Cargo.toml"),
        "publish": publish,
        "dependencies": dependencies or [],
    }


def dependency(root: Path, name: str, *, kind: str | None = None):
    return {
        "name": name,
        "kind": kind,
        "path": str(root / name),
    }


class ReleaseRustPlanTest(unittest.TestCase):
    def test_plan_is_topological_and_ignores_dev_dependencies(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            core = package(root, "core")
            service = package(
                root,
                "service",
                dependencies=[dependency(root, "core")],
            )
            facade = package(
                root,
                "facade",
                dependencies=[
                    dependency(root, "service"),
                    dependency(root, "dev-only", kind="dev"),
                ],
            )
            dev_only = package(root, "dev-only")
            packages = [facade, service, dev_only, core]
            metadata = {
                "packages": packages,
                "workspace_members": [package["id"] for package in packages],
            }

            result = plan_from_metadata(metadata, root)

        positions = {package.name: index for index, package in enumerate(result)}
        self.assertEqual(set(positions), {"core", "dev-only", "service", "facade"})
        self.assertLess(positions["core"], positions["service"])
        self.assertLess(positions["service"], positions["facade"])

    def test_unpublishable_workspace_dependency_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            internal = package(root, "internal", publish=[])
            public = package(
                root,
                "public",
                dependencies=[dependency(root, "internal")],
            )
            packages = [internal, public]
            metadata = {
                "packages": packages,
                "workspace_members": [package["id"] for package in packages],
            }

            with self.assertRaisesRegex(AssertionError, "unpublished workspace package"):
                plan_from_metadata(metadata, root)

if __name__ == "__main__":
    unittest.main()
