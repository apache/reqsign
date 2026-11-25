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
import shutil
import unittest
from unittest import mock

from plan import PROJECT_DIR, plan


def package(name, *, dependencies=(), publish=None, manifest_path=None):
    return {
        "name": name,
        "version": "1.0.0",
        "publish": publish,
        "manifest_path": manifest_path or f"/workspace/{name}/Cargo.toml",
        "dependencies": list(dependencies),
    }


def dependency(name, kind=None, *, path=None):
    return {"path": path or f"/workspace/{name}", "kind": kind}


def metadata_for(workspace, standalone=None):
    standalone = standalone or {}

    def check_output(command, cwd, text):
        if "--manifest-path" in command:
            manifest = command[command.index("--manifest-path") + 1]
            return json.dumps(standalone[manifest])
        return json.dumps(workspace)

    return check_output


class PublishPlanTest(unittest.TestCase):
    def test_local_dependencies_precede_dependents_and_dev_cycles_are_ignored(self):
        metadata = {
            "packages": [
                package("facade", dependencies=[dependency("service")]),
                package(
                    "service",
                    dependencies=[
                        dependency("core"),
                        dependency("core", "build"),
                        dependency("internal", "dev"),
                    ],
                ),
                package("core", dependencies=[dependency("facade", "dev")]),
                package("internal", publish=[]),
                package("private-registry", publish=["private"]),
            ]
        }
        with (
            mock.patch("plan.STANDALONE_MANIFESTS", ()),
            mock.patch(
                "plan.subprocess.check_output",
                side_effect=metadata_for(metadata),
            ),
        ):
            self.assertEqual([p.name for p in plan()], ["core", "service", "facade"])

    def test_unpublishable_local_dependency_is_rejected(self):
        metadata = {
            "packages": [
                package("public", dependencies=[dependency("internal")]),
                package("internal", publish=[]),
            ]
        }
        with (
            mock.patch("plan.STANDALONE_MANIFESTS", ()),
            mock.patch(
                "plan.subprocess.check_output",
                side_effect=metadata_for(metadata),
            ),
            self.assertRaisesRegex(
                AssertionError, "unpublished local package internal"
            ),
        ):
            plan()

    def test_standalone_manifest_publishes_after_its_local_path_dependencies(self):
        manifest = "standalone/Cargo.toml"
        standalone_path = str(PROJECT_DIR / manifest)
        workspace = {
            "packages": [
                package("core"),
                package("service", dependencies=[dependency("core")]),
            ]
        }
        standalone = {
            standalone_path: {
                "packages": [
                    package(
                        "backend",
                        dependencies=[
                            dependency("core", path="/workspace/core"),
                            dependency("service", "dev", path="/workspace/service"),
                        ],
                        manifest_path=standalone_path,
                    )
                ]
            }
        }
        with (
            mock.patch("plan.STANDALONE_MANIFESTS", (manifest,)),
            mock.patch(
                "plan.subprocess.check_output",
                side_effect=metadata_for(workspace, standalone),
            ),
        ):
            packages = plan()

        names = [package.name for package in packages]
        self.assertEqual(set(names), {"core", "service", "backend"})
        self.assertLess(names.index("core"), names.index("backend"))
        self.assertLess(names.index("service"), names.index("backend"))
        by_name = {package.name: package for package in packages}
        self.assertEqual(by_name["backend"].manifest, manifest)
        self.assertIsNone(by_name["core"].manifest)

    def test_standalone_manifest_is_skipped_when_unpublishable(self):
        manifest = "standalone/Cargo.toml"
        standalone_path = str(PROJECT_DIR / manifest)
        workspace = {"packages": [package("core")]}
        standalone = {
            standalone_path: {
                "packages": [
                    package("backend", publish=[], manifest_path=standalone_path)
                ]
            }
        }
        with (
            mock.patch("plan.STANDALONE_MANIFESTS", (manifest,)),
            mock.patch(
                "plan.subprocess.check_output",
                side_effect=metadata_for(workspace, standalone),
            ),
        ):
            self.assertEqual([p.name for p in plan()], ["core"])

    def test_standalone_manifest_must_contain_exactly_one_package(self):
        manifest = "standalone/Cargo.toml"
        standalone_path = str(PROJECT_DIR / manifest)
        standalone = {
            standalone_path: {
                "packages": [
                    package("first", manifest_path=standalone_path),
                    package("second", manifest_path=standalone_path),
                ]
            }
        }
        with (
            mock.patch("plan.STANDALONE_MANIFESTS", (manifest,)),
            mock.patch(
                "plan.subprocess.check_output",
                side_effect=metadata_for({"packages": []}, standalone),
            ),
            self.assertRaisesRegex(AssertionError, "exactly one package"),
        ):
            plan()

    def test_standalone_dependency_on_unpublished_local_package_is_rejected(self):
        manifest = "standalone/Cargo.toml"
        standalone_path = str(PROJECT_DIR / manifest)
        workspace = {"packages": [package("internal", publish=[])]}
        standalone = {
            standalone_path: {
                "packages": [
                    package(
                        "backend",
                        dependencies=[dependency("internal", "dev")],
                        manifest_path=standalone_path,
                    )
                ]
            }
        }
        with (
            mock.patch("plan.STANDALONE_MANIFESTS", (manifest,)),
            mock.patch(
                "plan.subprocess.check_output",
                side_effect=metadata_for(workspace, standalone),
            ),
            self.assertRaisesRegex(
                AssertionError, "unpublished local package internal"
            ),
        ):
            plan()

    @unittest.skipUnless(shutil.which("cargo"), "cargo is required")
    def test_repository_plan_orders_standalone_after_its_local_dependencies(self):
        packages = plan()
        by_name = {package.name: index for index, package in enumerate(packages)}
        standalone = [
            package for package in packages if package.manifest is not None
        ]
        self.assertEqual(
            [package.manifest for package in standalone],
            ["crypto/boring/Cargo.toml"],
        )
        boring = by_name["reqsign-crypto-boring"]
        for dependency in (
            "reqsign-core",
            "reqsign-crypto-rustcrypto",
            "reqsign-aws-core",
            "reqsign-aws-v4",
        ):
            self.assertLess(by_name[dependency], boring)


if __name__ == "__main__":
    unittest.main()
