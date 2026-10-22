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
import unittest
from unittest import mock

from plan import plan


def package(name, *, dependencies=(), publish=None):
    return {
        "name": name,
        "version": "1.0.0",
        "publish": publish,
        "manifest_path": f"/workspace/{name}/Cargo.toml",
        "dependencies": list(dependencies),
    }


def dependency(name, kind=None):
    return {"path": f"/workspace/{name}", "kind": kind}


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
        with mock.patch(
            "plan.subprocess.check_output", return_value=json.dumps(metadata)
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
            mock.patch(
                "plan.subprocess.check_output", return_value=json.dumps(metadata)
            ),
            self.assertRaisesRegex(
                AssertionError, "unpublished workspace package internal"
            ),
        ):
            plan()


if __name__ == "__main__":
    unittest.main()
