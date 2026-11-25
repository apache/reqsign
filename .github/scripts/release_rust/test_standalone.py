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

import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from plan import PROJECT_DIR, Package
from standalone import (
    REQUIRED_FILES,
    local_path_dependencies,
    patch_configs,
    verify_crate,
)


def package(name, *, dependencies=(), manifest_path=None, publish=None):
    return {
        "name": name,
        "version": "1.0.0",
        "publish": publish,
        "manifest_path": manifest_path or f"/workspace/{name}/Cargo.toml",
        "dependencies": list(dependencies),
    }


def dependency(name, kind=None, *, path=None):
    return {"name": name, "path": path or f"/workspace/{name}", "kind": kind}


def write_crate(path, manifest, *, files=()):
    prefix = "reqsign-crypto-boring-1.0.0/"
    entries = {"Cargo.toml": manifest, **dict(files)}
    with tarfile.open(path, "w:gz") as archive:
        for relative, content in entries.items():
            data = content.encode()
            info = tarfile.TarInfo(prefix + relative)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


NORMALIZED_MANIFEST = """
[package]
name = "reqsign-crypto-boring"
version = "1.0.0"

[dependencies.reqsign-core]
version = "4.0.0"

[dev-dependencies.reqsign-aws-v4]
version = "4.0.0"
"""

PLANNED = {"reqsign-core": "4.0.0", "reqsign-aws-v4": "4.0.0"}


class LocalPathDependenciesTest(unittest.TestCase):
    def test_stages_root_dev_dependencies_and_transitive_normal_dependencies(self):
        root = PROJECT_DIR / "standalone"
        core = PROJECT_DIR / "core"
        aws_v4 = PROJECT_DIR / "services/aws-v4"
        aws_core = PROJECT_DIR / "services/aws-core"
        test_tools = PROJECT_DIR / "test-tools"
        local = {
            root: package(
                "backend",
                dependencies=[
                    dependency("reqsign-core", path=str(core)),
                    dependency("reqsign-aws-v4", "dev", path=str(aws_v4)),
                ],
                manifest_path=str(root / "Cargo.toml"),
            ),
            core: package("reqsign-core"),
            aws_v4: package(
                "reqsign-aws-v4",
                dependencies=[
                    dependency("reqsign-core", path=str(core)),
                    dependency("reqsign-aws-core", path=str(aws_core)),
                    dependency("test-tools", "dev", path=str(test_tools)),
                ],
            ),
            aws_core: package("reqsign-aws-core"),
            test_tools: package("test-tools"),
        }
        with mock.patch("standalone.local_packages", return_value=local):
            required = local_path_dependencies("standalone/Cargo.toml")
        self.assertEqual(
            required,
            {
                "reqsign-core": core,
                "reqsign-aws-v4": aws_v4,
                "reqsign-aws-core": aws_core,
            },
        )

    def test_patch_configs_quote_absolute_paths(self):
        root = PROJECT_DIR / "standalone"
        core = PROJECT_DIR / "core"
        local = {
            root: package(
                "backend",
                dependencies=[dependency("reqsign-core", path=str(core))],
                manifest_path=str(root / "Cargo.toml"),
            ),
            core: package("reqsign-core"),
        }
        with mock.patch("standalone.local_packages", return_value=local):
            configs = patch_configs("standalone/Cargo.toml")
        self.assertEqual(
            configs,
            [f'patch.crates-io.reqsign-core.path="{core}"'],
        )

    def test_unknown_manifest_is_rejected(self):
        with (
            mock.patch("standalone.local_packages", return_value={}),
            self.assertRaisesRegex(AssertionError, "not a known local package"),
        ):
            local_path_dependencies("standalone/Cargo.toml")


class VerifyCrateTest(unittest.TestCase):
    def crate(self, directory, manifest=NORMALIZED_MANIFEST, files=None):
        path = Path(directory) / "reqsign-crypto-boring-1.0.0.crate"
        if files is None:
            files = {name: "" for name in REQUIRED_FILES if name != "Cargo.toml"}
        write_crate(path, manifest, files=files)
        return path

    def test_accepts_normalized_local_dependencies_and_package_files(self):
        with tempfile.TemporaryDirectory() as directory:
            crate = self.crate(directory)
            verify_crate(
                crate, Package("reqsign-crypto-boring", "1.0.0"), PLANNED
            )

    def test_rejects_missing_package_file(self):
        with tempfile.TemporaryDirectory() as directory:
            files = {
                name: ""
                for name in REQUIRED_FILES
                if name not in ("Cargo.toml", "NOTICE")
            }
            crate = self.crate(directory, files=files)
            with self.assertRaisesRegex(AssertionError, "missing NOTICE"):
                verify_crate(
                    crate, Package("reqsign-crypto-boring", "1.0.0"), PLANNED
                )

    def test_rejects_version_that_does_not_match_the_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            crate = self.crate(directory)
            with self.assertRaisesRegex(AssertionError, "the plan publishes"):
                verify_crate(
                    crate,
                    Package("reqsign-crypto-boring", "1.0.0"),
                    {**PLANNED, "reqsign-core": "5.0.0"},
                )

    def test_rejects_retained_path_dependency(self):
        manifest = NORMALIZED_MANIFEST.replace(
            'version = "4.0.0"\n\n[dev-dependencies.reqsign-aws-v4]',
            'version = "4.0.0"\npath = "../core"\n\n'
            "[dev-dependencies.reqsign-aws-v4]",
        )
        with tempfile.TemporaryDirectory() as directory:
            crate = self.crate(directory, manifest=manifest)
            with self.assertRaisesRegex(AssertionError, "keeps a path dependency"):
                verify_crate(
                    crate, Package("reqsign-crypto-boring", "1.0.0"), PLANNED
                )


if __name__ == "__main__":
    unittest.main()
