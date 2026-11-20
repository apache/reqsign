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

from pathlib import Path
import tempfile
import textwrap
import unittest

from check_crypto_dependencies import check_repository


class CryptoDependencyBoundaryTest(unittest.TestCase):
    def check(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(content))
            return check_repository(root)

    def test_normal_dependency_outside_crypto_is_rejected(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["service"]
                """,
                "service/Cargo.toml": """\
                    [dependencies]
                    sha2 = "0.11"
                """,
            }
        )
        self.assertEqual(
            [(item.table, item.key, item.package) for item in violations],
            [("dependencies", "sha2", "sha2")],
        )

    def test_renamed_dependency_is_checked_by_package_name(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["service"]
                """,
                "service/Cargo.toml": """\
                    [dependencies]
                    crypto-hash = { package = "sha2", version = "0.11" }
                """,
            }
        )
        self.assertEqual(violations[0].package, "sha2")
        self.assertEqual(violations[0].key, "crypto-hash")

    def test_target_specific_build_dependency_is_rejected(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["service"]
                """,
                "service/Cargo.toml": """\
                    [target.'cfg(unix)'.build-dependencies]
                    ring = "0.17"
                """,
            }
        )
        self.assertEqual(violations[0].table, "target.cfg(unix).build-dependencies")
        self.assertEqual(violations[0].package, "ring")

    def test_unused_workspace_alias_is_rejected(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["service"]

                    [workspace.dependencies]
                    crypto-random = { package = "getrandom", version = "0.3" }
                """,
                "service/Cargo.toml": """\
                    [dependencies]
                    anyhow = "1"
                """,
            }
        )
        self.assertEqual(
            [(item.table, item.key, item.package) for item in violations],
            [("workspace.dependencies", "crypto-random", "getrandom")],
        )

    def test_workspace_alias_used_by_a_member_is_rejected_in_both_places(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["service"]

                    [workspace.dependencies]
                    crypto-hash = { package = "sha2", version = "0.11" }
                """,
                "service/Cargo.toml": """\
                    [dependencies]
                    crypto-hash = { workspace = true }
                """,
            }
        )
        self.assertEqual(
            {(item.manifest, item.table) for item in violations},
            {
                ("Cargo.toml", "workspace.dependencies"),
                ("service/Cargo.toml", "dependencies"),
            },
        )

    def test_crypto_members_and_allowed_dependencies_are_ignored(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["crypto/backend", "service"]
                """,
                "crypto/backend/Cargo.toml": """\
                    [dependencies]
                    sha2 = "0.11"
                    rsa = "0.10"

                    [target.'cfg(not(target_arch = "wasm32"))'.dependencies]
                    getrandom = "0.3"
                """,
                "service/Cargo.toml": """\
                    [dependencies]
                    reqsign-crypto-rustcrypto = { path = "../crypto/backend" }
                    base64 = "0.23"
                    zeroize = "1"

                    [dev-dependencies]
                    aws-sigv4 = "1.2"
                """,
            }
        )
        self.assertEqual(violations, [])

    def test_target_directory_is_not_scanned(self):
        violations = self.check(
            {
                "Cargo.toml": """\
                    [workspace]
                    members = ["service"]
                """,
                "service/Cargo.toml": """\
                    [dependencies]
                    anyhow = "1"
                """,
                "target/package/example/Cargo.toml": """\
                    [dependencies]
                    sha1 = "0.11"
                """,
            }
        )
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
