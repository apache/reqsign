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

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bootstrap import (
    LEGACY_PLACEHOLDER_DESCRIPTION,
    LEGACY_REPOSITORY,
    PLACEHOLDER_DESCRIPTION,
    PUBLISHER,
    REPOSITORY,
    apply,
    write_placeholder_package,
)


def metadata(name, version="1.0.0", *, ready=True):
    return {
        "id": name,
        "max_version": version,
        "repository": REPOSITORY,
        "description": PLACEHOLDER_DESCRIPTION,
        "trustpub_only": ready,
    }


def publisher(name):
    return {"crate": name, **PUBLISHER}


class FakeRegistry:
    token = "bootstrap-token"

    def __init__(self, crates, configs):
        self.crates = crates
        self.configs = configs
        self.writes = []

    def get_crate(self, name):
        crate = self.crates.get(name)
        return dict(crate) if crate else None

    def list_github_configs(self, name):
        return self.configs.get(name, [])

    def create_github_config(self, name):
        self.writes.append(("publisher", name))
        config = publisher(name)
        self.configs[name] = [config]
        return config

    def set_trustpub_only(self, name):
        self.writes.append(("restrict", name))
        self.crates[name]["trustpub_only"] = True
        return self.get_crate(name)


class BootstrapTest(unittest.TestCase):
    def test_entire_plan_is_checked_before_any_write(self):
        for invalid in (
            "repository",
            "publisher",
            "multiple publishers",
            "trustpub_only",
        ):
            with self.subTest(invalid=invalid):
                crate = metadata("established")
                configs = [publisher("established")]
                if invalid == "repository":
                    crate["repository"] = "https://github.com/other/reqsign"
                elif invalid == "publisher":
                    configs[0]["repository_name"] = "opendal-reqsign"
                elif invalid == "multiple publishers":
                    configs.append(publisher("established"))
                else:
                    crate["trustpub_only"] = False
                registry = FakeRegistry(
                    {"established": crate}, {"established": configs}
                )
                with (
                    mock.patch("bootstrap.publish_placeholder") as publish,
                    self.assertRaises(AssertionError),
                ):
                    apply(["missing", "established"], registry)
                publish.assert_not_called()
                self.assertEqual(registry.writes, [])

    def test_bootstrap_resumes_partial_placeholders_and_is_safe_to_repeat(self):
        crates = {
            "partial": metadata("partial", "0.0.0", ready=False),
            "configured": metadata("configured", "0.0.0", ready=False),
            "ready": metadata("ready", "0.0.0"),
            "established": metadata("established"),
        }
        crates["partial"]["description"] = LEGACY_PLACEHOLDER_DESCRIPTION
        crates["established"]["repository"] = LEGACY_REPOSITORY
        registry = FakeRegistry(
            crates,
            {
                name: [publisher(name)]
                for name in ("configured", "ready", "established")
            },
        )
        published = []

        def publish(name, token):
            published.append(name)
            registry.crates[name] = metadata(name, "0.0.0", ready=False)

        names = ["missing", *crates]
        with mock.patch("bootstrap.publish_placeholder", publish):
            apply(names, registry)
            apply(names, registry)
        self.assertEqual(published, ["missing"])
        self.assertEqual(
            registry.writes,
            [
                ("publisher", "missing"),
                ("restrict", "missing"),
                ("publisher", "partial"),
                ("restrict", "partial"),
                ("restrict", "configured"),
            ],
        )

    def test_crate_that_becomes_established_after_audit_is_not_modified(self):
        registry = FakeRegistry({}, {})
        with (
            mock.patch.object(
                registry, "get_crate", side_effect=[None, metadata("new")]
            ),
            mock.patch("bootstrap.publish_placeholder") as publish,
            self.assertRaisesRegex(AssertionError, "established crate"),
        ):
            apply(["new"], registry)
        publish.assert_not_called()
        self.assertEqual(registry.writes, [])

    def test_placeholder_can_be_packaged_and_built_offline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            package_dir = Path(tmpdir)
            write_placeholder_package("reqsign-new", package_dir)
            process = subprocess.run(
                ["cargo", "package", "--offline"],
                cwd=package_dir,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(process.returncode, 0, process.stdout)
            self.assertTrue(
                (package_dir / "target/package/reqsign-new-0.0.0.crate").is_file()
            )


if __name__ == "__main__":
    unittest.main()
