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

import os
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
    discover,
    format_apply_summary,
    format_discover_summary,
    write_step_summary,
    write_placeholder_package,
)
from plan import Package


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
            first = apply(names, registry)
            second = apply(names, registry)
        self.assertEqual(published, ["missing"])
        self.assertEqual(
            first,
            [
                (
                    "missing",
                    [
                        "published `0.0.0`",
                        "configured Trusted Publisher",
                        "enabled `trustpub_only`",
                    ],
                ),
                (
                    "partial",
                    ["configured Trusted Publisher", "enabled `trustpub_only`"],
                ),
                ("configured", ["enabled `trustpub_only`"]),
                ("ready", []),
            ],
        )
        self.assertEqual(
            second,
            [("missing", []), ("partial", []), ("configured", []), ("ready", [])],
        )
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
        summary = format_apply_summary(len(names), first)
        self.assertIn("| `missing` | published `0.0.0`, configured Trusted Publisher, enabled `trustpub_only` |", summary)
        self.assertIn("| `ready` | already ready |", summary)

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

    def test_discover_classifies_crates_and_formats_summary(self):
        registry = FakeRegistry(
            {
                "placeholder-open": metadata("placeholder-open", "0.0.0", ready=False),
                "placeholder-ready": metadata("placeholder-ready", "0.0.0", ready=True),
                "established": metadata("established", "3.0.0", ready=True),
                "established-open": metadata("established-open", "2.0.0", ready=False),
            },
            {},
        )
        packages = [
            Package("missing-new", "1.0.0"),
            Package("placeholder-open", "1.0.0"),
            Package("placeholder-ready", "1.0.0"),
            Package("established", "4.0.0"),
            Package("established-open", "4.0.0"),
        ]
        statuses = discover(packages, registry)
        self.assertEqual(
            [(status.name, status.kind) for status in statuses],
            [
                ("missing-new", "missing"),
                ("placeholder-open", "placeholder"),
                ("placeholder-ready", "placeholder"),
                ("established", "established"),
                ("established-open", "established"),
            ],
        )
        summary = format_discover_summary(statuses)
        self.assertIn(
            "New crates to publish (`0.0.0` placeholder, irreversible): **1**", summary
        )
        self.assertIn("| `missing-new` | `1.0.0` |", summary)
        self.assertIn(
            "| `placeholder-open` | `1.0.0` | `false` | Configure Trusted Publisher, enable `trustpub_only` |",
            summary,
        )
        self.assertIn(
            "| `placeholder-ready` | `1.0.0` | `true` | Verify Trusted Publisher |",
            summary,
        )
        self.assertIn(
            "Established crates without `trustpub_only` enabled will fail the authenticated audit: `established-open`",
            summary,
        )
        self.assertIn("| `established` | `3.0.0` | `4.0.0` | `true` |", summary)

    def test_discover_summary_handles_no_missing_crates_and_rejects_foreign_crate(self):
        registry = FakeRegistry(
            {"established": metadata("established", "3.0.0", ready=True)}, {}
        )
        statuses = discover([Package("established", "4.0.0")], registry)
        summary = format_discover_summary(statuses)
        self.assertIn("None. No new crate names will be published", summary)
        self.assertNotIn("[!WARNING]", summary)

        foreign = metadata("foreign", "1.0.0", ready=True)
        foreign["repository"] = "https://github.com/other/foreign"
        with self.assertRaisesRegex(AssertionError, "unexpected repository"):
            discover([Package("foreign", "1.0.0")], FakeRegistry({"foreign": foreign}, {}))

    def test_write_step_summary_appends_when_configured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_file = Path(tmpdir) / "summary.md"
            with mock.patch.dict(
                os.environ, {"GITHUB_STEP_SUMMARY": str(summary_file)}
            ):
                write_step_summary("## Plan\n")
            self.assertEqual(summary_file.read_text(encoding="utf-8"), "## Plan\n")


if __name__ == "__main__":
    unittest.main()
