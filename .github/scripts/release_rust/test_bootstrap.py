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

import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bootstrap import (
    APPROVED_PLAN_SCHEMA,
    LEGACY_PLACEHOLDER_DESCRIPTION,
    LEGACY_REPOSITORY,
    PLACEHOLDER_DESCRIPTION,
    PLACEHOLDER_VERSION,
    PUBLISHER,
    REPOSITORY,
    apply,
    approved_plan,
    discover,
    format_apply_summary,
    format_discover_summary,
    load_approved_plan,
    validate_approved_plan,
    write_approved_plan,
    write_placeholder_package,
    write_step_summary,
)
from plan import Package

DISPATCH_SHA = "a" * 40


def crate_payload(
    name,
    version="1.0.0",
    *,
    ready=True,
    versions=None,
    repository=REPOSITORY,
    description=PLACEHOLDER_DESCRIPTION,
    max_version=None,
):
    if versions is None:
        versions = ((version, False),)
    versions = tuple(versions)
    return {
        "crate": {
            "id": name,
            "max_version": version if max_version is None else max_version,
            "num_versions": len(versions),
            "repository": repository,
            "description": description,
            "trustpub_only": ready,
        },
        "versions": [
            {"num": published, "yanked": yanked} for published, yanked in versions
        ],
    }


def publisher(name):
    return {"crate": name, **PUBLISHER}


def crate_record(name, *args, **kwargs):
    payload = crate_payload(name, *args, **kwargs)
    return payload["crate"], payload["versions"]


def plan_artifact(packages, missing, writable=None):
    if writable is None:
        writable = [package.name for package in packages]
    return {
        "schema_version": APPROVED_PLAN_SCHEMA,
        "repository": REPOSITORY,
        "dispatch_sha": DISPATCH_SHA,
        "plan": [
            {"name": package.name, "version": package.version}
            for package in packages
        ],
        "missing": list(missing),
        "writable": list(writable),
    }


class FakeRegistry:
    token = "bootstrap-token"

    def __init__(self, crates, configs):
        self.crates = crates
        self.configs = configs
        self.writes = []

    def get_crate(self, name):
        crate = self.crates.get(name)
        if crate is None:
            return None
        payload = copy.deepcopy(crate)
        return payload["crate"], payload["versions"]

    def list_github_configs(self, name):
        return copy.deepcopy(self.configs.get(name, []))

    def create_github_config(self, name):
        self.writes.append(("publisher", name))
        config = publisher(name)
        self.configs[name] = [config]
        return config

    def set_trustpub_only(self, name):
        self.writes.append(("restrict", name))
        self.crates[name]["crate"]["trustpub_only"] = True
        return copy.deepcopy(self.crates[name]["crate"])


class BootstrapTest(unittest.TestCase):
    def test_entire_plan_is_checked_before_any_write(self):
        for invalid in (
            "repository",
            "publisher",
            "multiple publishers",
            "trustpub_only",
        ):
            with self.subTest(invalid=invalid):
                packages = [Package("missing", "1.0.0"), Package("established", "2.0.0")]
                crate = crate_payload("established", "1.0.0")
                configs = [publisher("established")]
                if invalid == "repository":
                    crate["crate"]["repository"] = "https://github.com/other/reqsign"
                elif invalid == "publisher":
                    configs[0]["repository_name"] = "opendal-reqsign"
                elif invalid == "multiple publishers":
                    configs.append(publisher("established"))
                else:
                    crate["crate"]["trustpub_only"] = False
                registry = FakeRegistry(
                    {"established": crate}, {"established": configs}
                )
                with (
                    mock.patch("bootstrap.publish_placeholder") as publish,
                    self.assertRaises(AssertionError),
                ):
                    apply(
                        packages,
                        plan_artifact(packages, ["missing"], writable=["missing"]),
                        registry,
                        dispatch_sha=DISPATCH_SHA,
                    )
                publish.assert_not_called()
                self.assertEqual(registry.writes, [])

    def test_bootstrap_resumes_partial_placeholders_and_is_safe_to_repeat(self):
        names = ["missing", "partial", "configured", "ready", "established"]
        packages = [
            Package(name, "2.0.0" if name == "established" else "1.0.0")
            for name in names
        ]
        crates = {
            "partial": crate_payload(
                "partial",
                PLACEHOLDER_VERSION,
                ready=False,
                description=LEGACY_PLACEHOLDER_DESCRIPTION,
            ),
            "configured": crate_payload(
                "configured", PLACEHOLDER_VERSION, ready=False
            ),
            "ready": crate_payload("ready", PLACEHOLDER_VERSION),
            "established": crate_payload(
                "established", "1.0.0", repository=LEGACY_REPOSITORY
            ),
        }
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
            registry.crates[name] = crate_payload(
                name, PLACEHOLDER_VERSION, ready=False
            )

        approved = plan_artifact(
            packages,
            ["missing"],
            writable=["missing", "partial", "configured", "ready"],
        )
        with mock.patch("bootstrap.publish_placeholder", publish):
            first = apply(packages, approved, registry, dispatch_sha=DISPATCH_SHA)
            second = apply(packages, approved, registry, dispatch_sha=DISPATCH_SHA)
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
        summary = format_apply_summary(len(packages), first)
        self.assertIn(
            "| `missing` | published `0.0.0`, configured Trusted Publisher, enabled `trustpub_only` |",
            summary,
        )
        self.assertIn("| `ready` | already ready |", summary)

    def test_crate_that_becomes_established_after_audit_is_not_modified(self):
        packages = [Package("new", "1.0.0")]
        registry = FakeRegistry({}, {})
        with (
            mock.patch.object(
                registry,
                "get_crate",
                side_effect=[None, crate_record("new")],
            ),
            mock.patch("bootstrap.publish_placeholder") as publish,
            self.assertRaisesRegex(AssertionError, "established crate"),
        ):
            apply(
                packages,
                plan_artifact(packages, ["new"], writable=["new"]),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
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
                "placeholder-open": crate_payload(
                    "placeholder-open", PLACEHOLDER_VERSION, ready=False
                ),
                "placeholder-ready": crate_payload(
                    "placeholder-ready", PLACEHOLDER_VERSION
                ),
                "established": crate_payload("established", "3.0.0"),
                "established-open": crate_payload(
                    "established-open", "2.0.0", ready=False
                ),
                "established-yanked": crate_payload(
                    "established-yanked",
                    PLACEHOLDER_VERSION,
                    versions=((PLACEHOLDER_VERSION, False), ("1.0.0", True)),
                ),
            },
            {},
        )
        packages = [
            Package("missing-new", "1.0.0"),
            Package("placeholder-open", "1.0.0"),
            Package("placeholder-ready", "1.0.0"),
            Package("established", "4.0.0"),
            Package("established-open", "4.0.0"),
            Package("established-yanked", "4.0.0"),
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
                ("established-yanked", "established"),
            ],
        )
        summary = format_discover_summary(statuses)
        self.assertIn(
            "New crates to publish (`0.0.0` placeholder, irreversible): **1**", summary
        )
        self.assertIn("| `missing-new` | `1.0.0` |", summary)
        self.assertIn("Publish `0.0.0` placeholder after approval", summary)
        self.assertIn(
            "The protected job only reconciles the missing and placeholder",
            summary,
        )
        self.assertIn(
            "| `placeholder-open` | `1.0.0` | `false` | "
            "Authenticated publisher verification or creation; "
            "enable `trustpub_only` |",
            summary,
        )
        self.assertIn(
            "| `placeholder-ready` | `1.0.0` | `true` | "
            "Authenticated publisher verification or creation; "
            "`trustpub_only` already enabled |",
            summary,
        )
        self.assertIn(
            "Established crates without `trustpub_only` enabled will fail the authenticated audit: `established-open`",
            summary,
        )
        self.assertIn(
            "| `established` | 3.0.0 | `4.0.0` | `true` |", summary
        )
        self.assertIn(
            "| `established-yanked` | 0.0.0 | `4.0.0` | `true` |", summary
        )
        self.assertIn("including yanked versions", summary)
        self.assertIn("after approval", summary)

    def test_discover_summary_handles_no_missing_crates_and_rejects_foreign_crate(self):
        registry = FakeRegistry(
            {"established": crate_payload("established", "3.0.0")}, {}
        )
        statuses = discover([Package("established", "4.0.0")], registry)
        summary = format_discover_summary(statuses)
        self.assertIn("None. No new crate names will be published", summary)
        self.assertNotIn("[!WARNING]", summary)

        foreign = crate_payload("foreign")
        foreign["crate"]["repository"] = "https://github.com/other/foreign"
        with self.assertRaisesRegex(AssertionError, "unexpected repository"):
            discover(
                [Package("foreign", "1.0.0")],
                FakeRegistry({"foreign": foreign}, {}),
            )

    def test_discover_rejects_incomplete_version_history(self):
        incomplete = crate_payload("incomplete")
        incomplete["crate"]["num_versions"] += 1
        with self.assertRaisesRegex(AssertionError, "incomplete version history"):
            discover(
                [Package("incomplete", "1.0.0")],
                FakeRegistry({"incomplete": incomplete}, {}),
            )

        empty = crate_payload("empty")
        empty["crate"]["num_versions"] = 0
        empty["versions"] = []
        with self.assertRaisesRegex(AssertionError, "has no versions"):
            discover(
                [Package("empty", "1.0.0")],
                FakeRegistry({"empty": empty}, {}),
            )

    def test_apply_rejects_an_unapproved_newly_missing_name_before_writes(self):
        packages = [
            Package("reviewed-placeholder", "1.0.0"),
            Package("approved", "1.0.0"),
        ]
        registry = FakeRegistry({}, {})
        with (
            mock.patch("bootstrap.publish_placeholder") as publish,
            self.assertRaisesRegex(AssertionError, "not in the reviewed plan"),
        ):
            apply(
                packages,
                plan_artifact(
                    packages,
                    ["approved"],
                    writable=["reviewed-placeholder", "approved"],
                ),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        publish.assert_not_called()
        self.assertEqual(registry.writes, [])

    def test_apply_publishes_only_approved_missing_names(self):
        packages = [
            Package("missing", "1.0.0"),
            Package("placeholder", "1.0.0"),
            Package("established", "2.0.0"),
        ]
        registry = FakeRegistry(
            {
                "placeholder": crate_payload(
                    "placeholder", PLACEHOLDER_VERSION, ready=False
                ),
                "established": crate_payload("established", "1.0.0"),
            },
            {"established": [publisher("established")]},
        )
        published = []

        def publish(name, token):
            published.append(name)
            registry.crates[name] = crate_payload(
                name, PLACEHOLDER_VERSION, ready=False
            )

        with mock.patch("bootstrap.publish_placeholder", publish):
            results = apply(
                packages,
                plan_artifact(
                    packages, ["missing"], writable=["missing", "placeholder"]
                ),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        self.assertEqual(published, ["missing"])
        self.assertEqual([name for name, _ in results], ["missing", "placeholder"])
        self.assertEqual(
            registry.writes,
            [
                ("publisher", "missing"),
                ("restrict", "missing"),
                ("publisher", "placeholder"),
                ("restrict", "placeholder"),
            ],
        )

    def test_apply_accepts_an_approved_name_that_is_now_a_placeholder(self):
        packages = [Package("name", "1.0.0")]
        registry = FakeRegistry(
            {"name": crate_payload("name", PLACEHOLDER_VERSION, ready=False)}, {}
        )
        with mock.patch("bootstrap.publish_placeholder") as publish:
            results = apply(
                packages,
                plan_artifact(packages, ["name"], writable=["name"]),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        publish.assert_not_called()
        self.assertEqual(
            results,
            [
                (
                    "name",
                    ["configured Trusted Publisher", "enabled `trustpub_only`"],
                )
            ],
        )

    def test_apply_accepts_an_approved_name_that_is_now_established(self):
        packages = [Package("name", "2.0.0")]
        registry = FakeRegistry(
            {"name": crate_payload("name", "1.0.0")},
            {"name": [publisher("name")]},
        )
        with mock.patch("bootstrap.publish_placeholder") as publish:
            results = apply(
                packages,
                plan_artifact(packages, ["name"], writable=["name"]),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        publish.assert_not_called()
        self.assertEqual(results, [])
        self.assertEqual(registry.writes, [])

    def test_apply_does_not_modify_established_crate_with_yanked_version(self):
        packages = [Package("name", "4.0.0")]
        registry = FakeRegistry(
            {
                "name": crate_payload(
                    "name",
                    PLACEHOLDER_VERSION,
                    versions=((PLACEHOLDER_VERSION, False), ("1.0.0", True)),
                )
            },
            {"name": [publisher("name")]},
        )
        with mock.patch("bootstrap.publish_placeholder") as publish:
            results = apply(
                packages,
                plan_artifact(packages, [], writable=[]),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        publish.assert_not_called()
        self.assertEqual(results, [])
        self.assertEqual(registry.writes, [])

    def test_apply_refuses_unapproved_placeholder_that_disappeared_after_audit(self):
        packages = [Package("placeholder", "1.0.0")]
        registry = FakeRegistry(
            {"placeholder": crate_payload("placeholder", PLACEHOLDER_VERSION)}, {}
        )
        with (
            mock.patch.object(
                registry,
                "get_crate",
                side_effect=[
                    crate_record("placeholder", PLACEHOLDER_VERSION),
                    None,
                ],
            ),
            mock.patch("bootstrap.publish_placeholder") as publish,
            self.assertRaisesRegex(AssertionError, "disappeared after the reviewed plan"),
        ):
            apply(
                packages,
                plan_artifact(packages, [], writable=["placeholder"]),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        publish.assert_not_called()
        self.assertEqual(registry.writes, [])

    def test_apply_refuses_write_outside_reviewed_writable_set(self):
        packages = [Package("was-established", "2.0.0")]
        registry = FakeRegistry(
            {
                "was-established": crate_payload(
                    "was-established", PLACEHOLDER_VERSION
                )
            },
            {},
        )
        with (
            mock.patch("bootstrap.publish_placeholder") as publish,
            self.assertRaisesRegex(
                AssertionError, "changed state after the reviewed plan"
            ),
        ):
            apply(
                packages,
                plan_artifact(packages, [], writable=[]),
                registry,
                dispatch_sha=DISPATCH_SHA,
            )
        publish.assert_not_called()
        self.assertEqual(registry.writes, [])

    def test_apply_rejects_stale_or_malformed_approved_plans(self):
        packages = [Package("a", "1.0.0"), Package("b", "2.0.0")]
        base = plan_artifact(packages, ["a"])
        invalid = {
            "schema": {**base, "schema_version": APPROVED_PLAN_SCHEMA + 1},
            "repository": {**base, "repository": "https://github.com/other/repo"},
            "dispatch": {**base, "dispatch_sha": "b" * 40},
            "plan": {
                **base,
                "plan": [
                    {"name": "a", "version": "9.9.9"},
                    {"name": "b", "version": "2.0.0"},
                ],
            },
            "missing type": {**base, "missing": "a"},
            "missing duplicate": {**base, "missing": ["a", "a"]},
            "missing unplanned": {**base, "missing": ["a", "c"]},
            "missing order": {**base, "missing": ["b", "a"]},
            "missing key": {
                key: value for key, value in base.items() if key != "missing"
            },
            "writable type": {**base, "writable": "a"},
            "writable unplanned": {**base, "writable": ["a", "c"]},
            "missing not writable": {**base, "writable": ["b"]},
            "writable order": {**base, "writable": ["b", "a"]},
            "writable key": {
                key: value for key, value in base.items() if key != "writable"
            },
        }
        for label, approved in invalid.items():
            with self.subTest(label=label), self.assertRaises(AssertionError):
                apply(
                    packages,
                    approved,
                    FakeRegistry({}, {}),
                    dispatch_sha=DISPATCH_SHA,
                )

    def test_load_approved_plan_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.json"
            with self.assertRaisesRegex(AssertionError, "cannot read approved plan"):
                load_approved_plan(missing)

            malformed = Path(tmpdir) / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "cannot read approved plan"):
                load_approved_plan(malformed)

    def test_approved_plan_records_reviewed_sets(self):
        packages = [Package("missing", "1.0.0"), Package("ready", "2.0.0")]
        registry = FakeRegistry(
            {"ready": crate_payload("ready", PLACEHOLDER_VERSION)}, {}
        )
        statuses = discover(packages, registry)
        artifact = approved_plan(packages, statuses, DISPATCH_SHA)
        self.assertEqual(
            artifact,
            plan_artifact(
                packages, ["missing"], writable=["missing", "ready"]
            ),
        )
        self.assertEqual(
            validate_approved_plan(artifact, packages, DISPATCH_SHA),
            (["missing"], ["missing", "ready"]),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bootstrap-plan.json"
            write_approved_plan(path, artifact)
            self.assertEqual(load_approved_plan(path), artifact)

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
