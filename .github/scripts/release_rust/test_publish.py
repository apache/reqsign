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
import unittest
from contextlib import contextmanager
from unittest import mock

from plan import Package
from publish import (
    INDEX_RETRY_ATTEMPTS,
    INDEX_RETRY_DELAY,
    already_published,
    publish_command,
    publish_package,
)

# Captured from `cargo package --no-verify` for `crypto/boring/Cargo.toml`
# while `reqsign-aws-v4 4.0.0` was published but not visible in the index.
INDEX_LAG_ERROR = (
    "error: failed to prepare local package for uploading\n"
    "\n"
    "Caused by:\n"
    '  failed to select a version for the requirement `reqsign-aws-v4 = "^4.0.0"`\n'
    "  candidate versions found which didn't match: 3.5.0, 3.4.0, 3.3.1, ...\n"
    "  location searched: crates.io index\n"
    "  required by package `reqsign-crypto-boring v1.0.0`\n"
)


def subprocess_result(returncode: int, output: str):
    return mock.Mock(returncode=returncode, stdout=output)


@contextmanager
def token_provider():
    yield "temporary-token"


class ReleaseRustPublishCommandTest(unittest.TestCase):
    def test_workspace_member_is_selected_by_package_name(self):
        self.assertEqual(
            publish_command(Package("reqsign-core", "4.0.0")),
            ["cargo", "publish", "--package", "reqsign-core", "--no-verify"],
        )

    def test_standalone_package_is_selected_by_manifest_path(self):
        self.assertEqual(
            publish_command(
                Package(
                    "reqsign-crypto-boring",
                    "1.0.0",
                    manifest="crypto/boring/Cargo.toml",
                )
            ),
            [
                "cargo",
                "publish",
                "--manifest-path",
                "crypto/boring/Cargo.toml",
                "--no-verify",
            ],
        )


class ReleaseRustPublishTest(unittest.TestCase):
    def test_live_publish_fetches_a_new_token_for_every_attempt(self):
        package = Package("reqsign-test", "1.0.0")
        tokens = iter(("first-token", "second-token"))
        revoked: list[str] = []
        cargo_tokens: list[str | None] = []

        @contextmanager
        def temporary_tokens():
            token = next(tokens)
            try:
                yield token
            finally:
                revoked.append(token)

        results = iter(
            (
                subprocess_result(
                    1, "Too many requests. Please try again after invalid."
                ),
                subprocess_result(0, "published"),
            )
        )

        def run(*args, **kwargs):
            cargo_tokens.append(kwargs["env"].get("CARGO_REGISTRY_TOKEN"))
            return next(results)

        with (
            mock.patch.dict(
                "publish.os.environ",
                {"CARGO_REGISTRY_TOKEN": "legacy-token"},
                clear=True,
            ),
            mock.patch(
                "publish.temporary_trusted_publishing_token", temporary_tokens
            ),
            mock.patch("publish.subprocess.run", run),
            mock.patch("publish.time.sleep") as sleep,
        ):
            result = publish_package(package, planned_versions={})

        self.assertEqual(result, "published")
        self.assertEqual(cargo_tokens, ["first-token", "second-token"])
        self.assertEqual(revoked, ["first-token", "second-token"])
        sleep.assert_called_once_with(610)

    def test_delayed_index_visibility_is_retried_with_a_fresh_token(self):
        package = Package(
            "reqsign-crypto-boring", "1.0.0", manifest="crypto/boring/Cargo.toml"
        )
        planned = {"reqsign-aws-v4": "4.0.0", "reqsign-crypto-boring": "1.0.0"}
        tokens = iter(("first-token", "second-token"))
        cargo_tokens: list[str | None] = []
        results = iter(
            (
                subprocess_result(101, INDEX_LAG_ERROR),
                subprocess_result(0, "published"),
            )
        )

        @contextmanager
        def temporary_tokens():
            yield next(tokens)

        def run(*args, **kwargs):
            cargo_tokens.append(kwargs["env"].get("CARGO_REGISTRY_TOKEN"))
            return next(results)

        with (
            mock.patch(
                "publish.temporary_trusted_publishing_token", temporary_tokens
            ),
            mock.patch("publish.subprocess.run", run),
            mock.patch("publish.time.sleep") as sleep,
        ):
            result = publish_package(package, planned_versions=planned)

        self.assertEqual(result, "published")
        self.assertEqual(cargo_tokens, ["first-token", "second-token"])
        sleep.assert_called_once_with(INDEX_RETRY_DELAY)

    def test_index_visibility_recovery_is_bounded(self):
        package = Package("reqsign-test", "1.0.0")
        planned = {"reqsign-aws-v4": "4.0.0"}

        with (
            mock.patch(
                "publish.temporary_trusted_publishing_token", token_provider
            ),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(101, INDEX_LAG_ERROR),
            ) as run,
            mock.patch("publish.time.sleep") as sleep,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            publish_package(package, planned_versions=planned)

        self.assertEqual(run.call_count, INDEX_RETRY_ATTEMPTS + 1)
        self.assertEqual(sleep.call_count, INDEX_RETRY_ATTEMPTS)

    def test_requirement_for_another_version_is_not_retried(self):
        package = Package("reqsign-test", "1.0.0")
        output = INDEX_LAG_ERROR.replace('"^4.0.0"', '"^5.0.0"')

        with (
            mock.patch(
                "publish.temporary_trusted_publishing_token", token_provider
            ),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(101, output),
            ) as run,
            mock.patch("publish.time.sleep") as sleep,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            publish_package(
                package, planned_versions={"reqsign-aws-v4": "4.0.0"}
            )

        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_index_error_for_unplanned_package_is_not_retried(self):
        package = Package("reqsign-test", "1.0.0")
        output = INDEX_LAG_ERROR.replace("reqsign-aws-v4", "some-dependency")

        with (
            mock.patch(
                "publish.temporary_trusted_publishing_token", token_provider
            ),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(101, output),
            ) as run,
            mock.patch("publish.time.sleep") as sleep,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            publish_package(package, planned_versions={})

        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_already_published_package_is_recoverable(self):
        package = Package("reqsign-test", "1.0.0")

        with (
            mock.patch(
                "publish.temporary_trusted_publishing_token", token_provider
            ),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(
                    101,
                    "error: crate reqsign-test@1.0.0 already exists on crates.io index",
                ),
            ),
        ):
            result = publish_package(package, planned_versions={})

        self.assertEqual(result, "already published")

    def test_unrelated_already_exists_error_is_not_ignored(self):
        package = Package("reqsign-test", "1.0.0")
        self.assertFalse(
            already_published(
                "crate another@1.0.0 already exists on crates.io index", package
            )
        )

    def test_non_retryable_failure_is_reported(self):
        package = Package("reqsign-test", "1.0.0")

        with (
            mock.patch(
                "publish.temporary_trusted_publishing_token", token_provider
            ),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(101, "permission denied"),
            ) as run,
            mock.patch("publish.time.sleep") as sleep,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            publish_package(package, planned_versions={})

        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
