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
import re
import subprocess
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from plan import PROJECT_DIR, Package, plan
from trusted_publishing import temporary_trusted_publishing_token

# A successful upload or duplicate report does not promise that the crates.io
# index already exposes that version. Cargo reports the lag as a version
# selection failure against the index when packaging the next package. Retry
# the same package with a bounded budget before treating the failure as real.
INDEX_RETRY_ATTEMPTS = 10
INDEX_RETRY_DELAY = 30


def parse_retry_after(output: str) -> int:
    match = re.search(r"Please try again after ([^\n]+)", output)
    if match:
        value = match.group(1).strip().rstrip(".")
        for parser in (
            parsedate_to_datetime,
            lambda text: datetime.fromisoformat(text.replace("Z", "+00:00")),
        ):
            try:
                retry_at = parser(value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max(
                    60,
                    int((retry_at - datetime.now(timezone.utc)).total_seconds()) + 8,
                )
            except ValueError:
                continue
    return 610


def should_retry(output: str) -> bool:
    lowered = output.lower()
    return (
        "too many requests" in lowered
        or "rate limit" in lowered
        or "you have published too many crates" in lowered
    )


def already_published(output: str, package: Package) -> bool:
    lowered = output.lower()
    identity = f"{package.name}@{package.version}".lower()
    return identity in lowered and (
        "already exists" in lowered or "already uploaded" in lowered
    )


def not_yet_indexed_dependency(
    output: str, planned_versions: dict[str, str]
) -> str | None:
    """Return a planned dependency the index does not expose yet.

    Cargo fails to prepare the next package when a just-published dependency
    version is not visible through the index. Only an index resolution failure
    for exactly the planned version is recoverable this way; a requirement for
    another version or an unplanned package is a manifest, registry, or
    ordering error that must fail the run.
    """
    if "location searched: crates.io index" not in output:
        return None
    match = re.search(
        r"failed to select a version for the requirement `([^`]+) = \"([^\"]+)\"`",
        output,
    )
    if match is None:
        return None
    name, requirement = match.groups()
    version = planned_versions.get(name)
    if version is None or requirement.lstrip("^=") != version:
        return None
    return name


def publish_command(package: Package) -> list[str]:
    # A standalone manifest is not a workspace member, so Cargo cannot select
    # it by package name from the project directory.
    if package.manifest is None:
        selector = ["--package", package.name]
    else:
        selector = ["--manifest-path", package.manifest]
    return ["cargo", "publish", *selector, "--no-verify"]


def publish_package(package: Package, *, planned_versions: dict[str, str]) -> str:
    command = publish_command(package)
    index_attempts = 0

    while True:
        print(f"Publishing {package.name} {package.version}", flush=True)
        with temporary_trusted_publishing_token() as token:
            env = os.environ.copy()
            env["CARGO_REGISTRY_TOKEN"] = token
            process = subprocess.run(
                command,
                cwd=PROJECT_DIR,
                check=False,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output = process.stdout or ""
            print(output, end="", flush=True)

        if process.returncode == 0:
            return "published"
        if already_published(output, package):
            print(
                f"Skipping {package.name} {package.version}: already published",
                flush=True,
            )
            return "already published"
        if should_retry(output):
            delay = parse_retry_after(output)
            print(
                f"crates.io rate limited {package.name}; sleeping {delay}s",
                flush=True,
            )
            time.sleep(delay)
            continue
        pending = not_yet_indexed_dependency(output, planned_versions)
        if pending is not None:
            if index_attempts < INDEX_RETRY_ATTEMPTS:
                index_attempts += 1
                print(
                    f"crates.io index has not caught up with "
                    f"{pending} {planned_versions[pending]}; retry "
                    f"{index_attempts}/{INDEX_RETRY_ATTEMPTS}",
                    flush=True,
                )
                time.sleep(INDEX_RETRY_DELAY)
                continue
            print(
                f"crates.io index did not expose {pending} "
                f"{planned_versions[pending]} after {index_attempts} retries",
                flush=True,
            )
        raise subprocess.CalledProcessError(process.returncode, command, output=output)


def main() -> int:
    packages = plan()
    planned_versions = {package.name: package.version for package in packages}
    results = [
        (package, publish_package(package, planned_versions=planned_versions))
        for package in packages
    ]

    print("Publish plan completed:", flush=True)
    for package, result in results:
        print(f"- {package.name} {package.version}: {result}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
