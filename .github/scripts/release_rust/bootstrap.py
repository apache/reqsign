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

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from plan import PROJECT_DIR, plan
from publish import parse_retry_after, should_retry
from trusted_publishing import REGISTRY_URL, USER_AGENT

REPOSITORY = "https://github.com/apache/reqsign"
# Published versions keep their original metadata after a repository rename.
LEGACY_REPOSITORY = "https://github.com/apache/opendal-reqsign"
PLACEHOLDER_VERSION = "0.0.0"
APPROVED_PLAN_SCHEMA = 1
PLACEHOLDER_DESCRIPTION = "Namespace reservation for a crate planned by Apache Reqsign."
LEGACY_PLACEHOLDER_DESCRIPTION = (
    "Namespace reservation for a crate planned by Apache OpenDAL reqsign."
)
PUBLISHER = {
    "repository_owner": "apache",
    "repository_name": "reqsign",
    "workflow_filename": "release.yml",
    "environment": "release",
}


class CratesIoClient:
    def __init__(self, token: str | None = None):
        self.token = token

    def request(self, method, path, body=None, *, authenticated=False):
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
        if authenticated:
            assert self.token, "a crates.io bootstrap token is required"
            headers["Authorization"] = self.token
        request = urllib.request.Request(
            f"{REGISTRY_URL}/api/v1/{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def get_crate(self, name):
        try:
            payload = self.request("GET", f"crates/{name}")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            error.close()
            return None
        metadata = payload.get("crate")
        versions = payload.get("versions")
        assert isinstance(metadata, dict), f"{name} returned malformed crate metadata"
        assert isinstance(versions, list), f"{name} returned malformed version history"
        return metadata, versions

    def list_github_configs(self, name):
        return self.request(
            "GET",
            f"trusted_publishing/github_configs?crate={name}&per_page=100",
            authenticated=True,
        )["github_configs"]

    def create_github_config(self, name):
        return self.request(
            "POST",
            "trusted_publishing/github_configs",
            {"github_config": {"crate": name, **PUBLISHER}},
            authenticated=True,
        )["github_config"]

    def set_trustpub_only(self, name):
        return self.request(
            "PATCH",
            f"crates/{name}",
            {"crate": {"trustpub_only": True}},
            authenticated=True,
        )["crate"]


def validate_crate(name, metadata, versions):
    assert metadata["id"] == name, f"crate name mismatch for {name}"
    repository = (metadata["repository"] or "").rstrip("/").removesuffix(".git").lower()
    assert repository in {REPOSITORY, LEGACY_REPOSITORY}, (
        f"{name} has an unexpected repository: {repository}"
    )
    assert isinstance(metadata["max_version"], (str, type(None))), (
        f"{name} has malformed public version metadata"
    )
    assert isinstance(metadata["trustpub_only"], bool), (
        f"{name} has malformed trustpub_only metadata"
    )
    assert isinstance(metadata["num_versions"], int), (
        f"{name} has malformed version count"
    )
    assert len(versions) == metadata["num_versions"], (
        f"{name} returned an incomplete version history"
    )
    assert versions, f"{name} has no versions"
    for version in versions:
        assert isinstance(version, dict), f"{name} has malformed version metadata"
        assert isinstance(version.get("num"), str), (
            f"{name} has malformed version metadata"
        )
        assert isinstance(version.get("yanked"), bool), (
            f"{name} has malformed yanked metadata"
        )
    if all(version["num"] == PLACEHOLDER_VERSION for version in versions):
        assert metadata["description"] in {
            PLACEHOLDER_DESCRIPTION,
            LEGACY_PLACEHOLDER_DESCRIPTION,
        }, f"{name} has an unexpected placeholder"


def validate_publisher(name, configs):
    expected = {"crate": name, **PUBLISHER}
    assert len(configs) == 1 and all(
        configs[0][key] == value for key, value in expected.items()
    ), f"{name} has unexpected Trusted Publishers: {configs}"


def audit(packages, client, *, ready=False):
    """Check every planned crate before any write; return statuses and candidates."""
    statuses = discover(packages, client)
    candidates = []
    for status in statuses:
        if status.kind == "missing":
            assert not ready, f"{status.name} does not exist on crates.io"
            candidates.append(status.name)
            continue
        configs = client.list_github_configs(status.name)
        if not ready and status.kind == "placeholder":
            if configs:
                validate_publisher(status.name, configs)
            candidates.append(status.name)
        else:
            validate_publisher(status.name, configs)
            assert status.trustpub_only is True, (
                f"{status.name} does not require Trusted Publishing"
            )
    return statuses, candidates


def _placeholder_manifest(name: str) -> str:
    return f"""# Licensed to the Apache Software Foundation (ASF) under one
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

[package]
name = {json.dumps(name)}
version = {json.dumps(PLACEHOLDER_VERSION)}
edition = "2024"
rust-version = "1.85.0"
description = {json.dumps(PLACEHOLDER_DESCRIPTION)}
homepage = "https://docs.rs/reqsign"
repository = {json.dumps(REPOSITORY)}
license = "Apache-2.0"
readme = "README.md"
include = ["src/lib.rs", "README.md", "LICENSE", "NOTICE"]
"""


def _placeholder_readme(name: str) -> str:
    return f"""# {name}

This crate belongs to [Apache Reqsign]({REPOSITORY}).

Version {PLACEHOLDER_VERSION} reserves the crates.io package name for Apache Reqsign.
It is not an ASF software release, contains no implementation, and must not be
used as a dependency.
"""


PLACEHOLDER_LIB = """// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![doc = include_str!("../README.md")]
"""


def write_placeholder_package(name: str, package_dir: Path) -> None:
    (package_dir / "src").mkdir()
    (package_dir / "Cargo.toml").write_text(
        _placeholder_manifest(name), encoding="utf-8"
    )
    (package_dir / "README.md").write_text(_placeholder_readme(name), encoding="utf-8")
    (package_dir / "src/lib.rs").write_text(PLACEHOLDER_LIB, encoding="utf-8")
    for filename in ("LICENSE", "NOTICE"):
        shutil.copyfile(PROJECT_DIR / filename, package_dir / filename)


def publish_placeholder(name, token):
    with tempfile.TemporaryDirectory(prefix=f"{name}-bootstrap-") as tmpdir:
        package_dir = Path(tmpdir)
        write_placeholder_package(name, package_dir)
        command = ["cargo", "publish", "--manifest-path", "Cargo.toml"]
        while True:
            process = subprocess.run(
                command,
                cwd=package_dir,
                check=False,
                env={**os.environ, "CARGO_REGISTRY_TOKEN": token},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            print(process.stdout, end="", flush=True)
            if process.returncode == 0:
                return
            if not should_retry(process.stdout):
                process.check_returncode()
            delay = parse_retry_after(process.stdout)
            print(f"crates.io rate limited {name}; sleeping {delay}s", flush=True)
            time.sleep(delay)


def wait_for_crate(client, name, *, ready=False):
    # Public metadata may lag behind a successful publish or settings update.
    deadline = time.monotonic() + 120
    while True:
        record = client.get_crate(name)
        if record is not None:
            metadata, versions = record
            reserved = any(
                version["num"] == PLACEHOLDER_VERSION for version in versions
            )
            if reserved and (not ready or metadata["trustpub_only"] is True):
                validate_crate(name, metadata, versions)
                return record
        assert time.monotonic() < deadline, f"timed out waiting for {name} on crates.io"
        time.sleep(2)


@dataclass(frozen=True)
class CrateStatus:
    name: str
    planned_version: str
    current_version: str | None
    trustpub_only: bool | None
    versions: tuple[str, ...]

    @property
    def kind(self) -> str:
        if not self.versions:
            return "missing"
        if all(version == PLACEHOLDER_VERSION for version in self.versions):
            return "placeholder"
        return "established"


def discover(packages, client) -> list[CrateStatus]:
    statuses = []
    for package in packages:
        record = client.get_crate(package.name)
        if record is None:
            statuses.append(
                CrateStatus(
                    name=package.name,
                    planned_version=package.version,
                    current_version=None,
                    trustpub_only=None,
                    versions=(),
                )
            )
            continue
        metadata, versions = record
        validate_crate(package.name, metadata, versions)
        statuses.append(
            CrateStatus(
                name=package.name,
                planned_version=package.version,
                current_version=metadata["max_version"],
                trustpub_only=metadata["trustpub_only"],
                versions=tuple(version["num"] for version in versions),
            )
        )
    return statuses


def format_discover_report(statuses: list[CrateStatus]) -> str:
    missing = [status for status in statuses if status.kind == "missing"]
    placeholders = [status for status in statuses if status.kind == "placeholder"]
    established = [status for status in statuses if status.kind == "established"]

    lines = [
        f"New crates to publish ({PLACEHOLDER_VERSION} placeholder): {len(missing)}"
    ]
    for status in missing:
        lines.append(f"  - {status.name} (planned {status.planned_version})")

    lines.append(f"Existing {PLACEHOLDER_VERSION} placeholders: {len(placeholders)}")
    for status in placeholders:
        flag = "true" if status.trustpub_only else "false"
        lines.append(
            f"  - {status.name} (planned {status.planned_version}, trustpub_only={flag})"
        )

    lines.append(f"Established crates (audited only): {len(established)}")
    for status in established:
        flag = "true" if status.trustpub_only else "false"
        current = status.current_version or "none (all versions yanked)"
        lines.append(
            f"  - {status.name} (crates.io {current}, "
            f"planned {status.planned_version}, trustpub_only={flag})"
        )

    return "\n".join(lines) + "\n"


def format_discover_summary(statuses: list[CrateStatus]) -> str:
    missing = [status for status in statuses if status.kind == "missing"]
    placeholders = [status for status in statuses if status.kind == "placeholder"]
    established = [status for status in statuses if status.kind == "established"]
    unrestricted_established = [
        status for status in established if status.trustpub_only is not True
    ]

    lines = [
        "## Bootstrap Plan",
        "",
        f"- Workspace publish plan: **{len(statuses)}** crates",
        f"- New crates to publish (`{PLACEHOLDER_VERSION}` placeholder, irreversible): **{len(missing)}**",
        f"- Existing `{PLACEHOLDER_VERSION}` placeholders to reconcile/verify: **{len(placeholders)}**",
        f"- Established crates (audited only, never modified): **{len(established)}**",
    ]

    if unrestricted_established:
        names = ", ".join(f"`{status.name}`" for status in unrestricted_established)
        lines.extend(
            [
                "",
                "> [!WARNING]",
                f"> Established crates without `trustpub_only` enabled will fail the authenticated audit: {names}",
            ]
        )

    lines.extend(
        [
            "",
            "> [!NOTE]",
            "> Established means any non-`0.0.0` version exists in the complete",
            "> version history, including yanked versions. `trustpub_only` is public",
            "> crates.io metadata; the protected job verifies or creates the Trusted",
            "> Publisher with an authenticated token after approval.",
        ]
    )

    lines.extend(
        [
            "",
            "> [!IMPORTANT]",
            "> The protected job only reconciles the missing and placeholder",
            "> crates listed below. It may only first-publish the missing names.",
            "> If another planned crate becomes missing after this preview, it",
            "> stops before any write and requires a new preview.",
        ]
    )

    lines.extend(
        ["", f"### New crates to publish (`{PLACEHOLDER_VERSION}` placeholder)", ""]
    )
    if missing:
        lines.extend(
            [
                "| Crate | Planned version | Action |",
                "| --- | --- | --- |",
            ]
        )
        for status in missing:
            lines.append(
                f"| `{status.name}` | `{status.planned_version}` | "
                f"Publish `{PLACEHOLDER_VERSION}` placeholder after approval; "
                f"verify or create Trusted Publisher, enable `trustpub_only` |"
            )
    else:
        lines.append(
            "None. No new crate names will be published; the protected job will "
            "only reconcile placeholders and run the authenticated audit."
        )

    if placeholders:
        lines.extend(["", f"### Existing `{PLACEHOLDER_VERSION}` placeholders", ""])
        lines.extend(
            [
                "| Crate | Planned version | `trustpub_only` | Action |",
                "| --- | --- | --- | --- |",
            ]
        )
        for status in placeholders:
            flag = "true" if status.trustpub_only else "false"
            action = (
                "Authenticated publisher verification or creation; "
                "`trustpub_only` already enabled"
                if status.trustpub_only
                else "Authenticated publisher verification or creation; "
                "enable `trustpub_only`"
            )
            lines.append(
                f"| `{status.name}` | `{status.planned_version}` | `{flag}` | {action} |"
            )

    if established:
        lines.extend(
            [
                "",
                "<details>",
                f"<summary>Established crates ({len(established)}, audited only)</summary>",
                "",
                "| Crate | Crates.io version | Planned version | `trustpub_only` |",
                "| --- | --- | --- | --- |",
            ]
        )
        for status in established:
            flag = "true" if status.trustpub_only else "false"
            current = status.current_version or "none (all versions yanked)"
            lines.append(
                f"| `{status.name}` | {current} | "
                f"`{status.planned_version}` | `{flag}` |"
            )
        lines.extend(["", "</details>"])

    return "\n".join(lines) + "\n"


def format_apply_summary(total: int, results: list[tuple[str, list[str]]]) -> str:
    lines = [
        "## Bootstrap Result",
        "",
        f"Verified all **{total}** crates on crates.io.",
    ]
    if results:
        lines.extend(
            [
                "",
                "| Crate | Result |",
                "| --- | --- |",
            ]
        )
        for name, actions in results:
            result = ", ".join(actions) if actions else "already ready"
            lines.append(f"| `{name}` | {result} |")
    else:
        lines.extend(["", "No missing crates or placeholders required changes."])
    return "\n".join(lines) + "\n"


def write_step_summary(markdown: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(markdown)


def approved_plan(packages, statuses, dispatch_sha):
    return {
        "schema_version": APPROVED_PLAN_SCHEMA,
        "repository": REPOSITORY,
        "dispatch_sha": dispatch_sha,
        "plan": [
            {"name": package.name, "version": package.version}
            for package in packages
        ],
        "missing": [
            status.name for status in statuses if status.kind == "missing"
        ],
        "writable": [
            status.name
            for status in statuses
            if status.kind in {"missing", "placeholder"}
        ],
    }


def write_approved_plan(path, value) -> None:
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def load_approved_plan(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError(f"cannot read approved plan {path}: {error}") from error


def validate_approved_plan(approved, packages, dispatch_sha):
    assert isinstance(approved, dict), "approved plan must be a JSON object"
    assert approved.get("schema_version") == APPROVED_PLAN_SCHEMA, (
        "approved plan has an unsupported schema"
    )
    assert approved.get("repository") == REPOSITORY, (
        "approved plan is for another repository"
    )
    assert approved.get("dispatch_sha") == dispatch_sha, (
        "approved plan is for another dispatch commit"
    )
    expected_plan = [
        {"name": package.name, "version": package.version}
        for package in packages
    ]
    assert approved.get("plan") == expected_plan, (
        "approved plan does not match the dispatch publish plan"
    )
    missing = approved.get("missing")
    assert isinstance(missing, list), "approved plan has no missing-name list"
    assert all(isinstance(name, str) for name in missing), (
        "approved plan has a malformed missing-name list"
    )
    assert len(missing) == len(set(missing)), (
        "approved plan contains duplicate missing names"
    )
    writable = approved.get("writable")
    assert isinstance(writable, list), "approved plan has no writable-name list"
    assert all(isinstance(name, str) for name in writable), (
        "approved plan has a malformed writable-name list"
    )
    assert len(writable) == len(set(writable)), (
        "approved plan contains duplicate writable names"
    )
    plan_names = [package.name for package in packages]
    missing_names = set(missing)
    writable_names = set(writable)
    assert missing_names <= writable_names, (
        "approved missing names are not writable"
    )
    assert writable_names <= set(plan_names), (
        "approved plan contains an unplanned writable name"
    )
    assert missing == [name for name in plan_names if name in missing_names], (
        "approved missing names must follow the dispatch plan order"
    )
    assert writable == [name for name in plan_names if name in writable_names], (
        "approved writable names must follow the dispatch plan order"
    )
    return missing, writable


def reconcile(name, client, *, approved_missing) -> list[str]:
    actions = []
    record = client.get_crate(name)
    if record is None:
        assert name in approved_missing, (
            f"{name} disappeared after the reviewed plan; rerun the plan job"
        )
        publish_placeholder(name, client.token)
        record = wait_for_crate(client, name)
        actions.append(f"published `{PLACEHOLDER_VERSION}`")
    metadata, versions = record
    validate_crate(name, metadata, versions)
    assert all(version["num"] == PLACEHOLDER_VERSION for version in versions), (
        f"{name} is an established crate; bootstrap must not modify it"
    )
    configs = client.list_github_configs(name)
    if not configs:
        configs = [client.create_github_config(name)]
        actions.append("configured Trusted Publisher")
    validate_publisher(name, configs)
    if metadata["trustpub_only"] is not True:
        updated = client.set_trustpub_only(name)
        assert isinstance(updated, dict) and updated.get("trustpub_only") is True, (
            f"failed to restrict {name}"
        )
        actions.append("enabled `trustpub_only`")
    wait_for_crate(client, name, ready=True)
    print(f"{name}: bootstrapped", flush=True)
    return actions


def apply(packages, approved, client, *, dispatch_sha):
    approved_missing, writable = validate_approved_plan(
        approved, packages, dispatch_sha
    )
    statuses, candidates = audit(packages, client)
    unexpected = [
        status.name
        for status in statuses
        if status.kind == "missing" and status.name not in approved_missing
    ]
    assert not unexpected, (
        "crates missing from crates.io were not in the reviewed plan: "
        f"{', '.join(unexpected)}; rerun the plan job"
    )
    unexpected_writes = [name for name in candidates if name not in writable]
    assert not unexpected_writes, (
        "crates changed state after the reviewed plan: "
        f"{', '.join(unexpected_writes)}; rerun the plan job"
    )
    print(f"Authenticated audit passed; bootstrap candidates: {candidates}", flush=True)
    results = [
        (name, reconcile(name, client, approved_missing=approved_missing))
        for name in candidates
    ]
    audit(packages, client, ready=True)
    print(f"Verified all {len(packages)} crates", flush=True)
    return results


def main():
    parser = argparse.ArgumentParser(description="Bootstrap reqsign crates.io names.")
    parser.add_argument("command", choices=("discover", "apply", "verify"))
    parser.add_argument(
        "--plan-file",
        type=Path,
        help="approved plan artifact from the dispatch plan job (apply)",
    )
    parser.add_argument(
        "--plan-output",
        type=Path,
        help="write the reviewed plan for this dispatch (discover)",
    )
    args = parser.parse_args()
    packages = plan()
    if args.command == "apply":
        assert args.plan_file is not None, "--plan-file is required for apply"
        assert args.plan_output is None, "--plan-output is only valid for discover"
        dispatch_sha = os.environ.get("GITHUB_SHA")
        assert dispatch_sha, "GITHUB_SHA is required for apply"
        approved = load_approved_plan(args.plan_file)
        results = apply(
            packages,
            approved,
            CratesIoClient(os.environ["CARGO_REGISTRY_BOOTSTRAP_TOKEN"]),
            dispatch_sha=dispatch_sha,
        )
        write_step_summary(format_apply_summary(len(packages), results))
        return
    assert args.plan_file is None, "--plan-file is only valid for apply"
    client = CratesIoClient()
    if args.command == "discover":
        statuses = discover(packages, client)
        print(format_discover_report(statuses), end="", flush=True)
        if args.plan_output is not None:
            dispatch_sha = os.environ.get("GITHUB_SHA")
            assert dispatch_sha, "GITHUB_SHA is required to write the approved plan"
            write_approved_plan(
                args.plan_output,
                approved_plan(packages, statuses, dispatch_sha),
            )
        write_step_summary(format_discover_summary(statuses))
        return
    assert args.plan_output is None, "--plan-output is only valid for discover"
    for package in packages:
        record = client.get_crate(package.name)
        assert record is not None, f"{package.name} does not exist on crates.io"
        metadata, versions = record
        validate_crate(package.name, metadata, versions)
        assert metadata["trustpub_only"] is True, (
            f"{package.name} does not require Trusted Publishing"
        )
        print(f"{package.name}: {metadata['max_version']}")


if __name__ == "__main__":
    main()
