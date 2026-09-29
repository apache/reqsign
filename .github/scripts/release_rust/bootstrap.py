#!/usr/bin/env python3
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

from plan import PROJECT_DIR
from plan import plan
from publish import parse_retry_after
from publish import should_retry


REGISTRY_URL = "https://crates.io"
REPOSITORY = "https://github.com/apache/reqsign"
# Published versions retain their original manifest metadata after a repo rename.
LEGACY_REPOSITORY = "https://github.com/apache/opendal-reqsign"
PLACEHOLDER_VERSION = "0.0.0"
PLACEHOLDER_DESCRIPTION = (
    "Namespace reservation for a crate planned by Apache Reqsign."
)
# Published placeholders retain their original description after a project rename.
LEGACY_PLACEHOLDER_DESCRIPTION = (
    "Namespace reservation for a crate planned by Apache OpenDAL reqsign."
)
PUBLISHER = {
    "repository_owner": "apache",
    "repository_name": "reqsign",
    "workflow_filename": "release.yml",
    "environment": "release",
}
USER_AGENT = (
    "apache-reqsign-release-bootstrap/1.0 "
    "(https://github.com/apache/reqsign)"
)


@dataclass(frozen=True)
class PlannedCrate:
    name: str
    path: str


@dataclass(frozen=True)
class ReconcileResult:
    name: str
    actions: tuple[str, ...]


def planned_crates(project_dir: Path = PROJECT_DIR) -> list[PlannedCrate]:
    packages = [
        PlannedCrate(name=package.name, path=package.path)
        for package in plan(project_dir.resolve())
    ]
    names = [package.name for package in packages]
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate crates.io package name in publish plan")
    return packages


class CratesIoClient:
    def __init__(self, registry_url: str = REGISTRY_URL, token: str | None = None):
        self.registry_url = registry_url.rstrip("/")
        self.token = token

    def request(self, method, path, body=None, *, authenticated=False):
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
        if authenticated:
            assert self.token, "a crates.io bootstrap token is required"
            headers["Authorization"] = self.token
        request = urllib.request.Request(
            f"{self.registry_url}/api/v1/{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def get_crate(self, name):
        try:
            return self.request("GET", f"crates/{name}")["crate"]
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            error.close()
            return None

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

def validate_crate_metadata(planned, metadata, client):
    name = planned.name
    assert metadata["id"] == name, f"crate name mismatch for {name}"
    repository = (metadata["repository"] or "").rstrip("/").removesuffix(".git").lower()
    assert repository in {REPOSITORY, LEGACY_REPOSITORY}, (
        f"{name} has an unexpected repository: {repository}"
    )
    if metadata["max_version"] == PLACEHOLDER_VERSION:
        assert metadata["description"] in {
            PLACEHOLDER_DESCRIPTION,
            LEGACY_PLACEHOLDER_DESCRIPTION,
        }, f"{name} has an unexpected placeholder"


def validate_github_configs(name, configs):
    expected = {"crate": name, **PUBLISHER}
    assert len(configs) == 1 and all(
        configs[0][key] == value for key, value in expected.items()
    ), f"{name} has unexpected Trusted Publishers: {configs}"


def preflight_authenticated(
    packages: list[PlannedCrate],
    candidate_names: set[str],
    client: CratesIoClient,
) -> list[str]:
    verified: list[str] = []
    for planned in packages:
        metadata = client.get_crate(planned.name)
        is_candidate = planned.name in candidate_names
        if metadata is None:
            if not is_candidate:
                raise RuntimeError(
                    f"{planned.name} is missing but was not selected for bootstrap"
                )
            verified.append(planned.name)
            continue

        validate_crate_metadata(planned, metadata, client)
        is_placeholder = metadata.get("max_version") == PLACEHOLDER_VERSION
        if is_placeholder != is_candidate:
            state = "a placeholder" if is_placeholder else "an established crate"
            raise RuntimeError(
                f"{planned.name} is now {state}, which does not match discovery"
            )

        configs = client.list_github_configs(planned.name)
        if is_placeholder:
            if configs:
                validate_github_configs(planned.name, configs)
        else:
            validate_github_configs(planned.name, configs)
            if metadata.get("trustpub_only") is not True:
                raise RuntimeError(
                    f"{planned.name} does not require Trusted Publishing"
                )
        verified.append(planned.name)
    return verified


def verify_authenticated(
    packages: list[PlannedCrate], client: CratesIoClient
) -> list[str]:
    verified: list[str] = []
    for planned in packages:
        metadata = client.get_crate(planned.name)
        if metadata is None:
            raise RuntimeError(f"{planned.name} does not exist on crates.io")
        validate_crate_metadata(planned, metadata, client)
        validate_github_configs(planned.name, client.list_github_configs(planned.name))
        if metadata.get("trustpub_only") is not True:
            raise RuntimeError(f"{planned.name} does not require Trusted Publishing")
        verified.append(planned.name)
    return verified


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


def write_placeholder_package(
    project_dir: Path, planned: PlannedCrate, package_dir: Path
) -> None:
    source_dir = package_dir / "src"
    source_dir.mkdir()
    (package_dir / "Cargo.toml").write_text(
        _placeholder_manifest(planned.name), encoding="utf-8"
    )
    (package_dir / "README.md").write_text(
        _placeholder_readme(planned.name), encoding="utf-8"
    )
    (source_dir / "lib.rs").write_text(PLACEHOLDER_LIB, encoding="utf-8")
    shutil.copyfile(project_dir / "LICENSE", package_dir / "LICENSE")
    shutil.copyfile(project_dir / "NOTICE", package_dir / "NOTICE")


def publish_placeholder(project_dir: Path, planned: PlannedCrate, token: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"{planned.name}-bootstrap-") as tmpdir:
        package_dir = Path(tmpdir)
        write_placeholder_package(project_dir, planned, package_dir)

        env = os.environ.copy()
        env["CARGO_REGISTRY_TOKEN"] = token
        command = ["cargo", "publish", "--manifest-path", "Cargo.toml"]
        while True:
            process = subprocess.run(
                command,
                cwd=package_dir,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output = process.stdout or ""
            print(output, end="", flush=True)
            if process.returncode == 0:
                return
            if should_retry(output):
                delay = parse_retry_after(output)
                print(
                    f"crates.io rate limited {planned.name}; sleeping {delay}s",
                    flush=True,
                )
                time.sleep(delay)
                continue
            raise subprocess.CalledProcessError(
                process.returncode, command, output=output
            )


def wait_for_crate(
    client: CratesIoClient, name: str, timeout: int = 120
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while True:
        metadata = client.get_crate(name)
        if metadata is not None:
            return metadata
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out waiting for {name} to become visible on crates.io"
            )
        time.sleep(2)


def wait_for_trustpub_only(
    client: CratesIoClient, name: str, timeout: int = 120
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while True:
        metadata = client.get_crate(name)
        if metadata is not None and metadata.get("trustpub_only") is True:
            return metadata
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out waiting for {name} to require Trusted Publishing"
            )
        time.sleep(2)


def wait_for_expected_config(
    client: CratesIoClient, name: str, timeout: int = 120
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        configs = client.list_github_configs(name)
        if configs:
            validate_github_configs(name, configs)
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out waiting for the Trusted Publisher for {name}"
            )
        time.sleep(2)


def reconcile_crate(
    project_dir: Path,
    planned: PlannedCrate,
    client: CratesIoClient,
    token: str,
) -> ReconcileResult:
    actions: list[str] = []
    metadata = client.get_crate(planned.name)
    if metadata is None:
        publish_placeholder(project_dir, planned, token)
        metadata = wait_for_crate(client, planned.name)
        actions.append("created placeholder")
    elif metadata.get("max_version") != PLACEHOLDER_VERSION:
        raise RuntimeError(
            f"{planned.name} became an established crate after discovery; "
            "refusing to modify it in the bootstrap workflow"
        )

    validate_crate_metadata(planned, metadata, client)

    configs = client.list_github_configs(planned.name)
    if not configs:
        created = client.create_github_config(planned.name)
        validate_github_configs(planned.name, [created])
        actions.append("configured Trusted Publishing")
    else:
        validate_github_configs(planned.name, configs)

    if metadata.get("trustpub_only") is not True:
        updated = client.set_trustpub_only(planned.name)
        if updated.get("trustpub_only") is not True:
            raise RuntimeError(
                f"crates.io did not enable Trusted Publishing only for {planned.name}"
            )
        actions.append("enabled Trusted Publishing only")

    verified_metadata = wait_for_trustpub_only(client, planned.name)
    validate_crate_metadata(planned, verified_metadata, client)
    wait_for_expected_config(client, planned.name)

    if not actions:
        actions.append("verified")
    return ReconcileResult(planned.name, tuple(actions))


def discover(
    project_dir: Path, client: CratesIoClient
) -> tuple[list[PlannedCrate], list[str], list[str]]:
    packages = planned_crates(project_dir)
    missing: list[str] = []
    placeholders: list[str] = []
    for planned in packages:
        metadata = client.get_crate(planned.name)
        if metadata is None:
            missing.append(planned.name)
            continue
        validate_crate_metadata(planned, metadata, client)
        if metadata.get("max_version") == PLACEHOLDER_VERSION:
            placeholders.append(planned.name)
    return packages, missing, placeholders


def verify_public(project_dir: Path, client: CratesIoClient) -> list[str]:
    verified: list[str] = []
    for planned in planned_crates(project_dir):
        metadata = client.get_crate(planned.name)
        if metadata is None:
            raise RuntimeError(f"{planned.name} does not exist on crates.io")
        validate_crate_metadata(planned, metadata, client)
        if metadata.get("trustpub_only") is not True:
            raise RuntimeError(f"{planned.name} does not require Trusted Publishing")
        verified.append(planned.name)
    return verified


def run_discover(args: argparse.Namespace) -> int:
    client = CratesIoClient(args.registry_url)
    packages, missing, placeholders = discover(args.project_dir, client)
    candidates = [*missing, *placeholders]
    result = {
        "packages": len(packages),
        "missing": missing,
        "placeholders": placeholders,
        "bootstrap_candidates": candidates,
    }
    print(json.dumps(result, indent=2))
    return 0


def run_apply(args: argparse.Namespace) -> int:
    token = os.environ.get("CARGO_REGISTRY_BOOTSTRAP_TOKEN")
    if not token:
        raise RuntimeError("CARGO_REGISTRY_BOOTSTRAP_TOKEN is not set")

    client = CratesIoClient(args.registry_url, token=token)
    packages, missing, placeholders = discover(args.project_dir, client)
    candidate_set = {*missing, *placeholders}
    candidates = [package for package in packages if package.name in candidate_set]

    preflight_authenticated(packages, candidate_set, client)
    print(f"authenticated preflight passed for {len(packages)} planned crates", flush=True)
    print(f"bootstrap candidates: {len(candidates)}", flush=True)
    for planned in candidates:
        result = reconcile_crate(args.project_dir, planned, client, token)
        print(f"{result.name}: {', '.join(result.actions)}", flush=True)
    authenticated = verify_authenticated(packages, client)
    print(f"authenticated final audit passed for {len(authenticated)} planned crates", flush=True)
    return 0


def run_verify(args: argparse.Namespace) -> int:
    verified = verify_public(args.project_dir, CratesIoClient(args.registry_url))
    print(json.dumps({"verified": verified}, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create and secure crates.io names in the reqsign Rust publish plan."
        )
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=PROJECT_DIR,
        help="Path to the repository root.",
    )
    parser.add_argument(
        "--registry-url",
        default=REGISTRY_URL,
        help="crates.io-compatible registry API URL.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser(
        "discover", help="Report missing and placeholder crate names."
    )
    discover_parser.set_defaults(run=run_discover)

    apply_parser = subparsers.add_parser(
        "apply",
        help="Audit all planned crates and reconcile missing names and placeholders.",
    )
    apply_parser.set_defaults(run=run_apply)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify public crate existence and Trusted Publishing only."
    )
    verify_parser.set_defaults(run=run_verify)

    args = parser.parse_args()
    args.project_dir = args.project_dir.resolve()
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
