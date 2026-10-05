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
from pathlib import Path

from plan import PROJECT_DIR, plan
from publish import parse_retry_after, should_retry
from trusted_publishing import REGISTRY_URL, USER_AGENT

REPOSITORY = "https://github.com/apache/reqsign"
# Published versions keep their original metadata after a repository rename.
LEGACY_REPOSITORY = "https://github.com/apache/opendal-reqsign"
PLACEHOLDER_VERSION = "0.0.0"
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


def validate_crate(name, metadata):
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


def validate_publisher(name, configs):
    expected = {"crate": name, **PUBLISHER}
    assert len(configs) == 1 and all(
        configs[0][key] == value for key, value in expected.items()
    ), f"{name} has unexpected Trusted Publishers: {configs}"


def audit(names, client, *, ready=False):
    """Check every crate before any write; return names eligible for bootstrap."""
    candidates = []
    for name in names:
        metadata = client.get_crate(name)
        if metadata is None:
            assert not ready, f"{name} does not exist on crates.io"
            candidates.append(name)
            continue
        validate_crate(name, metadata)
        configs = client.list_github_configs(name)
        if not ready and metadata["max_version"] == PLACEHOLDER_VERSION:
            if configs:
                validate_publisher(name, configs)
            candidates.append(name)
        else:
            validate_publisher(name, configs)
            assert metadata["trustpub_only"] is True, (
                f"{name} does not require Trusted Publishing"
            )
    return candidates


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
        metadata = client.get_crate(name)
        if metadata is not None and (not ready or metadata["trustpub_only"] is True):
            validate_crate(name, metadata)
            return metadata
        assert time.monotonic() < deadline, f"timed out waiting for {name} on crates.io"
        time.sleep(2)


def reconcile(name, client):
    metadata = client.get_crate(name)
    if metadata is None:
        publish_placeholder(name, client.token)
        metadata = wait_for_crate(client, name)
    validate_crate(name, metadata)
    assert metadata["max_version"] == PLACEHOLDER_VERSION, (
        f"{name} is an established crate; bootstrap must not modify it"
    )
    configs = client.list_github_configs(name)
    if not configs:
        configs = [client.create_github_config(name)]
    validate_publisher(name, configs)
    if metadata["trustpub_only"] is not True:
        updated = client.set_trustpub_only(name)
        assert updated["trustpub_only"] is True, f"failed to restrict {name}"
    wait_for_crate(client, name, ready=True)
    print(f"{name}: bootstrapped", flush=True)


def apply(names, client):
    candidates = audit(names, client)
    print(f"Authenticated audit passed; bootstrap candidates: {candidates}", flush=True)
    for name in candidates:
        reconcile(name, client)
    audit(names, client, ready=True)
    print(f"Verified all {len(names)} crates", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Bootstrap reqsign crates.io names.")
    parser.add_argument("command", choices=("discover", "apply", "verify"))
    command = parser.parse_args().command
    names = [package.name for package in plan()]
    if command == "apply":
        apply(names, CratesIoClient(os.environ["CARGO_REGISTRY_BOOTSTRAP_TOKEN"]))
        return
    client = CratesIoClient()
    for name in names:
        metadata = client.get_crate(name)
        if metadata is not None:
            validate_crate(name, metadata)
        if command == "verify":
            assert metadata is not None, f"{name} does not exist on crates.io"
            assert metadata["trustpub_only"] is True, (
                f"{name} does not require Trusted Publishing"
            )
        version = metadata["max_version"] if metadata else "missing"
        print(f"{name}: {version}")


if __name__ == "__main__":
    main()
