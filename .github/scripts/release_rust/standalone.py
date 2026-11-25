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

"""Stage the standalone manifests the way `cargo publish --workspace` stages members.

`crypto/boring` is excluded from the root workspace, so the workspace dry run
never packages it. A plain `cargo publish --manifest-path
crypto/boring/Cargo.toml --dry-run` also cannot resolve the planned but
unpublished local path dependencies. This command patches those dependencies
from the checkout, which is the same source set the workspace staging uses,
runs the packaging step for every standalone manifest, and checks the
produced package. It deliberately skips Cargo's verification build:
building BoringSSL stays in the `crypto_boring` workflow, and release
validation must not need CMake.
"""

import json
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

from plan import (
    PROJECT_DIR,
    STANDALONE_MANIFESTS,
    Package,
    local_packages,
    plan,
)

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
REQUIRED_FILES = ("Cargo.toml", "LICENSE", "NOTICE", "README.md", "src/lib.rs")


def local_path_dependencies(manifest: str) -> dict[str, Path]:
    """Every local package Cargo resolves while packaging this manifest.

    The standalone package is also resolved for its tests, so its own dev
    path dependencies participate. Packages it depends on are resolved as
    libraries, so only their normal and build dependencies expand.
    """
    local = local_packages()
    root = (PROJECT_DIR / manifest).parent
    assert root in local, f"{manifest} is not a known local package"
    required: dict[str, Path] = {}
    queue = [(root, True)]
    seen = {root}
    while queue:
        path, include_dev = queue.pop()
        for dependency in local[path]["dependencies"]:
            if "path" not in dependency:
                continue
            if dependency["kind"] == "dev" and not include_dev:
                continue
            dependency_path = Path(dependency["path"])
            required.setdefault(dependency["name"], dependency_path)
            if dependency_path in local and dependency_path not in seen:
                seen.add(dependency_path)
                queue.append((dependency_path, False))
    return required


def patch_configs(manifest: str) -> list[str]:
    return [
        f"patch.crates-io.{name}.path={json.dumps(str(path))}"
        for name, path in local_path_dependencies(manifest).items()
    ]


def dependency_entries(manifest: dict) -> list[tuple[str, object]]:
    entries: list[tuple[str, object]] = []
    for table in DEPENDENCY_TABLES:
        entries.extend(manifest.get(table, {}).items())
    for target in manifest.get("target", {}).values():
        for table in DEPENDENCY_TABLES:
            entries.extend(target.get(table, {}).items())
    return entries


def verify_crate(crate: Path, package: Package, planned: dict[str, str]) -> None:
    prefix = f"{package.name}-{package.version}/"
    with tarfile.open(crate) as archive:
        names = {name.removeprefix(prefix) for name in archive.getnames()}
        for required in REQUIRED_FILES:
            assert required in names, (
                f"{package.name} package is missing {required}"
            )
        manifest = tomllib.load(archive.extractfile(prefix + "Cargo.toml"))
    for name, spec in dependency_entries(manifest):
        if name not in planned:
            continue
        assert isinstance(spec, dict), (
            f"{package.name} normalizes its {name} dependency unexpectedly"
        )
        assert "path" not in spec, (
            f"{package.name} package keeps a path dependency on {name}"
        )
        version = spec.get("version")
        assert version == planned[name], (
            f"{package.name} depends on {name} = {version!r}, "
            f"but the plan publishes {planned[name]!r}"
        )


def check() -> int:
    packages = plan()
    by_manifest = {package.manifest: package for package in packages}
    for manifest in STANDALONE_MANIFESTS:
        package = by_manifest.get(manifest)
        assert package is not None, (
            f"{manifest} is listed as standalone but is not in the publish plan"
        )
        patches = patch_configs(manifest)
        with tempfile.TemporaryDirectory(prefix="reqsign-standalone-") as target:
            command = [
                "cargo",
                "package",
                "--no-verify",
                # The release manager runs the same check during preparation,
                # where the working tree may still carry uncommitted edits.
                "--allow-dirty",
                "--manifest-path",
                manifest,
                "--target-dir",
                target,
            ]
            for patch in patches:
                command += ["--config", patch]
            subprocess.run(command, cwd=PROJECT_DIR, check=True)
            crate = (
                Path(target) / "package" / f"{package.name}-{package.version}.crate"
            )
            assert crate.is_file(), f"{crate} was not produced"
            verify_crate(crate, package, {p.name: p.version for p in packages})
        print(
            f"{manifest}: packaged {package.name} {package.version} with "
            f"{len(patches)} staged local dependencies",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
