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

"""Check the RustCrypto algorithm feature surface and facade mappings."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tomllib

BACKEND_FEATURES = {"default", "rsa", "p256", "aes-gcm"}
BACKEND_DEFAULT = ["rsa", "p256", "aes-gcm"]
FACADE_ALGORITHM_FEATURES = {"rsa", "p256", "aes-gcm"}
FACADE_WEAK_MAPPINGS = {
    "aws-v4a": "p256",
    "azure": "rsa",
    "google": "rsa",
    "oracle": "rsa",
    "http-message-signatures": "rsa",
}
REMOVED_FACADE_FEATURES = {"google-credential-access-boundary-client-side"}


def load_manifest(path: Path) -> dict:
    with path.open("rb") as file:
        return tomllib.load(file)


def cargo_metadata(root: Path) -> dict:
    output = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(output)


def package(metadata: dict, name: str) -> dict:
    for candidate in metadata["packages"]:
        if candidate["name"] == name:
            return candidate
    raise AssertionError(f"package {name!r} is missing from cargo metadata")


def check_backend(root: Path, metadata: dict) -> None:
    manifest = load_manifest(root / "crypto/rustcrypto/Cargo.toml")
    features = manifest["features"]
    assert set(features) == BACKEND_FEATURES, (
        f"unexpected backend features: {sorted(features)}"
    )
    assert features["default"] == BACKEND_DEFAULT, (
        f"unexpected backend defaults: {features['default']}"
    )
    assert features["rsa"] == ["dep:rsa"], features["rsa"]
    assert features["p256"] == ["dep:p256"], features["p256"]
    assert features["aes-gcm"] == ["dep:aes-gcm", "dep:getrandom"], features["aes-gcm"]

    dependencies = manifest["dependencies"]
    assert dependencies["p256"].get("optional") is True, "p256 must be optional"
    assert dependencies["p256"].get("default-features") is False, (
        "p256 must disable default features"
    )

    target_dependencies = manifest["target"]['cfg(not(target_arch = "wasm32"))'][
        "dependencies"
    ]
    for name in ("rsa", "aes-gcm", "getrandom"):
        assert target_dependencies[name].get("optional") is True, (
            f"{name} must be optional"
        )
    assert target_dependencies["aes-gcm"].get("default-features") is False, (
        "aes-gcm must disable default features"
    )

    package_features = package(metadata, "reqsign-crypto-rustcrypto")["features"]
    assert set(package_features) == BACKEND_FEATURES, (
        f"cargo metadata exposes extra backend features: {sorted(package_features)}"
    )


def check_facade(root: Path) -> None:
    manifest = load_manifest(root / "reqsign/Cargo.toml")
    features = manifest["features"]
    assert not (set(features) & FACADE_ALGORITHM_FEATURES), (
        "the facade must not expose algorithm features"
    )
    assert not (set(features) & REMOVED_FACADE_FEATURES), (
        "removed facade features are still present"
    )
    assert features["default-crypto"] == ["dep:reqsign-crypto-rustcrypto"], (
        "default-crypto must only enable the backend dependency"
    )

    for feature, algorithm in FACADE_WEAK_MAPPINGS.items():
        mapping = f"reqsign-crypto-rustcrypto?/{algorithm}"
        assert mapping in features[feature], f"{feature} must include {mapping}"

    for feature, values in features.items():
        if feature == "default-crypto":
            continue
        for value in values:
            assert not value.startswith("reqsign-crypto-rustcrypto/"), (
                f"{feature} strongly enables the backend: {value}"
            )
            if value.startswith("reqsign-crypto-rustcrypto?/"):
                expected = FACADE_WEAK_MAPPINGS.get(feature)
                assert expected is not None, f"unexpected weak mapping in {feature}"
                assert value == f"reqsign-crypto-rustcrypto?/{expected}", (
                    f"unexpected weak mapping in {feature}: {value}"
                )

    workspace = load_manifest(root / "Cargo.toml")["workspace"]["dependencies"]
    backend = workspace["reqsign-crypto-rustcrypto"]
    assert backend.get("default-features") is False, (
        "workspace backend dependency must disable default features"
    )

    assert "google" in features["full"], "full must keep the google service feature"
    assert "google-credential-access-boundary-client-side" not in features["full"], (
        "full must not include the removed CAB feature"
    )


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    root = root.resolve()
    metadata = cargo_metadata(root)
    check_backend(root, metadata)
    check_facade(root)
    print("crypto feature surface and facade mappings are clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
