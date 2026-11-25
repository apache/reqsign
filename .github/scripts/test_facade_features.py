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

"""Build and behavior-test every facade service feature in isolation.

Each probe is a downstream package built with only the facade feature under
test. Each service runs in its own Cargo invocation, so feature resolution is
not unified with another service. With `default-crypto`, the probe exercises
the actual crypto operations selected by the facade mapping; without it, the
probe verifies that the service feature alone does not pull the crypto backend.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
FACADE_MANIFEST = ROOT / "reqsign/Cargo.toml"
RSA_FIXTURE = ROOT / "crypto/rustcrypto/tests/fixtures/rsa_pkcs8.pem"

# Facade service feature -> backend algorithm features. Keep in sync with
# reqsign/Cargo.toml; the script fails when a facade feature is added or removed.
SERVICE_ALGORITHMS = {
    "aliyun": set(),
    "aliyun-drive": set(),
    "aws": set(),
    "aws-v4": set(),
    "aws-v4a": {"p256"},
    "azure": {"rsa"},
    "b2": set(),
    "baidu-netdisk": set(),
    "cloudflare": set(),
    "dropbox": set(),
    "github": set(),
    "google": {"rsa"},
    "huaweicloud": set(),
    "http-message-signatures": {"rsa"},
    "koofr": set(),
    "oauth2": set(),
    "onedrive": set(),
    "openstack": set(),
    "oracle": {"rsa"},
    "seafile": set(),
    "tencent": set(),
    "upyun": set(),
    "vercel": set(),
    "volcengine": set(),
    "yandex-disk": set(),
}
NON_SERVICE_FEATURES = {"default", "default-context", "default-crypto", "full"}

PROBE_MAIN = r'''
#[cfg(feature = "default-crypto")]
use std::env;

#[cfg(feature = "default-crypto")]
use reqsign::crypto::CryptoProvider;
#[cfg(feature = "default-crypto")]
use reqsign::{ErrorKind, RustCryptoProvider};

#[cfg(feature = "default-crypto")]
const RSA_PKCS8: &[u8] = include_bytes!("rsa_pkcs8.pem");

#[cfg(feature = "default-crypto")]
fn assert_missing(err: reqsign::Error, feature: &str) {
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(
        err.to_string().contains(&format!("`{feature}`")),
        "error did not name the `{feature}` feature: {err}"
    );
}

#[cfg(feature = "default-crypto")]
fn main() {
    let service = env::var("REQSIGN_PROBE_SERVICE").expect("service name");
    let expected_raw = env::var("REQSIGN_PROBE_EXPECTED").expect("expected features");
    let expected: Vec<&str> = if expected_raw.is_empty() {
        Vec::new()
    } else {
        expected_raw.split(',').collect()
    };
    let provider = RustCryptoProvider::new();

    // Hash and HMAC operations are unconditional.
    provider.sha1(b"abc").expect("SHA-1 must always work");
    provider.sha256(b"abc").expect("SHA-256 must always work");
    provider.md5(b"abc").expect("MD5 must always work");
    provider
        .hmac_sha1(b"key", b"message")
        .expect("HMAC-SHA1 must always work");
    provider
        .hmac_sha256(b"key", b"message")
        .expect("HMAC-SHA256 must always work");
    provider
        .hmac_sha512(b"key", b"message")
        .expect("HMAC-SHA512 must always work");

    if expected.contains(&"rsa") {
        provider
            .rsa_pkcs1v15_sha256_sign(RSA_PKCS8, b"message")
            .expect("RSA must be enabled");
    } else {
        let err = provider
            .rsa_pkcs1v15_sha256_sign(RSA_PKCS8, b"message")
            .expect_err("RSA must be disabled");
        assert_missing(err, "rsa");
    }

    if expected.contains(&"p256") {
        provider
            .ecdsa_p256_sha256_sign(&[7u8; 32], b"message")
            .expect("P-256 must be enabled");
    } else {
        let err = provider
            .ecdsa_p256_sha256_sign(&[7u8; 32], b"message")
            .expect_err("P-256 must be disabled");
        assert_missing(err, "p256");
    }

    if expected.contains(&"aes-gcm") {
        provider
            .aes_gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", b"message")
            .expect("AES-GCM must be enabled");
        let mut random = [0u8; 16];
        provider
            .fill_random(&mut random)
            .expect("random generation must be enabled");
    } else {
        let err = provider
            .aes_gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", b"message")
            .expect_err("AES-GCM must be disabled");
        assert_missing(err, "aes-gcm");
        let mut random = [0u8; 16];
        let err = provider
            .fill_random(&mut random)
            .expect_err("random generation must be disabled");
        assert_missing(err, "aes-gcm");
    }

    println!("{service}: ok ({expected_raw})");
}

#[cfg(not(feature = "default-crypto"))]
fn main() {
    println!("service alone builds without the crypto backend");
}
'''


def cargo(args: list[str], cwd: Path, target_dir: Path, env: dict | None = None) -> str:
    process_env = os.environ.copy()
    process_env["CARGO_TARGET_DIR"] = str(target_dir)
    if env:
        process_env.update(env)
    result = subprocess.run(
        ["cargo", *args],
        cwd=cwd,
        env=process_env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, result.args)
    return result.stdout + result.stderr


def facade_features() -> dict[str, list[str]]:
    with FACADE_MANIFEST.open("rb") as file:
        return tomllib.load(file)["features"]


def service_features(features: dict[str, list[str]]) -> list[str]:
    names = sorted(set(features) - NON_SERVICE_FEATURES)
    missing = sorted(set(names) - set(SERVICE_ALGORITHMS))
    extra = sorted(set(SERVICE_ALGORITHMS) - set(names))
    assert not missing, f"add algorithm expectations for new facade features: {missing}"
    assert not extra, f"remove algorithm expectations for removed features: {extra}"
    return names


def expected_algorithms(name: str) -> set[str]:
    if name == "full":
        algorithms: set[str] = set()
        for mapping in SERVICE_ALGORITHMS.values():
            algorithms.update(mapping)
        return algorithms
    return SERVICE_ALGORITHMS[name]


def write_probe(probe: Path, features: dict[str, list[str]]) -> None:
    (probe / "src").mkdir(parents=True)
    shutil.copyfile(RSA_FIXTURE, probe / "src/rsa_pkcs8.pem")
    (probe / "src/main.rs").write_text(PROBE_MAIN)

    forwarded = []
    for name in sorted(features):
        if name == "default":
            continue
        forwarded.append(f'"{name}" = ["reqsign/{name}"]')
    manifest = f'''[package]
name = "reqsign-facade-feature-probe"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
reqsign = {{ path = "{ROOT / "reqsign"}", default-features = false }}

[features]
default = []
{os.linesep.join(forwarded)}
'''
    (probe / "Cargo.toml").write_text(manifest)


def run_probe(
    probe: Path,
    target_dir: Path,
    service: str,
    expected: set[str],
) -> None:
    expected_text = ",".join(sorted(expected))

    cargo(
        [
            "run",
            "--quiet",
            "--no-default-features",
            "--features",
            f"default-crypto,{service}",
        ],
        cwd=probe,
        target_dir=target_dir,
        env={
            "REQSIGN_PROBE_SERVICE": service,
            "REQSIGN_PROBE_EXPECTED": expected_text,
        },
    )

    cargo(
        ["check", "--quiet", "--no-default-features", "--features", service],
        cwd=probe,
        target_dir=target_dir,
    )
    tree = cargo(
        [
            "tree",
            "--no-default-features",
            "--features",
            service,
            "--edges",
            "normal",
            "--prefix",
            "none",
        ],
        cwd=probe,
        target_dir=target_dir,
    )
    leaked = [
        line
        for line in tree.splitlines()
        if line.startswith(("reqsign-crypto-rustcrypto v", "rsa v", "p256 v", "aes-gcm v"))
    ]
    assert not leaked, f"{service} alone pulled crypto dependencies: {leaked}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--service",
        action="append",
        help="probe only this facade feature (repeatable; default: all)",
    )
    args = parser.parse_args(argv[1:])

    features = facade_features()
    services = service_features(features)
    if args.service:
        unknown = sorted(set(args.service) - set(services) - {"full"})
        assert not unknown, f"unknown facade features: {unknown}"
        selected = args.service
    else:
        selected = services + ["full"]

    with tempfile.TemporaryDirectory(prefix="reqsign-facade-features-") as temp:
        temp_path = Path(temp)
        probe = temp_path / "probe"
        target_dir = temp_path / "target"
        write_probe(probe, features)
        for service in selected:
            print(f"probing {service}...", flush=True)
            run_probe(probe, target_dir, service, expected_algorithms(service))
    print("all facade service features are isolated and mapped correctly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
