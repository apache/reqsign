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

"""Verify the downloaded Apache Reqsign source RC in the current directory (Python 3.12+)."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from functools import partial
from pathlib import Path
from urllib.request import urlopen

KEYS = "https://downloads.apache.org/reqsign/KEYS"


def download(url, dest):
    print(f"Download {url}", flush=True)
    with urlopen(url, timeout=90) as response, dest.open("wb") as output:
        shutil.copyfileobj(response, output)


def run_and_echo_stdout(command, *, cwd=None, env=None, stderr=None):
    """Keep stdout visible even when the verifier needs to parse it."""
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=stderr,
        text=True,
        check=False,
    )
    print(result.stdout, end="", flush=True)
    return result


def check_signature(command, env):
    result = run_and_echo_stdout(command, env=env, stderr=subprocess.STDOUT)
    # GnuPG can return zero for a mathematically valid but expired signature.
    statuses = [
        line.split()
        for line in result.stdout.splitlines()
        if line.startswith("[GNUPG:] ")
    ]
    valid = [s[2] for s in statuses if s[1] == "VALIDSIG"]
    if (
        result.returncode
        or len(valid) != 1
        or not any(s[1] == "GOODSIG" for s in statuses)
    ):
        raise ValueError("signature verification failed")
    print(f"  verified signature by {valid[0]}", flush=True)


def verify_download(work):
    candidates = sorted(Path.cwd().glob("apache-reqsign-*.tar.gz"))
    if len(candidates) != 1:
        raise ValueError(
            f"expected one apache-reqsign-*.tar.gz in {Path.cwd()}, found {len(candidates)}"
        )
    filename = candidates[0].name
    for name in (filename, filename + ".sha512", filename + ".asc"):
        shutil.copyfile(name, work / name)

    archive = work / filename
    checksum = (work / (filename + ".sha512")).read_text().strip()
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha512").hexdigest()
    if not re.fullmatch(digest + r" [ *]" + re.escape(filename), checksum):
        raise ValueError(f"SHA-512 or checksum filename mismatch for {filename}")
    print(f"  verified SHA-512 for {filename}", flush=True)

    keyring = work / "gnupg"
    keyring.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(keyring))
    download(KEYS, work / "KEYS")
    gpg = ["gpg", "--batch", "--no-options", "--no-auto-key-retrieve"]
    subprocess.run([*gpg, "--import", work / "KEYS"], env=env, check=True)
    check_signature(
        [*gpg, "--status-fd=1", "--verify", work / (filename + ".asc"), archive], env
    )

    return archive


def extract_source(archive, destination):
    root = archive.name.removesuffix(".tar.gz")
    with tarfile.open(archive, "r:gz") as package:
        for member in package:
            if Path(member.name).parts[:1] != (root,) or ".." in Path(member.name).parts:
                raise ValueError(f"unexpected archive path: {member.name}")
            if member.isfile():
                data = package.extractfile(member).read()
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    raise ValueError(f"unexpected binary file: {member.name}") from None
                if re.search(rb"[\x00-\x08\x0b\x0e-\x1f\x7f]", data):
                    raise ValueError(f"unexpected binary file: {member.name}")
        package.extractall(destination, filter="data")
    return destination / root


def license_headers(source):
    result = run_and_echo_stdout(
        ["hawkeye", "--output-format", "json", "check"], cwd=source
    )
    if not result.stdout.strip():
        raise ValueError("Hawkeye returned no report")
    files = json.loads(result.stdout).get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("Hawkeye reported no checked files")
    problems = [
        f"{f['path']} ({f['outcome']})" for f in files if f["outcome"] != "clean"
    ]
    # Older RCs have a narrower Hawkeye configuration. Also inspect source
    # files outside its selection, before Cargo creates any build products.
    covered = {source / f["path"] for f in files}
    source_types = {".rs", ".py", ".sh", ".js", ".jsx", ".mjs", ".css", ".mdx"}
    for path in sorted(source.rglob("*")):
        if path.suffix in source_types and path not in covered and path.is_file():
            with path.open("rb") as stream:
                header = stream.read(2048)
            if b"Licensed to the Apache Software Foundation (ASF)" not in header:
                problems.append(f"{path.relative_to(source)} (missing ASF header)")
    if problems or result.returncode:
        raise ValueError(
            "\n".join(problems) or f"Hawkeye exited with status {result.returncode}"
        )


def check_source(source, full):
    results = []

    def check(label, action):
        print(f"\nChecking {label}", flush=True)
        try:
            action()
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            results.append((label, str(error)))
        else:
            results.append((label, None))

    def legal_files():
        missing = [
            name
            for name in ("LICENSE", "NOTICE")
            if not (source / name).is_file() or not (source / name).stat().st_size
        ]
        if missing:
            raise ValueError("missing or empty: " + ", ".join(missing))

    check("LICENSE and NOTICE", legal_files)
    check("ASF source headers", partial(license_headers, source))
    commands = [
        ("workspace build", ["cargo", "build", "--workspace"]),
        (
            "workspace tests",
            ["cargo", "test", "--workspace", "--all-features", "--no-fail-fast"],
        ),
    ]
    if full:
        commands += [
            (
                "workspace publish dry run",
                ["cargo", "publish", "--workspace", "--dry-run", "--allow-dirty"],
            ),
            (
                "standalone packaging",
                [sys.executable, ".github/scripts/release_rust/standalone.py"],
            ),
            (
                "BoringSSL tests",
                ["cargo", "test", "--manifest-path", "crypto/boring/Cargo.toml"],
            ),
        ]
    for label, argv in commands:
        check(label, partial(subprocess.run, argv, cwd=source, check=True))

    print(
        "\nRelease verification report\nPASS  SHA-512, archive signature and binary scan"
    )
    for label, error in results:
        print(f"FAIL  {label}\n{error}" if error is not None else f"PASS  {label}")
    return int(any(error is not None for _, error in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run the Cargo publish dry run, standalone packaging and BoringSSL tests",
    )
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error("Python 3.12 or newer is required")
    with tempfile.TemporaryDirectory(prefix="reqsign-verify-") as directory:
        try:
            work = Path(directory)
            archive = verify_download(work)
            source = extract_source(archive, work / "src")
        except (
            OSError,
            ValueError,
            EOFError,
            tarfile.TarError,
            subprocess.CalledProcessError,
        ) as error:
            print(f"STOP  {error}", file=sys.stderr)
            return 1
        return check_source(source, args.full)


if __name__ == "__main__":
    sys.exit(main())
