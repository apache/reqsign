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

"""Verify an Apache Reqsign source release candidate (Python 3.12+)."""

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zlib
from functools import partial
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import urlopen

KEYS = "https://downloads.apache.org/reqsign/KEYS"
ATR_BASE = "https://releases.apache.org"
DEFAULT_REPO_URL = "https://github.com/apache/reqsign.git"
RFC1952_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
GPG_PROGRAM = shutil.which("gpg") or "gpg"
GPG_BASE = [GPG_PROGRAM, "--batch", "--no-options", "--no-auto-key-retrieve"]


def download(url, dest):
    print(f"Download {url}", flush=True)
    with urlopen(url, timeout=90) as response, dest.open("wb") as output:
        shutil.copyfileobj(response, output)


def fetch_json(url):
    print(f"Fetch {url}", flush=True)
    try:
        with urlopen(url, timeout=90) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise ValueError(f"HTTP {error.code} fetching {url}") from error
    except URLError as error:
        raise ValueError(f"failed fetching {url}: {error.reason}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON from {url}: {error}") from error


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


def parse_validsig_fingerprint(tokens):
    # Modern GnuPG emits: VALIDSIG <sig_fp> <date> <ts> <exp> <ver> <res> <pk> <hash> <sig_class> <primary_fp>
    return tokens[11] if len(tokens) >= 12 else tokens[2]


def check_signature(command, env):
    result = run_and_echo_stdout(command, env=env, stderr=subprocess.STDOUT)
    # GnuPG can return zero for a mathematically valid but expired signature.
    statuses = [
        line.split()
        for line in result.stdout.splitlines()
        if line.startswith("[GNUPG:] ")
    ]
    valid = [parse_validsig_fingerprint(s) for s in statuses if s[1] == "VALIDSIG"]
    if (
        result.returncode
        or len(valid) != 1
        or not any(s[1] == "GOODSIG" for s in statuses)
    ):
        raise ValueError("signature verification failed")
    print(f"  verified signature by {valid[0]}", flush=True)
    return valid[0]


def file_digest_hex(path, algorithm):
    with path.open("rb") as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def verify_atr_manifest(version, atr_revision):
    url = f"{ATR_BASE}/api/release/manifest/reqsign/{version}/{atr_revision}"
    payload = fetch_json(url)
    if payload.get("project") != "reqsign" or payload.get("version") != version:
        raise ValueError(
            f"ATR manifest mismatch: expected reqsign {version}, got {payload.get('project')} {payload.get('version')}"
        )
    files = payload.get("files")
    if not isinstance(files, list):
        raise ValueError("ATR manifest missing files list")

    filename = f"apache-reqsign-{version}.tar.gz"
    required = (filename, f"{filename}.sha512", f"{filename}.asc")
    matched = {}
    for name in required:
        exact = [entry for entry in files if isinstance(entry, dict) and entry.get("path") == name]
        if len(exact) == 1:
            entry = exact[0]
        else:
            by_basename = [
                entry
                for entry in files
                if isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and entry["path"].rsplit("/", 1)[-1] == name
            ]
            if len(by_basename) != 1:
                raise ValueError(f"ATR manifest for revision {atr_revision} missing unique entry for {name}")
            entry = by_basename[0]

        size = entry.get("size")
        digest = entry.get("digest")
        if not isinstance(size, int) or size < 0:
            raise ValueError(f"ATR manifest entry for {name} is missing valid byte size")
        if not isinstance(digest, str) or not re.fullmatch(r"sha3-256:[0-9a-fA-F]{64}", digest):
            raise ValueError(f"ATR manifest entry for {name} is missing sha3-256 digest")
        matched[name] = {
            "path": entry["path"],
            "size": size,
            "sha3_256": digest.split(":", 1)[1].lower(),
        }
    return matched


def acquire_artifacts(work, version, atr_revision=None, source_dir=None):
    filename = f"apache-reqsign-{version}.tar.gz"
    required = (filename, f"{filename}.sha512", f"{filename}.asc")

    if atr_revision is None:
        base_dir = source_dir if source_dir is not None else Path.cwd()
        for name in required:
            shutil.copyfile(base_dir / name, work / name)
        return None

    manifest = verify_atr_manifest(version, atr_revision)
    if source_dir is not None:
        target_dir = source_dir
        target_dir.mkdir(parents=True, exist_ok=True)
    elif all((Path.cwd() / name).is_file() for name in required):
        target_dir = Path.cwd()
    else:
        target_dir = work

    for name in required:
        entry = manifest[name]
        dest = target_dir / name
        if not dest.is_file():
            encoded_path = quote(entry["path"], safe="/")
            url = f"{ATR_BASE}/download/path/reqsign/{version}/{encoded_path}"
            try:
                download(url, dest)
            except HTTPError as error:
                dest.unlink(missing_ok=True)
                if error.code in (401, 403):
                    raise ValueError(
                        f"ATR download for {name} returned HTTP {error.code}; "
                        "download the artifacts manually and re-run with --dir"
                    ) from error
                raise ValueError(f"ATR download for {name} failed with HTTP {error.code}") from error
            except URLError as error:
                dest.unlink(missing_ok=True)
                raise ValueError(f"ATR download for {name} failed: {error.reason}") from error

        actual_size = dest.stat().st_size
        if actual_size != entry["size"]:
            raise ValueError(
                f"ATR manifest size mismatch for {name}: expected {entry['size']} bytes, got {actual_size}"
            )
        actual_sha3 = file_digest_hex(dest, "sha3_256")
        if actual_sha3 != entry["sha3_256"]:
            raise ValueError(
                f"ATR manifest SHA3-256 mismatch for {name}: expected {entry['sha3_256']}, got {actual_sha3}"
            )
        if dest != work / name:
            shutil.copyfile(dest, work / name)

    print(
        f"  verified ATR manifest (revision {atr_revision}) size and SHA3-256 for 3 artifacts",
        flush=True,
    )
    return manifest


def verify_sha512(work, version):
    filename = f"apache-reqsign-{version}.tar.gz"
    archive = work / filename
    checksum = (work / (filename + ".sha512")).read_text(encoding="utf-8").strip()
    digest = file_digest_hex(archive, "sha512")
    if not re.fullmatch(digest + r" [ *]" + re.escape(filename), checksum):
        raise ValueError(f"SHA-512 or checksum filename mismatch for {filename}")
    print(f"  verified SHA-512 for {filename}", flush=True)
    return archive, digest


def prepare_keyring(work, keyring_dir):
    os.chmod(keyring_dir, 0o700)
    env = dict(os.environ, GNUPGHOME=str(keyring_dir))
    keys_path = work / "KEYS"
    download(KEYS, keys_path)
    subprocess.run([*GPG_BASE, "--import", str(keys_path)], env=env, check=True)
    return env


def verify_archive_signature(work, version, gpg_env):
    filename = f"apache-reqsign-{version}.tar.gz"
    archive = work / filename
    return check_signature(
        [*GPG_BASE, "--status-fd=1", "--verify", str(work / (filename + ".asc")), str(archive)],
        gpg_env,
    )


def discover_rc_tag(repo_url, version, expected_commit):
    result = subprocess.run(
        ["git", "ls-remote", "--tags", repo_url, f"refs/tags/v{version}-rc.*"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise ValueError(f"git ls-remote failed for {repo_url}: {detail}")

    pattern = re.compile(rf"^refs/tags/(v{re.escape(version)}-rc\.([1-9][0-9]*))\^\{{}}$")
    matches = []
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        sha, ref = line.split("\t", 1)
        m = pattern.fullmatch(ref)
        if m and sha.lower() == expected_commit:
            matches.append((int(m.group(2)), m.group(1)))
    if not matches:
        raise ValueError(
            f"no annotated RC tag v{version}-rc.* on {repo_url} dereferences to {expected_commit}"
        )
    matches.sort(reverse=True)
    return matches[0][1]


def init_isolated_repo(repo_dir):
    subprocess.run(["git", "init", "-q", str(repo_dir)], check=True)


def fetch_commit_into_repo(repo_dir, repo_url, expected_commit):
    shallow = subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "--no-tags", "--depth=1", repo_url, expected_commit],
        capture_output=True,
        text=True,
        check=False,
    )
    if shallow.returncode != 0:
        subprocess.run(
            ["git", "-C", str(repo_dir), "fetch", "--tags", repo_url, "refs/heads/*:refs/remotes/origin/*"],
            check=True,
        )
    resolved = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--verify", f"{expected_commit}^{{commit}}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip().lower()
    if resolved != expected_commit:
        raise ValueError(f"fetched commit mismatch: expected {expected_commit}, got {resolved}")


def verify_rc_tag(repo_dir, repo_url, version, expected_commit, gpg_env, rc_tag=None):
    tag_name = rc_tag or discover_rc_tag(repo_url, version, expected_commit)
    if not re.fullmatch(rf"v{re.escape(version)}-rc\.[1-9][0-9]*", tag_name):
        raise ValueError(f"expected RC tag v{version}-rc.N, got {tag_name!r}")

    ref = f"refs/tags/{tag_name}"
    subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "--no-tags", "--depth=1", repo_url, f"+{ref}:{ref}"],
        check=True,
    )
    obj_type = subprocess.run(
        ["git", "-C", str(repo_dir), "cat-file", "-t", ref],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if obj_type != "tag":
        raise ValueError(f"RC tag {tag_name} must be an annotated signed tag, found {obj_type}")

    target_commit = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--verify", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip().lower()
    if target_commit != expected_commit:
        raise ValueError(
            f"RC tag {tag_name} dereferences to {target_commit}, expected {expected_commit}"
        )

    fingerprint = check_signature(
        [
            "git",
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={GPG_PROGRAM}",
            "-c",
            f"gpg.openpgp.program={GPG_PROGRAM}",
            "-C",
            str(repo_dir),
            "verify-tag",
            "--raw",
            ref,
        ],
        gpg_env,
    )
    return tag_name, fingerprint


def build_deterministic_targz(repo, commit, prefix, dest):
    cmd = [
        "git",
        "-C",
        str(repo),
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "tar.umask=0022",
        "archive",
        "--format=tar",
        f"--prefix={prefix}/",
        commit,
    ]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        assert proc.stdout is not None
        assert proc.stderr is not None

        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS, 8, zlib.Z_DEFAULT_STRATEGY)
        crc = 0
        isize = 0
        try:
            with dest.open("wb") as out:
                out.write(RFC1952_HEADER)
                while chunk := proc.stdout.read(65536):
                    crc = zlib.crc32(chunk, crc)
                    isize = (isize + len(chunk)) & 0xFFFFFFFF
                    compressed = compressor.compress(chunk)
                    if compressed:
                        out.write(compressed)
                stderr_output = proc.stderr.read().decode("utf-8", errors="replace").strip()
                returncode = proc.wait()
                if returncode != 0:
                    raise ValueError(
                        f"git archive failed ({returncode}): {stderr_output or 'unknown error'}"
                    )
                flushed = compressor.flush(zlib.Z_FINISH)
                if flushed:
                    out.write(flushed)
                out.write(struct.pack("<II", crc & 0xFFFFFFFF, isize & 0xFFFFFFFF))
        except Exception:
            dest.unlink(missing_ok=True)
            raise


def verify_reproducible_archive(repo_dir, repo_url, version, expected_commit, expected_sha512, work, *, already_fetched=False):
    if not already_fetched:
        fetch_commit_into_repo(repo_dir, repo_url, expected_commit)
    else:
        has_commit = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", "-e", f"{expected_commit}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        if has_commit.returncode != 0:
            fetch_commit_into_repo(repo_dir, repo_url, expected_commit)

    root = f"apache-reqsign-{version}"
    rebuilt = work / f"rebuilt-{root}.tar.gz"
    build_deterministic_targz(repo_dir, expected_commit, root, rebuilt)
    rebuilt_sha512 = file_digest_hex(rebuilt, "sha512")
    if rebuilt_sha512 != expected_sha512:
        raise ValueError(
            f"reproduced archive SHA-512 mismatch: candidate={expected_sha512}, rebuilt={rebuilt_sha512}"
        )
    print(f"  verified reproducible archive SHA-512 {rebuilt_sha512}", flush=True)
    return rebuilt_sha512


def validate_link_target(member, root):
    if member.islnk():
        target = member.linkname
        if target.startswith("/") or Path(target).parts[:1] != (root,) or ".." in Path(target).parts:
            raise ValueError(f"hardlink escapes archive root: {member.name} -> {target}")
        return
    if member.issym():
        target = member.linkname
        if target.startswith("/") or Path(target).is_absolute():
            raise ValueError(f"absolute symlink target is forbidden: {member.name} -> {target}")
        parent = posixpath.dirname(member.name)
        resolved = posixpath.normpath(posixpath.join(parent, target))
        parts = Path(resolved).parts
        if not parts or parts[0] != root or ".." in parts:
            raise ValueError(f"symlink escapes archive root: {member.name} -> {target}")


def extract_source(archive, destination, expected_commit):
    root = archive.name.removesuffix(".tar.gz")
    with tarfile.open(archive, "r:gz") as package:
        # git archive records the commit in the global PAX header.
        commit = package.pax_headers.get("comment")
        if commit != expected_commit:
            raise ValueError(
                f"expected Git commit {expected_commit}, found {commit or '(missing)'}"
            )
        for member in package:
            parts = Path(member.name).parts
            if member.name.startswith("/") or parts[:1] != (root,) or ".." in parts:
                raise ValueError(f"unexpected archive path: {member.name}")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"unsupported tar entry type for {member.name}")
            validate_link_target(member, root)
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


def verify_package_version(source, expected_version):
    cargo_toml = source / "reqsign" / "Cargo.toml"
    if not cargo_toml.is_file():
        raise ValueError("missing reqsign/Cargo.toml in extracted source")
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    actual_version = data.get("package", {}).get("version")
    if actual_version != expected_version:
        raise ValueError(
            f"reqsign/Cargo.toml [package].version is {actual_version!r}, expected {expected_version!r}"
        )


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


def check_source(source, full, verified_commit, expected_version=None, extra_passes=()):
    results = []

    def check(label, action):
        print(f"\nChecking {label}", flush=True)
        try:
            action()
        except (OSError, ValueError, tomllib.TOMLDecodeError, subprocess.CalledProcessError) as error:
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

    if expected_version is not None:
        check("reqsign/Cargo.toml version", partial(verify_package_version, source, expected_version))
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
    for line in extra_passes:
        print(f"PASS  {line}")
    print(f"PASS  Git commit {verified_commit}")
    for label, error in results:
        print(f"FAIL  {label}\n{error}" if error is not None else f"PASS  {label}")
    return int(any(error is not None for _, error in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version from the vote, e.g. 0.21.0")
    parser.add_argument("commit", help="full Git commit SHA from the vote")
    parser.add_argument(
        "--atr-revision",
        help="ATR revision number (e.g. 00001) to verify manifest and download missing files",
    )
    parser.add_argument(
        "--rc-tag",
        help="annotated Git RC tag to verify (e.g. v0.21.0-rc.1); auto-discovered when --atr-revision is set",
    )
    parser.add_argument(
        "--dir",
        type=Path,
        help="directory containing (or to store) release candidate artifacts",
    )
    parser.add_argument(
        "--repo-url",
        default=DEFAULT_REPO_URL,
        help=f"Git repository URL for RC tag and reproduction checks (default: {DEFAULT_REPO_URL})",
    )
    parser.add_argument(
        "--reproduce",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="independently rebuild the archive from Git and assert bit-for-bit SHA-512 match (default: on with --atr-revision)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run the Cargo publish dry run, standalone packaging and BoringSSL tests",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("expected a release version of the form X.Y.Z")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.commit):
        parser.error("expected a full 40-character Git commit SHA")
    if args.atr_revision is not None and not re.fullmatch(r"[0-9A-Za-z._-]+", args.atr_revision):
        parser.error("invalid --atr-revision format")
    if args.rc_tag is not None and not re.fullmatch(rf"v{re.escape(args.version)}-rc\.[1-9][0-9]*", args.rc_tag):
        parser.error(f"expected --rc-tag of the form v{args.version}-rc.N")

    expected_commit = args.commit.lower()
    if sys.version_info < (3, 12):
        parser.error("Python 3.12 or newer is required")

    reproduce = args.reproduce if args.reproduce is not None else (args.atr_revision is not None)
    gpg_parent = "/tmp" if Path("/tmp").is_dir() else None

    with (
        tempfile.TemporaryDirectory(prefix="reqsign-verify-") as directory,
        tempfile.TemporaryDirectory(prefix="rq-gpg-", dir=gpg_parent) as gpg_dir,
    ):
        try:
            work = Path(directory)
            extra_passes = []
            acquire_artifacts(work, args.version, args.atr_revision, args.dir)
            if args.atr_revision is not None:
                extra_passes.append(f"ATR manifest revision {args.atr_revision} (size + SHA3-256)")

            archive, sha512 = verify_sha512(work, args.version)
            gpg_env = prepare_keyring(work, Path(gpg_dir))
            archive_fp = verify_archive_signature(work, args.version, gpg_env)
            extra_passes.append(f"Archive OpenPGP signature ({archive_fp})")

            repo_dir = work / "git-repo"
            need_tag_check = args.atr_revision is not None or args.rc_tag is not None
            tag_fetched = False
            if need_tag_check or reproduce:
                init_isolated_repo(repo_dir)
            if need_tag_check:
                tag_name, tag_fp = verify_rc_tag(
                    repo_dir, args.repo_url, args.version, expected_commit, gpg_env, args.rc_tag
                )
                tag_fetched = True
                extra_passes.append(f"RC tag {tag_name} signature ({tag_fp})")
            if reproduce:
                verify_reproducible_archive(
                    repo_dir,
                    args.repo_url,
                    args.version,
                    expected_commit,
                    sha512,
                    work,
                    already_fetched=tag_fetched,
                )
                extra_passes.append("Reproducible archive build (SHA-512 match)")

            source = extract_source(archive, work / "src", expected_commit)
        except (
            OSError,
            ValueError,
            EOFError,
            tarfile.TarError,
            subprocess.CalledProcessError,
        ) as error:
            print(f"STOP  {error}", file=sys.stderr)
            return 1
        return check_source(
            source,
            args.full,
            expected_commit,
            expected_version=args.version,
            extra_passes=extra_passes,
        )


if __name__ == "__main__":
    sys.exit(main())
