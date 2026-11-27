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

"""Build and verify a deterministic Apache Reqsign source archive (Python 3.12+)."""

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
from dataclasses import dataclass
from pathlib import Path

SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RFC1952_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"


@dataclass(frozen=True)
class Perturbation:
    run: int
    tz: str
    utime: int
    mode: int


PERTURBATIONS = (
    Perturbation(run=1, tz="UTC", utime=1_700_000_000, mode=0o644),
    Perturbation(run=2, tz="Asia/Shanghai", utime=1_800_000_000, mode=0o755),
)


def run_git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def detect_repo(repo_arg: Path | None) -> Path:
    if repo_arg is not None:
        return repo_arg.resolve()
    cwd_check = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if cwd_check.returncode == 0 and cwd_check.stdout.strip():
        return Path(cwd_check.stdout.strip()).resolve()
    return Path(__file__).resolve().parents[2]


def resolve_commit(repo: Path, revision: str) -> str:
    commit = run_git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").strip().lower()
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError(f"expected 40-character commit SHA for {revision!r}, got {commit!r}")
    return commit


def verify_cargo_version(repo: Path, commit: str, version: str) -> None:
    cargo_toml = run_git(repo, "show", f"{commit}:reqsign/Cargo.toml")
    data = tomllib.loads(cargo_toml)
    package_version = data.get("package", {}).get("version")
    if package_version != version:
        raise ValueError(
            f"{commit}:reqsign/Cargo.toml [package].version is {package_version!r}, expected {version!r}"
        )


def build_deterministic_targz(
    repo: Path,
    commit: str,
    prefix: str,
    dest: Path,
    *,
    env: dict[str, str] | None = None,
) -> None:
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
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) as proc:
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


def validate_link_target(member: tarfile.TarInfo, root: str) -> None:
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


def inspect_archive(archive: Path, expected_commit: str, root: str) -> tuple[str, int]:
    file_count = 0
    with tarfile.open(archive, "r:gz") as package:
        commit = package.pax_headers.get("comment")
        if commit != expected_commit:
            raise ValueError(f"expected PAX comment {expected_commit}, found {commit or '(missing)'}")
        for member in package:
            parts = Path(member.name).parts
            if member.name.startswith("/") or not parts or parts[0] != root or ".." in parts:
                raise ValueError(f"unexpected archive path: {member.name}")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"unsupported tar entry type for {member.name}")
            validate_link_target(member, root)
            if member.isfile():
                file_count += 1
    if file_count == 0:
        raise ValueError(f"archive {archive.name} contains no regular files")
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha512").hexdigest()
    return digest, archive.stat().st_size


def perturb_checkout(checkout: Path, perturbation: Perturbation) -> None:
    raw = subprocess.run(
        ["git", "-C", str(checkout), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout
    for entry in raw.split(b"\x00"):
        if not entry:
            continue
        path = checkout / entry.decode("utf-8")
        if path.is_symlink() or not path.is_file():
            continue
        os.chmod(path, perturbation.mode)
        os.utime(path, (perturbation.utime, perturbation.utime))


def compare_existing(compare_dir: Path, archive_name: str, expected_sha512: str) -> None:
    target = compare_dir / archive_name
    if not target.is_file():
        raise ValueError(f"comparison archive not found: {target}")
    with target.open("rb") as stream:
        actual_sha512 = hashlib.file_digest(stream, "sha512").hexdigest()
    if actual_sha512 != expected_sha512:
        raise ValueError(
            f"SHA-512 mismatch against {target}: expected {expected_sha512}, found {actual_sha512}"
        )
    sidecar = compare_dir / f"{archive_name}.sha512"
    if sidecar.is_file():
        text = sidecar.read_text(encoding="utf-8").strip()
        if not re.fullmatch(expected_sha512 + r" [ *]" + re.escape(archive_name), text):
            raise ValueError(f"checksum sidecar mismatch in {sidecar}")


def compose_source(
    repo: Path,
    revision: str,
    version: str,
    output_dir: Path,
    compare_dir: Path | None = None,
) -> dict[str, object]:
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"expected stable X.Y.Z version, got {version!r}")

    commit = resolve_commit(repo, revision)
    verify_cargo_version(repo, commit, version)

    root = f"apache-reqsign-{version}"
    archive_name = f"{root}.tar.gz"
    output_dir.mkdir(parents=True, exist_ok=True)

    runs: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="reqsign-compose-") as tmp_dir:
        tmp = Path(tmp_dir)
        run_archives: list[Path] = []
        for perturbation in PERTURBATIONS:
            checkout = tmp / f"checkout-{perturbation.run}"
            env = dict(os.environ, LC_ALL="C", TZ=perturbation.tz)
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--shared",
                    "--no-checkout",
                    "-c",
                    "core.autocrlf=false",
                    str(repo),
                    str(checkout),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            run_git(checkout, "-c", "advice.detachedHead=false", "checkout", "--detach", commit, env=env)
            perturb_checkout(checkout, perturbation)

            run_archive = tmp / f"run-{perturbation.run}-{archive_name}"
            build_deterministic_targz(checkout, commit, root, run_archive, env=env)
            digest, size = inspect_archive(run_archive, commit, root)
            run_archives.append(run_archive)
            runs.append(
                {
                    "run": perturbation.run,
                    "tz": perturbation.tz,
                    "utime": perturbation.utime,
                    "mode": oct(perturbation.mode),
                    "sha512": digest,
                    "size": size,
                }
            )

        matched = runs[0]["sha512"] == runs[1]["sha512"] and runs[0]["size"] == runs[1]["size"]
        if not matched:
            raise ValueError(
                f"non-deterministic archive build: run 1={runs[0]['sha512']} vs run 2={runs[1]['sha512']}"
            )

        sha512 = str(runs[0]["sha512"])
        size = int(runs[0]["size"])
        if compare_dir is not None:
            compare_existing(compare_dir, archive_name, sha512)

        final_archive = output_dir / archive_name
        shutil.copyfile(run_archives[0], final_archive)

    (output_dir / f"{archive_name}.sha512").write_text(
        f"{sha512}  {archive_name}\n",
        encoding="utf-8",
    )
    report: dict[str, object] = {
        "commit": commit,
        "version": version,
        "archive": archive_name,
        "sha512": sha512,
        "size": size,
        "matched": True,
        "runs": runs,
    }
    (output_dir / "report.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    if sys.version_info < (3, 12):
        print("Python 3.12 or newer is required", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="Git revision or commit SHA to archive")
    parser.add_argument("--version", required=True, help="release version X.Y.Z")
    parser.add_argument("--output", required=True, type=Path, help="output directory for archive, .sha512, and report.json")
    parser.add_argument("--compare", type=Path, help="optional directory containing an existing archive to compare against")
    parser.add_argument("--repo", type=Path, help="optional path to Git repository (defaults to current repo)")
    args = parser.parse_args()

    try:
        repo = detect_repo(args.repo)
        report = compose_source(repo, args.revision, args.version, args.output, args.compare)
    except (OSError, ValueError, tomllib.TOMLDecodeError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"STOP  {error}", file=sys.stderr)
        return 1

    print(
        f"Composed {report['archive']} ({report['size']} bytes, SHA-512 {report['sha512']}) from {report['commit']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
