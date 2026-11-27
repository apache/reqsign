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

"""Unit tests for compose_source.py."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import compose_source
import verify


def git(repo: Path, *args: str) -> str:
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="Test User",
        GIT_AUTHOR_EMAIL="test@example.org",
        GIT_COMMITTER_NAME="Test User",
        GIT_COMMITTER_EMAIL="test@example.org",
    )
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def create_sample_repo(root: Path, version: str = "0.21.0") -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "tag.gpgsign", "false")

    (repo / "LICENSE-APACHE").write_text("Apache License 2.0\n", encoding="utf-8")
    (repo / "NOTICE").write_text("Apache Reqsign\n", encoding="utf-8")
    (repo / "reqsign").mkdir()
    (repo / "reqsign" / "Cargo.toml").write_text(
        f'[package]\nname = "reqsign"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    os.symlink("../LICENSE-APACHE", repo / "reqsign" / "LICENSE")
    os.symlink("../NOTICE", repo / "reqsign" / "NOTICE")
    (repo / "reqsign" / "lib.rs").write_text("pub fn ok() {}\n", encoding="utf-8")
    (repo / "bin.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    os.chmod(repo / "bin.sh", 0o755)

    git(repo, "add", "-A")
    git(repo, "commit", "-m", "Initial commit")
    commit = git(repo, "rev-parse", "HEAD")
    return repo, commit


class ComposeSourceTests(unittest.TestCase):
    def test_deterministic_compose_and_parity_with_verify(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compose-test-") as tmp:
            root = Path(tmp)
            repo, commit = create_sample_repo(root, "0.21.0")
            out_dir = root / "out"

            report = compose_source.compose_source(repo, commit[:12], "0.21.0", out_dir)
            self.assertTrue(report["matched"])
            self.assertEqual(report["commit"], commit)
            self.assertEqual(report["version"], "0.21.0")
            self.assertEqual(report["archive"], "apache-reqsign-0.21.0.tar.gz")
            self.assertEqual(len(report["runs"]), 2)
            self.assertEqual(report["runs"][0]["tz"], "UTC")
            self.assertEqual(report["runs"][1]["tz"], "Asia/Shanghai")
            self.assertEqual(report["runs"][0]["utime"], 1_700_000_000)
            self.assertEqual(report["runs"][1]["utime"], 1_800_000_000)
            self.assertEqual(report["runs"][0]["mode"], "0o644")
            self.assertEqual(report["runs"][1]["mode"], "0o755")
            self.assertEqual(report["runs"][0]["sha512"], report["runs"][1]["sha512"])

            archive = out_dir / "apache-reqsign-0.21.0.tar.gz"
            sidecar = out_dir / "apache-reqsign-0.21.0.tar.gz.sha512"
            report_file = out_dir / "report.json"
            self.assertTrue(archive.is_file())
            self.assertTrue(sidecar.is_file())
            self.assertTrue(report_file.is_file())

            digest = hashlib.sha512(archive.read_bytes()).hexdigest()
            self.assertEqual(digest, report["sha512"])
            self.assertEqual(
                sidecar.read_text(encoding="utf-8"),
                f"{digest}  apache-reqsign-0.21.0.tar.gz\n",
            )
            loaded_report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(loaded_report, report)

            # Verify exact byte-for-byte parity with verify.py's rebuild helper.
            rebuilt = root / "verify-rebuilt.tar.gz"
            verify.build_deterministic_targz(repo, commit, "apache-reqsign-0.21.0", rebuilt)
            self.assertEqual(rebuilt.read_bytes(), archive.read_bytes())

            # Compare flag succeeds when pointed at matching output.
            out_dir2 = root / "out2"
            report2 = compose_source.compose_source(repo, commit, "0.21.0", out_dir2, compare_dir=out_dir)
            self.assertEqual(report2["sha512"], report["sha512"])

    def test_compare_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compose-cmp-") as tmp:
            root = Path(tmp)
            repo, commit = create_sample_repo(root, "0.21.0")
            out_dir = root / "out"
            compose_source.compose_source(repo, commit, "0.21.0", out_dir)

            bad_dir = root / "bad"
            bad_dir.mkdir()
            bad_archive = bad_dir / "apache-reqsign-0.21.0.tar.gz"
            bad_archive.write_bytes(b"corrupted-archive")

            with self.assertRaisesRegex(ValueError, "SHA-512 mismatch"):
                compose_source.compose_source(repo, commit, "0.21.0", root / "out2", compare_dir=bad_dir)

            # Matching archive bytes but corrupted .sha512 sidecar also fails.
            bad_archive.write_bytes((out_dir / "apache-reqsign-0.21.0.tar.gz").read_bytes())
            (bad_dir / "apache-reqsign-0.21.0.tar.gz.sha512").write_text(
                "0" * 128 + "  apache-reqsign-0.21.0.tar.gz\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "checksum sidecar mismatch"):
                compose_source.compose_source(repo, commit, "0.21.0", root / "out3", compare_dir=bad_dir)

    def test_version_validation_and_cargo_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compose-ver-") as tmp:
            root = Path(tmp)
            repo, commit = create_sample_repo(root, "0.21.0")

            with self.assertRaisesRegex(ValueError, "expected stable X.Y.Z"):
                compose_source.compose_source(repo, commit, "0.21.0-rc.1", root / "out1")

            with self.assertRaisesRegex(ValueError, "reqsign/Cargo.toml"):
                compose_source.compose_source(repo, commit, "0.22.0", root / "out2")

    def test_inspect_archive_rejects_bad_pax_and_escaping_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compose-inspect-") as tmp:
            root = Path(tmp)
            repo, commit = create_sample_repo(root, "0.21.0")
            out_dir = root / "out"
            compose_source.compose_source(repo, commit, "0.21.0", out_dir)
            archive = out_dir / "apache-reqsign-0.21.0.tar.gz"

            with self.assertRaisesRegex(ValueError, "expected PAX comment"):
                compose_source.inspect_archive(archive, "f" * 40, "apache-reqsign-0.21.0")

            bad_tar = root / "escape.tar.gz"
            with tarfile.open(bad_tar, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
                info = tarfile.TarInfo("apache-reqsign-0.21.0/reqsign/LICENSE")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../etc/passwd"
                tf.addfile(info)
                finfo = tarfile.TarInfo("apache-reqsign-0.21.0/file.txt")
                data = b"ok\n"
                finfo.size = len(data)
                tf.addfile(finfo, io.BytesIO(data))

            with self.assertRaisesRegex(ValueError, "symlink escapes archive root"):
                compose_source.inspect_archive(bad_tar, commit, "apache-reqsign-0.21.0")


if __name__ == "__main__":
    unittest.main()
