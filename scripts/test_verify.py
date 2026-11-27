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

"""Unit tests for verify.py."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import compose_source
import verify


def create_gpg_key(gnupg_home: Path, uid: str = "Test Release Manager <rm@apache.org>") -> tuple[str, Path]:
    gnupg_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = dict(os.environ, GNUPGHOME=str(gnupg_home))
    subprocess.run(
        [
            verify.GPG_PROGRAM,
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            uid,
            "default",
            "default",
            "never",
        ],
        env=env,
        capture_output=True,
        check=True,
    )
    colons = subprocess.run(
        [verify.GPG_PROGRAM, "--batch", "--with-colons", "--list-keys", uid],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    fpr = next(line.split(":")[9] for line in colons.splitlines() if line.startswith("fpr:"))
    keys_file = gnupg_home / "KEYS"
    exported = subprocess.run(
        [verify.GPG_PROGRAM, "--batch", "--armor", "--export", fpr],
        env=env,
        capture_output=True,
        check=True,
    ).stdout
    keys_file.write_bytes(exported)
    return fpr, keys_file


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    merged_env = dict(
        os.environ if env is None else env,
        GIT_AUTHOR_NAME="Test RM",
        GIT_AUTHOR_EMAIL="rm@apache.org",
        GIT_COMMITTER_NAME="Test RM",
        GIT_COMMITTER_EMAIL="rm@apache.org",
    )
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=merged_env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


class FakeHTTPResponse:
    def __init__(self, body: bytes):
        self._stream = io.BytesIO(body)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stream.close()


class VerifyTests(unittest.TestCase):
    def test_parse_validsig_fingerprint_primary_and_fallback(self) -> None:
        # Subkey fp differs from primary fp (12th token / s[-1]).
        modern = (
            "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
            "2026-11-27 1795799930 0 4 0 22 10 00 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        ).split()
        self.assertEqual(
            verify.parse_validsig_fingerprint(modern),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )

        # Older 11-token format without trailing primary fingerprint.
        legacy = (
            "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
            "2026-11-27 1795799930 0 4 0 22 10 00"
        ).split()
        self.assertEqual(
            verify.parse_validsig_fingerprint(legacy),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

    def test_atr_manifest_download_and_digest_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verify-atr-") as tmp:
            root = Path(tmp)
            version = "0.21.0"
            archive_name = f"apache-reqsign-{version}.tar.gz"
            payloads = {
                archive_name: b"fake-tar-gz-bytes",
                f"{archive_name}.sha512": b"0" * 128 + f"  {archive_name}\n".encode("utf-8"),
                f"{archive_name}.asc": b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n",
            }
            manifest = {
                "endpoint": "/release/manifest",
                "project": "reqsign",
                "version": version,
                "revision": "00003",
                "files": [
                    {
                        "path": name,
                        "size": len(data),
                        "digest": f"sha3-256:{hashlib.sha3_256(data).hexdigest()}",
                        "swhid_dir_inner": None,
                    }
                    for name, data in payloads.items()
                ],
            }

            def fake_urlopen(url: str, timeout: int = 90) -> FakeHTTPResponse:
                if url == "https://releases.apache.org/api/release/manifest/reqsign/0.21.0/00003":
                    return FakeHTTPResponse(json.dumps(manifest).encode("utf-8"))
                prefix = "https://releases.apache.org/download/path/reqsign/0.21.0/"
                if url.startswith(prefix):
                    name = url.removeprefix(prefix)
                    if name in payloads:
                        return FakeHTTPResponse(payloads[name])
                raise AssertionError(f"unexpected URL {url}")

            work = root / "work"
            work.mkdir()
            dl_dir = root / "downloads"
            with mock.patch.object(verify, "urlopen", side_effect=fake_urlopen):
                verify.acquire_artifacts(work, version, atr_revision="00003", source_dir=dl_dir)

            for name, data in payloads.items():
                self.assertEqual((dl_dir / name).read_bytes(), data)
                self.assertEqual((work / name).read_bytes(), data)

            # Tampered local file triggers SHA3-256 or size mismatch.
            (dl_dir / archive_name).write_bytes(b"wrong-len")
            with mock.patch.object(verify, "urlopen", side_effect=fake_urlopen):
                with self.assertRaisesRegex(ValueError, "ATR manifest size mismatch"):
                    verify.acquire_artifacts(work, version, atr_revision="00003", source_dir=dl_dir)

            (dl_dir / archive_name).write_bytes(b"X" * len(payloads[archive_name]))
            with mock.patch.object(verify, "urlopen", side_effect=fake_urlopen):
                with self.assertRaisesRegex(ValueError, "ATR manifest SHA3-256 mismatch"):
                    verify.acquire_artifacts(work, version, atr_revision="00003", source_dir=dl_dir)

            # 403 download reports clear guidance to use --dir.
            def forbidden_urlopen(url: str, timeout: int = 90):
                if url.endswith("/00003"):
                    return FakeHTTPResponse(json.dumps(manifest).encode("utf-8"))
                raise HTTPError(url, 403, "Forbidden", {}, None)

            with mock.patch.object(verify, "urlopen", side_effect=forbidden_urlopen):
                with self.assertRaisesRegex(ValueError, "re-run with --dir"):
                    verify.acquire_artifacts(work, version, atr_revision="00003", source_dir=root / "fresh")

    def test_extract_source_security_and_binary_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verify-tar-") as tmp:
            root = Path(tmp)
            commit = "a" * 40
            archive = root / "apache-reqsign-0.21.0.tar.gz"

            # Valid archive with internal crate symlink.
            with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
                lic = tarfile.TarInfo("apache-reqsign-0.21.0/LICENSE-APACHE")
                lic_data = b"Apache License\n"
                lic.size = len(lic_data)
                tf.addfile(lic, io.BytesIO(lic_data))

                sym = tarfile.TarInfo("apache-reqsign-0.21.0/reqsign/LICENSE")
                sym.type = tarfile.SYMTYPE
                sym.linkname = "../LICENSE-APACHE"
                tf.addfile(sym)

                cargo = tarfile.TarInfo("apache-reqsign-0.21.0/reqsign/Cargo.toml")
                cargo_data = b'[package]\nname = "reqsign"\nversion = "0.21.0"\n'
                cargo.size = len(cargo_data)
                tf.addfile(cargo, io.BytesIO(cargo_data))

            extracted = verify.extract_source(archive, root / "out1", commit)
            self.assertTrue((extracted / "reqsign" / "Cargo.toml").is_file())
            verify.verify_package_version(extracted, "0.21.0")
            with self.assertRaisesRegex(ValueError, "reqsign/Cargo.toml"):
                verify.verify_package_version(extracted, "0.22.0")

            # Wrong PAX commit fails.
            with self.assertRaisesRegex(ValueError, "expected Git commit"):
                verify.extract_source(archive, root / "out2", "b" * 40)

            # Escaping symlink fails.
            escape_tar = root / "apache-reqsign-0.21.0.tar.gz"
            with tarfile.open(escape_tar, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
                sym = tarfile.TarInfo("apache-reqsign-0.21.0/reqsign/LICENSE")
                sym.type = tarfile.SYMTYPE
                sym.linkname = "../../etc/passwd"
                tf.addfile(sym)
            with self.assertRaisesRegex(ValueError, "symlink escapes archive root"):
                verify.extract_source(escape_tar, root / "out3", commit)

            # Binary file fails.
            bin_tar = root / "apache-reqsign-0.21.0.tar.gz"
            with tarfile.open(bin_tar, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
                finfo = tarfile.TarInfo("apache-reqsign-0.21.0/blob.bin")
                blob = b"\x00\x01\xff"
                finfo.size = len(blob)
                tf.addfile(finfo, io.BytesIO(blob))
            with self.assertRaisesRegex(ValueError, "unexpected binary file"):
                verify.extract_source(bin_tar, root / "out4", commit)

    def test_rc_tag_discovery_and_end_to_end_reproduce(self) -> None:
        gpg_parent = "/tmp" if Path("/tmp").is_dir() else None
        with (
            tempfile.TemporaryDirectory(prefix="verify-e2e-") as tmp,
            tempfile.TemporaryDirectory(prefix="rq-test-gpg-", dir=gpg_parent) as gpg_dir,
        ):
            root = Path(tmp)
            fpr, keys_file = create_gpg_key(Path(gpg_dir))
            gpg_env = dict(os.environ, GNUPGHOME=gpg_dir)

            # Build sample git repo with annotated GPG-signed RC tag v0.21.0-rc.2.
            repo = root / "remote-repo"
            repo.mkdir()
            git(repo, "init", "-b", "main", env=gpg_env)
            git(repo, "config", "commit.gpgsign", "false", env=gpg_env)
            git(repo, "config", "tag.gpgSign", "false", env=gpg_env)
            git(repo, "config", "gpg.format", "openpgp", env=gpg_env)
            git(repo, "config", "gpg.program", verify.GPG_PROGRAM, env=gpg_env)
            git(repo, "config", "gpg.openpgp.program", verify.GPG_PROGRAM, env=gpg_env)
            git(repo, "config", "user.signingkey", fpr, env=gpg_env)
            (repo / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
            (repo / "LICENSE-APACHE").write_text("Apache-2.0\n", encoding="utf-8")
            (repo / "NOTICE").write_text("Apache Reqsign\n", encoding="utf-8")
            (repo / "reqsign").mkdir()
            (repo / "reqsign" / "Cargo.toml").write_text(
                '[package]\nname = "reqsign"\nversion = "0.21.0"\n',
                encoding="utf-8",
            )
            os.symlink("../LICENSE-APACHE", repo / "reqsign" / "LICENSE")
            os.symlink("../NOTICE", repo / "reqsign" / "NOTICE")
            git(repo, "add", "-A", env=gpg_env)
            git(repo, "commit", "-m", "Release 0.21.0", env=gpg_env)
            commit = git(repo, "rev-parse", "HEAD", env=gpg_env)
            git(repo, "tag", "-s", "-m", "RC 2", "v0.21.0-rc.2", commit, env=gpg_env)
            # Also add a lightweight tag on another commit to ensure it is ignored.
            git(repo, "tag", "--no-sign", "v0.21.0-rc.1-lightweight", commit, env=gpg_env)

            # Compose deterministic archive and sign it with the same ephemeral key.
            stage = root / "stage"
            compose_source.compose_source(repo, commit, "0.21.0", stage)
            archive_name = "apache-reqsign-0.21.0.tar.gz"
            archive = stage / archive_name
            subprocess.run(
                [verify.GPG_PROGRAM, "--batch", "--yes", "--armor", "--detach-sign", "--local-user", fpr, str(archive)],
                env=gpg_env,
                check=True,
            )

            # Build mocked ATR manifest + download + KEYS server.
            payloads = {
                name: (stage / name).read_bytes()
                for name in (archive_name, f"{archive_name}.sha512", f"{archive_name}.asc")
            }
            manifest = {
                "endpoint": "/release/manifest",
                "project": "reqsign",
                "version": "0.21.0",
                "revision": "00001",
                "files": [
                    {
                        "path": name,
                        "size": len(data),
                        "digest": f"sha3-256:{hashlib.sha3_256(data).hexdigest()}",
                        "swhid_dir_inner": None,
                    }
                    for name, data in payloads.items()
                ],
            }
            keys_bytes = keys_file.read_bytes()

            def fake_urlopen(url: str, timeout: int = 90) -> FakeHTTPResponse:
                if url == verify.KEYS:
                    return FakeHTTPResponse(keys_bytes)
                if url == "https://releases.apache.org/api/release/manifest/reqsign/0.21.0/00001":
                    return FakeHTTPResponse(json.dumps(manifest).encode("utf-8"))
                prefix = "https://releases.apache.org/download/path/reqsign/0.21.0/"
                if url.startswith(prefix):
                    name = url.removeprefix(prefix)
                    if name in payloads:
                        return FakeHTTPResponse(payloads[name])
                raise AssertionError(f"unexpected URL {url}")

            # Verify RC tag discovery, signature, ATR manifest, and reproducible rebuild end-to-end.
            with tempfile.TemporaryDirectory(prefix="verify-work-") as wdir:
                work = Path(wdir)
                iso_gpg = work / "gnupg"
                iso_gpg.mkdir(mode=0o700)
                with mock.patch.object(verify, "urlopen", side_effect=fake_urlopen):
                    verify.acquire_artifacts(work, "0.21.0", atr_revision="00001", source_dir=root / "dl")
                    _, sha512 = verify.verify_sha512(work, "0.21.0")
                    v_gpg_env = verify.prepare_keyring(work, iso_gpg)
                    arch_fp = verify.verify_archive_signature(work, "0.21.0", v_gpg_env)
                    self.assertEqual(arch_fp, fpr)

                    iso_repo = work / "git-repo"
                    verify.init_isolated_repo(iso_repo)
                    tag_name, tag_fp = verify.verify_rc_tag(
                        iso_repo, repo.as_uri(), "0.21.0", commit, v_gpg_env
                    )
                    self.assertEqual(tag_name, "v0.21.0-rc.2")
                    self.assertEqual(tag_fp, fpr)

                    rebuilt_sha512 = verify.verify_reproducible_archive(
                        iso_repo,
                        repo.as_uri(),
                        "0.21.0",
                        commit,
                        sha512,
                        work,
                        already_fetched=True,
                    )
                    self.assertEqual(rebuilt_sha512, sha512)

                    extracted = verify.extract_source(work / archive_name, work / "src", commit)
                    verify.verify_package_version(extracted, "0.21.0")

            # Lightweight tag explicitly passed as --rc-tag is rejected.
            git(repo, "tag", "--no-sign", "v0.21.0-rc.3", commit, env=gpg_env)
            with tempfile.TemporaryDirectory(prefix="verify-lw-") as lw_dir:
                lw_repo = Path(lw_dir) / "repo"
                verify.init_isolated_repo(lw_repo)
                with self.assertRaisesRegex(ValueError, "annotated signed tag"):
                    verify.verify_rc_tag(
                        lw_repo, repo.as_uri(), "0.21.0", commit, gpg_env, rc_tag="v0.21.0-rc.3"
                    )

            # Untrusted signer fails tag signature verification.
            with tempfile.TemporaryDirectory(prefix="rq-untrusted-", dir=gpg_parent) as other_gpg:
                other_fpr, _ = create_gpg_key(Path(other_gpg), "Other <other@example.org>")
                other_env = dict(os.environ, GNUPGHOME=other_gpg)
                git(repo, "config", "user.signingkey", other_fpr, env=other_env)
                git(repo, "tag", "-s", "-m", "Untrusted RC", "v0.21.0-rc.4", commit, env=other_env)

                with tempfile.TemporaryDirectory(prefix="verify-untrusted-") as u_dir:
                    u_work = Path(u_dir)
                    u_gpg = u_work / "gnupg"
                    u_gpg.mkdir(mode=0o700)
                    with mock.patch.object(verify, "urlopen", side_effect=fake_urlopen):
                        u_gpg_env = verify.prepare_keyring(u_work, u_gpg)
                    u_repo = u_work / "repo"
                    verify.init_isolated_repo(u_repo)
                    with self.assertRaisesRegex(ValueError, "signature verification failed"):
                        verify.verify_rc_tag(
                            u_repo, repo.as_uri(), "0.21.0", commit, u_gpg_env, rc_tag="v0.21.0-rc.4"
                        )

    def test_global_git_config_tag_gpgsign_and_gpg_program_override(self) -> None:
        gpg_parent = "/tmp" if Path("/tmp").is_dir() else None
        with (
            tempfile.TemporaryDirectory(prefix="verify-cfg-") as tmp,
            tempfile.TemporaryDirectory(prefix="rq-cfg-gpg-", dir=gpg_parent) as gpg_dir,
        ):
            root = Path(tmp)
            fpr, keys_file = create_gpg_key(Path(gpg_dir))
            global_cfg = root / "gitconfig"
            global_cfg.write_text(
                f"[tag]\n\tgpgSign = true\n[gpg]\n\tformat = openpgp\n\tprogram = {verify.GPG_PROGRAM}\n",
                encoding="utf-8",
            )
            env = dict(
                os.environ,
                GNUPGHOME=gpg_dir,
                GIT_CONFIG_GLOBAL=str(global_cfg),
                GIT_CONFIG_NOSYSTEM="1",
            )

            repo = root / "remote-repo"
            repo.mkdir()
            git(repo, "init", "-b", "main", env=env)
            git(repo, "config", "commit.gpgsign", "false", env=env)
            git(repo, "config", "user.signingkey", fpr, env=env)
            (repo / "README").write_text("hello\n", encoding="utf-8")
            git(repo, "add", "README", env=env)
            git(repo, "commit", "-m", "Init", env=env)
            commit = git(repo, "rev-parse", "HEAD", env=env)

            # Under global tag.gpgSign=true, --no-sign still creates a lightweight tag rejected by verify_rc_tag.
            git(repo, "tag", "--no-sign", "v0.21.0-rc.1", commit, env=env)
            self.assertEqual(git(repo, "cat-file", "-t", "refs/tags/v0.21.0-rc.1", env=env), "commit")

            # Without --no-sign, global tag.gpgSign=true creates an annotated signed tag accepted by verify_rc_tag.
            git(repo, "tag", "-m", "RC 2", "v0.21.0-rc.2", commit, env=env)
            self.assertEqual(git(repo, "cat-file", "-t", "refs/tags/v0.21.0-rc.2", env=env), "tag")

            with tempfile.TemporaryDirectory(prefix="verify-cfg-work-") as wdir:
                work = Path(wdir)
                iso_gpg = work / "gnupg"
                iso_gpg.mkdir(mode=0o700)
                with mock.patch.object(
                    verify,
                    "urlopen",
                    return_value=FakeHTTPResponse(keys_file.read_bytes()),
                ):
                    v_gpg_env = verify.prepare_keyring(work, iso_gpg)

                with mock.patch.dict(
                    os.environ,
                    {"GIT_CONFIG_GLOBAL": str(global_cfg), "GIT_CONFIG_NOSYSTEM": "1"},
                ):
                    v_env = dict(v_gpg_env, GIT_CONFIG_GLOBAL=str(global_cfg), GIT_CONFIG_NOSYSTEM="1")
                    lw_repo = work / "lw-repo"
                    verify.init_isolated_repo(lw_repo)
                    with self.assertRaisesRegex(ValueError, "annotated signed tag"):
                        verify.verify_rc_tag(
                            lw_repo, repo.as_uri(), "0.21.0", commit, v_env, rc_tag="v0.21.0-rc.1"
                        )

                    ok_repo = work / "ok-repo"
                    verify.init_isolated_repo(ok_repo)
                    tag_name, tag_fp = verify.verify_rc_tag(
                        ok_repo, repo.as_uri(), "0.21.0", commit, v_env, rc_tag="v0.21.0-rc.2"
                    )
                    self.assertEqual(tag_name, "v0.21.0-rc.2")
                    self.assertEqual(tag_fp, fpr)

                # Broken gpg.program / gpg.openpgp.program in global git config is overridden by verify_rc_tag.
                global_cfg.write_text(
                    "[gpg]\n\tformat = ssh\n\tprogram = /nonexistent/broken-gpg\n"
                    '[gpg "openpgp"]\n\tprogram = /nonexistent/broken-gpg\n',
                    encoding="utf-8",
                )
                with mock.patch.dict(
                    os.environ,
                    {"GIT_CONFIG_GLOBAL": str(global_cfg), "GIT_CONFIG_NOSYSTEM": "1"},
                ):
                    broken_env = dict(
                        v_gpg_env,
                        GIT_CONFIG_GLOBAL=str(global_cfg),
                        GIT_CONFIG_NOSYSTEM="1",
                    )
                    broken_repo = work / "broken-cfg-repo"
                    verify.init_isolated_repo(broken_repo)
                    tag_name, tag_fp = verify.verify_rc_tag(
                        broken_repo,
                        repo.as_uri(),
                        "0.21.0",
                        commit,
                        broken_env,
                        rc_tag="v0.21.0-rc.2",
                    )
                    self.assertEqual(tag_name, "v0.21.0-rc.2")
                    self.assertEqual(tag_fp, fpr)


if __name__ == "__main__":
    unittest.main()
