<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Verify an Apache Reqsign Release Candidate

Use [`release/scripts/verify.py`](../scripts/verify.py) (standalone Python 3.12+ script) on independent hardware outside GitHub Actions to verify every release candidate before voting, or use the manual commands below if you prefer to run checks step by step.

## Automated Verification with `verify.py`

Download `verify.py` pinned to the candidate's commit SHA from the vote email and run verification against the pinned ATR revision:

```bash
curl -fsSL "https://raw.githubusercontent.com/apache/reqsign/<COMMIT_SHA>/release/scripts/verify.py" -o verify.py
python3 verify.py X.Y.Z "<COMMIT_SHA>" --atr-revision "<REVISION>" --full
```

To verify files already downloaded into a local directory without `--atr-revision` (or alongside `--atr-revision` to validate local files against the ATR manifest):

```bash
python3 verify.py X.Y.Z "<COMMIT_SHA>" --dir /path/to/downloads --full
```

### Supported Flags

- `--atr-revision <REVISION>`: Queries `https://releases.apache.org/api/release/manifest/reqsign/<version>/<rev>`, downloads missing `.tar.gz`, `.sha512`, and `.asc` files from `https://releases.apache.org/download/path/reqsign/<version>/`, checks exact byte lengths and `sha3-256` digests against the ATR manifest, verifies the Git RC tag signature, and performs deterministic archive reproduction.
- `--rc-tag <vX.Y.Z-rc.N>`: Explicitly specifies the RC tag to verify when multiple RC tags exist or when checking offline; otherwise `verify.py` discovers `refs/tags/v<version>-rc.*` dereferencing to `<COMMIT_SHA>` via `git ls-remote`.
- `--reproduce`: Rebuilds `apache-reqsign-<version>.tar.gz` in an isolated temporary clone of `<COMMIT_SHA>` (automatically enabled when `--atr-revision` is passed, or selectable explicitly for local directory checks).
- `--repo-url <URL>`: Overrides the Git remote URL used for tag discovery and `--reproduce` (defaults to `https://github.com/apache/reqsign.git`).
- `--dir <PATH>`: Reads candidate artifacts from `<PATH>` instead of the current working directory.
- `--full`: Runs `cargo publish --workspace --dry-run --allow-dirty`, `python3 .github/scripts/release_rust/standalone.py`, and `cargo test --manifest-path crypto/boring/Cargo.toml` in addition to the default workspace build and tests.

## What `verify.py` Checks

1. **ATR manifest integrity (`--atr-revision`)**: Confirms `apache-reqsign-X.Y.Z.tar.gz`, `.sha512`, and `.asc` match the exact byte size and `sha3-256` digest recorded by ATR for that revision.
2. **Checksum**: Verifies the candidate `.sha512` file matches `apache-reqsign-X.Y.Z.tar.gz` and carries the expected filename.
3. **Dual-signer OpenPGP verification**: Imports `https://downloads.apache.org/reqsign/KEYS` into an isolated temporary `GNUPGHOME` and requires `[GNUPG:] VALIDSIG` + `GOODSIG` (rejecting expired or revoked signatures even when `gpg` exits zero) for both:
   - The detached `.asc` signature on `apache-reqsign-X.Y.Z.tar.gz` (signed by the project's automated release signing key provisioned by ASF Infra).
   - The annotated Git RC tag `vX.Y.Z-rc.N` (signed by the release manager's personal `<id>@apache.org` key), verifying that the tag dereferences to `<COMMIT_SHA>`.
4. **Cross-OS deterministic archive reproduction (`--reproduce` / `--atr-revision`)**: Reconstructs the archive using `git -c core.attributesFile=/dev/null -c tar.umask=0022 archive --format=tar --prefix=apache-reqsign-X.Y.Z/ <COMMIT_SHA>` framed with fixed RFC 1952 `zlib` headers (`OS=0xff`, `mtime=0`, `XFL=2`, level 9, matching [`release/scripts/compose_source.py`](../scripts/compose_source.py)) and requires a bit-for-bit SHA-512 match against the ATR archive. Because `zlib` framing is fixed, reviewers reproduce identical bytes on both macOS and Linux.
5. **Archive layout, PAX commit, and binary scan**: Checks the global PAX `comment` header equals `<COMMIT_SHA>`, enforces single root directory `apache-reqsign-X.Y.Z/` with no `..` path traversal, scans regular files for valid UTF-8 and absence of unexpected binary control bytes, and verifies `reqsign/Cargo.toml` `[package].version` equals `X.Y.Z`.
6. **Legal files and ASF headers**: Checks root `LICENSE` and `NOTICE` are present and non-empty, runs `hawkeye --output-format json check` when `hawkeye` is installed, and scans `.rs`, `.py`, `.sh`, `.js`, `.jsx`, `.mjs`, `.css`, and `.mdx` files outside Hawkeye's selection for the ASF header.
7. **Build, tests, and packaging**: Runs `cargo build --workspace` and `cargo test --workspace --all-features --no-fail-fast`, plus `--full` packaging and BoringSSL checks when requested.

## Manual Verification Fallback

If you want to verify manually without `verify.py`, download the three artifacts from the ATR revision URL in a clean temporary directory and run:

```bash
# 1. Import project KEYS into a temporary GNUPGHOME
export GNUPGHOME="$(mktemp -d)"
chmod 700 "${GNUPGHOME}"
curl -fsSL https://downloads.apache.org/reqsign/KEYS -o KEYS
gpg --import KEYS

# 2. Verify checksum and archive signature
shasum -a 512 -c apache-reqsign-X.Y.Z.tar.gz.sha512
gpg --verify apache-reqsign-X.Y.Z.tar.gz.asc apache-reqsign-X.Y.Z.tar.gz

# 3. Verify the signed RC tag points to COMMIT_SHA
git clone --depth 1 --branch "vX.Y.Z-rc.N" https://github.com/apache/reqsign.git reqsign-tag-check
git -C reqsign-tag-check verify-tag "vX.Y.Z-rc.N"
test "$(git -C reqsign-tag-check rev-parse 'vX.Y.Z-rc.N^{commit}')" = "<COMMIT_SHA>"

# 4. Extract, check PAX commit, compare contents against git archive, and test
tar -xzf apache-reqsign-X.Y.Z.tar.gz
cd apache-reqsign-X.Y.Z
test -s LICENSE && test -s NOTICE
cargo build --workspace
cargo test --workspace --all-features --no-fail-fast
cargo publish --workspace --dry-run --allow-dirty
python3 .github/scripts/release_rust/standalone.py
cargo test --manifest-path crypto/boring/Cargo.toml
```

Remember to install CMake, Go (`>= 1.27.0`), and a C/C++ toolchain before running the `crypto/boring` test suite locally.
