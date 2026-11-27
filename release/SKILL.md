---
name: reqsign-release
description: Release Apache Reqsign end-to-end through ATR composition, verification, single-round PMC email voting, dist publication, formal Git tagging, crates.io Trusted Publishing, GitHub Release, website refresh, and announcement.
---

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

# Apache Reqsign Release Skill

Use this skill when preparing, verifying, or executing an Apache Reqsign release. Apache Reqsign is an ASF Top-Level Project (TLP), not an Incubator podling: releases use a single-round 72-hour PMC vote on `dev@reqsign.apache.org`, have no IPMC round, carry no `-incubating` suffix, and ship no `DISCLAIMER`.

GitHub Actions composes and signs the deterministic source archive and stages it to the [Apache Trusted Releases (ATR)](https://releases.apache.org/projects/reqsign) platform; ATR manages the PMC email vote, promotes the voted revision to ASF `downloads.apache.org`, and sends the announcement; the formal signed Git tag triggers crates.io OIDC Trusted Publishing.

Load the reference guides as needed:

- [ATR operations](references/atr.md): one-time PMC/Infra onboarding, `.asf.yaml` `atr_sync` policy, Compose, Vote, Resolve, Finish, Announce, and recovery rules.
- [Verification guide](references/verification.md): `release/scripts/verify.py`, ATR manifest SHA3-256 verification, dual OpenPGP signers, cross-OS deterministic reproduction, and manual fallback checks.
- [Tracking issue template](references/tracking-issue.md): copy-pasteable GitHub issue checklist for coordinating a release.
- [Troubleshooting guide](references/troubleshooting.md): ATR OIDC, `KEYS` propagation, job reruns, RAT exclusions, and crates.io Trusted Publishing recovery.

## Hard Rules

- Never push the formal `vX.Y.Z` tag before the PMC vote passes on ATR and ATR Finish publishes the source release.
- The release candidate tag `vX.Y.Z-rc.N` (`N >= 1`) must be a signed annotated tag created with the release manager's personal ASF GPG key (listed in `KEYS`) on the reviewed release commit.
- The formal `vX.Y.Z` tag must point to the exact same commit as the voted RC tag (`git rev-parse vX.Y.Z-rc.N^{commit}`), even if `main` has advanced after the vote started.
- Never mutate voted artifacts or reuse an RC tag for changed contents; any source or workflow change requires a new reviewed commit and a higher RC number `vX.Y.Z-rc.(N+1)` (which creates a new ATR revision under version `X.Y.Z`).
- Every crate in the publish plan (currently 31 workspace crates plus 1 standalone crate `crypto/boring/Cargo.toml` = `reqsign-crypto-boring`) must exist on crates.io with the exact `apache/reqsign`, `release.yml`, `release` Trusted Publisher and `trustpub_only` enabled before cutting the RC tag.
- `.github/workflows/release.yml` publishes to crates.io only on formal `vX.Y.Z` tags using short-lived GitHub OIDC credentials (`publish.py`), never on `-rc.N` tags, never on `workflow_dispatch`, and never with a long-lived crates.io token.
- Official source artifacts are staged on ATR during Compose/Vote (`project: reqsign`, `version: X.Y.Z`) and published by ATR Finish to `https://dist.apache.org/repos/dist/release/reqsign/reqsign-X.Y.Z/` (`https://downloads.apache.org/reqsign/reqsign-X.Y.Z/`) via `download_path_suffix: "reqsign-{{VERSION}}"`.
- If a formal `vX.Y.Z` tag is pushed early by mistake, immediately cancel the `Release` workflow run, delete the remote tag, and audit crates.io to confirm nothing published.

## 1. Pre-flight and Tracking Issue

Check live project, ATR, `KEYS`, Git tag, and crates.io state before touching versions:

```bash
git fetch origin main --tags
git status --short --branch
git tag --list 'vX.Y.Z*' --sort=version:refname
git ls-remote --tags origin 'refs/tags/vX.Y.Z*'
curl -fsSL https://releases.apache.org/api/project/get/reqsign | jq .
curl -fsSL https://downloads.apache.org/reqsign/KEYS | gpg --show-keys
```

Confirm that the release manager's personal ASF `<id>@apache.org` signing key and the automated project release signing key (`SOURCE_SIGNING_FINGERPRINT`) are both present in `https://downloads.apache.org/reqsign/KEYS`, and that one-time ATR onboarding in [ATR operations](references/atr.md) is complete.

Inventory the live crates.io registry against the authoritative publish plan in [`.github/scripts/release_rust/plan.py`](../.github/scripts/release_rust/plan.py). This check is read-only, requires no credentials, and exits nonzero if the plan is empty:

```bash
python3 - <<'EOF'
import json, subprocess, urllib.error, urllib.request
plan = json.loads(subprocess.check_output(
    ["python3", ".github/scripts/release_rust/plan.py"], text=True))
if not plan:
    raise SystemExit("plan.py returned an empty publish plan")
for package in plan:
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{package['name']}",
        headers={"User-Agent": "reqsign-release"})
    try:
        published = [v["num"] for v in
                     json.load(urllib.request.urlopen(request, timeout=20))["versions"]]
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        print(f"missing name: {package['name']}")
        continue
    if package["version"] in published:
        print(f"already published: {package['name']} {package['version']}")
EOF
```

Open a tracking issue in `apache/reqsign` using [the tracking issue template](references/tracking-issue.md) and pin the runbook link to the current `origin/main` commit SHA.

## 2. Release Preparation PR

Prepare a reviewed PR targeting `main` (or the agreed `release/*` / `rel/*` branch).

### Crate and Version-Track Policy

Reqsign publishes 32 crates on five version tracks (31 workspace members plus 1 excluded standalone crate `crypto/boring/Cargo.toml`), with the `reqsign` facade crate (`0.21.0` line) setting the overall project release version `X.Y.Z`:

- `reqsign`: patch bump for a compatible release (e.g., `0.21.0 -> 0.21.1`), or next `0.x` minor for a breaking or feature release because `0.x` minors are the facade's breaking channel.
- Core and the established service line (`reqsign-core`, `reqsign-aws-core`, established `reqsign-<provider>` crates, `reqsign-http-message-signatures`, `reqsign-file-read-tokio`, `reqsign-command-execute-tokio`): bump together on the lockstep major (`4.0.0` line) on breaking core changes, or minor for a backwards-compatible new public capability.
- `reqsign-http-send-reqwest` (`5.0.0` line): patch or minor by its own change, and bump major whenever the core lockstep major changes so it remains one major ahead of core.
- Provider and shared crates on independent `1.0.0` lines (`reqsign-aliyun-drive`, `reqsign-b2`, `reqsign-baidu-netdisk`, `reqsign-cloudflare`, `reqsign-dropbox`, `reqsign-github`, `reqsign-koofr`, `reqsign-oauth2`, `reqsign-onedrive`, `reqsign-seafile`, `reqsign-upyun`, `reqsign-vercel`, `reqsign-yandex-disk`, and newly added provider crates): `1.0.0` for initial release, then bumped by their own change.
- `reqsign-crypto-rustcrypto` and `reqsign-crypto-boring`: independent `1.0.0` lines, bumped by their own change.
- Root [`Cargo.toml`](../Cargo.toml) `[workspace.dependencies]` version requirements must match each workspace crate's manifest version, and standalone [`crypto/boring/Cargo.toml`](../crypto/boring/Cargo.toml) bounds (`reqsign-core` and dev-dependencies) must be updated by hand in the same PR because `crypto/boring` is excluded from the workspace (`exclude = ["crypto/boring"]`).
- Update [`CHANGELOG.md`](../CHANGELOG.md) with the release notes and crate-version table, and add or update migration steps under [`website/docs/guides/`](../website/docs/guides/) when breaking changes ship.

### Validate Plan, Packaging, and Headers

Run all release-helper unit tests, plan resolution, workspace dry-run, standalone validation, and license header checks before merging:

```bash
python3 -m unittest discover -s .github/scripts/release_rust -p "test_*.py"
python3 -m unittest discover -s release/scripts -p "test_*.py"
python3 .github/scripts/release_rust/plan.py
cargo publish --workspace --dry-run --allow-dirty
python3 .github/scripts/release_rust/standalone.py
hawkeye check
```

`cargo publish --workspace --dry-run` stages the 31 workspace crates together so intra-workspace dependencies resolve locally before publication. Never substitute per-package `cargo publish -p <crate> --dry-run` before the real dependency versions are live on crates.io: it fails with a version-selection error (`failed to select a version for the requirement reqsign-core = "^4.0.0"`), and `0.0.0` bootstrap reservations do not satisfy `^4.0.0`.

[`standalone.py`](../.github/scripts/release_rust/standalone.py) validates standalone entries in `STANDALONE_MANIFESTS` (`crypto/boring/Cargo.toml`) by temporarily patching local path dependencies from the checkout, running `cargo package --no-verify` without requiring a BoringSSL build, checking `LICENSE`/`NOTICE`/`README`/source files, and verifying normalized dependency versions without `path`. BoringSSL compilation and tests are covered by [`.github/workflows/crypto_boring.yml`](../.github/workflows/crypto_boring.yml) and `verify.py --full`.

Merge the reviewed preparation PR into `main` and record the frozen commit SHA (`COMMIT_SHA`) in the tracking issue.

## 3. Bootstrap Newly Added Unpublished Crates

If the crates.io inventory check in Step 1 reported any `missing name` (such as a newly added provider crate or `reqsign-crypto-boring` prior to its first reservation), reserve it before cutting the RC tag. Wait until the crate set is on `apache/reqsign` `main` and a PMC release manager confirms the reservation window, then run from a clean `origin/main` checkout:

```bash
release/scripts/bootstrap-rust-crates.sh
```

[`release/scripts/bootstrap-rust-crates.sh`](scripts/bootstrap-rust-crates.sh) requires a clean `main` checkout, verifies that the `rust-bootstrap` GitHub environment has required reviewers (`prevent_self_review: true` in [`.asf.yaml`](../.asf.yaml)), dispatches [`.github/workflows/bootstrap_rust_crates.yml`](../.github/workflows/bootstrap_rust_crates.yml), waits for completion, and runs `bootstrap.py verify`.

Inside `bootstrap_rust_crates.yml`:

- The `plan` job runs `bootstrap.py discover --plan-output bootstrap-plan.json` across the full `plan.py` set (workspace plus standalone manifests), uploads the plan as an attempt-scoped artifact, and records the exact artifact ID in the job summary.
- After a non-self PMC reviewer approves `rust-bootstrap`, the protected `bootstrap` job downloads by that exact artifact ID and runs `bootstrap.py apply` using `secrets.CARGO_REGISTRY_BOOTSTRAP_TOKEN` (scoped solely to `publish-new` and `trusted-publishing` for reqsign crates).
- `apply` audits every existing crate's ownership and Trusted Publisher (`apache/reqsign`, `release.yml`, `release`), publishes a dependency-free `0.0.0` placeholder only for reviewed missing names, configures the Trusted Publisher and enables `trustpub_only`, and stops immediately if an unexpected crate disappeared or an established crate lacks the expected publisher.

## 4. Cut and Push Signed RC Tag

Create a signed annotated RC tag `vX.Y.Z-rc.N` (`N >= 1`) with the release manager's personal ASF GPG key on the frozen commit `COMMIT_SHA` on `main` (or an agreed `release/*` / `rel/*` branch):

```bash
git fetch origin main --tags
git switch --detach "<COMMIT_SHA>"
git tag -s "vX.Y.Z-rc.N" -m "Apache Reqsign X.Y.Z release candidate N"
git tag -v "vX.Y.Z-rc.N"
git push origin "vX.Y.Z-rc.N"
```

Pushing `vX.Y.Z-rc.N` triggers two workflows:

- [`.github/workflows/release-compose.yml`](../.github/workflows/release-compose.yml):
  1. `compose` (`ubuntu-24.04`) runs `release/scripts` unit tests, validates the RC tag, `reqsign/Cargo.toml` version, and `origin/main` / `release/*` / `rel/*` containment, runs [`release/scripts/compose_source.py`](scripts/compose_source.py), and emits `apache-reqsign-X.Y.Z.tar.gz` and `apache-reqsign-X.Y.Z.tar.gz.sha512` (with `reproduce-macos` additionally checking macOS vs Ubuntu parity on PRs).
  2. A PMC reviewer listed in `.asf.yaml` approves the `release` GitHub environment.
  3. `sign` checks that `SOURCE_SIGNING_FINGERPRINT` matches the imported `GPG_SECRET_KEY` and appears in `https://downloads.apache.org/reqsign/KEYS`, then signs `apache-reqsign-X.Y.Z.tar.gz.asc` and verifies `GOODSIG` + `VALIDSIG`.
  4. `upload` verifies the exact three files (`apache-reqsign-X.Y.Z.tar.gz`, `.sha512`, `.asc`) and pushes them via `apache/tooling-actions/upload-to-atr` to ATR (`project: reqsign`, `version: X.Y.Z`), creating a new revision (`00001`, `00002`, ...).
- [`.github/workflows/release.yml`](../.github/workflows/release.yml): `validate` runs `release_rust` and `release/scripts` unit tests, `plan.py`, `cargo publish --workspace --dry-run`, and `standalone.py`. The `publish` job is skipped on `-rc.N` tags.

Record the workflow run URLs, ATR candidate revision, and SHA-512 in the tracking issue.

## 5. Independent Candidate Verification

Before starting the PMC vote, open the candidate in [ATR](https://releases.apache.org/projects/reqsign) to inspect automated checks (Apache RAT 0.18, lightweight headers, `LICENSE`/`NOTICE`, tag protection), then verify the pinned ATR revision on independent hardware outside GitHub Actions following the [verification guide](references/verification.md):

```bash
curl -fsSL "https://raw.githubusercontent.com/apache/reqsign/<COMMIT_SHA>/release/scripts/verify.py" -o verify.py
python3 verify.py X.Y.Z "<COMMIT_SHA>" --atr-revision "<REVISION>" --full
```

`verify.py` verifies ATR manifest `sha3-256` digests and byte sizes, both OpenPGP signatures (archive `.asc` signed by the project signing key and Git RC tag signed by the RM's personal key, both against `KEYS`), bit-for-bit deterministic archive reproduction from Git, PAX commit metadata, `reqsign/Cargo.toml` version, `LICENSE`/`NOTICE`, UTF-8/binary cleanliness, ASF headers, workspace build/tests/dry-run, `standalone.py`, and BoringSSL tests.

## 6. Start Single-Round PMC Vote via ATR

Follow [ATR operations](references/atr.md) to send the vote email from ATR to `dev@reqsign.apache.org` with a minimum duration of 72 hours.

- Include the RC number (`vX.Y.Z-rc.N`), tag signer, ATR candidate URL and revision, frozen commit SHA, and your verification evidence.
- Keep the email plain text (no Markdown or backticks, prose wrapped near 72 characters). Edit durable template defaults in `.asf.yaml`, not in ATR's web UI (`atr_sync: true` overwrites UI edits).
- The release manager has no implicit `+1`; cast an explicit `+1` vote with your checks on ATR or in the mailing list thread.
- Passing requires at least 72 hours, at least 3 binding PMC `+1` votes, and more binding `+1` votes than `-1` votes.

## 7. Resolve Vote and Finish on ATR

ATR neither auto-resolves email votes nor sends closing reminders. After the 72-hour window and required binding PMC votes:

1. Compare ATR's tally against the `dev@reqsign.apache.org` thread on `lists.apache.org` and confirm only eligible binding PMC votes (latest vote per voter) are counted toward the binding threshold.
2. Resolve the vote as `Passed` in ATR; ATR sends the `[RESULT][VOTE]` email and advances the release to Finish.
3. Run Finish in ATR to publish the exact voted revision to `https://dist.apache.org/repos/dist/release/reqsign/reqsign-X.Y.Z/` (`https://downloads.apache.org/reqsign/reqsign-X.Y.Z/`), and verify the published `.tar.gz`, `.asc`, and `.sha512` match the voted candidate.

## 8. Push Formal Tag `vX.Y.Z` and Publish Crates

Create and push the signed formal tag `vX.Y.Z` at the exact voted RC commit (never a newer `main` commit):

```bash
git fetch origin --tags
test "$(git rev-parse 'vX.Y.Z-rc.N^{commit}')" = "<COMMIT_SHA>"
git tag -s "vX.Y.Z" "<COMMIT_SHA>" -m "Apache Reqsign X.Y.Z"
git tag -v "vX.Y.Z"
git push origin "vX.Y.Z"
```

Monitor [`.github/workflows/release.yml`](../.github/workflows/release.yml) and approve the `release` environment deployment once `validate` passes:

```bash
gh run list --repo apache/reqsign --workflow Release --limit 5
gh run view "<RUN_ID>" --repo apache/reqsign --json status,conclusion,url,jobs
```

`publish.py` exchanges short-lived GitHub OIDC tokens (`audience=crates.io`, immediately revoked after each attempt) to publish all 32 crates in topological order, including standalone `reqsign-crypto-boring`. Verify live crates.io versions match `plan.py`:

```bash
python3 - <<'EOF'
import json, subprocess, urllib.error, urllib.request
plan = json.loads(subprocess.check_output(
    ["python3", ".github/scripts/release_rust/plan.py"], text=True))
if not plan:
    raise SystemExit("plan.py returned an empty publish plan")
missing = []
for package in plan:
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{package['name']}",
        headers={"User-Agent": "reqsign-release"})
    try:
        versions = {version["num"] for version in
                    json.load(urllib.request.urlopen(request, timeout=20))["versions"]}
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        versions = set()
    if package["version"] in versions:
        print(f"published: {package['name']} {package['version']}")
    else:
        missing.append(package["name"])
        shown = ", ".join(sorted(versions)) or "no versions"
        print(f"not published: {package['name']} {package['version']} (found: {shown})")
if missing:
    raise SystemExit(f"{len(missing)} crate(s) did not publish the planned version")
EOF
```

## 9. GitHub Release, Website, Announce, and Archive

1. Publish a curated GitHub Release for tag `vX.Y.Z` using the `X.Y.Z` section of [`CHANGELOG.md`](../CHANGELOG.md) (notable changes and crate-version table) plus links to `https://www.apache.org/dyn/closer.lua/reqsign/reqsign-X.Y.Z/apache-reqsign-X.Y.Z.tar.gz`, `https://downloads.apache.org/reqsign/reqsign-X.Y.Z/apache-reqsign-X.Y.Z.tar.gz.asc`, `https://downloads.apache.org/reqsign/reqsign-X.Y.Z/apache-reqsign-X.Y.Z.tar.gz.sha512`, and `https://downloads.apache.org/reqsign/KEYS`.
2. Verify the project website refreshes cleanly: [`website/docusaurus.config.js`](../website/docusaurus.config.js) resolves `websiteVersion` automatically from the latest non-RC `v*` tag on the next `website.yml` build (`https://reqsign.apache.org/download/`). Confirm the download and `KEYS` links work live before announcing.
3. Send the `[ANNOUNCE]` email from ATR (`to: dev@reqsign.apache.org`, `cc: announce@apache.org`) and record the `lists.apache.org` permalink in the tracking issue.
4. Archive superseded releases in ATR so older releases move cleanly to `https://archive.apache.org/dist/reqsign/`, then close the tracking issue.
