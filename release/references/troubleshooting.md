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

# Troubleshoot Release Workflows, ATR, and crates.io

Start from the failing stage below and confirm configuration before rerunning or cutting a new RC.

## ATR OIDC or Trusted Publishing Rejection (`upload` job)

If `apache/tooling-actions/upload-to-atr` fails authentication or authorization:

- Check ATR's web UI Trusted Publishing configuration for project `reqsign`: `Repository name` must be `reqsign`, `Repository branch` must be **empty** (so tag builds and `release/*` or `rel/*` branches are accepted), and `Compose workflows` must list `.github/workflows/release-compose.yml`.
- Check the initiating GitHub actor (`github.actor`): ATR OIDC requires an ASF-linked user actor. Dispatches triggered by `github-actions[bot]` fail ATR OIDC.
- Do not add `github_repository_name` or `github_compose_workflow_path` to `.asf.yaml`: ATR's config endpoint strips or rejects `_TRUSTED_PUBLISHING_FIELDS`, so Trusted Publishing must be managed in the ATR web UI.

## Signing Key Mismatch or `KEYS` Propagation Failure (`sign` job)

- `sign` validates that `SOURCE_SIGNING_FINGERPRINT` (`secrets.SOURCE_SIGNING_FINGERPRINT` or `vars.SOURCE_SIGNING_FINGERPRINT`) is 40 or 64 uppercase hex characters, matches the fingerprint imported from `secrets.GPG_SECRET_KEY`, and exists in `https://downloads.apache.org/reqsign/KEYS`.
- ATR uses `keys_mode: reflect` from `https://downloads.apache.org/reqsign/KEYS`. Do not try to upload keys manually in ATR; append new RM personal keys or the ASF Infra automated signing key to `https://dist.apache.org/repos/dist/release/reqsign/KEYS` via SVN and wait for `downloads.apache.org` propagation before running `sign` or `verify.py`.
- If `GPG_SECRET_KEY` or `SOURCE_SIGNING_FINGERPRINT` is missing from the GitHub `release` environment, complete the ASF Infra onboarding ticket documented in [ATR operations](atr.md#one-time-pmc-onboarding-checklist).

## Rerunning `sign` or `upload` Without Cutting a New RC Tag

- If `compose` succeeded and uploaded `source-<run_id>-<attempt>`, fixing an external secret, `KEYS`, or ATR Trusted Publishing setting does not require a new RC tag. Rerun only the failed `sign` or `upload` job in the same GitHub Actions run (`source-*` artifacts remain available for 30 days; a `release` environment reviewer re-approves `sign`).
- Before rerunning `upload`, check ATR first: if all three files (`apache-reqsign-X.Y.Z.tar.gz`, `.sha512`, `.asc`) already arrived in ATR despite a late failure, verify and record that revision instead of creating a duplicate revision.
- If ATR rejects the upload layout, verify `compose` staged only `apache-reqsign-X.Y.Z.tar.gz` and `apache-reqsign-X.Y.Z.tar.gz.sha512` (never `report.json` or extra metadata files).

## Cross-OS Reproducibility or `verify.py --reproduce` Mismatch

- Do not replace [`compose_source.py`](../scripts/compose_source.py) or [`verify.py`](../scripts/verify.py) compression with shell `gzip -n -9`: macOS Apple `zlib` and Linux GNU `gzip` emit different compressed byte streams, and Python's `gzip.compress` varies the RFC 1952 `OS` byte across platforms/versions. Both scripts use fixed RFC 1952 `zlib` framing (`OS=0xff`, `mtime=0`, `XFL=2`, level 9).
- Confirm `git rev-parse vX.Y.Z-rc.N^{commit}` equals the `<COMMIT_SHA>` passed to `verify.py`, and that `core.attributesFile=/dev/null` and `tar.umask=0022` were used.

## ATR Apache RAT 0.18 or Lightweight Header Failures

- [`.asf.yaml`](../../.asf.yaml) sets `license_check_mode: Both` and configures `source_excludes_rat` for fixtures, testdata, `website/pnpm-lock.yaml`, `website/static/**`, and unheadered root/crate documentation while keeping `docs/**/*.md`, `website/docs/**/*.md`, `SECURITY.md`, `THREAT_MODEL.md`, and `release/**/*.md` in RAT scan scope.
- `source_excludes_lightweight` is intentionally omitted because every checked source file carries an ASF header (kept aligned with [`licenserc.toml`](../../licenserc.toml) for `hawkeye check`).
- If a newly added Markdown or source file triggers a RAT or lightweight failure, add the ASF header on `main` (or add a justified fixture exclusion to `source_excludes_rat`) and cut `vX.Y.Z-rc.(N+1)`.
- If ATR reports a tag-protection `CONCERN`, verify the `"Release tags"` raw ruleset in `.asf.yaml` (`creation`, `update`, `deletion`, `non_fast_forward` on `refs/tags/v*`) has synced to GitHub.

## ATR Vote and `phase == "release"` Quirks

- ATR email votes do not auto-resolve or send reminders at 72 hours, and the RM has no implicit `+1`. Cast an explicit `+1` and resolve manually once binding requirements are met.
- Do not edit vote or announcement templates only in ATR's web UI; `atr_sync: true` overwrites UI edits from `.asf.yaml`.
- Once ATR promotes a release into `phase == "release"`, `latest_revision_number` from `GET /api/release/get/reqsign/<version>` can be `null`. Any script or inspection logic checking published releases must accept `latest_revision_number: null` when `phase == "release"`.

## Crates.io Trusted Publishing Failures (`release.yml` and `publish.py`)

- **Partial failure, rate limits, or index lag**: [`.github/scripts/release_rust/publish.py`](../../.github/scripts/release_rust/publish.py) retries crates.io index lag (`10 x 30s`), honors `Retry-After` rate-limit delays, and skips already-published `(name, version)` pairs. Rerun the exact `vX.Y.Z` tag workflow run rather than pushing a new tag or adding a `CARGO_REGISTRY_TOKEN`.
- **Standalone `reqsign-crypto-boring` failure**: Confirm `crypto/boring/Cargo.toml` dependency bounds match the newly published workspace crate versions and that `reqsign-crypto-boring` was bootstrapped with `apache/reqsign`, `release.yml`, `release` Trusted Publisher and `trustpub_only`.
- **Wrong formal tag pushed early**: Cancel `release.yml` immediately, delete the remote `vX.Y.Z` tag (using PMC ruleset bypass if needed), and check crates.io to ensure nothing published.

## Bootstrap Failures (`bootstrap_rust_crates.yml`)

`bootstrap.py apply` stops before making any write if a crate disappeared after the `plan` preview, if an established crate lacks the exact `apache/reqsign`, `release.yml`, `release` Trusted Publisher, or if the attempt-scoped artifact ID is missing or expired. Inspect the `plan` summary and authenticated preflight log, migrate any established crate manually on crates.io, and rerun `release/scripts/bootstrap-rust-crates.sh` for a fresh preview.
