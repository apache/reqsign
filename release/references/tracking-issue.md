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

# Release Tracking Issue Template

Create a GitHub Issue in `apache/reqsign` titled `Tracking Issue to Release ${VERSION}` to coordinate the release and record audit/verification evidence so any PMC member can inspect or resume the release. Pin `RUNBOOK_COMMIT` to the full commit SHA of `origin/main` when opening the issue, and pass the issue body via standard input (`gh issue create --title "Tracking Issue to Release X.Y.Z" --body-file -`).

```markdown
- **Release manager:** @<github-login> (<asf-id>@apache.org)
- **Target version:** <X.Y.Z>
- **Previous release:** <prev-version> (`v<prev-version>`)
- **Source cutoff:** <commit-or-notes>
- **Release PR:** pending
- **Frozen release commit (`COMMIT_SHA`):** pending
- **Current phase / next action:** pre-flight and release preparation PR
- **Runbook:** https://github.com/apache/reqsign/blob/<RUNBOOK_COMMIT>/release/SKILL.md

## 1. Pre-flight and Preparation

- [ ] Verify ATR project policy (`https://releases.apache.org/projects/reqsign`) and confirm RM + automated project keys exist in `https://downloads.apache.org/reqsign/KEYS`.
- [ ] Run read-only crates.io inventory against `.github/scripts/release_rust/plan.py` (31 workspace crates + `crypto/boring/Cargo.toml`).
- [ ] Merge release preparation PR (version bumps across changed tracks, `[workspace.dependencies]`, `crypto/boring/Cargo.toml` bounds, `CHANGELOG.md`, and `website/docs/guides/` upgrade notes if applicable); record `COMMIT_SHA`.
- [ ] Confirm local/CI validation on `COMMIT_SHA`: `release_rust` + `release/scripts` unit tests, `plan.py`, `cargo publish --workspace --dry-run --allow-dirty`, `standalone.py`, and `hawkeye check`.

## 2. Crates.io Bootstrap

- [ ] Confirm whether `plan.py` introduces any unpublished crate name; if yes, run `release/scripts/bootstrap-rust-crates.sh` on `main` and record the `bootstrap_rust_crates.yml` run URL and `bootstrap.py verify` pass.
- [ ] Confirm all planned crates exist on crates.io with `apache/reqsign`, `release.yml`, `release` Trusted Publishing and `trustpub_only` enabled.

## 3. Release Candidate and ATR Staging

- **RC signed tag:** pending (`v<X.Y.Z>-rc.1`)
- **Tag signer fingerprint:** pending
- **Compose workflow run (`release-compose.yml`):** pending
- **Validate workflow run (`release.yml`):** pending
- **ATR candidate URL & revision:** pending
- **Archive SHA-512:** pending
- **Archive signer fingerprint:** pending

Checklist:

- [ ] Push signed annotated tag `v<X.Y.Z>-rc.N` at `COMMIT_SHA`; confirm `compose`, `release` env approval, `sign`, and `upload` to ATR (`project: reqsign`, `version: <X.Y.Z>`).
- [ ] Confirm `release.yml` `validate` passes on `v<X.Y.Z>-rc.N` (and `publish` is skipped).
- [ ] Inspect ATR Compose checks (RAT 0.18, lightweight headers, `LICENSE`/`NOTICE`, tag protection) and enter `COMMIT_SHA` if empty.
- [ ] Run independent verification (`python3 release/scripts/verify.py <X.Y.Z> <COMMIT_SHA> --atr-revision <REVISION> --full`) outside GitHub Actions and record the result.

## 4. PMC Vote and ATR Finish

- **ATR vote URL:** pending
- **Vote thread (`dev@reqsign.apache.org`):** pending
- **Vote closing time (UTC, >= 72h):** pending
- **Result thread:** pending
- **ATR Finish SVN revision & URL:** pending

Checklist:

- [ ] Send `[VOTE]` email from ATR to `dev@reqsign.apache.org` (minimum 72h); record thread link and closing time.
- [ ] Cast explicit RM `+1` vote with verification checks.
- [ ] After >= 72h, verify >= 3 binding PMC `+1` votes (and more `+1` than `-1`), resolve as `Passed` in ATR, and record `[RESULT][VOTE]` permalink.
- [ ] Run Finish in ATR to publish `apache-reqsign-<X.Y.Z>.tar.gz{.asc,.sha512}` to `https://downloads.apache.org/reqsign/reqsign-<X.Y.Z>/`; verify published checksums and signatures.

## 5. Formal Tag, crates.io, Release, Website, and Announcement

- **Formal tag:** pending (`v<X.Y.Z>` at `<COMMIT_SHA>`)
- **Crates.io publish run (`release.yml`):** pending
- **GitHub Release URL:** pending
- **Announcement thread:** pending

Checklist:

- [ ] Push signed formal tag `v<X.Y.Z>` pointing to the exact voted `COMMIT_SHA`.
- [ ] Approve `release` environment deployment in `release.yml` and confirm all planned crates (including `reqsign-crypto-boring`) match `plan.py` live on crates.io.
- [ ] Publish curated GitHub Release `v<X.Y.Z>` from `CHANGELOG.md` with `closer.lua` and `downloads.apache.org` verification links.
- [ ] Confirm `website.yml` deploys `https://reqsign.apache.org/download/` cleanly with the updated `v<X.Y.Z>` version.
- [ ] Send `[ANNOUNCE]` from ATR (`dev@reqsign.apache.org` + CC `announce@apache.org`) and record the permalink.
- [ ] Archive superseded releases in ATR (verifying `https://archive.apache.org/dist/reqsign/` retention).
- [ ] Close this tracking issue.
```

If a candidate must be replaced, preserve the prior RC tag, commit, ATR revision, and vote history in this issue, update the active candidate fields to `vX.Y.Z-rc.(N+1)`, and rerun affected verification checks.
