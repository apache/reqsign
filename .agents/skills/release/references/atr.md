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

# Operate Apache Reqsign Releases in ATR

Open the [Apache Reqsign ATR project](https://releases.apache.org/projects/reqsign) with an ASF committer or PMC login. Apache Reqsign is a Top-Level Project (TLP) configured with `vote_mode: email` and a minimum 72-hour single-round PMC vote on `dev@reqsign.apache.org`.

## One-Time PMC Onboarding Checklist

Complete these one-time prerequisites before cutting the first ATR-composed release candidate:

1. **ASF Security reproducible-build review**: Obtain ASF Security sign-off for automated source archive signing via [`.github/workflows/release-compose.yml`](../../../../.github/workflows/release-compose.yml) and [`scripts/compose_source.py`](../../../../scripts/compose_source.py) per [ASF automated release signing](https://infra.apache.org/release-signing.html#automated-release-signing).
2. **ASF Infra key provisioning**: File an ASF Infra Jira ticket to generate and provision the project's automated release signing key (`Reqsign Automated Release Signing <private@reqsign.apache.org>`) into the GitHub `release` environment secrets (`GPG_SECRET_KEY`, optional `GPG_PASSPHRASE`, and `SOURCE_SIGNING_FINGERPRINT`), and append its ASCII-armored public key to `https://dist.apache.org/repos/dist/release/reqsign/KEYS`.
3. **ATR committee upload opt-in**: Once `Reqsign Automated Release Signing <private@reqsign.apache.org>` is in `KEYS` and reflected in ATR, a PMC member must tick **Allow uploads from GitHub Actions** in the Permissions card on the `reqsign` committee page and save (see [Step 5: Allow uploads on the committee page](https://releases.apache.org/docs/github-actions-uploads#step-5-allow-uploads-on-the-committee-page)).
4. **ATR project GitHub OIDC restrictions**: On the `reqsign` project page, confirm `https://github.com/apache/reqsign.git` is listed under *Repositories* (synced from `project.metadata.repositories` in `.asf.yaml`; see [Step 6: List the repository on the project](https://releases.apache.org/docs/github-actions-uploads#step-6-list-the-repository-on-the-project)). Under *Actions* -> *Advanced settings* ([Restricting which runs can upload](https://releases.apache.org/docs/github-actions-uploads#restricting-which-runs-can-upload)), add `.github/workflows/release-compose.yml` to **Workflow paths** and leave **Branches or tags** and **Branch or tag patterns** unrestricted or permitting `v*` tags so RC tag runs on `main`, `release/*`, or `rel/*` commits can upload. These OIDC restrictions are stored only in ATR (and legacy `_TRUSTED_PUBLISHING_FIELDS` are rejected over the `.asf.yaml` config API), so they cannot be managed via `.asf.yaml` alone.
5. **`.asf.yaml` `atr_sync` verification**: Confirm [`.asf.yaml`](../../../../.asf.yaml) has merged onto `main` and synced to ATR (`https://releases.apache.org/api/project/get/reqsign`).

## `.asf.yaml` Policy and `KEYS` Synchronization

[`.asf.yaml`](../../../../.asf.yaml) sets `project.features.atr_sync: true`, which keeps project metadata, license rules, download layout, vote/announce recipients, and plain-text email templates synchronized from Git into ATR:

- **Top-level project download suffix**: Reqsign is a TLP (`project.metadata.key == committee`), so an empty `download_path_suffix` in ATR would publish files into the `dist/release/reqsign/` root. `.asf.yaml` sets `download_path_suffix: "reqsign-{{VERSION}}"` so ATR Finish publishes to `https://downloads.apache.org/reqsign/reqsign-X.Y.Z/`, matching existing releases and [`website/src/pages/download.mdx`](../../../../website/src/pages/download.mdx).
- **Archive pattern and license modes**: `source_artifact_paths: ["apache-reqsign-*.tar.gz"]`, `require_version_in_filenames: true`, `license_check_mode: Both` (runs both Apache RAT 0.18 and ATR lightweight header checks), and `source_excludes_rat` covering test fixtures, testdata, `website/pnpm-lock.yaml`, `website/static/**`, and unheadered root/crate documentation while keeping `docs/**/*.md`, `website/docs/**/*.md`, `SECURITY.md`, `THREAT_MODEL.md`, and `.agents/skills/release/**/*.md` inside RAT scope.
- **Email templates**: Update `start_vote_subject`, `start_vote_template`, `announce_release_subject`, and `announce_release_template` in `.asf.yaml` rather than ATR's web UI, because `atr_sync` overwrites manual UI edits.
- **`KEYS` reflection (`keys_mode: reflect`)**: ATR automatically reflects `https://downloads.apache.org/reqsign/KEYS`. Never upload keys manually in ATR; a new release manager appends their exported `<id>@apache.org` public key to `https://dist.apache.org/repos/dist/release/reqsign/KEYS` via SVN and waits for `downloads.apache.org` propagation before tagging.

## Compose Stage

1. Push signed RC tag `vX.Y.Z-rc.N` from the frozen commit `COMMIT_SHA` to trigger `.github/workflows/release-compose.yml`.
2. After `compose` builds and verifies the deterministic source bundle on `ubuntu-24.04` (with `reproduce-macos` additionally checking macOS parity on PRs touching release files), a PMC reviewer approves the `release` environment deployment for `sign` (and `upload` runs after `sign`).
3. `upload` creates or appends a numbered revision (`00001`, `00002`, ...) under ATR project `reqsign`, version `X.Y.Z`.
4. Open the draft in ATR Compose, confirm the archive `apache-reqsign-X.Y.Z.tar.gz`, `.sha512`, and `.asc` are present, inspect all ATR check results (RAT 0.18, lightweight headers, `LICENSE`/`NOTICE`, tag protection), and enter `COMMIT_SHA` in ATR's commit field if blank.
5. Complete independent candidate verification using [the verification guide](verification.md) before starting the vote.

## Vote Stage (Single-Round PMC Vote)

1. Open the voting form in ATR for the verified revision. Confirm recipient `dev@reqsign.apache.org` and minimum duration `72` hours.
2. Review the generated subject (`[VOTE] Release Apache Reqsign X.Y.Z`) and plain-text body: add the RC tag (`vX.Y.Z-rc.N`), tag signer fingerprint, source archive signer fingerprint, and verification evidence. Do not use Markdown formatting or backticks, keep prose wrapped near 72 characters, and keep URLs and checksums unbroken on their own lines.
3. Submit **Send vote email** and record the `lists.apache.org` permalink and closing UTC timestamp in the tracking issue.
4. Cast an explicit `+1` vote with your verification checks on ATR or by replying in the `dev@reqsign.apache.org` thread. A release manager has no implicit `+1` vote.

## Resolve Stage

ATR does not automatically resolve email votes or send reminders when 72 hours elapse. After the voting period ends:

1. Open the ATR vote resolution page and cross-check ATR's parsed tally against the `dev@reqsign.apache.org` thread on `lists.apache.org`.
2. Confirm at least 72 hours have passed, at least 3 binding Reqsign PMC `+1` votes were cast, and binding `+1` votes outnumber binding `-1` votes (counting only each voter's latest vote).
3. Select `Passed` and resolve the vote. ATR sends the `[RESULT][VOTE]` email automatically and moves the release to Finish.

## Finish, Announce, and Archive

1. In ATR Finish, execute **Publish to ASF Distribution Area** (confirming destination `dist/release/reqsign/reqsign-X.Y.Z/`) to promote the exact voted revision without altering any bytes. Record the SVN revision and verify `https://downloads.apache.org/reqsign/reqsign-X.Y.Z/apache-reqsign-X.Y.Z.tar.gz{.asc,.sha512}`.
2. Return to [the release skill](../SKILL.md#8-push-formal-tag-vxyz-and-publish-crates) to push the formal signed `vX.Y.Z` tag, verify all 32 crates.io publications, publish the GitHub Release, and confirm the website download page is live.
3. Once ASF downloads, crates.io packages, GitHub Release, and website updates are confirmed live, run **Announce** in ATR (`to: dev@reqsign.apache.org`, `cc: announce@apache.org`), review the plain-text message, and submit. Record the `lists.apache.org` announcement permalink.
4. Archive superseded releases in ATR so older versions move out of `downloads.apache.org/reqsign/` and remain permanently available in `https://archive.apache.org/dist/reqsign/`.

## Inspection via ATR Public API and CLI

You can inspect project policy, release state, and pinned revision manifests without authentication:

```bash
curl -fsSL https://releases.apache.org/api/project/get/reqsign | jq .
curl -fsSL https://releases.apache.org/api/release/get/reqsign/X.Y.Z | jq .
curl -fsSL https://releases.apache.org/api/release/manifest/reqsign/X.Y.Z/00001 | jq .
```

Note that once ATR transitions a release to `phase == "release"`, `latest_revision_number` in `/api/release/get/reqsign/X.Y.Z` may become `null`. For scripted ATR operations, consult the [ATR CLI (`tooling-releases-client`)](https://github.com/apache/tooling-releases-client) and [ATR server API documentation](https://releases.apache.org/docs/).

## Recover Without Replacing Voted Files

- **Failed `sign` or `upload` due to external config**: Always check [ATR](https://releases.apache.org/projects/reqsign) for a complete revision first; if all three files already arrived and verify cleanly, record that revision instead of creating a duplicate upload. Because ATR rejects GitHub Actions rerun attempts (`run_attempt > 1`, see [ATR upload policy](https://releases.apache.org/docs/github-actions-uploads#what-atr-checks)), do not use GitHub's rerun button after fixing secrets, `KEYS` propagation, or ATR settings. Instead, start a fresh workflow run with `gh workflow run release-compose.yml --repo apache/reqsign --ref "$rc_tag"` using the same verified RC tag and no workflow inputs.
- **Code, Cargo, or workflow fix needed**: Land a reviewed PR on `main`, create a new signed RC tag `vX.Y.Z-rc.(N+1)`, and compose a fresh ATR revision (`00002`, ...). Never move an existing RC tag or mutate an uploaded revision after starting a vote.
- **Rejected or cancelled vote**: Resolve the vote outcome in ATR to return the release to Compose, retain the prior RC tag and vote thread in the tracking issue history, then cut `vX.Y.Z-rc.(N+1)` for a new revision under `X.Y.Z`.
