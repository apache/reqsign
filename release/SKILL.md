---
name: reqsign-release
description: Release Apache Reqsign through the Apache RC, vote, dist, tag, crates.io, and announcement flow.
---

# Apache Reqsign Release Skill

Use this skill when preparing or executing an Apache Reqsign release.

## Hard Rules

- Do not push the formal `vX.Y.Z` tag before the Apache vote passes.
- The voted release candidate tag is `vX.Y.Z-rc.N`; it must be a signed tag.
- The formal `vX.Y.Z` tag must point to the exact same commit as the voted RC tag, even if `main` has advanced after the vote started.
- Every crate in the current publish plan must exist with the exact `apache/reqsign`, `release.yml`, `release` Trusted Publisher and `trustpub_only` enabled before creating the RC tag.
- The repo release workflow publishes only formal `vX.Y.Z` tags. It uses short-lived GitHub OIDC credentials and never a long-lived crates.io token.
- Source release artifacts live under Apache dist:
  - RC: `https://dist.apache.org/repos/dist/dev/reqsign/reqsign-X.Y.Z/`
  - Final: `https://dist.apache.org/repos/dist/release/reqsign/reqsign-X.Y.Z/`
- If a wrong formal tag is pushed early, immediately cancel the Release workflow, delete the remote tag, and verify crates.io did not publish anything.

## Release Preparation

Prepare, then reserve, then vote, then publish. The order is: version and notes
PR merged into `main`; reserve every missing crate name with the bootstrap
workflow; RC tag and source artifact; vote; formal tag from the voted commit;
Release workflow publishes the plan; GitHub Release from `CHANGELOG.md`.

1. Sync live state.

   ```bash
   git fetch origin main --tags
   git status --short --branch
   git tag --list 'vX.Y.Z*' --sort=version:refname
   git ls-remote --tags origin 'refs/tags/vX.Y.Z*'
   svn ls https://dist.apache.org/repos/dist/dev/reqsign/reqsign-X.Y.Z/ || true
   svn ls https://dist.apache.org/repos/dist/release/reqsign/reqsign-X.Y.Z/ || true
   ```

2. Prepare version bump on a PR.

   Version policy by track. The current line is facade `0.21.0`, lockstep
   `4.0.0`, reqwest adapter `5.0.0`, and `1.0.0` for first-release crates.

   - `reqsign`: patch bump for a compatible release, for example
     `0.21.0 -> 0.21.1`. A breaking or feature release takes the next `0.x`
     minor because 0.x minors are the facade's breaking channel.
   - Core and the established service line (`reqsign-core`, `reqsign-aws-core`,
     every established `reqsign-<provider>` crate,
     `reqsign-http-message-signatures`, `reqsign-file-read-tokio`,
     `reqsign-command-execute-tokio`): bump the whole line together. A breaking
     core change, including a lockstep major, moves every crate on it to the
     same major. A new public capability without a break takes a minor.
   - `reqsign-http-send-reqwest`: patch or minor by its own change, and a major
     whenever the core lockstep major changes. It stays one major ahead of core.
   - Provider and shared crates on independent `1.0.0` lines
     (`reqsign-cloudflare`, the B2 crate, `reqsign-baidu-netdisk`,
     `reqsign-oauth2`, `reqsign-dropbox`, `reqsign-aliyun-drive`,
     `reqsign-github`, `reqsign-onedrive`, `reqsign-seafile`, `reqsign-upyun`,
     `reqsign-vercel`, `reqsign-yandex-disk`, `reqsign-koofr`): keep `1.0.0`
     until the first publication, then bump by their own change.
   - `reqsign-crypto-rustcrypto` and `reqsign-crypto-boring`: independent
     `1.0.0` lines, bumped by their own change.
   - Keep root `[workspace.dependencies]` version requirements equal to each
     crate manifest version, and update the standalone
     `crypto/boring/Cargo.toml` bounds separately because that crate is outside
     the workspace.
   - Add the release-notes entry to `CHANGELOG.md` and the migration steps to
     `website/docs/guides/` in the same PR.

3. Validate the publish plan and packages.

   ```bash
   python3 -m unittest discover \
     -s .github/scripts/release_rust \
     -p "test_*.py"
   python3 .github/scripts/release_rust/plan.py
   cargo publish --workspace --dry-run --allow-dirty
   python3 .github/scripts/release_rust/standalone.py
   ```

   `cargo publish --workspace --dry-run` stages the workspace as one set, so it
   packages members whose intra-workspace dependencies are not on crates.io yet.
   Do not substitute a per-package `cargo publish -p <crate> --dry-run` before
   the real dependency versions exist on crates.io: it fails with a
   version-selection error such as
   `failed to select a version for the requirement reqsign-core = "^4.0.0"`
   because that dependency version is unpublished. Bootstrap does not unblock
   the per-package form: its `0.0.0` reservations are dependency-free and do not
   satisfy requirements such as `^4.0.0`. The form only starts working after the
   release workflow has published the real dependency versions.

   `standalone.py` packages the explicit standalone manifests against the local
   path dependencies instead of the workspace set. It patches the planned
   local dependencies from the checkout, runs `cargo package --no-verify` for
   each one without a BoringSSL build, and checks that the produced package
   carries LICENSE, NOTICE, README, and source files and that normalized local
   dependencies keep the planned version without a path. It covers packaging
   only: the BoringSSL build and tests stay in `crypto_boring.yml`, and the
   upload path is covered by the release workflow at publish time.

   Inventory the plan against the registry before asking for a bootstrap. The
   check is read-only and needs no credentials. An empty plan exits nonzero
   instead of passing vacuously:

   ```bash
   python3 - <<'EOF'
   import json, subprocess, urllib.request, urllib.error
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

   Every `missing name` must be reserved by the bootstrap workflow before the
   RC tag, and no line may report an already-published planned version. The
   0.21.0 plan has 31 workspace packages plus the explicit standalone
   `crypto/boring/Cargo.toml` manifest. The 15 workspace names that were missing
   were reserved by run `45139940320`; that reviewed plan predates the standalone
   entry, so `reqsign-crypto-boring` is the one name a new bootstrap must
   reserve. The other 16 workspace names are already published crates whose
   planned 0.21 versions are not published yet.

4. Merge the version bump PR into `main`.

   Do not create the RC tag from an unmerged side branch unless the release manager explicitly accepts that the voted commit will not be on `main`.

## Bootstrap Rust Crates

Wait until the intended crate-name set is present on the
`apache/reqsign` `main` branch. The release manager chooses the exact
reservation time, normally about three days before the planned release. At that
time, check out the current `main` commit and run:

```bash
release/scripts/bootstrap-rust-crates.sh
```

This command performs the transition to a bootstrapped publish plan. Run it
without asking for a second confirmation after a PMC release manager explicitly
chooses the reservation time. Do not run it for release status checks or dry-run
planning. Publishing a `0.0.0` package is externally visible and irreversible,
but it is a namespace reservation rather than an ASF software release.

The helper:

- Requires a clean checkout at the current `apache/reqsign` `main`.
- Verifies that the `rust-bootstrap` environment has required reviewers.
- Dispatches the input-free `bootstrap_rust_crates.yml` workflow, which first
  previews the crate bootstrap plan in the workflow run summary before the
  protected `rust-bootstrap` job requests PMC approval.
- Resolves the exact run, verifies its `headSha`, and waits for completion.
- Blocks while the protected environment awaits PMC approval.
- Verifies publicly that every crate in the checked publish plan exists and has
  `trustpub_only` enabled.

The protected job authenticates ownership and audits the complete publish plan
before any write. The plan job records the reviewed missing and placeholder
names for the dispatch commit, uploads them as an attempt-scoped artifact, and
records the artifact ID in the plan summary. The protected job downloads exactly
that ID, not an artifact by name. Re-running only the protected job reuses the
successful plan job's output; re-running the plan creates a separate artifact
and summary. A missing, invalid, expired, or unavailable artifact stops before
`apply`. The protected job only reconciles crates in the reviewed writable set,
and only first-publishes names in the reviewed missing subset. It stops before
any write if another planned crate became missing after the preview; rerun the
helper for a new preview. The preview's `trustpub_only` column is public
metadata and cannot show the configured publisher; the protected job performs
authenticated publisher verification or creation and any required configuration
after approval.

A Trusted Publisher cannot be configured for a name that does not exist on
crates.io yet, so every missing name is resolved by the bootstrap
first: the `0.0.0` reservation is what makes the publisher configuration
possible. Existing crates must already have exactly one Trusted Publisher with:

- Repository owner: `apache`
- Repository name: `reqsign`
- Workflow filename: `release.yml`
- Environment: `release`

The job never changes an established crate. Migrate those crates through
crates.io before using the bootstrap workflow and enable `trustpub_only` on
each. For a missing name, the workflow publishes a dependency-free `0.0.0`
placeholder, creates the expected Trusted Publisher, enables `trustpub_only`,
and reconciles partial placeholders on rerun.

The `rust-bootstrap` environment in `.asf.yaml` accepts dispatches only from
`main`, requires reviewers, and sets `prevent_self_review`, so a dispatch by the
release manager still needs one of the other configured reviewers to approve.
The helper's public verification uses unauthenticated crates.io data and covers
name existence, the reservation version, and `trustpub_only`. The authenticated
preflight inside the job covers ownership and publisher metadata; the two checks
have different scopes, and the public one is not a substitute for the preflight.
The last successful reservation run for this repository was `45139940320` at
commit `485d90da`; its reviewed plan covered only the 31 workspace crates.

ASF Infrastructure provisions the `release` and `rust-bootstrap` environments
from `.asf.yaml`. A PMC release manager must add
`CARGO_REGISTRY_BOOTSTRAP_TOKEN` to the `rust-bootstrap` environment. The token
must have only the `publish-new` and `trusted-publishing` endpoint scopes, with
crate scopes restricted to reqsign package names. Never expose it to the normal
release workflow.

Run the helper again if the publish plan gains another crate after a successful
bootstrap. A new run previews the complete plan (workspace plus standalone),
reserves only the names still missing, and never modifies an established crate.

### What the publish plan covers

`plan.py` is the authoritative crates.io package set. It combines the root
workspace members with the explicit `STANDALONE_MANIFESTS` list, keeps every
package that allows the crates.io registry, and orders them by local path
dependencies. A directory excluded from the workspace is not published merely
because a package exists there; the standalone list is the decision.

`cargo publish --workspace` publishes only workspace members. The release
workflow publishes `reqsign-crypto-boring` as an explicit standalone entry
(`crypto/boring/Cargo.toml`, `exclude = ["crypto/boring"]`) by manifest path,
after every local path dependency it resolves, including `reqsign-core` and the
crates its tests use. Packaging a crate outside the workspace resolves all of
those against crates.io, so each must be published first. Its dependency
version bounds in `crypto/boring/Cargo.toml` are not inherited from the root
workspace, so align them by hand in the same preparation PR.

## Create RC Tag

Create the RC tag from the merged version-bump commit on `main`.

Before tagging, confirm that the bootstrap workflow succeeded for the current
publish plan and that no later commit added another crate.

```bash
git fetch origin main --tags
git switch --detach origin/main
git tag -s vX.Y.Z-rc.N -m "vX.Y.Z-rc.N"
git tag -v vX.Y.Z-rc.N
git push origin vX.Y.Z-rc.N
```

The RC tag should not trigger the formal publish workflow.

## Build Source Artifact

Create the Apache source artifact from the RC tag.

```bash
rm -rf /tmp/reqsign-release-X.Y.Z
mkdir -p /tmp/reqsign-release-X.Y.Z/dist

git archive \
  --format=tar.gz \
  --prefix=apache-reqsign-X.Y.Z/ \
  -o /tmp/reqsign-release-X.Y.Z/dist/apache-reqsign-X.Y.Z.tar.gz \
  vX.Y.Z-rc.N

cd /tmp/reqsign-release-X.Y.Z/dist
gpg --armor --detach-sign apache-reqsign-X.Y.Z.tar.gz
shasum -a 512 apache-reqsign-X.Y.Z.tar.gz > apache-reqsign-X.Y.Z.tar.gz.sha512

gpg --verify apache-reqsign-X.Y.Z.tar.gz.asc apache-reqsign-X.Y.Z.tar.gz
shasum -a 512 -c apache-reqsign-X.Y.Z.tar.gz.sha512
tar -tzf apache-reqsign-X.Y.Z.tar.gz | rg '(^|/)LICENSE$|(^|/)NOTICE$|(^|/)Cargo.toml$'
```

Confirm the signing key is present in Apache Reqsign KEYS:

```bash
svn cat https://dist.apache.org/repos/dist/release/reqsign/KEYS | rg 'xuanwo@apache.org|Xuanwo|KEY_FINGERPRINT'
```

## Upload RC Artifacts

Upload to Apache dev dist.

```bash
rm -rf /tmp/reqsign-dist-dev-X.Y.Z
svn co --depth=empty https://dist.apache.org/repos/dist/dev/reqsign /tmp/reqsign-dist-dev-X.Y.Z

cd /tmp/reqsign-dist-dev-X.Y.Z
mkdir reqsign-X.Y.Z
cp /tmp/reqsign-release-X.Y.Z/dist/* reqsign-X.Y.Z/
svn add reqsign-X.Y.Z
svn status
svn commit --force-interactive -m "Prepare reqsign X.Y.Z release candidate"
```

Verify the remote copy:

```bash
svn ls https://dist.apache.org/repos/dist/dev/reqsign/reqsign-X.Y.Z/
rm -rf /tmp/reqsign-verify-X.Y.Z
svn co https://dist.apache.org/repos/dist/dev/reqsign/reqsign-X.Y.Z /tmp/reqsign-verify-X.Y.Z
cd /tmp/reqsign-verify-X.Y.Z
shasum -a 512 -c apache-reqsign-X.Y.Z.tar.gz.sha512
gpg --verify apache-reqsign-X.Y.Z.tar.gz.asc apache-reqsign-X.Y.Z.tar.gz
```

## Start Vote

Create a GitHub Discussion in `apache/reqsign` General. Confirm that the vote is
forwarded to `dev@reqsign.apache.org` and that the mailing-list thread is linked
from the Discussion before counting the voting period.

Title:

```text
[VOTE] Release Apache Reqsign X.Y.Z - Vote Round 1
```

Body:

```text
Hello, Apache Reqsign Community,

This is a call for a vote to release Apache Reqsign version X.Y.Z.

The release candidate:

https://dist.apache.org/repos/dist/dev/reqsign/reqsign-X.Y.Z/

Keys to verify the release candidate:

https://downloads.apache.org/reqsign/KEYS

Git tag for the release candidate:

https://github.com/apache/reqsign/releases/tag/vX.Y.Z-rc.N

The tag points to commit:

COMMIT_SHA

Please download, verify, and test.

The VOTE will be open for at least 72 hours and until the necessary number of votes are reached.

- [ ] +1 approve
- [ ] +0 no opinion
- [ ] -1 disapprove with the reason

Checklist for reference:

- [ ] Download links are valid.
- [ ] Checksums and signatures are valid.
- [ ] LICENSE/NOTICE files exist.
- [ ] No unexpected binary files.
- [ ] All source files have ASF headers.
- [ ] Can compile from source.

Thanks,
NAME
```

## After Vote Passes

1. Verify vote state.

   Confirm at least three binding `+1` votes from Reqsign PMC members and no blocking `-1` votes.

2. Publish vote result.

   Create a GitHub Discussion in General.

   Title:

   ```text
   [RESULT][VOTE] Release Apache Reqsign X.Y.Z - Vote Round 1
   ```

   Body:

   ```text
   Hello, Apache Reqsign Community,

   The vote to release Apache Reqsign X.Y.Z has passed.

   The vote PASSED with N +1 binding votes, no +0 or -1 votes.

   Binding votes:

   - VOTER_1
   - VOTER_2
   - VOTER_3

   Vote thread: VOTE_THREAD_URL

   Thanks,
   NAME
   ```

3. Push the formal signed tag.

   Use the exact voted RC commit.

   ```bash
   git checkout vX.Y.Z-rc.N
   test "$(git rev-parse vX.Y.Z-rc.N^{})" = "COMMIT_SHA"
   git tag -s vX.Y.Z -m "vX.Y.Z"
   git tag -v vX.Y.Z
   git push origin vX.Y.Z
   ```

4. Move ASF artifacts from dev to release.

   ```bash
   svn mv --force-interactive \
     https://dist.apache.org/repos/dist/dev/reqsign/reqsign-X.Y.Z \
     https://dist.apache.org/repos/dist/release/reqsign/reqsign-X.Y.Z \
     -m "Release reqsign X.Y.Z"
   ```

5. Monitor the GitHub Release workflow.

   ```bash
   gh run list --repo apache/reqsign --workflow Release --limit 5
   gh run view RUN_ID --repo apache/reqsign --json status,conclusion,url,jobs
   ```

   The workflow validates the complete publish plan, then publishes
   crates in dependency order. Every package attempt receives a new
   OIDC-derived crates.io token that is revoked immediately afterward. Reruns
   skip versions already published by an earlier partial run. A package whose
   planned dependency version is not visible in the crates.io index yet is
   retried with a bounded budget before the run fails.

6. Verify crates.io versions.

   Derive the expected `(name, version)` pairs from `plan.py` and require every
   planned version to be published. A missing name, a missing planned version,
   an older release, or a `0.0.0` reservation fails the check. An empty plan
   also exits nonzero instead of passing vacuously:

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

7. Create a GitHub Release.

   Use the formal tag. The `0.21.0` section of `CHANGELOG.md` is the release
   notes source: keep its notable changes and crate-version table, and add the
   source artifact links.

## Recovery Notes

- If `main` advances after the vote starts, formal `vX.Y.Z` still points to the RC commit, not latest `origin/main`.
- If SVN authentication fails, retry with `--force-interactive`; run `svn cleanup` if a killed commit leaves the working copy locked.
- If crates.io publishing fails after some packages succeed, rerun the exact formal-tag workflow. Do not create another tag or use a long-lived token; the publisher resumes after matching already-published versions.
- If the bootstrap workflow fails, inspect the authenticated preflight first. It deliberately refuses to modify established crates or continue with unexpected repository or Trusted Publisher metadata.
