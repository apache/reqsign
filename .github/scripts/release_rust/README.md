# Rust release helpers

These scripts define and publish the crates.io package set for Apache Reqsign.

## Publish plan

`plan.py` reads `cargo metadata --no-deps`, selects workspace packages that can
publish to crates.io, and orders them by non-dev local dependencies using
Python's `TopologicalSorter`.

```bash
python3 .github/scripts/release_rust/plan.py
```

The release workflow first runs the complete workspace dry run:

```bash
cargo publish --workspace --dry-run
```

That dry run stages the workspace as one set, so it also packages members whose
intra-workspace dependency versions are not on crates.io yet. A single-package
`cargo publish -p <crate> --dry-run` does not, and fails before a bootstrap with
a version-selection error for the unpublished dependency.

It then runs `publish.py`. The publisher uploads one package at a time, requests
and revokes a fresh GitHub OIDC-derived crates.io token for every attempt,
retries crates.io rate limits, and treats an already-published matching
name/version as a completed step. Individual uploads use `--no-verify` because
the workflow has already verified the complete package set from the same
commit.

Live publishing requires the `release` GitHub environment and a job with
`id-token: write`. It never reads a long-lived crates.io token.

## Bootstrap crate names

Trusted Publishing cannot create the first version of a crate.
`bootstrap.py` reserves new names and audits the complete publish plan:

- `discover` reports missing names, existing `0.0.0` placeholders, and
  established crates with their public `trustpub_only` status. With
  `--plan-output`, it also writes the reviewed plan for the dispatch commit,
  including the exact publish plan, the missing-name set, and the writable set
  of missing and placeholder crates. It writes a Markdown summary to
  `GITHUB_STEP_SUMMARY` when running in GitHub Actions.
- `apply --plan-file` requires that reviewed plan for the same dispatch commit.
  It authenticates every existing crate before any write, rejects names that
  became missing after the review, publishes a dependency-free `0.0.0` namespace
  reservation only for reviewed missing names, verifies or creates the exact
  `apache/reqsign`, `release.yml`, `release` Trusted Publisher, enables
  `trustpub_only`, performs a final authenticated audit, and writes the applied
  result to `GITHUB_STEP_SUMMARY`. Reviewed missing names that already became
  valid placeholders are reconciled without another publish. Established crates
  are never modified.
- `verify` checks public crate metadata and `trustpub_only`. It cannot verify
  ownership or the exact Trusted Publisher because those APIs require
  authentication.

Crate classification uses the complete version history, including yanked
versions: a crate with any non-`0.0.0` version is established even when its
public `max_version` is `0.0.0`.

`bootstrap_rust_crates.yml` runs `discover` in an unprivileged `plan` job first
so reviewers can inspect the exact crate list and missing-name set in the
workflow summary before approving the protected `rust-bootstrap` job. The plan
job uploads that reviewed plan as an artifact. The protected job downloads it,
checks that it belongs to the same dispatch commit and publish plan, and audits
the complete plan before any write, including when no names are missing. It only
reconciles crates in the reviewed writable set, and first-publishes only the
reviewed missing names. If a planned crate that was not reviewed as missing
disappears after the preview, the job stops before any write and requires a new
preview. It never changes an established crate. Existing crates must be
migrated independently before the workflow can succeed.

The preview's `trustpub_only` value is public crates.io metadata. It does not
prove which Trusted Publisher is configured. The protected job performs the
authenticated publisher verification or creation and any required configuration
only after approval.

Published crate metadata may still reference the former repository URL or the
former project name in a `0.0.0` placeholder description. The audit accepts that
historical metadata, but every Trusted Publisher must target `apache/reqsign`.
New placeholders and releases use the current project name and repository URL.

Version `0.0.0` is an irreversible namespace reservation. It is not an ASF
software release and contains no implementation.

The local dispatch helper uses GitHub REST API version `2026-03-10` to obtain
the exact workflow run ID, then checks its commit and waits for completion.

These are repository-specific scripts: run them with normal Python (without
`-O` or `PYTHONOPTIMIZE`, which disable assertions). Cargo and crates.io response
fields are used directly; unexpected package or publisher state fails an
assertion. Failed API requests stop the run; rerun after resolving the failure.
Only Cargo publish rate limits and public metadata propagation are retried.

## Tests

```bash
python3 -m unittest discover \
  -s .github/scripts/release_rust \
  -p "test_*.py"
```
