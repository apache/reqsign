#!/usr/bin/env bash
#
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

set -euo pipefail

cd "$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
test "$#" -eq 0
test -z "$(git status --porcelain)"

repo="apache/reqsign"
workflow="bootstrap_rust_crates.yml"
git fetch "https://github.com/${repo}.git" main
source_commit="$(git rev-parse FETCH_HEAD)"
test "$(git rev-parse HEAD)" = "${source_commit}"

gh api "repos/${repo}/environments/rust-bootstrap" |
  jq -e '[.protection_rules[] | select(.type == "required_reviewers")] | length > 0' >/dev/null

# The versioned dispatch API returns the exact run; no polling or title matching.
run_id="$(
  gh api --method POST \
    -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/${repo}/actions/workflows/${workflow}/dispatches" \
    -f ref=main |
    jq -er '.workflow_run_id'
)"
run_head_sha="$(gh run view "${run_id}" --repo "${repo}" --json headSha --jq '.headSha')"
test "${run_head_sha}" = "${source_commit}"

echo "Waiting for crates.io bootstrap run ${run_id}"
if ! gh run watch "${run_id}" --repo "${repo}" --exit-status; then
  gh run view "${run_id}" --repo "${repo}" --log-failed
  exit 1
fi
python3 .github/scripts/release_rust/bootstrap.py verify
