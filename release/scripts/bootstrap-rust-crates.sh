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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(git -C "${script_dir}" rev-parse --show-toplevel)"
cd "${repo_dir}"

for command in gh git jq python3; do
  command -v "${command}" >/dev/null || {
    echo "required command is unavailable: ${command}" >&2
    exit 1
  }
done

if [[ "$#" -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "the release checkout must be clean" >&2
  exit 1
fi

apache_remote="$(
  git remote -v |
    awk '$2 ~ /github.com[:\/]apache\/reqsign(\.git)?$/ && $3 == "(fetch)" { print $1; exit }'
)"
if [[ -z "${apache_remote}" ]]; then
  echo "cannot find a git remote for apache/reqsign" >&2
  exit 1
fi

git fetch "${apache_remote}" main
source_commit="$(git rev-parse FETCH_HEAD)"
if [[ "$(git rev-parse HEAD)" != "${source_commit}" ]]; then
  echo "the release checkout must be at the current apache/reqsign main: ${source_commit}" >&2
  exit 1
fi

git cat-file -e \
  "${source_commit}:.github/workflows/bootstrap_rust_crates.yml"
git cat-file -e \
  "${source_commit}:.github/scripts/release_rust/bootstrap.py"

repo="apache/reqsign"
workflow="bootstrap_rust_crates.yml"
environment="rust-bootstrap"
if ! environment_json="$(gh api "repos/${repo}/environments/${environment}")"; then
  echo "GitHub environment ${environment} is not configured" >&2
  exit 1
fi
if ! jq -e \
  '[.protection_rules[]? | select(.type == "required_reviewers")] | length > 0' \
  >/dev/null <<<"${environment_json}"; then
  echo "GitHub environment ${environment} must require reviewers" >&2
  exit 1
fi

# The versioned dispatch API returns the exact run; no polling or title matching.
run_id="$(
  gh api --method POST \
    -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/${repo}/actions/workflows/${workflow}/dispatches" \
    -f ref=main |
    jq -er '.workflow_run_id'
)"
run_head_sha="$(
  gh run view "${run_id}" --repo "${repo}" --json headSha --jq '.headSha'
)"
if [[ "${run_head_sha}" != "${source_commit}" ]]; then
  echo "workflow run ${run_id} uses ${run_head_sha}, expected ${source_commit}" >&2
  exit 1
fi

echo "Waiting for crates.io bootstrap run ${run_id}"
if ! gh run watch "${run_id}" --repo "${repo}" --exit-status; then
  gh run view "${run_id}" --repo "${repo}" --log-failed
  exit 1
fi

gh run view "${run_id}" \
  --repo "${repo}" \
  --json displayTitle,headSha,status,conclusion,url \
  --jq '{title: .displayTitle, head_sha: .headSha, status, conclusion, url}'

python3 .github/scripts/release_rust/bootstrap.py verify
