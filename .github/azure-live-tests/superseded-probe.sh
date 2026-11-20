#!/usr/bin/env bash
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

# Decide whether a newer run of this workflow on the same branch and event will
# cover this live probe. The probe group keeps pending entries, so a probe can
# start long after its own commit was superseded.
#
# Skip only when a newer run exists that already got past the workflow's path
# filters: a change that filters the workflow out creates no run, so an older
# queued probe stays the only live validation for its commit. Any missing or
# unexpected answer keeps the probe; a wasted probe costs a runner, a missing
# live validation costs coverage.
set -euo pipefail

workflow=${1:?Usage: superseded-probe.sh <workflow-file>}
: "${GITHUB_OUTPUT:?Set by Actions}"

superseded=false
replacement=""
branch=""
case "${GITHUB_EVENT_NAME:-}" in
  pull_request|pull_request_target) branch=${GITHUB_HEAD_REF:-} ;;
  push) branch=${GITHUB_REF_NAME:-} ;;
esac

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Cannot check for a newer run without a token; running the probe"
elif [[ -z "${GITHUB_REPOSITORY:-}" || -z "${GITHUB_RUN_ID:-}" || -z "$branch" ]]; then
  echo "Cannot check for a newer run without the run context; running the probe"
else
  response_file=$(mktemp)
  trap 'rm -f "$response_file"' EXIT
  if ! http_status=$(curl --get --silent --show-error \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --header "Authorization: Bearer $GITHUB_TOKEN" \
    --header "Accept: application/vnd.github+json" \
    --data-urlencode "event=$GITHUB_EVENT_NAME" \
    --data-urlencode "branch=$branch" \
    --data-urlencode "per_page=50" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/workflows/${workflow}/runs"); then
    echo "Could not list workflow runs; running the probe" >&2
  elif [[ "$http_status" != "200" ]]; then
    echo "Could not list workflow runs (HTTP $http_status); running the probe" >&2
  else
    replacement=$(jq --raw-output \
      --argjson run_id "$GITHUB_RUN_ID" \
      --arg event "$GITHUB_EVENT_NAME" \
      --arg branch "$branch" '
      [ .workflow_runs[]?
        | select(.id > $run_id)
        | select(.event == $event)
        | select(.head_branch == $branch)
        | select(.status != "completed")
        | .id ] | sort | first // empty' "$response_file" 2>/dev/null) || replacement=""
    [[ -z "$replacement" ]] || superseded=true
  fi
fi

echo "superseded=$superseded" >> "$GITHUB_OUTPUT"
if [[ "$superseded" == true ]]; then
  echo "Skipping the live probe: newer run $replacement on $branch will cover it"
else
  echo "Running the live probe: no newer run of $workflow on $branch is in flight"
fi
