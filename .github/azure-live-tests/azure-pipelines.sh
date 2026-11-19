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

# Keep the fixture alive while Azure Pipelines uses its read-only identity.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_id=""
completed=false

# A run that is still waiting for the pool agent has not exercised the probe,
# so one shared deadline cannot tell a queue stall from a slow probe. Bound the
# wait for an agent and the execution after it starts separately; the defaults
# keep the worst case plus cleanup inside the GitHub job's 60-minute timeout
# and inside the lifetime of an access token, which cleanup can renew.
queue_wait_limit=${REQSIGN_AZURE_PIPELINES_QUEUE_LIMIT:-1200}
execution_limit=${REQSIGN_AZURE_PIPELINES_EXECUTION_LIMIT:-900}
# Local fixtures shorten these so the bounds are testable without waiting.
poll_interval=${REQSIGN_AZURE_PIPELINES_POLL_INTERVAL:-15}

# A DevOps read is idempotent. Retry the observed TLS send reset (curl 35) and
# HTTP 503 (curl 22) within a poll so one transient failure does not fail the
# job. Other HTTP failures are permanent for this job.
devops_read_attempts=3
devops_read_retry_delay=1
status_response_file="$RUNNER_TEMP/azure-pipelines-status-response.json"
timeline_response_file="$RUNNER_TEMP/azure-pipelines-timeline-response.json"

read_devops_json() {
  local access_token=$1 path=$2 response_file=$3 allow_missing=${4:-false}
  local attempt curl_status http_status response retryable
  for (( attempt = 1; attempt <= devops_read_attempts; attempt++ )); do
    if http_status=$(curl --fail --silent --show-error \
      --output "$response_file" \
      --write-out '%{http_code}' \
      --header "Authorization: Bearer $access_token" \
      "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}${path}"); then
      response=$(<"$response_file")
      rm -f "$response_file"
      printf '%s\n' "$response"
      return 0
    else
      curl_status=$?
    fi
    rm -f "$response_file"
    # A build that is still queued may not have a timeline yet. That is a
    # missing record, not a failed read.
    if [[ "$allow_missing" == true ]] && (( curl_status == 22 )) && [[ "$http_status" == "404" ]]; then
      return 0
    fi
    retryable=false
    if (( curl_status == 35 )); then
      retryable=true
    elif (( curl_status == 22 )) && [[ "$http_status" == "503" ]]; then
      retryable=true
    fi
    if [[ "$retryable" != true ]] || (( attempt == devops_read_attempts )); then
      return "$curl_status"
    fi
    sleep "$devops_read_retry_delay"
  done
}

# Called by the EXIT handler and the polling loop.
read_run_status() {
  read_devops_json "$1" \
    "/_apis/pipelines/${AZURE_DEVOPS_PIPELINE_ID}/runs/${run_id}?api-version=7.1" \
    "$status_response_file"
}

# Azure DevOps reports the agent that runs a job on the build timeline. A Job
# record carries workerName once an agent picked it up, and startTime is when it
# started there. Stage records also start before any agent is assigned, and a
# build's own startTime comes from the orchestration, so only Job records are
# evidence that execution began on an agent.
read_agent_started_at() {
  local access_token=$1 timeline job_start allow_missing=true
  timeline=$(read_devops_json "$access_token" \
    "/_apis/build/builds/${run_id}/timeline?api-version=7.1" \
    "$timeline_response_file" "$allow_missing") || return
  [[ -n "$timeline" ]] || return 0
  # The timeline may be one timeline object or a list of them.
  job_start=$(jq --raw-output '
    (if type == "array" then map(.records // []) | add // [] else .records // [] end)
    | [ .[] | select(.type == "Job")
        | select((.workerName // "") != "" and (.startTime // "") != "")
        | .startTime ]
    | sort | .[0] // empty' <<< "$timeline") || return
  printf '%s\n' "$job_start"
}

# A delayed cleanup can outlive the GitHub OIDC assertion used by the initial
# login. Retry once through a fresh login as the same service principal.
# Set the global access_token directly instead of returning it: the login
# helper must write its ::add-mask:: command to the runner's stdout, not into
# the captured token.
load_devops_access_token() {
  if access_token=$(az account get-access-token \
    --resource https://app.vssps.visualstudio.com/ \
    --query accessToken \
    --output tsv); then
    return 0
  fi
  bash "$script_dir/azure-oidc-login.sh" || return
  access_token=$(az account get-access-token \
    --resource https://app.vssps.visualstudio.com/ \
    --query accessToken \
    --output tsv)
}

# Called by the EXIT handler.
# shellcheck disable=SC2329
cancel_unfinished_run() {
  local response
  load_devops_access_token || return
  response=$(read_run_status "$access_token") || return $?
  state=$(jq --raw-output '.state' <<< "$response") || return
  if [[ "$state" != "completed" ]]; then
    curl --fail-with-body --silent --show-error \
      --request PATCH \
      --header "Authorization: Bearer $access_token" \
      --header "Content-Type: application/json" \
      --data '{"status":"cancelling"}' \
      "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}/_apis/build/builds/${run_id}?api-version=7.1" \
      >/dev/null
  fi
}
# shellcheck disable=SC2329
cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n "$run_id" && "$completed" != true ]]; then
    if ! cancel_unfinished_run; then
      echo "Failed to cancel the unfinished Azure Pipelines run" >&2
      if (( result == 0 )); then result=1; fi
    fi
  fi
  exit "$result"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

access_token=$(az account get-access-token \
  --resource https://app.vssps.visualstudio.com/ \
  --query accessToken \
  --output tsv)
test -n "$access_token"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  echo "::add-mask::$access_token"
fi

# Pass the probe as a run variable so the bootstrap YAML needs no new parameter.
request_body=$(jq --null-input \
  --arg github_sha "$GITHUB_SHA" \
  --arg github_ref "$GITHUB_REF" \
  --arg probe_url "$REQSIGN_AZURE_STORAGE_PROBE_URL" \
  '{templateParameters: {githubSha: $github_sha, githubRef: $github_ref},
    variables: {REQSIGN_AZURE_STORAGE_PROBE_URL: {value: $probe_url}}}')
response_file="$RUNNER_TEMP/azure-pipelines-queue-response.json"
if ! http_status=$(curl --silent --show-error \
  --output "$response_file" \
  --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer $access_token" \
  --header "Content-Type: application/json" \
  --data "$request_body" \
  "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}/_apis/pipelines/${AZURE_DEVOPS_PIPELINE_ID}/runs?api-version=7.1"); then
  echo "Failed to send the Azure Pipelines queue request" >&2
  exit 1
fi
if (( http_status < 200 || http_status >= 300 )); then
  message=$(jq --raw-output '.message // .error.message // "No error message returned"' \
    "$response_file" 2>/dev/null || echo "Non-JSON error response")
  message=$(tr '\r\n' '  ' <<< "$message" | cut -c1-1000)
  echo "Azure Pipelines queue request failed with HTTP $http_status: $message" >&2
  exit 1
fi
response=$(<"$response_file")

run_id=$(jq --raw-output '.id // empty' <<< "$response")
run_url=$(jq --raw-output '._links.web.href // empty' <<< "$response")
test -n "$run_id"
test -n "$run_url"
echo "Queued Azure Pipelines run: $run_url"
echo "Azure Pipelines probe limits: ${queue_wait_limit}s queue wait, ${execution_limit}s execution after agent start: $run_url"

queue_deadline=$(( $(date +%s) + queue_wait_limit ))
agent_started_at=""
agent_started_epoch=""
while true; do
  load_devops_access_token || exit $?
  response=$(read_run_status "$access_token") || exit $?
  state=$(jq --raw-output '.state' <<< "$response")
  result=$(jq --raw-output '.result // empty' <<< "$response")
  if [[ "$state" == "completed" ]]; then
    completed=true
    echo "Azure Pipelines run completed with result '$result': $run_url"
    test "$result" = "succeeded"
    exit
  fi

  now=$(date +%s)
  if [[ -z "$agent_started_epoch" ]]; then
    agent_started_at=$(read_agent_started_at "$access_token") || exit $?
    if [[ -n "$agent_started_at" ]]; then
      if ! agent_started_epoch=$(date --date="$agent_started_at" +%s); then
        echo "Failed to parse the Azure Pipelines job start time '$agent_started_at': $run_url" >&2
        exit 1
      fi
      echo "Azure Pipelines job started on an agent at $agent_started_at (execution limit ${execution_limit}s): $run_url"
    elif (( now >= queue_deadline )); then
      echo "Azure Pipelines run did not start on an agent within ${queue_wait_limit}s of queueing: $run_url" >&2
      exit 1
    fi
  fi
  if [[ -n "$agent_started_epoch" ]] && (( now >= agent_started_epoch + execution_limit )); then
    echo "Azure Pipelines run did not complete within ${execution_limit}s after its job started on an agent at ${agent_started_at}: $run_url" >&2
    exit 1
  fi
  sleep "$poll_interval"
done
