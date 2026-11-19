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

# Renew the existing Azure CLI login through the job's id-token permission.
# The initial azure/login assertion expires long before a delayed cleanup.
# Requesting a fresh assertion with the same audience and logging in as the
# same service principal adds no credential source or permission.
set -euo pipefail

: "${AZURE_CLIENT_ID:?Set the existing Azure client ID}"
: "${AZURE_TENANT_ID:?Set the existing Azure tenant ID}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?The job needs id-token: write}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?The job needs id-token: write}"

token_response=$(curl --fail --silent --show-error \
  --header "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange")
federated_token=$(jq --raw-output '.value // empty' <<< "$token_response")
unset token_response
test -n "$federated_token"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  echo "::add-mask::$federated_token"
fi
az login \
  --service-principal \
  --username "$AZURE_CLIENT_ID" \
  --tenant "$AZURE_TENANT_ID" \
  --federated-token "$federated_token" \
  --output none
unset federated_token
