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

import json
import os
import urllib.request
from contextlib import contextmanager

REGISTRY_URL = "https://crates.io"
USER_AGENT = "apache-reqsign-release/1.0 (https://github.com/apache/reqsign)"


def request_json(url: str, *, headers=None, body=None):
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


@contextmanager
def temporary_trusted_publishing_token():
    request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in request_url else "?"
    jwt = request_json(
        f"{request_url}{separator}audience=crates.io",
        headers={
            "Authorization": f"Bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"
        },
    )["value"]
    assert jwt, "GitHub returned an empty OIDC token"
    print(f"::add-mask::{jwt}", flush=True)
    token = request_json(
        f"{REGISTRY_URL}/api/v1/trusted_publishing/tokens", body={"jwt": jwt}
    )["token"]
    assert token, "crates.io returned an empty Trusted Publishing token"
    print(f"::add-mask::{token}", flush=True)
    try:
        yield token
    finally:
        request = urllib.request.Request(
            f"{REGISTRY_URL}/api/v1/trusted_publishing/tokens",
            headers={"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT},
            method="DELETE",
        )
        with urllib.request.urlopen(request, timeout=30):
            pass
