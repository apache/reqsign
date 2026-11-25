#!/usr/bin/env python3
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

"""Shared facade service-to-algorithm expectations.

Keep this table in sync with `reqsign/Cargo.toml`. The static feature check
validates the weak mappings against it, and the downstream probe drives actual
crypto operations from it, so a manifest change cannot silently pass both.
"""

from __future__ import annotations

# Facade service feature -> backend algorithm features.
SERVICE_ALGORITHMS = {
    "aliyun": set(),
    "aliyun-drive": set(),
    "aws": set(),
    "aws-v4": set(),
    "aws-v4a": {"p256"},
    "azure": {"rsa"},
    "b2": set(),
    "baidu-netdisk": set(),
    "cloudflare": set(),
    "dropbox": set(),
    "github": set(),
    "google": {"rsa"},
    "huaweicloud": set(),
    "http-message-signatures": {"rsa"},
    "koofr": set(),
    "oauth2": set(),
    "onedrive": set(),
    "openstack": set(),
    "oracle": {"rsa"},
    "seafile": set(),
    "tencent": set(),
    "upyun": set(),
    "vercel": set(),
    "volcengine": set(),
    "yandex-disk": set(),
}

NON_SERVICE_FEATURES = {"default", "default-context", "default-crypto", "full"}
