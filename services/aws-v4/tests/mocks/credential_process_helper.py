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

"""
Mock credential process helper for testing ProcessCredentialProvider

This script outputs credentials in the format expected by AWS credential_process.
It can be used in ~/.aws/config as:
    credential_process = /path/to/credential_process_helper.py
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone


def generate_credentials(profile=None):
    """Generate mock AWS credentials in the credential_process format"""

    # Calculate expiration time (1 hour from now)
    expiration = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    live_values = {
        "access_key": os.environ.get("REQSIGN_AWS_PROCESS_ACCESS_KEY_ID"),
        "secret_key": os.environ.get("REQSIGN_AWS_PROCESS_SECRET_ACCESS_KEY"),
        "session_token": os.environ.get("REQSIGN_AWS_PROCESS_SESSION_TOKEN"),
    }
    if any(live_values.values()) and not (
        live_values["access_key"] and live_values["secret_key"]
    ):
        raise RuntimeError(
            "REQSIGN_AWS_PROCESS_ACCESS_KEY_ID and "
            "REQSIGN_AWS_PROCESS_SECRET_ACCESS_KEY must be set together"
        )

    if live_values["access_key"] and live_values["secret_key"]:
        access_key = live_values["access_key"]
        secret_key = live_values["secret_key"]
        session_token = live_values["session_token"]
    elif profile == "test":
        access_key = "ASIAPROCESSTEST"
        secret_key = "process/test/secret/key/EXAMPLE"
        session_token = "FwoGZXIvYXdzEPROCESS//////////wEaDEXAMPLETOKEN"
    else:
        access_key = "ASIAPROCESSEXAMPLE"
        secret_key = "process/secret/key/EXAMPLE"
        session_token = "FwoGZXIvYXdzEPROCESS//////////wEaDEXAMPLETOKEN"

    credentials = {
        "Version": 1,
        "AccessKeyId": access_key,
        "SecretAccessKey": secret_key,
        "Expiration": expiration,
    }
    if session_token:
        credentials["SessionToken"] = session_token

    return credentials


def main():
    """Main entry point for the credential process helper"""

    # Check if a profile argument was provided
    profile = None
    if len(sys.argv) > 2 and sys.argv[1] == "--profile":
        profile = sys.argv[2]

    # Generate and output credentials
    credentials = generate_credentials(profile)
    print(json.dumps(credentials, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
