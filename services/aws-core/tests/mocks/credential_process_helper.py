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
Mock credential process helper for testing ProcessCredentialProvider.
"""

import json
import sys
from datetime import datetime, timedelta, timezone


def generate_credentials(profile=None):
    """Generate mock AWS credentials in the credential_process format."""
    expiration = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    if profile == "test":
        access_key = "ASIAPROCESSTEST"
        secret_key = "process/test/secret/key/EXAMPLE"
    else:
        access_key = "ASIAPROCESSEXAMPLE"
        secret_key = "process/secret/key/EXAMPLE"

    return {
        "Version": 1,
        "AccessKeyId": access_key,
        "SecretAccessKey": secret_key,
        "SessionToken": "FwoGZXIvYXdzEPROCESS//////////wEaDEXAMPLETOKEN",
        "Expiration": expiration,
    }


def main():
    """Write credentials for the requested profile."""
    profile = None
    if len(sys.argv) > 2 and sys.argv[1] == "--profile":
        profile = sys.argv[2]

    print(json.dumps(generate_credentials(profile), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
