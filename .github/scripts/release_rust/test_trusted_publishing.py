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

import io
import json
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from trusted_publishing import temporary_trusted_publishing_token


class TrustedPublishingTest(unittest.TestCase):
    def test_exchange_masks_and_revokes_credentials_even_when_publishing_fails(self):
        requests = []
        responses = iter(
            (
                io.BytesIO(b'{"value":"github-jwt"}'),
                io.BytesIO(b'{"token":"crates-token"}'),
                io.BytesIO(b""),
            )
        )

        def urlopen(request, timeout):
            requests.append(request)
            return next(responses)

        environment = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://github.test/oidc?api-version=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
        }
        with (
            mock.patch.dict("os.environ", environment, clear=True),
            mock.patch("trusted_publishing.urllib.request.urlopen", urlopen),
            mock.patch("sys.stdout", new_callable=io.StringIO) as output,
            self.assertRaisesRegex(RuntimeError, "publish failed"),
            temporary_trusted_publishing_token() as token,
        ):
            self.assertEqual(token, "crates-token")
            self.assertIn("::add-mask::github-jwt", output.getvalue())
            self.assertIn("::add-mask::crates-token", output.getvalue())
            raise RuntimeError("publish failed")

        self.assertEqual(
            parse_qs(urlsplit(requests[0].full_url).query),
            {
                "api-version": ["1"],
                "audience": ["crates.io"],
            },
        )
        self.assertEqual(
            requests[0].get_header("Authorization"), "Bearer request-token"
        )
        self.assertEqual(json.loads(requests[1].data), {"jwt": "github-jwt"})
        self.assertEqual(requests[2].get_method(), "DELETE")
        self.assertEqual(requests[2].get_header("Authorization"), "Bearer crates-token")


if __name__ == "__main__":
    unittest.main()
