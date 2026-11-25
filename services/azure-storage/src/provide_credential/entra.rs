// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use reqsign_core::time::Timestamp;
use reqsign_core::{Error, Result};
use std::time::Duration;

#[derive(Debug, serde::Deserialize)]
pub(super) struct EntraTokenResponse {
    pub(super) access_token: String,
    pub(super) expires_in: u64,
}

impl EntraTokenResponse {
    pub(super) fn expires_at(&self, now: Timestamp) -> Result<Timestamp> {
        now.checked_add(Duration::from_secs(self.expires_in))
            .ok_or_else(|| {
                Error::unexpected("Microsoft Entra token response expires_in is out of range")
            })
    }
}

pub(super) fn parse_token_response(
    body: &[u8],
    response_name: &'static str,
) -> Result<EntraTokenResponse> {
    serde_json::from_slice(body).map_err(|err| {
        Error::unexpected(format!("failed to parse {response_name}")).with_source(err)
    })
}

pub(super) fn token_request_error(request_name: &'static str, status: http::StatusCode) -> Error {
    Error::credential_invalid(format!("{request_name} failed"))
        .with_context(format!("http_status: {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::ErrorKind;

    #[test]
    fn parses_redacted_real_entra_response() {
        let response = include_bytes!("../../tests/fixtures/entra_token_response.json");
        let token = parse_token_response(response, "Microsoft Entra token response")
            .expect("real response fixture must parse");

        assert_eq!(token.access_token, "REDACTED");
        assert_eq!(token.expires_in, 3599);
    }

    #[test]
    fn normal_expiry_preserves_token_and_expiry_semantics() {
        let response =
            br#"{"token_type":"Bearer","expires_in":3599,"access_token":"synthetic-access-token"}"#;
        let token = parse_token_response(response, "test token response")
            .expect("synthetic response must parse");
        let now = Timestamp::from_second(1_700_000_000).expect("fixed time must be valid");

        assert_eq!(token.access_token, "synthetic-access-token");
        assert_eq!(
            token
                .expires_at(now)
                .expect("normal expiry must be representable"),
            now + Duration::from_secs(3599)
        );
    }

    #[test]
    fn unrepresentable_expiry_is_unexpected_and_sanitized() {
        let response = br#"{"token_type":"Bearer","expires_in":18446744073709551615,"access_token":"synthetic-access-token"}"#;
        let token = parse_token_response(response, "test token response")
            .expect("synthetic response must parse");
        let now = Timestamp::from_second(1_700_000_000).expect("fixed time must be valid");

        let err = token
            .expires_at(now)
            .expect_err("unrepresentable expiry must fail");
        assert_eq!(ErrorKind::Unexpected, err.kind());
        assert_eq!(
            "Microsoft Entra token response expires_in is out of range",
            err.to_string()
        );
        assert!(!err.to_string().contains("synthetic-access-token"));
    }
}
