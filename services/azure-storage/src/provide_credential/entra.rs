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
use std::collections::HashMap;
use std::time::Duration;

pub(super) const STORAGE_SCOPE: &str = "https://storage.azure.com/.default";
const PUBLIC_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";

/// Convert a single client-credentials scope to the resource expected by managed identity.
pub(super) fn resource_from_scope(scope: &str) -> Result<&str> {
    scope
        .strip_suffix("/.default")
        .filter(|resource| !resource.is_empty() && !resource.contains(char::is_whitespace))
        .ok_or_else(|| {
            Error::config_invalid(
                "Microsoft Entra scope must be a single resource followed by /.default",
            )
        })
}

pub(super) fn client_credentials_scope(scope: Option<&str>) -> Result<&str> {
    let scope = scope.unwrap_or(STORAGE_SCOPE);
    resource_from_scope(scope)?;
    Ok(scope)
}

pub(super) fn token_endpoint(
    tenant_id: &str,
    authority_host: Option<&str>,
    envs: &HashMap<String, String>,
) -> Result<http::Uri> {
    let authority_host = authority_host
        .or_else(|| envs.get("AZURE_AUTHORITY_HOST").map(String::as_str))
        .filter(|host| !host.is_empty())
        .unwrap_or(PUBLIC_AUTHORITY_HOST)
        .trim_end_matches('/');
    format!("{authority_host}/{tenant_id}/oauth2/v2.0/token")
        .parse()
        .map_err(|err| {
            Error::config_invalid("invalid Microsoft Entra token endpoint").with_source(err)
        })
}

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
