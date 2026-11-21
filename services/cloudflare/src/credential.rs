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

use std::fmt::{self, Debug, Formatter};

use reqsign_core::SigningCredential;
use reqsign_core::utils::Redact;
use reqsign_core::{Error, Result};

/// A Cloudflare API token.
///
/// The token authenticates the Cloudflare API as a bearer token. The account,
/// database, and namespace identifiers appear in the request URL and select the
/// resource, so they stay with the caller that constructs the request instead of
/// living on the credential. One token can therefore sign for every account and
/// namespace it is scoped to.
///
/// Cloudflare assigns a token's permissions and optional expiry when the token is
/// created. Reqsign neither requests, exchanges, nor inspects them.
///
/// The token is a secret. `Debug` output redacts it, and
/// [`Credential::bearer_header_value`] is the supported way to obtain request
/// authentication material.
#[derive(Clone)]
pub struct Credential {
    api_token: String,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("api_token", &Redact::from(&self.api_token))
            .finish()
    }
}

impl Credential {
    /// Create a credential from a raw API token.
    ///
    /// Pass the token itself, not an `Authorization` header value. The token must
    /// be non-empty and contain only visible ASCII characters. Rejecting other
    /// input keeps malformed environment and static values from becoming request
    /// authentication material and keeps `Debug` redaction from slicing a
    /// non-ASCII string at an invalid byte boundary.
    pub fn new(api_token: impl Into<String>) -> Result<Self> {
        let api_token = api_token.into();
        if api_token.is_empty() {
            return Err(Error::config_invalid(
                "Cloudflare API token must not be empty",
            ));
        }
        if !api_token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::config_invalid(
                "Cloudflare API token must contain only visible ASCII characters",
            ));
        }

        Ok(Self { api_token })
    }

    /// Return the raw API token.
    pub fn api_token(&self) -> &str {
        &self.api_token
    }

    /// Build a sensitive `Authorization: Bearer` header value.
    ///
    /// Errors never contain the token.
    pub fn bearer_header_value(&self) -> Result<http::HeaderValue> {
        let mut value: http::HeaderValue =
            format!("Bearer {}", self.api_token).parse().map_err(|_| {
                Error::config_invalid("Cloudflare API token is not a valid HTTP header value")
            })?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        !self.api_token.is_empty()
    }
}
