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

use reqsign_core::SigningCredential;
use reqsign_core::utils::Redact;
use reqsign_core::{Error, Result};
use std::fmt::{self, Debug, Formatter};

/// A GitHub credential for the GitHub.com API.
///
/// A credential is either a bearer token or an explicit anonymous credential
/// for public resources. GitHub assigns a token's host and its scopes or
/// repository permissions when the token is created; Reqsign neither requests,
/// exchanges, nor inspects those values.
///
/// The token is a secret. `Debug` output redacts it, and
/// [`Credential::bearer_header_value`] is the supported way to obtain request
/// authentication material.
#[derive(Clone)]
pub struct Credential {
    token: Option<String>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.token {
            Some(token) => f
                .debug_struct("Credential")
                .field("token", &Redact::from(token))
                .finish(),
            None => f
                .debug_struct("Credential")
                .field("anonymous", &true)
                .finish(),
        }
    }
}

impl Credential {
    /// Create a bearer-token credential from a raw token.
    ///
    /// Pass the token itself, not an `Authorization` header value. The token
    /// must be non-empty and contain only visible ASCII characters. Rejecting
    /// other input keeps malformed environment, CLI, and static values from
    /// becoming request authentication material and keeps `Debug` redaction
    /// from slicing a non-ASCII string at an invalid byte boundary.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() {
            return Err(Error::config_invalid("GitHub token must not be empty"));
        }
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::config_invalid(
                "GitHub token must contain only visible ASCII characters",
            ));
        }

        Ok(Self { token: Some(token) })
    }

    /// Create an explicit anonymous credential for public GitHub resources.
    ///
    /// Signing with this credential removes any existing `Authorization`
    /// header. Anonymous requests are subject to GitHub's unauthenticated rate
    /// limit.
    pub fn anonymous() -> Self {
        Self { token: None }
    }

    /// Return the bearer token, or `None` for an anonymous credential.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Return whether this credential represents anonymous access.
    pub fn is_anonymous(&self) -> bool {
        self.token.is_none()
    }

    /// Build a sensitive `Authorization: Bearer` header value.
    ///
    /// Returns `Ok(None)` for an anonymous credential. Errors never contain
    /// the token.
    pub fn bearer_header_value(&self) -> Result<Option<http::HeaderValue>> {
        let Some(token) = &self.token else {
            return Ok(None);
        };

        let mut value: http::HeaderValue = format!("Bearer {token}")
            .parse()
            .map_err(|_| Error::config_invalid("GitHub token is not a valid HTTP header value"))?;
        value.set_sensitive(true);
        Ok(Some(value))
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.token.as_deref().is_none_or(|token| !token.is_empty())
    }
}
