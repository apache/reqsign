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

use crate::scope::DeploymentScope;
use reqsign_core::utils::Redact;
use reqsign_core::{Error, Result, SigningCredential};
use std::fmt::{self, Debug, Formatter};

/// A Seafile account token or repository API token.
///
/// The token is a secret. `Debug` output redacts it, and
/// [`Credential::authorization_header_value`] is the supported way to obtain
/// request authentication material. Seafile currently issues 40-character
/// tokens, but this type only requires a non-empty visible-ASCII value so it
/// does not assume that the token format stays fixed. Credentials discovered
/// from `seaf-cli` configuration or obtained through the account exchange also
/// carry the deployment they belong to; [`Credential::new`] creates an explicit
/// caller-supplied credential without that restriction.
#[derive(Clone)]
pub struct Credential {
    token: String,
    deployment: Option<DeploymentScope>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Credential");
        debug.field("token", &Redact::from(&self.token));
        if let Some(deployment) = &self.deployment {
            debug.field("deployment", deployment);
        }
        debug.finish()
    }
}

impl Credential {
    /// Create a credential from a raw Seafile token.
    ///
    /// Pass the token itself, not an `Authorization` header value. The token
    /// must be non-empty and contain only visible ASCII characters. Rejecting
    /// other input keeps malformed values from becoming request authentication
    /// material and keeps redaction from slicing a non-ASCII string at an
    /// invalid byte boundary.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() {
            return Err(Error::config_invalid("Seafile token must not be empty"));
        }
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::config_invalid(
                "Seafile token must contain only visible ASCII characters",
            ));
        }

        Ok(Self {
            token,
            deployment: None,
        })
    }

    pub(crate) fn with_deployment_scope(mut self, deployment: DeploymentScope) -> Self {
        self.deployment = Some(deployment);
        self
    }

    pub(crate) fn deployment_scope(&self) -> Option<&DeploymentScope> {
        self.deployment.as_ref()
    }

    /// Return the token value.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Build a sensitive `Authorization: Token` header value.
    ///
    /// Errors never contain the token.
    pub fn authorization_header_value(&self) -> Result<http::HeaderValue> {
        let mut value: http::HeaderValue = format!("Token {}", self.token)
            .parse()
            .map_err(|_| Error::config_invalid("Seafile token is not a valid HTTP header value"))?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        !self.token.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_non_visible_tokens() {
        assert_eq!(
            Credential::new("")
                .expect_err("empty token must fail")
                .kind(),
            reqsign_core::ErrorKind::ConfigInvalid
        );
        assert_eq!(
            Credential::new("token with space")
                .expect_err("space is not visible ASCII")
                .kind(),
            reqsign_core::ErrorKind::ConfigInvalid
        );
        assert_eq!(
            Credential::new("token-\u{00e9}")
                .expect_err("non-ASCII token must fail")
                .kind(),
            reqsign_core::ErrorKind::ConfigInvalid
        );
    }

    #[test]
    fn debug_and_headers_redact_the_token() {
        let credential = Credential::new("seafile-token-value").expect("token must be valid");

        let debug = format!("{credential:?}");
        assert!(!debug.contains("seafile-token-value"));

        let header = credential
            .authorization_header_value()
            .expect("header must be valid");
        assert_eq!(header, "Token seafile-token-value");
        assert!(header.is_sensitive());
    }
}
