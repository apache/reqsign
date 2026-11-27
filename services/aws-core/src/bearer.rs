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

//! AWS HTTP Bearer authentication using a static or service-scoped environment token.
//!
//! Available with the `http-bearer` feature. Combine a credential provider and
//! [`RequestSigner`] with [`reqsign_core::Signer`].

use std::time::Duration;

use http::{HeaderValue, header::AUTHORIZATION};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result, SignRequest, SigningCredential};

/// A validated AWS HTTP Bearer token. Its value is masked in `Debug` output.
///
/// Reqsign treats these tokens as opaque and does not track their expiration.
/// A [`reqsign_core::Signer`] caches a loaded token for its lifetime. Replace
/// the credential provider when the token changes.
#[derive(Clone, Debug)]
pub struct Credential {
    authorization: HeaderValue,
}

impl Credential {
    /// Create a credential from the raw token using the RFC 6750 Bearer syntax.
    /// An empty or malformed token returns [`reqsign_core::ErrorKind::CredentialInvalid`].
    pub fn new(token: impl AsRef<str>) -> Result<Self> {
        let token = token.as_ref();
        // RFC 6750 b64token permits one or more token characters followed by padding.
        let unpadded = token.trim_end_matches('=');
        if unpadded.is_empty()
            || !unpadded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        {
            return Err(Error::credential_invalid(
                "AWS bearer token must be a non-empty RFC 6750 token",
            ));
        }

        let mut authorization = HeaderValue::try_from(format!("Bearer {token}")).map_err(|_| {
            Error::credential_invalid("AWS bearer token is not a valid header value")
        })?;
        authorization.set_sensitive(true);
        Ok(Self { authorization })
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        true
    }
}

/// Provides an explicit AWS HTTP Bearer token.
#[derive(Clone, Debug)]
pub struct StaticCredentialProvider(Credential);

impl StaticCredentialProvider {
    /// Create a provider from a raw token, validating it with [`Credential::new`].
    pub fn new(token: impl AsRef<str>) -> Result<Self> {
        Credential::new(token).map(Self)
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(self.0.clone()))
    }
}

/// Loads a token from `AWS_BEARER_TOKEN_<SERVICE>` through the supplied context.
/// A missing or empty variable yields no credential. An unusable token returns
/// [`reqsign_core::ErrorKind::CredentialInvalid`].
#[derive(Clone, Debug)]
pub struct EnvCredentialProvider {
    variable: String,
}

impl EnvCredentialProvider {
    /// Select the AWS service's signing name. The environment variable suffix
    /// uses uppercase and replaces hyphens and spaces with underscores, matching
    /// the AWS SDK convention. For example, `bedrock` selects
    /// `AWS_BEARER_TOKEN_BEDROCK`.
    ///
    /// Blank signing names and names containing `=` or NUL return
    /// [`reqsign_core::ErrorKind::ConfigInvalid`].
    pub fn new(signing_name: &str) -> Result<Self> {
        if signing_name.trim().is_empty() || signing_name.contains(['=', '\0']) {
            return Err(Error::config_invalid(
                "AWS signing name must be non-blank and usable in an environment variable name",
            ));
        }

        let suffix = signing_name.replace(['-', ' '], "_").to_uppercase();
        Ok(Self {
            variable: format!("AWS_BEARER_TOKEN_{suffix}"),
        })
    }
}

impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(token) = ctx
            .env_var(&self.variable)
            .filter(|token| !token.is_empty())
        else {
            return Ok(None);
        };

        Credential::new(token).map(Some).map_err(|error| {
            error.with_context(format!("environment variable: {:?}", self.variable))
        })
    }
}

/// Signs requests for AWS services that accept HTTP Bearer authentication.
///
/// Supply a request URI with an authority. Signing replaces `Authorization`
/// with a sensitive Bearer value and preserves the URI and all other headers.
/// Pass `None` for `expires_in`. With a credential, a requested duration
/// returns [`reqsign_core::ErrorKind::RequestInvalid`] without changing the request.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // These opaque tokens have no tracked expiry and signing adds no timestamp.
        Timestamp::default()
    }

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        if expires_in.is_some() {
            return Err(Error::request_invalid(
                "AWS HTTP Bearer signing does not support presigning",
            ));
        }
        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("an AWS bearer token is required for request signing")
        })?;
        if req.uri.authority().is_none() {
            return Err(Error::request_invalid(
                "AWS HTTP Bearer signing requires a request URI with an authority",
            ));
        }

        req.headers
            .insert(AUTHORIZATION, credential.authorization.clone());
        Ok(())
    }
}
