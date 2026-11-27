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

//! Explicit API key header authentication for Azure APIs.
//!
//! Compose a [`Signer`](reqsign_core::Signer) with a [static key](StaticCredentialProvider)
//! or a [caller-named environment variable](EnvCredentialProvider), and a [`RequestSigner`].
//! Supply the trusted endpoint and choose the required header. Use
//! [`api-key`](RequestSigner::api_key) for services such as Azure OpenAI and
//! Azure AI Search, [`Ocp-Apim-Subscription-Key`](RequestSigner::subscription_key)
//! for Azure API Management and Azure AI Services, or a
//! [custom header name](RequestSigner::new).
//!
//! Reqsign treats keys as opaque and caches a loaded key without an expiry.
//! When the key rotates, create a new signer or use
//! [`Signer::with_credential_provider`](reqsign_core::Signer::with_credential_provider)
//! to load the rotated key into a fresh cache. Replace any signer clones still
//! serving requests, since they share the original cache.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result, SignRequest, SigningCredential};

/// A validated Azure API key with redacted debug output.
#[derive(Clone)]
pub struct Credential {
    key: HeaderValue,
}

impl Credential {
    /// Create a credential from a non-empty key containing only visible ASCII.
    /// Blank or malformed keys return [`CredentialInvalid`](reqsign_core::ErrorKind::CredentialInvalid).
    pub fn new(key: impl AsRef<str>) -> Result<Self> {
        let key = key.as_ref();
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::credential_invalid(
                "Azure API key must be non-empty and contain only visible ASCII characters",
            ));
        }

        let mut value = HeaderValue::from_str(key)
            .map_err(|_| Error::credential_invalid("Azure API key is not a valid header value"))?;
        value.set_sensitive(true);
        Ok(Self { key: value })
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("key", &"REDACTED")
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        true
    }
}

/// Provides an explicit key without reading from the context.
#[derive(Clone, Debug)]
pub struct StaticCredentialProvider(Credential);

impl StaticCredentialProvider {
    /// Create a provider from a key, validating it with [`Credential::new`].
    pub fn new(key: impl AsRef<str>) -> Result<Self> {
        Credential::new(key).map(Self)
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(self.0.clone()))
    }
}

/// Reads only the selected variable through [`Context::env_var`].
/// An unavailable variable yields no credential. An empty or malformed value
/// returns [`CredentialInvalid`](reqsign_core::ErrorKind::CredentialInvalid).
#[derive(Clone, Debug)]
pub struct EnvCredentialProvider {
    variable: String,
}

impl EnvCredentialProvider {
    /// Use a caller-selected environment variable name as supplied.
    /// Blank names and names containing `=` or NUL return
    /// [`ConfigInvalid`](reqsign_core::ErrorKind::ConfigInvalid).
    pub fn new(variable: &str) -> Result<Self> {
        if variable.trim().is_empty() || variable.contains(['=', '\0']) {
            return Err(Error::config_invalid(
                "Azure API key environment variable name must be non-blank and contain neither '=' nor NUL",
            ));
        }
        Ok(Self {
            variable: variable.to_owned(),
        })
    }
}

impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(key) = ctx.env_var(&self.variable) else {
            return Ok(None);
        };
        Credential::new(key).map(Some).map_err(|error| {
            error.with_context(format!("environment variable: {:?}", self.variable))
        })
    }
}

/// Replaces all values of the configured header with one sensitive API key.
/// The request URI must have an authority. The URI and other headers are
/// preserved. Pass `None` for `expires_in`. A duration or a URI without an
/// authority returns [`RequestInvalid`](reqsign_core::ErrorKind::RequestInvalid).
#[derive(Debug)]
pub struct RequestSigner {
    header_name: HeaderName,
}

impl RequestSigner {
    /// Choose a custom header name. Invalid HTTP header names return
    /// [`ConfigInvalid`](reqsign_core::ErrorKind::ConfigInvalid).
    pub fn new(header_name: &str) -> Result<Self> {
        let header_name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
            Error::config_invalid("Azure API key requires a valid HTTP header name")
        })?;
        Ok(Self { header_name })
    }

    /// Use the `api-key` header, as in Azure OpenAI and Azure AI Search.
    pub fn api_key() -> Self {
        Self {
            header_name: HeaderName::from_static("api-key"),
        }
    }

    /// Use the `Ocp-Apim-Subscription-Key` header, as in Azure API Management and Azure AI Services.
    pub fn subscription_key() -> Self {
        Self {
            header_name: HeaderName::from_static("ocp-apim-subscription-key"),
        }
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // Opaque API keys have no tracked expiry and header injection needs no clock.
        Timestamp::default()
    }

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        if expires_in.is_some() {
            return Err(Error::request_invalid(
                "Azure API key authentication does not support presigning",
            ));
        }
        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("an Azure API key is required for request signing")
        })?;
        if req.uri.authority().is_none() {
            return Err(Error::request_invalid(
                "Azure API key authentication requires a request URI with an authority",
            ));
        }

        req.headers
            .try_insert(self.header_name.clone(), credential.key.clone())
            .map_err(|_| Error::request_invalid("no room for the Azure API key header"))?;
        Ok(())
    }
}
