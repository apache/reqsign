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

use log::debug;
use reqsign_core::utils::Redact;
use reqsign_core::{Context, Error, Result};

/// A validated bearer token shared by the Vercel service credentials.
///
/// The token never appears in `Debug` output or error messages. Validation
/// rejects values that cannot become an HTTP header value before any request
/// is changed.
#[derive(Clone)]
pub(crate) struct BearerToken(String);

impl BearerToken {
    pub(crate) fn new(token: impl Into<String>, service: &str) -> Result<Self> {
        let token = token.into();
        if token.is_empty() {
            return Err(Error::config_invalid(format!(
                "{service} token must not be empty"
            )));
        }
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::config_invalid(format!(
                "{service} token must contain only visible ASCII characters"
            )));
        }

        Ok(Self(token))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn bearer_header_value(&self, service: &str) -> Result<http::HeaderValue> {
        let mut value: http::HeaderValue = format!("Bearer {}", self.0).parse().map_err(|_| {
            Error::config_invalid(format!("{service} token is not a valid HTTP header value"))
        })?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl Debug for BearerToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BearerToken")
            .field(&Redact::from(&self.0))
            .finish()
    }
}

/// Read one documented environment variable as a bearer token.
///
/// A missing or empty variable is absent, while a present but unusable value is
/// a configuration error. This keeps a malformed credential from silently
/// falling through to another identity.
pub(crate) fn env_token(ctx: &Context, var: &str, service: &str) -> Result<Option<BearerToken>> {
    let Some(token) = ctx.env_var(var) else {
        debug!("{var} not set, skipping environment credential provider");
        return Ok(None);
    };
    if token.is_empty() {
        debug!("{var} is empty, skipping environment credential provider");
        return Ok(None);
    }

    BearerToken::new(token, service)
        .map(Some)
        .map_err(|_| Error::config_invalid(format!("{var} is not a usable {service} token")))
}
