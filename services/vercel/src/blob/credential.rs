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

use reqsign_core::Result;
use reqsign_core::SigningCredential;

use crate::bearer::BearerToken;

/// A Vercel Blob bearer token.
///
/// The default provider discovers a long-lived read-write token from
/// `BLOB_READ_WRITE_TOKEN`. The token is scoped to a Blob store, while the
/// endpoint, pathname, access level, upload options, and Blob API headers are
/// part of the request that the caller constructs.
///
/// Vercel's OIDC and client-token flows need store or operation context in the
/// request, so this crate neither discovers nor refreshes them. Supply a token
/// through [`crate::BlobStaticCredentialProvider`] when the caller already owns
/// such a credential.
///
/// The token is a secret. `Debug` output redacts it, and
/// [`BlobCredential::bearer_header_value`] is the supported way to obtain request
/// authentication material.
#[derive(Clone)]
pub struct BlobCredential {
    token: BearerToken,
}

impl Debug for BlobCredential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobCredential")
            .field("token", &self.token)
            .finish()
    }
}

impl BlobCredential {
    /// Create a credential from a raw bearer token.
    ///
    /// Pass the token itself, not an `Authorization` header value. The token must
    /// be non-empty and contain only visible ASCII characters.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            token: BearerToken::new(token, "Vercel Blob")?,
        })
    }

    /// Return the raw bearer token.
    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    /// Build a sensitive `Authorization: Bearer` header value.
    ///
    /// Errors never contain the token.
    pub fn bearer_header_value(&self) -> Result<http::HeaderValue> {
        self.token.bearer_header_value("Vercel Blob")
    }

    pub(crate) fn from_bearer_token(token: BearerToken) -> Self {
        Self { token }
    }
}

impl SigningCredential for BlobCredential {
    fn is_valid(&self) -> bool {
        !self.token.as_str().is_empty()
    }
}
