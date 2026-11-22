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
use std::fmt::{self, Debug, Formatter};

/// An access token for the Baidu Netdisk Open Platform.
///
/// Baidu issues this token to an authorized Open Platform application. The
/// token is a secret and is sent as the `access_token` query parameter.
/// [`Credential::new`] accepts the token as-is; an empty token is not valid for
/// signing. `Debug` output never contains the token.
#[derive(Clone)]
pub struct Credential {
    access_token: String,
}

impl Credential {
    /// Create a credential from an access token.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
        }
    }

    /// Return the access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn is_valid_token(token: &str) -> bool {
        !token.is_empty()
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        Self::is_valid_token(&self.access_token)
    }
}
