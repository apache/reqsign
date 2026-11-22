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
use reqsign_core::time::Timestamp;
use reqsign_oauth2::AccessToken;
use std::fmt::{self, Debug, Formatter};

/// A Microsoft Graph access token used for OneDrive requests.
///
/// This service-specific wrapper keeps the OneDrive credential boundary
/// separate from the shared OAuth 2.0 token type. The token remains redacted in
/// `Debug` output.
#[derive(Clone)]
pub struct Credential {
    access_token: AccessToken,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_token", &self.access_token)
            .finish()
    }
}

impl Credential {
    /// Create a OneDrive credential from a Microsoft Graph access token.
    pub fn new(access_token: AccessToken) -> Self {
        Self { access_token }
    }

    /// Return the shared access token.
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.access_token.is_valid()
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        self.access_token.is_valid_at(timestamp)
    }
}
