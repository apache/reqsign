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

use crate::Credential;
use reqsign_core::{Context, ProvideCredential, Result};

/// Provides an explicit anonymous credential for public GitHub resources.
///
/// This is the last slot in the default chain so that public reads keep
/// working without a token. Signing with this credential removes any existing
/// `Authorization` header and leaves other headers and the URI unchanged.
/// Anonymous requests are limited to public data and GitHub's unauthenticated
/// rate limit.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnonymousCredentialProvider;

impl AnonymousCredentialProvider {
    /// Create a new anonymous credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for AnonymousCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(Credential::anonymous()))
    }
}
