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

//! Seafile service support with convenience APIs.

pub use reqsign_seafile::*;

use crate::{Context, Signer};

/// Default Seafile signer type with the documented credential chain.
pub type DefaultSigner = Signer<Credential>;

/// Create a default Seafile signer with the supplied runtime context.
///
/// The default credential provider reads the `token` from the `[account]`
/// section of `~/.seafile.conf`, the user configuration file read by Seafile's
/// first-party `seaf-cli`. A context without a file reader yields no
/// credential. Replace the provider with [`StaticCredentialProvider`] when the
/// token is managed explicitly, or [`AccountTokenCredentialProvider`] when the
/// caller wants to exchange a username and password with a configured server.
pub fn default_signer(ctx: Context) -> DefaultSigner {
    Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner)
}
