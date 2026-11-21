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

//! Dropbox authentication and request signing for reqsign.
//!
//! The default credential provider reads the access token documented by the
//! official `dbxcli` tool from `DBXCLI_ACCESS_TOKEN` through
//! [`reqsign_core::Context`] environment access. Explicit access tokens and
//! OAuth 2.0 refresh-token credentials are available through
//! [`StaticCredentialProvider`] and [`RefreshCredentialProvider`].
//!
//! [`RequestSigner`] adds only a sensitive `Authorization: Bearer` header. It
//! rejects `expires_in` because Dropbox does not support query authentication;
//! signing never changes the URI or any other header.

mod constants;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, EnvCredentialProvider,
    RefreshCredentialProvider, StaticCredentialProvider,
};
