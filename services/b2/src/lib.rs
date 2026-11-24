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

//! Backblaze B2 Native API authentication for reqsign.
//!
//! This crate exchanges an application key for a B2 Native API authorization
//! token with `b2_authorize_account`, keeps the returned API and download base
//! URLs on the credential, and signs Native API requests with the required
//! `Authorization` header.
//!
//! The default provider reads `B2_APPLICATION_KEY_ID` and
//! `B2_APPLICATION_KEY`, the environment variables used by the official B2
//! command line tools. Use [`AccountAuthorizationCredentialProvider`] for an
//! explicit application key or [`StaticCredentialProvider`] for a token obtained
//! elsewhere.
//!
//! B2 caps an authorization token at 24 hours. When the application key carries
//! an expiration timestamp, that earlier deadline is kept on the credential so
//! the [`Signer`](reqsign_core::Signer) refreshes before either limit. Key
//! restrictions such as capabilities, bucket allow-lists, and name prefixes are
//! enforced by B2 and are not needed for signing.
//!
//! Bucket- and file-dependent operations stay with the caller. In particular,
//! `b2_get_upload_url`, `b2_get_upload_part_url`,
//! `b2_get_download_authorization`, and the S3-compatible API use different
//! authorization values or request shapes.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_b2::{DefaultCredentialProvider, RequestSigner};
//! use reqsign_core::{Context, OsEnv, Result, Signer};
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! # async fn example() -> Result<()> {
//! let context = Context::new()
//!     .with_http_send(ReqwestHttpSend::default())
//!     .with_env(OsEnv);
//!
//! // The default chain reads B2_APPLICATION_KEY_ID and B2_APPLICATION_KEY.
//! let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);
//!
//! // Load the credential first: api_url belongs to the application key and
//! // selects the account's endpoint.
//! let credential = signer.credential_for(None).await?;
//! let uri = format!(
//!     "{}/b2api/v4/b2_list_buckets?accountId=account-id",
//!     credential.api_url
//! );
//!
//! let mut request = http::Request::get(uri).body(()).unwrap().into_parts().0;
//!
//! // Sign with the same credential that supplied api_url.
//! signer.sign_with_credential(&mut request, &credential, None).await?;
//! # Ok(())
//! # }
//! ```

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    AccountAuthorizationCredentialProvider, DefaultCredentialProvider,
    DefaultCredentialProviderBuilder, EnvCredentialProvider, StaticCredentialProvider,
};
