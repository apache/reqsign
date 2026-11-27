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

//! Azure Storage signing and explicit [API key authentication](api_key) for Azure APIs.
//!
//! This module provides Azure Storage signing functionality along with convenience
//! functions for common use cases.
//!
//! ## Azure API keys
//!
//! Choose the credential source and header explicitly. Set your chosen
//! environment variable and use a context with an environment adapter. For
//! a key supplied by your application, use [`api_key::StaticCredentialProvider`]
//! with `Context::new()`.
//!
//! ```no_run
//! use reqsign::azure::api_key::{EnvCredentialProvider, RequestSigner};
//! use reqsign::{Context, OsEnv, Signer};
//!
//! # async fn example() -> reqsign::Result<()> {
//! let signer = Signer::new(
//!     Context::new().with_env(OsEnv),
//!     EnvCredentialProvider::new("MY_APIM_KEY")?,
//!     RequestSigner::subscription_key(),
//! );
//! let mut request = http::Request::get("https://my-gateway.azure-api.net/catalog")
//!     .body(())
//!     .unwrap()
//!     .into_parts()
//!     .0;
//! signer.sign(&mut request, None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Blob Storage Service SAS
//!
//! Shared Key credentials can grant a typed Blob Storage Service SAS.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use reqsign::azure::{
//!     ServiceSasBlobPermissions, ServiceSasConfig, ServiceSasGrant,
//!     ServiceSasGranter, StaticCredentialProvider,
//! };
//! use reqsign::{Context, Granter};
//!
//! # async fn example() -> reqsign::Result<()> {
//! let grant = ServiceSasGrant::for_blob(
//!     "customer-data",
//!     "reports/current.csv",
//!     ServiceSasBlobPermissions::READ,
//! );
//! let credential = Granter::new(
//!     Context::new(),
//!     StaticCredentialProvider::new_shared_key(
//!         "mystorageaccount",
//!         "<base64-encoded 512-bit account key>",
//!     ),
//!     ServiceSasGranter::new(ServiceSasConfig::new("mystorageaccount"), grant),
//! )
//! .grant(Some(Duration::from_secs(900)))
//! .await?;
//! # let _ = credential;
//! # Ok(())
//! # }
//! ```

// Re-export all Azure Storage signing types
pub use reqsign_azure_storage::*;

use crate::{Context, Signer};

/// Default Azure Storage Signer type with commonly used components
pub type DefaultSigner = Signer<Credential>;

/// Create a default Azure Storage signer with the supplied runtime context.
///
/// This function creates a signer with:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()` when `default-context` is enabled)
/// - Default credential provider (reads from env vars, managed identity, CLI, etc.)
/// - Request signer for Azure Storage
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::azure::default_signer(ctx);
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://myaccount.blob.core.windows.net/mycontainer/myblob")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// You can customize the signer using the `with_*` methods:
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// use reqsign::azure::{default_signer, StaticCredentialProvider};
///
/// let ctx = reqsign::default_context();
/// let signer = default_signer(ctx)
///     .with_credential_provider(StaticCredentialProvider::new_shared_key(
///         "myaccount",
///         "my-account-key",
///     ));
/// # Ok(())
/// # }
/// ```
pub fn default_signer(ctx: Context) -> DefaultSigner {
    let provider = DefaultCredentialProvider::new();
    let signer = RequestSigner::new();
    Signer::new(ctx, provider, signer)
}
