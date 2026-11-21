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

//! RFC 9421 HTTP Message Signatures for request heads.
//!
//! This crate implements the signing side of
//! [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) for HTTP requests.
//! It emits `Signature-Input` and `Signature` dictionary members with a
//! caller-selected label and ordered component list.
//!
//! Verification, response signing, multiple signatures in one invocation,
//! component parameters, `@request-target`, and request body I/O are outside
//! this first version. The library signs the request head it is given and
//! leaves sending the request to the caller.
//!
//! ## Supported algorithms
//!
//! - HMAC-SHA256 with [`Credential::hmac_sha256`], using raw key bytes.
//! - RSASSA-PKCS1-v1_5 with SHA-256 and an unencrypted PKCS#1 or PKCS#8 PEM
//!   private key, using [`Credential::rsa_v1_5_sha256`].
//!
//! Algorithms are provided by the selected [`reqsign_core::crypto::CryptoProvider`]. HMAC needs the
//! provider's `hmac_sha256` operation. RSA needs its
//! `rsa_pkcs1v15_sha256_sign` operation; the RustCrypto provider supports that
//! operation on native targets and returns `ConfigInvalid` for it on
//! `wasm32-unknown-unknown`.
//!
//! ## Covered components
//!
//! A policy covers an ordered, nonempty, duplicate-free list of ordinary
//! request fields and these derived components: `@method`, `@target-uri`,
//! `@authority`, `@scheme`, `@path`, and `@query`. The URI must be absolute
//! and use HTTP or HTTPS. Existing percent escapes, query ordering, and
//! repeated query parameters are preserved. A present `Host` header must be
//! unique and consistent with the URI authority.
//!
//! ## Body coverage
//!
//! This crate does not read the request body. To cover a body, compute a
//! `Content-Digest` header before signing and include that header as a
//! [`Component::Header`]. Do not sign a digest that does not match the bytes
//! that will actually be sent.
//!
//! ## Example
//!
//! ```no_run
//! use http::header::HeaderName;
//! use reqsign_core::{Context, Signer};
//! use reqsign_crypto_rustcrypto::RustCryptoProvider;
//! use reqsign_http_message_signatures::{
//!     Component, Credential, RequestSigner, StaticCredentialProvider,
//! };
//!
//! # async fn example() -> reqsign_core::Result<()> {
//! let credential = Credential::hmac_sha256("my-key", b"shared secret")?;
//! let provider = StaticCredentialProvider::new(credential);
//! let request_signer = RequestSigner::new(
//!     "sig1",
//!     [
//!         Component::Method,
//!         Component::Authority,
//!         Component::Path,
//!         Component::Header(HeaderName::from_static("content-digest")),
//!     ],
//! )?;
//!
//! let ctx = Context::new().with_crypto(RustCryptoProvider::new());
//! let signer = Signer::new(ctx, provider, request_signer);
//!
//! let mut parts = http::Request::builder()
//!     .method("POST")
//!     .uri("https://example.com/upload?part=1")
//!     .header("content-digest", "sha-256=:...:")
//!     .body(())
//!     .unwrap()
//!     .into_parts()
//!     .0;
//!
//! signer.sign(&mut parts, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod component;
mod credential;
mod request_signer;
mod static_provider;
mod structured_field;

pub use component::Component;
pub use credential::Credential;
pub use request_signer::RequestSigner;
pub use static_provider::StaticCredentialProvider;

#[cfg(test)]
mod tests;
