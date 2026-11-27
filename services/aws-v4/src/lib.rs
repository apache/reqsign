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

//! AWS SigV4 signing implementation for reqsign.
//!
//! This crate provides AWS Signature Version 4 (SigV4) signing capabilities
//! for authenticating requests to AWS services like S3, DynamoDB, Lambda, and more.
//!
//! ## Overview
//!
//! AWS SigV4 is the authentication protocol used by most AWS services. This crate
//! implements the complete signing algorithm along with credential loading from
//! various sources including environment variables, credential files, IAM roles,
//! and more.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_aws_v4::{DefaultCredentialProvider, EMPTY_STRING_SHA256, RequestSigner};
//! use reqsign_core::{Context, Signer};
//! use reqsign_crypto_rustcrypto::RustCryptoProvider;
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create context
//!     let ctx = Context::new()
//!         .with_crypto(RustCryptoProvider::new())
//!         .with_file_read(TokioFileRead::default())
//!         .with_http_send(ReqwestHttpSend::default());
//!
//!     // Create credential loader
//!     let loader = DefaultCredentialProvider::new();
//!
//!     // Create request builder for S3
//!     let builder = RequestSigner::new("s3", "us-east-1");
//!
//!     // Create the signer
//!     let signer = Signer::new(ctx, loader, builder);
//!
//!     // Sign requests
//!     let mut req = http::Request::get("https://s3.amazonaws.com/mybucket/mykey")
//!         .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
//!         .body(())
//!         .unwrap()
//!         .into_parts()
//!         .0;
//!
//!     signer.sign(&mut req, None).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Payload Signing
//!
//! `RequestSigner` receives request parts, not the request body. The caller
//! owns the body and may stream it, so the signer cannot hash it without
//! buffering or implementing a streaming signature. When
//! `x-amz-content-sha256` is absent, header authentication adds
//! `x-amz-content-sha256: UNSIGNED-PAYLOAD` (including for an empty body), while
//! presigning uses that value in the canonical request without adding the
//! header.
//!
//! `UNSIGNED-PAYLOAD` is an Amazon S3 payload mode. Other AWS services define
//! their own payload requirements, and some require the actual payload hash;
//! check the service's SigV4 documentation.
//!
//! To sign the actual payload, set `x-amz-content-sha256` before signing to the
//! lowercase hex SHA-256 of the exact transmitted bytes. Use
//! [`EMPTY_STRING_SHA256`] for an empty body (SHA-256 of the empty string:
//! `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) and
//! [`reqsign_core::hash::hex_sha256`] for non-empty bytes. Hash after any
//! content encoding or compression, and do not change the payload after
//! signing. For `aws-chunked` uploads, use
//! [`RequestSigner::sign_streaming_request`].
//!
//! The SigV4 digest does not replace TLS, and S3's `Content-MD5` and
//! `x-amz-checksum-*` headers are separate Base64-encoded integrity checks
//! whose support depends on the operation, bucket, and transfer mode. See
//! [`RequestSigner`] for the detailed payload and checksum contract.
//!
//! ## S3 Browser Uploads
//!
//! Use [`sign_s3_post_policy`] to sign a caller-built policy for a browser-based
//! S3 upload. It returns the SigV4 authentication fields for the multipart form.
//!
//! ## Credential Sources
//!
//! The crate supports loading credentials from multiple sources:
//!
//! 1. **Environment Variables**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
//! 2. **Credential File**: `~/.aws/credentials`
//! 3. **IAM Roles**: For EC2 instances and ECS tasks
//! 4. **AssumeRole**: Via STS AssumeRole operations
//! 5. **WebIdentity**: For Kubernetes service accounts
//! 6. **SSO**: AWS SSO credentials
//!
//! ## Supported Services
//!
//! This implementation works with any AWS service that uses SigV4:
//!
//! - Amazon S3
//! - Amazon DynamoDB
//! - AWS Lambda
//! - Amazon SQS
//! - Amazon SNS
//! - And many more...
//!
//! ## Advanced Configuration
//!
//! ### Using Custom Credential Providers
//!
//! ```no_run
//! use reqsign_aws_v4::{EnvCredentialProvider, ProfileCredentialProvider};
//! use reqsign_core::ProvideCredentialChain;
//!
//! // Create a custom credential chain
//! let chain = ProvideCredentialChain::new()
//!     .push(EnvCredentialProvider::new())
//!     .push(ProfileCredentialProvider::new()
//!         .with_profile("production"));
//! ```
//!
//! ### Customizing DefaultCredentialProvider Slots
//!
//! ```no_run
//! use reqsign_aws_v4::{DefaultCredentialProvider, ProfileCredentialProvider};
//!
//! let provider = DefaultCredentialProvider::builder()
//!     .no_env()
//!     .profile(ProfileCredentialProvider::new().with_profile("production"))
//!     .no_imds()
//!     .build();
//! ```
//!
//! ### Selecting a Profile
//!
//! Use one explicit profile for the shared profile, SSO, and process credential
//! sources:
//!
//! ```no_run
//! use reqsign_aws_v4::DefaultCredentialProvider;
//!
//! let provider = DefaultCredentialProvider::builder()
//!     .with_profile("production")
//!     .build();
//! ```
//!
//! ### Custom Credential Provider
//!
//! You can create custom credential providers by implementing the `ProvideCredential` trait:
//!
//! ```no_run
//! use reqsign_core::{ProvideCredential, Context, Result};
//!
//! # #[derive(Debug)]
//! # struct MyCredentialProvider;
//! # type Credential = reqsign_aws_v4::Credential;
//! impl ProvideCredential for MyCredentialProvider {
//!     type Credential = Credential;
//!     
//!     async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
//!         // Your custom credential loading logic
//!         Ok(None)
//!     }
//! }
//! ```
//!
//! ## Examples
//!
//! Check out the examples directory for more detailed usage:
//! - [S3 signing example](examples/s3_sign.rs)
//! - [DynamoDB signing example](examples/dynamodb_sign.rs)

mod assume_role;
pub use assume_role::AssumeRoleGranter;
mod s3_post_policy;
pub use s3_post_policy::{S3PostPolicyFields, sign_s3_post_policy};
mod sign_request;
pub use sign_request::RequestSigner;
mod s3_access_grants;
pub use s3_access_grants::{
    S3AccessGrantsConfig, S3AccessGrantsGrant, S3AccessGrantsGranter, S3AccessGrantsPermission,
    S3AccessGrantsPrivilege, S3AccessGrantsTarget,
};
mod provide_credential;
pub use provide_credential::{
    S3ExpressSessionConfig, S3ExpressSessionGrant, S3ExpressSessionGrantSelection,
    S3ExpressSessionGranter, S3ExpressSessionMode, S3ExpressSessionPartition,
    S3ExpressSessionProvider,
};
pub use reqsign_aws_core::constants;
pub use reqsign_aws_core::signing::StreamingSigner;
pub use reqsign_aws_core::{
    AssumeRoleCredentialProvider, AssumeRoleGrant, AssumeRoleWithWebIdentityCredentialProvider,
    CognitoIdentityCredentialProvider, Credential, DefaultCredentialProvider,
    DefaultCredentialProviderBuilder, ECSCredentialProvider, EnvCredentialProvider,
    IMDSv2CredentialProvider, ProfileCredentialProvider, StaticCredentialProvider,
};
pub use reqsign_aws_core::{IMDSv2RegionProvider, Profile, SharedConfig};
pub use reqsign_aws_core::{PercentEncodingMode, UriPathNormalizationMode};
#[cfg(not(target_arch = "wasm32"))]
pub use reqsign_aws_core::{ProcessCredentialProvider, SSOCredentialProvider};

pub const EMPTY_STRING_SHA256: &str = reqsign_aws_core::EMPTY_STRING_SHA256;

#[cfg(test)]
pub(crate) fn test_context() -> reqsign_core::Context {
    reqsign_core::Context::new().with_crypto(reqsign_crypto_rustcrypto::RustCryptoProvider::new())
}
