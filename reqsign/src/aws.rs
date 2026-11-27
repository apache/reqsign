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

//! AWS signing support.
//!
//! SigV4 remains available directly under `reqsign::aws` for compatibility.
//! The explicit authentication modules are `bearer`, `v4`, and `v4a`.

/// AWS HTTP Bearer token authentication.
#[cfg(feature = "aws-bearer")]
pub mod bearer {
    pub use reqsign_aws_core::bearer::*;

    use crate::{Context, Result, Signer};

    /// AWS HTTP Bearer signer type.
    pub type DefaultSigner = Signer<Credential>;

    /// Create a signer that loads the bearer token for an AWS signing name
    /// through the supplied context. For example, `bedrock` selects
    /// `AWS_BEARER_TOKEN_BEDROCK`. Use [`StaticCredentialProvider`] with
    /// [`Signer::new`] to supply a token directly.
    pub fn default_signer(ctx: Context, signing_name: &str) -> Result<DefaultSigner> {
        Ok(Signer::new(
            ctx,
            EnvCredentialProvider::new(signing_name)?,
            RequestSigner,
        ))
    }
}

/// AWS Signature Version 4 support.
#[cfg(feature = "aws-v4")]
pub mod v4 {
    pub use reqsign_aws_v4::*;

    use crate::{Context, Signer};

    /// Default SigV4 signer type.
    pub type DefaultSigner = Signer<Credential>;

    /// Create a default SigV4 signer for an AWS service and region using the supplied context.
    ///
    /// The signer uses the caller-supplied [`Context`] and AWS credential provider chain.
    pub fn default_signer(ctx: Context, service: &str, region: &str) -> DefaultSigner {
        Signer::new(
            ctx,
            DefaultCredentialProvider::new(),
            RequestSigner::new(service, region),
        )
    }
}

// Preserve the existing reqsign::aws::* API and make reqsign::aws::v4 explicit.
#[cfg(feature = "aws-v4")]
pub use v4::*;

/// AWS Signature Version 4A support.
#[cfg(feature = "aws-v4a")]
pub mod v4a {
    pub use reqsign_aws_v4a::*;

    use crate::{Context, Signer};

    /// Default SigV4a signer type.
    pub type DefaultSigner = Signer<Credential>;

    /// Create a default SigV4a signer for an AWS service and signing region set using the supplied context.
    ///
    /// The signer uses the caller-supplied [`Context`] and AWS credential provider chain.
    pub fn default_signer(
        ctx: Context,
        service: &str,
        region_set: SigningRegionSet,
    ) -> DefaultSigner {
        Signer::new(
            ctx,
            DefaultCredentialProvider::new(),
            RequestSigner::new(service, region_set),
        )
    }
}
