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

#![cfg(all(feature = "aws-v4", feature = "aws-v4a", feature = "default-crypto"))]

use std::time::Duration;

use anyhow::Result;
use http::{Request, header, request::Parts};
use reqsign::aws::{v4, v4a};
use reqsign::{Context, RustCryptoProvider, SignRequest, Signer};
use v4::{Credential, StaticCredentialProvider, UriPathNormalizationMode};

#[tokio::test]
async fn normalizes_only_the_path_used_for_signing() -> Result<()> {
    let region = "us-west-2";
    let time = "2026-07-22T00:00:00Z".parse()?;
    assert_path_normalization(|mode| {
        let signer = v4::RequestSigner::new("s3", region).with_time(time);
        match mode {
            Some(mode) => signer.with_uri_path_normalization_mode(mode),
            None => signer,
        }
    })
    .await?;

    let region_set = v4a::SigningRegionSet::new(region)?;
    assert_path_normalization(|mode: Option<v4a::UriPathNormalizationMode>| {
        let signer = v4a::RequestSigner::new("s3", region_set.clone()).with_time(time);
        match mode {
            Some(mode) => signer.with_uri_path_normalization_mode(mode),
            None => signer,
        }
    })
    .await
}

async fn assert_path_normalization<S: SignRequest<Credential = Credential>>(
    new_request_signer: impl Fn(Option<UriPathNormalizationMode>) -> S,
) -> Result<()> {
    const QUERY: &str = "dup=second&slash=%2f&dup=first&literal-plus=+&flag&empty=&";
    let original = format!("https://example.com/a//b/../c/.?{QUERY}");
    let normalized = format!("https://example.com/a/c/?{QUERY}");
    let signer = |mode| {
        Signer::new(
            Context::new().with_crypto(RustCryptoProvider::new()),
            StaticCredentialProvider::new("test-access-key", "test-secret-key"),
            new_request_signer(mode),
        )
    };
    let default = signer(None);
    let disabled = signer(Some(UriPathNormalizationMode::Disabled));
    let enabled = signer(Some(UriPathNormalizationMode::Enabled));

    for expires_in in [None, Some(Duration::from_secs(60))] {
        let unnormalized_request = sign(&default, &original, expires_in).await?;
        let disabled_request = sign(&disabled, &original, expires_in).await?;
        let enabled_request = sign(&enabled, &original, expires_in).await?;
        let normalized_request = sign(&default, &normalized, expires_in).await?;

        assert_eq!(unnormalized_request.headers, disabled_request.headers);
        assert_eq!(unnormalized_request.uri, disabled_request.uri);
        assert_eq!(enabled_request.headers, normalized_request.headers);
        if expires_in.is_some() {
            assert_eq!(enabled_request.uri.query(), normalized_request.uri.query());
            assert_ne!(
                enabled_request.uri.query(),
                unnormalized_request.uri.query()
            );
            assert!(enabled_request.uri.to_string().starts_with(&original));
        } else {
            assert_ne!(
                enabled_request.headers[header::AUTHORIZATION],
                unnormalized_request.headers[header::AUTHORIZATION],
            );
            assert_eq!(enabled_request.uri.to_string(), original);
        }
    }
    Ok(())
}

async fn sign(
    signer: &Signer<Credential>,
    uri: &str,
    expires_in: Option<Duration>,
) -> Result<Parts> {
    let mut parts = Request::get(uri).body(())?.into_parts().0;
    signer.sign(&mut parts, expires_in).await?;
    Ok(parts)
}
