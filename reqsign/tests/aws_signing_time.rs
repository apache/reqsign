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

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use http::{Request, header, request::Parts};
use reqsign::aws::{v4, v4a};
use reqsign::time::Timestamp;
use reqsign::{Context, ErrorKind, ProvideCredential, RustCryptoProvider, SignRequest, Signer};
use v4::Credential;

const REGION: &str = "us-east-1";
const HEADER_HEADROOM: Duration = Duration::from_secs(10);

fn request() -> Parts {
    Request::get("https://example.com/object")
        .body(())
        .expect("fixture request must be valid")
        .into_parts()
        .0
}

fn credential(access_key_id: &str, expires_in: Option<Timestamp>) -> Credential {
    Credential {
        access_key_id: access_key_id.to_string(),
        secret_access_key: "test-secret-key".to_string(),
        session_token: Some("test-session-token".to_string()),
        expires_in,
    }
}

#[tokio::test]
async fn sigv4_signing_time() -> Result<()> {
    let new_signer = || v4::RequestSigner::new("s3", REGION);
    let fixed_signer = |time| new_signer().with_time(time);
    assert_system_clock(new_signer()).await?;
    assert_fixed_signing_time(fixed_signer, "us-east-1/s3/aws4_request").await?;
    assert_cache_after_time_change(fixed_signer).await
}

#[tokio::test]
async fn sigv4a_signing_time() -> Result<()> {
    let new_signer = || v4a::RequestSigner::new("s3", v4a::SigningRegionSet::new(REGION).unwrap());
    let fixed_signer = |time| new_signer().with_time(time);
    assert_system_clock(new_signer()).await?;
    assert_fixed_signing_time(fixed_signer, "s3/aws4_request").await?;
    assert_cache_after_time_change(fixed_signer).await
}

async fn assert_system_clock(signer: impl SignRequest<Credential = Credential>) -> Result<()> {
    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let credential = credential("test-key", None);
    let mut parts = request();

    let before = Timestamp::now();
    let deadline = signer.required_valid_until(&credential, None);
    signer
        .sign_request(&ctx, &mut parts, Some(&credential), None)
        .await?;
    let after = Timestamp::now();

    assert!((before + HEADER_HEADROOM..=after + HEADER_HEADROOM).contains(&deadline));
    let before = before.format_iso8601();
    let after = after.format_iso8601();
    let date = parts.headers["x-amz-date"].to_str()?;
    assert!((before.as_str()..=after.as_str()).contains(&date));
    Ok(())
}

async fn assert_fixed_signing_time<S: SignRequest<Credential = Credential>>(
    new_signer: impl Fn(Timestamp) -> S,
    scope_suffix: &str,
) -> Result<()> {
    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let utc_midnight: Timestamp = "2025-01-01T00:00:00Z".parse()?;
    let adjustment = Duration::from_millis(500);
    for (time, wire_date) in [
        (utc_midnight - adjustment, "20241231T235959Z"),
        (utc_midnight + adjustment, "20250101T000000Z"),
    ] {
        let signer = new_signer(time);
        let scope = format!("test-key/{}/{scope_suffix}", &wire_date[..8]);
        for expires_in in [None, Some(Duration::from_millis(1500))] {
            let deadline = time + expires_in.unwrap_or(HEADER_HEADROOM);
            let mut credential = credential("test-key", Some(deadline));
            assert_eq!(
                signer.required_valid_until(&credential, expires_in),
                deadline
            );

            let original = request();
            let mut parts = original.clone();
            let err = signer
                .sign_request(&ctx, &mut parts, Some(&credential), expires_in)
                .await
                .expect_err("credential expiring at the deadline must be rejected");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            assert_eq!(parts.uri, original.uri);
            assert_eq!(parts.headers, original.headers);

            credential.expires_in = Some(deadline + Duration::from_nanos(1));
            signer
                .sign_request(&ctx, &mut parts, Some(&credential), expires_in)
                .await?;

            if expires_in.is_some() {
                let query = parts.uri.query().expect("presigned query must exist");
                for field in [
                    format!("X-Amz-Date={wire_date}"),
                    format!("X-Amz-Credential={}", scope.replace('/', "%2F")),
                    "X-Amz-Expires=1".to_string(),
                ] {
                    assert!(
                        query.split('&').any(|pair| pair == field),
                        "missing {field}"
                    );
                }
            } else {
                assert_eq!(parts.headers["x-amz-date"], wire_date);
                let authorization = parts.headers[header::AUTHORIZATION].to_str()?;
                assert!(authorization.contains(&format!(" Credential={scope},")));
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct SequenceProvider(Mutex<VecDeque<Credential>>);

impl ProvideCredential for SequenceProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _: &Context) -> reqsign::Result<Option<Credential>> {
        Ok(self.0.lock().unwrap().pop_front())
    }
}

async fn assert_cache_after_time_change<S: SignRequest<Credential = Credential>>(
    new_signer: impl Fn(Timestamp) -> S,
) -> Result<()> {
    let now = Timestamp::now();
    let adjusted_time = now + Duration::from_secs(600);
    let lifetime = Duration::from_secs(60);
    let provider = SequenceProvider(Mutex::new(VecDeque::from([
        credential("cached-key", Some(adjusted_time + lifetime)),
        credential("refreshed-key", None),
    ])));
    let signer = Signer::new(
        Context::new().with_crypto(RustCryptoProvider::new()),
        provider,
        new_signer(now),
    );
    assert_eq!(
        signer.credential_for(None).await?.access_key_id,
        "cached-key"
    );

    let signer = signer.with_request_signer(new_signer(adjusted_time));
    // Cache freshness still uses the system clock, and this credential covers header signing.
    assert_eq!(
        signer.credential_for(None).await?.access_key_id,
        "cached-key"
    );

    // The same cached credential expires exactly at the adjusted presigning deadline.
    let mut parts = request();
    signer.sign(&mut parts, Some(lifetime)).await?;
    let query = parts.uri.query().expect("presigned query must exist");
    assert!(
        query
            .split('&')
            .any(|pair| pair.starts_with("X-Amz-Credential=refreshed-key%2F"))
    );
    Ok(())
}
