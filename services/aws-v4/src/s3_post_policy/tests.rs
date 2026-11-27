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

use std::collections::BTreeMap;
use std::time::Duration;

use reqsign_core::ErrorKind;
use reqsign_core::hash::base64_decode;
use reqsign_crypto_rustcrypto::RustCryptoProvider;

use crate::{Credential, sign_s3_post_policy};

#[test]
fn signs_the_aws_post_policy_example() -> reqsign_core::Result<()> {
    // Decode the published Base64 to recover the exact CRLF policy bytes.
    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-post-example.html
    let encoded_policy = "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29u\
        ZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0\
        cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0K\
        ICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5h\
        bWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRD\
        b250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEy\
        NzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJz\
        dGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwi\
        OiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0K\
        ICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUi\
        OiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9";
    let policy = String::from_utf8(base64_decode(encoded_policy)?).unwrap();
    let credential = Credential {
        // Use the example ID from the signed policy's credential condition.
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        ..Default::default()
    };
    let fields = sign_s3_post_policy(
        &RustCryptoProvider::new(),
        &policy,
        &credential,
        "us-east-1",
        "2015-12-29T00:00:00Z".parse()?,
    )?
    .into_fields();

    assert_eq!(fields.len(), 5);
    assert_eq!(
        fields
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            ("Policy", encoded_policy),
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            (
                "X-Amz-Credential",
                "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request",
            ),
            ("X-Amz-Date", "20151229T000000Z"),
            (
                "X-Amz-Signature",
                "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e",
            ),
        ])
    );
    Ok(())
}

const REGION: &str = "us-east-1";
const SIGNING_TIME: &str = "2026-01-01T00:00:00Z";
const EXPIRATION: &str = "2026-01-01T00:00:30.001Z";
const SESSION_TOKEN: &str = "fixture+/session==";

fn fixture_credential() -> Credential {
    Credential {
        access_key_id: "fixture-access-key".to_string(),
        secret_access_key: "fixture-secret-access-key".to_string(),
        ..Default::default()
    }
}

#[test]
fn session_credential_must_outlast_the_policy() -> reqsign_core::Result<()> {
    let provider = RustCryptoProvider::new();
    let signing_time = SIGNING_TIME.parse()?;
    let expiration = EXPIRATION.parse()?;
    let policy = format!(
        r#"{{
  "conditions": [
    {{"bucket": "example-bucket"}},
    ["starts-with", "$key", "uploads/"],
    {{"x-amz-credential": "fixture-access-key/20260101/{REGION}/s3/aws4_request"}},
    {{"x-amz-algorithm": "AWS4-HMAC-SHA256"}},
    {{"x-amz-date": "20260101T000000Z"}},
    {{"x-amz-security-token": "{SESSION_TOKEN}"}},
    {{"x-amz-meta-filename": "résumé.txt"}}
  ],
  "expiration": "{EXPIRATION}"
}}"#
    );
    let mut credential = Credential {
        session_token: Some(SESSION_TOKEN.to_string()),
        expires_in: Some(expiration + Duration::from_nanos(1)),
        ..fixture_credential()
    };

    let fields = sign_s3_post_policy(&provider, &policy, &credential, REGION, signing_time)?;
    let debug = format!("{fields:?}");
    let fields = fields.into_fields();
    assert_eq!(fields.len(), 6);
    let encoded_policy = fields.iter().find(|(name, _)| *name == "Policy").unwrap();
    assert_eq!(base64_decode(&encoded_policy.1)?, policy.as_bytes());
    assert!(
        fields
            .iter()
            .any(|(name, value)| { *name == "X-Amz-Security-Token" && value == SESSION_TOKEN })
    );
    for (name, value) in fields {
        assert!(!debug.contains(&value), "Debug exposed {name}");
    }

    for credential_expiration in [expiration - Duration::from_nanos(1), expiration] {
        credential.expires_in = Some(credential_expiration);
        let error =
            sign_s3_post_policy(&provider, &policy, &credential, REGION, signing_time).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert!(
            error
                .to_string()
                .contains("valid through the S3 POST policy expiration")
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_credentials() -> reqsign_core::Result<()> {
    let provider = RustCryptoProvider::new();
    let signing_time = SIGNING_TIME.parse()?;
    let policy = format!(r#"{{"expiration":"{EXPIRATION}","conditions":[]}}"#);
    let cases = [
        (
            Credential {
                access_key_id: String::new(),
                ..fixture_credential()
            },
            "missing signing keys",
        ),
        (
            Credential {
                secret_access_key: String::new(),
                ..fixture_credential()
            },
            "missing signing keys",
        ),
        (
            Credential {
                expires_in: Some(signing_time),
                ..fixture_credential()
            },
            "expired at the signing time",
        ),
        (
            Credential {
                session_token: Some(SESSION_TOKEN.to_string()),
                ..fixture_credential()
            },
            "session credential expiration is required",
        ),
        (
            Credential {
                session_token: Some(String::new()),
                expires_in: Some("2026-01-01T00:01:00Z".parse()?),
                ..fixture_credential()
            },
            "session token is empty",
        ),
    ];

    for (credential, expected_error) in cases {
        let error =
            sign_s3_post_policy(&provider, &policy, &credential, REGION, signing_time).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert!(error.to_string().contains(expected_error), "{error}");
    }
    Ok(())
}

#[test]
fn rejects_invalid_policy_expirations() -> reqsign_core::Result<()> {
    let provider = RustCryptoProvider::new();
    let signing_time = SIGNING_TIME.parse()?;
    let credential = fixture_credential();
    let cases = [
        (r#"{"expiration": "2026-01-01T00:01:00Z""#, "JSON object"),
        (r#"["2026-01-01T00:01:00Z"]"#, "JSON object"),
        (
            r#"{"conditions":[{"expiration":"2026-01-01T00:01:00Z"}]}"#,
            "JSON object",
        ),
        (r#"{"expiration": 123}"#, "JSON object"),
        (
            r#"{"expiration":"2026-01-01T00:01:00Z","expiration":"2026-01-01T00:02:00Z"}"#,
            "JSON object",
        ),
        (
            r#"{"expiration":"private-policy-data"}"#,
            "ISO 8601 timestamp",
        ),
        (
            r#"{"expiration":"2025-12-31T23:59:59.999Z"}"#,
            "after the signing time",
        ),
        (
            r#"{"expiration":"2026-01-01T00:00:00Z"}"#,
            "after the signing time",
        ),
    ];

    for (policy, expected_error) in cases {
        let error =
            sign_s3_post_policy(&provider, policy, &credential, REGION, signing_time).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert!(error.to_string().contains(expected_error), "{error}");
        assert!(!format!("{error:?}\n{error}").contains("private-policy-data"));
    }
    Ok(())
}

#[test]
fn rejects_invalid_signing_region() -> reqsign_core::Result<()> {
    let policy = format!(r#"{{"expiration":"{EXPIRATION}","conditions":[]}}"#);
    let provider = RustCryptoProvider::new();
    let signing_time = SIGNING_TIME.parse()?;
    let credential = fixture_credential();
    for region in ["", "us-east-1/s3"] {
        let error =
            sign_s3_post_policy(&provider, &policy, &credential, region, signing_time).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert!(error.to_string().contains("invalid S3 POST signing region"));
    }
    Ok(())
}
