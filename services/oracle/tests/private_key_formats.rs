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

use std::sync::LazyLock;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, DATE};
use http::{Method, request::Parts};
use reqsign_core::{Context, ErrorKind, FileRead, Result, SignRequest, Signer};
use reqsign_oracle::{Credential, RequestSigner, StaticCredentialProvider};
use rsa::PrivateKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;

const KEY_PATH: &str = "test-key.pem";
const REQUEST_URI: &str = "https://iaas.example.com:8443/20160918/instances?name=a%2Fb&name=c+%20d";
const RSA_PKCS1_PEM: &str = include_str!("fixtures/rsa-2048-pkcs1.pem");
const RSA_PKCS8_PEM: &str = include_str!("fixtures/rsa-2048-pkcs8.pem");
const RSA_PUBLIC_PEM: &str = include_str!("fixtures/rsa-2048-public.pem");
const RSA_ENCRYPTED_PEM: &str = include_str!("fixtures/rsa-2048-pkcs8-encrypted.pem");

fn private_key() -> &'static PrivateKey {
    // All fixtures are synthetic and shared by the format tests.
    static KEY: LazyLock<PrivateKey> = LazyLock::new(|| {
        PrivateKey::from_pkcs8_pem(RSA_PKCS8_PEM).expect("test RSA key fixture must parse")
    });
    &KEY
}

struct KeyFile(Vec<u8>);

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile").finish_non_exhaustive()
    }
}

impl FileRead for KeyFile {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        assert_eq!(path, KEY_PATH);
        Ok(self.0.clone())
    }
}

fn context(pem: &str) -> Context {
    Context::new().with_file_read(KeyFile(pem.as_bytes().to_vec()))
}

fn credential() -> Credential {
    Credential {
        tenancy: "test-tenancy".into(),
        user: "test-user".into(),
        fingerprint: "test-fingerprint".into(),
        key_file: KEY_PATH.into(),
        expires_in: None,
    }
}

async fn sign(pem: &str, parts: &mut Parts) -> Result<()> {
    let cred = credential();
    let provider =
        StaticCredentialProvider::new(&cred.user, &cred.tenancy, &cred.key_file, &cred.fingerprint);
    Signer::new(context(pem), provider, RequestSigner::new())
        .sign(parts, None)
        .await
}

fn authorization_param<'a>(authorization: &'a str, name: &str) -> anyhow::Result<&'a str> {
    let prefix = format!("{name}=\"");
    let start = authorization
        .find(&prefix)
        .ok_or_else(|| anyhow::anyhow!("authorization is missing {name}"))?
        + prefix.len();
    let rest = &authorization[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| anyhow::anyhow!("authorization {name} is not quoted"))?;
    Ok(&rest[..end])
}

fn signed_headers(parts: &Parts) -> anyhow::Result<&str> {
    let authorization = parts.headers[AUTHORIZATION].to_str()?;
    authorization_param(authorization, "headers")
}

fn verify_authorization(parts: &Parts) -> anyhow::Result<()> {
    let authorization = parts.headers[AUTHORIZATION].to_str()?;
    let mut signing_input = String::new();

    // Reconstruct the wire signing input from the fields named in the
    // Authorization header, independently of the signer's helpers.
    for (index, name) in signed_headers(parts)?.split(' ').enumerate() {
        if index > 0 {
            signing_input.push('\n');
        }
        match name {
            "(request-target)" => {
                signing_input.push_str("(request-target): ");
                signing_input.push_str(&parts.method.as_str().to_lowercase());
                signing_input.push(' ');
                signing_input.push_str(
                    parts
                        .uri
                        .path_and_query()
                        .ok_or_else(|| anyhow::anyhow!("request URI is missing a target"))?
                        .as_str(),
                );
            }
            "host" => {
                signing_input.push_str("host: ");
                signing_input.push_str(
                    parts
                        .uri
                        .authority()
                        .ok_or_else(|| anyhow::anyhow!("request URI is missing an authority"))?
                        .as_str(),
                );
            }
            name => {
                let value = parts
                    .headers
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("signed header {name} is missing"))?
                    .to_str()?;
                signing_input.push_str(name);
                signing_input.push_str(": ");
                signing_input.push_str(value);
            }
        }
    }

    let signature_bytes = STANDARD.decode(authorization_param(authorization, "signature")?)?;
    let signature = Signature::try_from(signature_bytes.as_slice())?;
    let verifier = VerifyingKey::<Sha256>::new(private_key().to_public_key());
    verifier.verify(signing_input.as_bytes(), &signature)?;
    assert!(verifier.verify(b"different request", &signature).is_err());
    Ok(())
}

async fn verify_signed_request(pem: &str) -> anyhow::Result<()> {
    // Include a port, repeated query keys and escaped bytes in the signed target.
    let mut parts = http::Request::get(REQUEST_URI)
        .header("x-original", "preserved")
        .body(())?
        .into_parts()
        .0;
    let original_uri = parts.uri.clone();

    sign(pem, &mut parts).await?;

    assert_eq!(parts.uri, original_uri);
    assert_eq!(parts.headers["x-original"], "preserved");
    let authorization = parts.headers[AUTHORIZATION].to_str()?;
    assert!(authorization.starts_with("Signature version=\"1\","));
    assert!(authorization.contains("keyId=\"test-tenancy/test-user/test-fingerprint\""));
    assert!(authorization.contains("algorithm=\"rsa-sha256\""));
    assert_eq!(signed_headers(&parts)?, "date (request-target) host");

    verify_authorization(&parts)?;
    Ok(())
}

#[tokio::test]
async fn pkcs1_private_keys_produce_valid_signatures() -> anyhow::Result<()> {
    for pem in [
        RSA_PKCS1_PEM.to_string(),
        RSA_PKCS1_PEM.replace('\n', "\r\n"),
    ] {
        verify_signed_request(&pem).await?;
    }
    Ok(())
}

#[tokio::test]
async fn pkcs8_private_keys_produce_valid_signatures() -> anyhow::Result<()> {
    for pem in [
        RSA_PKCS8_PEM.to_string(),
        RSA_PKCS8_PEM.replace('\n', "\r\n"),
    ] {
        verify_signed_request(&pem).await?;
    }
    Ok(())
}

#[tokio::test]
async fn post_signs_caller_supplied_body_metadata() -> anyhow::Result<()> {
    let pem = RSA_PKCS8_PEM;
    let body_sha256 = "V9Z20UJTvkvpJ50flBzKE32+6m2zJjweHpDMX/U4Uy0=";
    let mut parts = http::Request::builder()
        .method(Method::POST)
        .uri("https://iaas.example.com/20160918/volumeAttachments?b=2&a=1")
        .header(CONTENT_LENGTH, "316")
        .header(CONTENT_TYPE, "application/json")
        .header("x-content-sha256", body_sha256)
        .header("x-original", "preserved")
        .body(())?
        .into_parts()
        .0;
    let original_uri = parts.uri.clone();

    sign(pem, &mut parts).await?;

    assert_eq!(parts.uri, original_uri);
    assert_eq!(parts.headers["x-original"], "preserved");
    assert_eq!(parts.headers[CONTENT_LENGTH], "316");
    assert_eq!(parts.headers[CONTENT_TYPE], "application/json");
    assert_eq!(parts.headers["x-content-sha256"], body_sha256);
    assert_eq!(
        signed_headers(&parts)?,
        "date (request-target) host content-length content-type x-content-sha256"
    );
    verify_authorization(&parts)?;
    Ok(())
}

#[tokio::test]
async fn object_storage_put_without_body_metadata_keeps_generic_headers() -> anyhow::Result<()> {
    let pem = RSA_PKCS8_PEM;
    let mut parts = http::Request::put(
        "https://namespace.compat.objectstorage.us-phoenix-1.oraclecloud.com/b/bucket/o/object",
    )
    .header("x-original", "preserved")
    .body(())?
    .into_parts()
    .0;

    sign(pem, &mut parts).await?;

    assert_eq!(parts.headers["x-original"], "preserved");
    assert_eq!(signed_headers(&parts)?, "date (request-target) host");
    assert!(!parts.headers.contains_key(CONTENT_LENGTH));
    assert!(!parts.headers.contains_key(CONTENT_TYPE));
    assert!(!parts.headers.contains_key("x-content-sha256"));
    verify_authorization(&parts)?;
    Ok(())
}

#[tokio::test]
async fn object_storage_upload_part_signs_supplied_content_length_only() -> anyhow::Result<()> {
    let pem = RSA_PKCS8_PEM;
    let mut parts = http::Request::builder()
        .method(Method::PUT)
        .uri("https://namespace.compat.objectstorage.us-phoenix-1.oraclecloud.com/b/bucket/o/object?uploadId=upload&partNumber=2")
        .header(CONTENT_LENGTH, "10485760")
        .body(())?
        .into_parts()
        .0;

    sign(pem, &mut parts).await?;

    assert_eq!(parts.headers[CONTENT_LENGTH], "10485760");
    assert_eq!(
        signed_headers(&parts)?,
        "date (request-target) host content-length"
    );
    assert!(!parts.headers.contains_key(CONTENT_TYPE));
    assert!(!parts.headers.contains_key("x-content-sha256"));
    verify_authorization(&parts)?;
    Ok(())
}

#[tokio::test]
async fn duplicate_signed_body_header_is_rejected_without_mutation() -> anyhow::Result<()> {
    let pem = RSA_PKCS8_PEM;
    let mut parts = http::Request::builder()
        .method(Method::POST)
        .uri("https://iaas.example.com/20160918/volumeAttachments")
        .header(CONTENT_LENGTH, "1")
        .header(CONTENT_LENGTH, "2")
        .header(CONTENT_TYPE, "application/json")
        .header(
            "x-content-sha256",
            "V9Z20UJTvkvpJ50flBzKE32+6m2zJjweHpDMX/U4Uy0=",
        )
        .body(())?
        .into_parts()
        .0;
    let original = parts.clone();

    let error = sign(pem, &mut parts)
        .await
        .expect_err("duplicate signed body headers must be rejected");

    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.version, original.version);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

async fn assert_rejected_without_mutation(pem: &str) -> anyhow::Result<()> {
    let mut parts = http::Request::get("https://iaas.example.com/resource?key=%2F")
        .header("x-original", "preserved")
        .header(DATE, "Tue, 01 Jan 2030 00:00:00 GMT")
        .header(AUTHORIZATION, "original-authorization")
        .body(())?
        .into_parts()
        .0;
    let original = parts.clone();
    let error = RequestSigner::new()
        .sign_request(&context(pem), &mut parts, Some(&credential()), None)
        .await
        .expect_err("invalid private key must be rejected");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.version, original.version);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn public_keys_are_rejected_without_mutating_request() -> anyhow::Result<()> {
    assert_rejected_without_mutation(RSA_PUBLIC_PEM).await
}

#[tokio::test]
async fn encrypted_private_keys_are_rejected_without_mutating_request() -> anyhow::Result<()> {
    assert_rejected_without_mutation(RSA_ENCRYPTED_PEM).await
}

#[tokio::test]
async fn malformed_private_keys_are_rejected_without_mutating_request() -> anyhow::Result<()> {
    for pem in ["", "not a private key"] {
        assert_rejected_without_mutation(pem).await?;
    }
    for label in ["RSA PRIVATE KEY", "PRIVATE KEY"] {
        let pem = format!("-----BEGIN {label}-----\nbm90LWRlcg==\n-----END {label}-----\n");
        assert_rejected_without_mutation(&pem).await?;
    }
    Ok(())
}

#[tokio::test]
async fn absent_or_incomplete_credentials_do_not_read_private_key() -> anyhow::Result<()> {
    for credential in [None, Some(Credential::default())] {
        let mut parts = http::Request::get(REQUEST_URI)
            .header("x-original", "preserved")
            .body(())?
            .into_parts()
            .0;
        let original = parts.clone();
        // No file adapter is installed: credential checks must precede key loading.
        let result = RequestSigner::default()
            .sign_request(&Context::new(), &mut parts, credential.as_ref(), None)
            .await;
        if credential.is_some() {
            assert_eq!(
                result
                    .expect_err("incomplete credential must be rejected")
                    .kind(),
                ErrorKind::CredentialInvalid
            );
        } else {
            result?;
        }
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
    }
    Ok(())
}
