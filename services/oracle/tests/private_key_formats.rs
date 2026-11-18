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
use http::header::{AUTHORIZATION, DATE};
use reqsign_core::{Context, ErrorKind, FileRead, Result, SignRequest, Signer};
use reqsign_oracle::{Credential, RequestSigner, StaticCredentialProvider};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{RsaPrivateKey, RsaPublicKey};

const KEY_PATH: &str = "test-key.pem";
const REQUEST_URI: &str = "https://iaas.example.com:8443/20160918/instances?name=a%2Fb&name=c+%20d";

fn private_key() -> &'static RsaPrivateKey {
    // Generate one ephemeral key for all formats; never read a developer's OCI files.
    static KEY: LazyLock<RsaPrivateKey> = LazyLock::new(|| {
        RsaPrivateKey::new(&mut OsRng, 2048).expect("test RSA key generation must succeed")
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

async fn verify_signed_request(pem: &str) -> anyhow::Result<()> {
    // Include a port, repeated query keys and escaped bytes in the signed target.
    let mut parts = http::Request::get(REQUEST_URI)
        .header("x-original", "preserved")
        .body(())?
        .into_parts()
        .0;
    let original_uri = parts.uri.clone();

    let cred = credential();
    let provider =
        StaticCredentialProvider::new(&cred.user, &cred.tenancy, &cred.key_file, &cred.fingerprint);
    Signer::new(context(pem), provider, RequestSigner::new())
        .sign(&mut parts, None)
        .await?;

    assert_eq!(parts.uri, original_uri);
    assert_eq!(parts.headers["x-original"], "preserved");
    let authorization = parts.headers[AUTHORIZATION].to_str()?;
    assert!(authorization.starts_with("Signature version=\"1\","));
    assert!(authorization.contains("headers=\"date (request-target) host\""));
    assert!(authorization.contains("keyId=\"test-tenancy/test-user/test-fingerprint\""));
    assert!(authorization.contains("algorithm=\"rsa-sha256\""));

    let encoded_signature = authorization
        .split("signature=\"")
        .nth(1)
        .and_then(|value| value.strip_suffix('"'))
        .expect("authorization must contain a signature");
    let signature_bytes = STANDARD.decode(encoded_signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())?;

    // Reconstruct the wire signing input independently of the signer's helpers.
    let signing_input = format!(
        "date: {}\n(request-target): get {}\nhost: {}",
        parts.headers[DATE].to_str()?,
        original_uri.path_and_query().expect("request target"),
        original_uri.authority().expect("request authority"),
    );
    let verifier = VerifyingKey::<Sha256>::new(RsaPublicKey::from(private_key()));
    verifier.verify(signing_input.as_bytes(), &signature)?;
    assert!(verifier.verify(b"different request", &signature).is_err());
    Ok(())
}

#[tokio::test]
async fn pkcs1_private_keys_produce_valid_signatures() -> anyhow::Result<()> {
    for line_ending in [LineEnding::LF, LineEnding::CRLF] {
        let pem = private_key().to_pkcs1_pem(line_ending)?;
        verify_signed_request(&pem).await?;
    }
    Ok(())
}

#[tokio::test]
async fn pkcs8_private_keys_produce_valid_signatures() -> anyhow::Result<()> {
    for line_ending in [LineEnding::LF, LineEnding::CRLF] {
        let pem = private_key().to_pkcs8_pem(line_ending)?;
        verify_signed_request(&pem).await?;
    }
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
    let pem = RsaPublicKey::from(private_key()).to_public_key_pem(LineEnding::LF)?;
    assert_rejected_without_mutation(&pem).await
}

#[tokio::test]
async fn encrypted_private_keys_are_rejected_without_mutating_request() -> anyhow::Result<()> {
    let pem =
        private_key().to_pkcs8_encrypted_pem(&mut OsRng, "test-passphrase", LineEnding::LF)?;
    assert_rejected_without_mutation(&pem).await
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
