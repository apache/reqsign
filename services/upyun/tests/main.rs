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

#![cfg(not(target_arch = "wasm32"))]

use http::header::{AUTHORIZATION, DATE};
use http::{Request, header};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash::base64_encode;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ErrorKind, FileRead, Result, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_upyun::{RequestSigner, StaticCredentialProvider, UpxConfigCredentialProvider};
use std::collections::HashMap;

const CONTENT_MD5: &str = "content-md5";

fn signing_time() -> Timestamp {
    "2016-11-09T14:26:58Z".parse().expect("timestamp parses")
}

fn test_context() -> Context {
    Context::new().with_crypto(RustCryptoProvider::new())
}

#[derive(Debug)]
struct TestFileRead {
    files: HashMap<String, Vec<u8>>,
}

impl FileRead for TestFileRead {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| Error::config_invalid(format!("unexpected file path: {path}")))
    }
}

fn encode_upx_config(value: &serde_json::Value) -> Vec<u8> {
    let json = serde_json::to_vec(value).expect("test config must serialize");
    let encoded = base64_encode(&json);

    encoded
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' => byte.to_ascii_uppercase(),
            b'A'..=b'Z' => byte.to_ascii_lowercase(),
            b'0'..=b'9' => b'9' - (byte - b'0'),
            _ => byte,
        })
        .collect()
}

#[tokio::test]
async fn signer_signs_the_published_upyun_vector() -> anyhow::Result<()> {
    let signer = Signer::new(
        test_context(),
        StaticCredentialProvider::new("operator123", "password123"),
        RequestSigner::new().with_time(signing_time()),
    );
    let mut req = Request::put("https://v0.api.upyun.com/upyun-temp/demo.jpg")
        .header(CONTENT_MD5, "7ac66c0f148de9519b8bd264312c4d64")
        .body(())?
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;

    assert_eq!(req.headers[DATE], "Wed, 09 Nov 2016 14:26:58 GMT");
    assert_eq!(
        req.headers[AUTHORIZATION],
        "UPYUN operator123:YUaAZX+WNAcJdNGHS5SBlITME5A="
    );
    Ok(())
}

#[tokio::test]
async fn signer_loads_the_current_upx_session() -> anyhow::Result<()> {
    let path = "/test/.upx.cfg";
    let content = encode_upx_config(&serde_json::json!({
        "user_idx": 1,
        "users": [
            {"bucket": "first", "username": "first-operator", "password": "first-password"},
            {"bucket": "upyun-temp", "username": "operator123", "password": "password123"}
        ]
    }));
    let ctx = test_context().with_file_read(TestFileRead {
        files: HashMap::from([(path.to_string(), content)]),
    });
    let signer = Signer::new(
        ctx,
        UpxConfigCredentialProvider::new().with_config_file(path),
        RequestSigner::new().with_time(signing_time()),
    );
    let mut req = Request::put("https://v0.api.upyun.com/upyun-temp/demo.jpg")
        .header(CONTENT_MD5, "7ac66c0f148de9519b8bd264312c4d64")
        .body(())?
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;

    assert_eq!(
        req.headers[AUTHORIZATION],
        "UPYUN operator123:YUaAZX+WNAcJdNGHS5SBlITME5A="
    );
    Ok(())
}

#[tokio::test]
async fn static_credentials_are_not_bucket_scoped() -> anyhow::Result<()> {
    let signer = Signer::new(
        test_context(),
        StaticCredentialProvider::new("operator123", "password123"),
        RequestSigner::new().with_time(signing_time()),
    );

    for bucket in ["first", "second"] {
        let mut req = Request::get(format!("https://v0.api.upyun.com/{bucket}/object.txt"))
            .body(())?
            .into_parts()
            .0;
        signer.sign(&mut req, None).await?;
        assert!(
            req.headers[AUTHORIZATION]
                .to_str()?
                .starts_with("UPYUN operator123:")
        );
    }
    Ok(())
}

#[tokio::test]
async fn cached_upx_credential_is_scoped_to_its_bucket() -> anyhow::Result<()> {
    let path = "/test/.upx.cfg";
    let content = encode_upx_config(&serde_json::json!({
        "user_idx": 0,
        "users": [
            {"bucket": "first", "username": "first-operator", "password": "first-password"},
            {"bucket": "second", "username": "second-operator", "password": "second-password"}
        ]
    }));
    let ctx = test_context().with_file_read(TestFileRead {
        files: HashMap::from([(path.to_string(), content)]),
    });
    let signer = Signer::new(
        ctx,
        UpxConfigCredentialProvider::new()
            .with_config_file(path)
            .with_bucket("first"),
        RequestSigner::new().with_time(signing_time()),
    );

    let mut first = Request::get("https://v0.api.upyun.com/first/object.txt")
        .body(())?
        .into_parts()
        .0;
    signer.sign(&mut first, None).await?;
    assert!(
        first.headers[AUTHORIZATION]
            .to_str()?
            .starts_with("UPYUN first-operator:")
    );

    let mut second = Request::get("https://v0.api.upyun.com/second/object.txt")
        .body(())?
        .into_parts()
        .0;
    let original = second.clone();
    let err = signer
        .sign(&mut second, None)
        .await
        .expect_err("a cached credential must not cross its bucket scope");

    assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(second.uri, original.uri);
    assert_eq!(second.headers, original.headers);
    Ok(())
}

#[derive(Debug)]
struct MissingMd5Provider;

impl CryptoProvider for MissingMd5Provider {
    fn sha1(&self, _: &[u8]) -> Result<[u8; 20]> {
        Ok([0; 20])
    }

    fn sha256(&self, _: &[u8]) -> Result<[u8; 32]> {
        Ok([0; 32])
    }

    fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<[u8; 20]> {
        Ok([0; 20])
    }

    fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> Result<[u8; 32]> {
        Ok([0; 32])
    }
}

#[tokio::test]
async fn signer_fails_closed_without_md5_and_preserves_the_request() -> anyhow::Result<()> {
    let signer = Signer::new(
        Context::new().with_crypto(MissingMd5Provider),
        StaticCredentialProvider::new("operator123", "password123"),
        RequestSigner::new().with_time(signing_time()),
    );
    let mut req = Request::put("https://v0.api.upyun.com/upyun-temp/demo.jpg")
        .header(header::CONTENT_TYPE, "image/jpeg")
        .body(())?
        .into_parts()
        .0;
    let original = req.clone();

    let err = signer
        .sign(&mut req, None)
        .await
        .expect_err("a provider without MD5 must not sign");

    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(req.uri, original.uri);
    assert_eq!(req.headers, original.headers);
    Ok(())
}
