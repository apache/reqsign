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

#![cfg(feature = "upyun")]

use reqsign::crypto::CryptoProvider;
#[cfg(feature = "default-context")]
use reqsign::default_context;
use reqsign::upyun::{StaticCredentialProvider, default_signer};
use reqsign::{Context, ErrorKind, Result};
#[cfg(feature = "default-context")]
use reqsign::{FileRead, StaticEnv};
#[cfg(feature = "default-context")]
use std::collections::HashMap;

#[derive(Debug)]
struct UnsupportedProvider;

impl CryptoProvider for UnsupportedProvider {
    fn sha1(&self, _: &[u8]) -> Result<[u8; 20]> {
        Err(reqsign::Error::config_invalid("unsupported test provider"))
    }

    fn sha256(&self, _: &[u8]) -> Result<[u8; 32]> {
        Err(reqsign::Error::config_invalid("unsupported test provider"))
    }

    fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<[u8; 20]> {
        Err(reqsign::Error::config_invalid("unsupported test provider"))
    }

    fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> Result<[u8; 32]> {
        Err(reqsign::Error::config_invalid("unsupported test provider"))
    }
}

#[cfg(feature = "default-context")]
#[derive(Debug)]
struct TestFileRead {
    files: HashMap<String, Vec<u8>>,
}

#[cfg(feature = "default-context")]
impl FileRead for TestFileRead {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| reqsign::Error::config_invalid(format!("unexpected file path: {path}")))
    }
}

#[cfg(feature = "default-context")]
#[tokio::test]
async fn default_signer_selects_the_upx_session_for_the_bucket() {
    let path = "/home/test/.upx.cfg";
    let ctx = default_context()
        .with_file_read(TestFileRead {
            files: HashMap::from([(
                path.to_string(),
                include_bytes!("../../services/upyun/testdata/upx.cfg").to_vec(),
            )]),
        })
        .with_env(StaticEnv {
            home_dir: Some("/home/test".into()),
            envs: HashMap::new(),
        });
    let signer = default_signer(ctx, "example-bucket");
    let mut parts = http::Request::put("https://v0.api.upyun.com/example-bucket/object.txt")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("the bucket session must sign");
    assert!(
        parts.headers[http::header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be text")
            .starts_with("UPYUN operator123:")
    );
}

#[cfg(feature = "default-context")]
#[tokio::test]
async fn default_signer_signs_with_static_credentials() {
    let signer = default_signer(default_context(), "bucket")
        .with_credential_provider(StaticCredentialProvider::new("operator", "password"));
    let mut parts = http::Request::put("https://v0.api.upyun.com/bucket/object.txt")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("default signer must use the context crypto provider");
    assert!(
        parts.headers[http::header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be text")
            .starts_with("UPYUN ")
    );
    assert!(parts.headers.contains_key(http::header::DATE));
}

#[tokio::test]
async fn default_signer_uses_an_explicitly_selected_context_provider() {
    let context = Context::new().with_crypto(UnsupportedProvider);
    let signer = default_signer(context, "bucket")
        .with_credential_provider(StaticCredentialProvider::new("operator", "password"));
    let mut parts = http::Request::put("https://v0.api.upyun.com/bucket/object.txt")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    let err = signer
        .sign(&mut parts, None)
        .await
        .expect_err("the explicitly selected provider must be used");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
}
