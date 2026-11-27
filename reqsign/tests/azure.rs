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

#![cfg(all(feature = "azure", feature = "default-crypto"))]

use std::collections::HashMap;

use http::{Request, header};
use reqsign::azure::default_signer;
use reqsign::hash::{base64_encode, base64_hmac_sha256};
use reqsign::{Context, RustCryptoProvider, StaticEnv};

#[tokio::test]
async fn default_signer_uses_x_ms_date_and_preserves_date() -> anyhow::Result<()> {
    let key = b"reqsign-azure-shared-key-fixture";
    let context = Context::new()
        .with_crypto(RustCryptoProvider::new())
        .with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([
                ("AZURE_STORAGE_ACCOUNT_NAME".into(), "azsignfixture".into()),
                ("AZURE_STORAGE_ACCOUNT_KEY".into(), base64_encode(key)),
            ]),
        });
    let signer = default_signer(context.clone());
    let uri = "https://azsignfixture.example/container/blob";
    let mut parts = Request::get(uri)
        .header(header::CONTENT_LENGTH, "0")
        .header(header::DATE, "Mon, 28 Feb 2022 08:12:34 GMT")
        .header(header::RANGE, "bytes=0-31")
        .header("x-ms-version", "2021-12-02")
        .body(())?
        .into_parts()
        .0;
    let original_headers = parts.headers.clone();

    signer.sign(&mut parts, None).await?;

    let date = parts.headers.remove("x-ms-date").unwrap();
    let expected = [
        "GET",
        "", // Content-Encoding
        "", // Content-Language
        "", // Content-Length is zero
        "", // Content-MD5
        "", // Content-Type
        "", // Date is covered by x-ms-date below
        "", // If-Modified-Since
        "", // If-Match
        "", // If-None-Match
        "", // If-Unmodified-Since
        "bytes=0-31",
        &format!("x-ms-date:{}", date.to_str()?),
        "x-ms-version:2021-12-02",
        "/azsignfixture/container/blob",
    ]
    .join("\n");
    let signature = base64_hmac_sha256(context.crypto_provider()?, key, expected.as_bytes())?;
    let authorization = parts.headers.remove(header::AUTHORIZATION).unwrap();
    assert_eq!(
        authorization,
        format!("SharedKey azsignfixture:{signature}")
    );
    assert_eq!(parts.headers, original_headers);
    assert_eq!(parts.uri.to_string(), uri);
    Ok(())
}
