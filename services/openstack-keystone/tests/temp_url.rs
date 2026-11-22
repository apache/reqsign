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

use std::time::Duration;

use http::{Method, Uri};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqsign_core::Context;
use reqsign_core::hash::{base64_encode, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_openstack_keystone::TempUrlSigner;

#[test]
fn public_presign_produces_the_expected_sha256_query() {
    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let uri: Uri =
        "https://swift.example.com/v1/AUTH_account/container/a%20b?filename=My+Test+File.pdf&x=a%2Fb"
            .parse()
            .expect("test URI must parse");

    let before = Timestamp::now().as_second();
    let signed = TempUrlSigner::new("mykey")
        .presign(&ctx, &Method::GET, &uri, Duration::from_secs(3600))
        .expect("public presign must succeed");
    let after = Timestamp::now().as_second();

    let expires = signed
        .query()
        .expect("presigned URL has a query")
        .split('&')
        .find_map(|pair| pair.strip_prefix("temp_url_expires="))
        .expect("presigned URL has an expiration")
        .parse::<i64>()
        .expect("expiration is an integer");
    assert!(
        expires >= before + 3600 && expires <= after + 3600,
        "expiration {expires} must cover the requested window"
    );

    assert_eq!(signed.path(), "/v1/AUTH_account/container/a%20b");

    let message = format!("GET\n{expires}\n/v1/AUTH_account/container/a b");
    let signature = format!(
        "sha256:{}",
        base64_encode(
            &hmac_sha256(
                ctx.crypto_provider().expect("provider is bound"),
                b"mykey",
                message.as_bytes(),
            )
            .expect("HMAC must succeed")
        )
    );
    let encoded_signature = utf8_percent_encode(&signature, NON_ALPHANUMERIC);
    let expected = format!(
        "filename=My+Test+File.pdf&x=a%2Fb&temp_url_sig={encoded_signature}&temp_url_expires={expires}"
    );
    assert_eq!(signed.query(), Some(expected.as_str()));
}
