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

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Re-export core types
pub use reqsign_core::*;

// The default cryptographic backend. Applications may install it process-wide;
// `default_context` binds it conditionally when no global provider is installed.
#[cfg(feature = "default-crypto")]
pub use reqsign_crypto_rustcrypto::RustCryptoProvider;

// Context utilities
#[cfg(feature = "default-context")]
mod context;
#[cfg(feature = "default-context")]
pub use context::default_context;

// Service modules with convenience APIs
#[cfg(feature = "aliyun")]
pub mod aliyun;

#[cfg(any(feature = "aws-v4", feature = "aws-v4a"))]
pub mod aws;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "huaweicloud")]
pub mod huaweicloud;

#[cfg(feature = "http-message-signatures")]
pub mod http_message_signatures;

#[cfg(feature = "openstack")]
pub mod openstack;

#[cfg(feature = "oracle")]
pub mod oracle;

#[cfg(feature = "tencent")]
pub mod tencent;

#[cfg(feature = "volcengine")]
pub mod volcengine;

#[cfg(all(test, feature = "aws-v4"))]
mod tests {
    use crate::crypto::CryptoProvider;
    use crate::{Context, Result, StaticEnv, aws};
    use std::collections::HashMap;

    #[derive(Debug)]
    struct TestCryptoProvider;

    impl CryptoProvider for TestCryptoProvider {
        fn sha1(&self, _: &[u8]) -> Result<[u8; 20]> {
            Ok([1; 20])
        }

        fn sha256(&self, _: &[u8]) -> Result<[u8; 32]> {
            Ok([2; 32])
        }

        fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<[u8; 20]> {
            Ok([3; 20])
        }

        fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> Result<[u8; 32]> {
            Ok([4; 32])
        }
    }

    #[tokio::test]
    async fn default_signer_works_without_default_context_feature() {
        let ctx = Context::new()
            .with_crypto(TestCryptoProvider)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([
                    ("AWS_ACCESS_KEY_ID".to_string(), "AKIDEXAMPLE".to_string()),
                    (
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                        "example-secret-key".to_string(),
                    ),
                ]),
            });
        let signer = aws::default_signer(ctx, "s3", "us-east-1");

        let mut req = http::Request::get("https://s3.amazonaws.com/my-bucket/my-object")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        signer.sign(&mut req, None).await.unwrap();
        assert!(req.headers.contains_key("authorization"));
    }
}
