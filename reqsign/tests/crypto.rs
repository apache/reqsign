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

//! The facade binds RustCrypto only when the global slot is empty.

#[cfg(feature = "default-context")]
#[test]
fn default_context_binds_rustcrypto_without_installing_global() {
    use reqsign::crypto::{CryptoProvider, get_default, install_default};
    use reqsign::hash;
    use reqsign::{Context, Result};

    #[derive(Debug)]
    struct TestProvider(u8);

    impl CryptoProvider for TestProvider {
        fn sha1(&self, _: &[u8]) -> Result<[u8; 20]> {
            Ok([self.0; 20])
        }

        fn sha256(&self, _: &[u8]) -> Result<[u8; 32]> {
            Ok([self.0; 32])
        }

        fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<[u8; 20]> {
            Ok([self.0; 20])
        }

        fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> Result<[u8; 32]> {
            Ok([self.0; 32])
        }
    }

    fn assert_sha256_abc(ctx: &Context) {
        assert_eq!(
            reqsign::hash::base64_encode(
                &hash::sha256(
                    ctx.crypto_provider().expect("provider must resolve"),
                    b"abc"
                )
                .expect("hashing must succeed")
            ),
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
    }

    assert!(get_default().is_none());
    let ctx = reqsign::default_context();
    assert!(get_default().is_none(), "default_context must not install");
    assert_sha256_abc(&ctx);

    install_default(TestProvider(9)).expect("global installation must succeed");
    assert_sha256_abc(&ctx);

    let after_global = reqsign::default_context();
    assert_eq!(
        hash::sha256(
            after_global.crypto_provider().expect("global must resolve"),
            b"x"
        )
        .expect("global hashing must succeed"),
        [9; 32],
        "a default_context created after installation must use the global provider"
    );

    let explicit = Context::new().with_crypto(TestProvider(2));
    assert_eq!(
        hash::sha256(
            explicit.crypto_provider().expect("explicit must resolve"),
            b"x"
        )
        .expect("explicit hashing must succeed"),
        [2; 32],
        "an explicit binding must keep priority over the global provider"
    );

    let first = Context::new().with_crypto(TestProvider(4));
    let second = Context::new().with_crypto(TestProvider(5));
    assert_eq!(
        hash::sha256(
            first.crypto_provider().expect("first context must resolve"),
            b"x"
        )
        .expect("first context hashing must succeed"),
        [4; 32]
    );
    assert_eq!(
        hash::sha256(
            second
                .crypto_provider()
                .expect("second context must resolve"),
            b"x"
        )
        .expect("second context hashing must succeed"),
        [5; 32]
    );
}
