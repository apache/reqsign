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

#![allow(dead_code)]

use reqsign_core::Result;
use reqsign_core::crypto::CryptoProvider;

/// Minimal provider used to test installation and hash delegation without
/// linking a second copy of `reqsign-core` through a provider crate.
#[derive(Debug)]
pub struct TestProvider {
    pub name: &'static str,
    expected_key: Option<&'static [u8]>,
    expected_input: Option<&'static [u8]>,
}

impl TestProvider {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            expected_key: None,
            expected_input: None,
        }
    }

    /// Create a provider that checks the key and input passed to hash helpers.
    pub fn expecting(name: &'static str, key: &'static [u8], input: &'static [u8]) -> Self {
        Self {
            name,
            expected_key: Some(key),
            expected_input: Some(input),
        }
    }

    fn check_input(&self, input: &[u8]) {
        if let Some(expected) = self.expected_input {
            assert_eq!(input, expected, "unexpected input passed to provider");
        }
    }

    fn check_key(&self, key: &[u8]) {
        if let Some(expected) = self.expected_key {
            assert_eq!(key, expected, "unexpected key passed to provider");
        }
    }
}

impl CryptoProvider for TestProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        self.check_input(input);
        Ok([1; 20])
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        self.check_input(input);
        Ok([2; 32])
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        self.check_key(key);
        self.check_input(input);
        Ok([3; 20])
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        self.check_key(key);
        self.check_input(input);
        Ok([4; 32])
    }
}

/// Provider whose digests identify the provider without using real crypto.
#[derive(Debug)]
pub struct ByteProvider(pub u8);

impl CryptoProvider for ByteProvider {
    fn sha1(&self, _input: &[u8]) -> Result<[u8; 20]> {
        Ok([self.0; 20])
    }

    fn sha256(&self, _input: &[u8]) -> Result<[u8; 32]> {
        Ok([self.0; 32])
    }

    fn hmac_sha1(&self, _key: &[u8], _input: &[u8]) -> Result<[u8; 20]> {
        Ok([self.0; 20])
    }

    fn hmac_sha256(&self, _key: &[u8], _input: &[u8]) -> Result<[u8; 32]> {
        Ok([self.0; 32])
    }
}
