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

use reqsign_core::SigningCredential;
use reqsign_core::time::Timestamp;
use std::fmt::{Debug, Formatter};

/// Credential for Upyun.
///
/// The operator name and password are used to compute the `Authorization` header.
/// Once built, the credential is read-only: [`Credential::operator`] and
/// [`Credential::bucket`] expose the routing metadata, while the password stays
/// private to the signer. `Debug` output never contains either value.
#[derive(Clone)]
pub struct Credential {
    operator: String,
    password: String,
    bucket: Option<String>,
}

impl Credential {
    /// Create a new unscoped credential from a operator name and password.
    pub fn new(operator: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            operator: operator.into(),
            password: password.into(),
            bucket: None,
        }
    }

    /// Scope this credential to a bucket.
    ///
    /// The signer rejects a request unless the first segment of the request's
    /// wire path exactly equals this bucket. Discovered Upyun CLI credentials
    /// are scoped to their session's bucket; explicit static credentials are
    /// unscoped unless the caller chooses a scope.
    pub fn with_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// Return the Upyun operator name.
    pub fn operator(&self) -> &str {
        &self.operator
    }

    /// Return the bucket this credential is scoped to, if any.
    ///
    /// When set, the first segment of the request's wire path must exactly
    /// equal this bucket. Explicit credentials created by [`Credential::new`]
    /// are unscoped and can sign any bucket.
    pub fn bucket(&self) -> Option<&str> {
        self.bucket.as_deref()
    }

    /// Return the operator password for signing.
    ///
    /// Kept crate-private so signing remains the only reader and the value does
    /// not become part of the public API.
    pub(crate) fn password(&self) -> &str {
        &self.password
    }

    fn is_usable(&self) -> bool {
        !self.operator.is_empty()
            && !self.password.is_empty()
            && self
                .bucket
                .as_deref()
                .is_none_or(|bucket| !bucket.is_empty())
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_usable()
    }

    fn is_valid_at(&self, _timestamp: Timestamp) -> bool {
        self.is_usable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_credentials_and_is_safe_for_unicode() {
        for (operator, password) in [
            ("fabricated-operator", "fabricated-password"),
            ("密码操作员", "密码密码密码"),
            ("🚀fabricated-operator", "🚀fabricated-password-value"),
        ] {
            let credential = Credential::new(operator, password);

            let debug = format!("{credential:?}");
            assert!(!debug.contains(operator));
            assert!(!debug.contains(password));
            assert!(debug.contains("Credential"));
        }
    }

    #[test]
    fn requires_both_credential_fields() {
        assert!(!Credential::new("", "").is_valid());

        assert!(!Credential::new("operator", "").is_valid());
        assert!(!Credential::new("", "password").is_valid());
        assert!(Credential::new("密码操作员", "密码密码密码").is_valid());
    }

    #[test]
    fn accessors_return_the_routing_metadata() {
        let credential = Credential::new("fabricated-operator", "fabricated-password")
            .with_bucket("fabricated-bucket");

        assert_eq!("fabricated-operator", credential.operator());
        assert_eq!(Some("fabricated-bucket"), credential.bucket());
    }

    #[test]
    fn rejects_an_empty_bucket_scope() {
        let credential = Credential::new("operator", "password").with_bucket("");

        assert!(!credential.is_valid());
        assert!(!credential.is_valid_at(Timestamp::now()));
    }
}
