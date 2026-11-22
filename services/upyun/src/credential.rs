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
use reqsign_core::utils::Redact;
use std::fmt::{Debug, Formatter};

/// Credential for Upyun.
#[derive(Default, Clone)]
pub struct Credential {
    /// Upyun operator name.
    pub operator: String,
    /// Upyun operator password.
    pub password: String,
}

impl Credential {
    /// Create a new credential from a operator name and password.
    pub fn new(operator: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            operator: operator.into(),
            password: password.into(),
        }
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("operator", &Redact::from(&self.operator))
            .field("password", &Redact::from(&self.password))
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        !self.operator.is_empty() && !self.password.is_empty()
    }

    fn is_valid_at(&self, _timestamp: Timestamp) -> bool {
        !self.operator.is_empty() && !self.password.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_material() {
        let credential = Credential::new("operator-example", "password-example");

        let debug = format!("{credential:?}");
        assert!(!debug.contains("operator-example"));
        assert!(!debug.contains("password-example"));
    }

    #[test]
    fn requires_both_credential_fields() {
        assert!(!Credential::default().is_valid());

        let credential = Credential::new("operator", "");
        assert!(!credential.is_valid());

        let credential = Credential::new("", "password");
        assert!(!credential.is_valid());

        assert!(Credential::new("operator", "password").is_valid());
    }
}
