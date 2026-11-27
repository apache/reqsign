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

use std::fmt;

use reqsign_aws_core::signing::sigv4_signature;
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash::base64_encode;
use reqsign_core::time::Timestamp;
use reqsign_core::{Error, Result, SigningCredential};
use serde::Deserialize;

use crate::Credential;

/// Authentication fields for an S3 browser-based POST upload.
pub struct S3PostPolicyFields {
    fields: Vec<(&'static str, String)>,
}

impl S3PostPolicyFields {
    /// Return the form field names and values. The values authorize an upload
    /// and should be kept out of logs.
    pub fn into_fields(self) -> Vec<(&'static str, String)> {
        self.fields
    }
}

impl fmt::Debug for S3PostPolicyFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3PostPolicyFields").finish_non_exhaustive()
    }
}

/// Sign a UTF-8 [S3 POST policy] using AWS Signature Version 4.
///
/// `policy` is the original JSON document. The signature covers its Base64
/// encoding, including all whitespace in the original bytes. The caller builds
/// the policy conditions and serializes the multipart form. Match conditions
/// on signing fields to `AWS4-HMAC-SHA256`, the `<access key ID>/<YYYYMMDD>/<region>/s3/aws4_request`
/// scope, the UTC `YYYYMMDDTHHMMSSZ` signing time, and the session token when
/// present. Add the returned fields to the form along with the upload fields.
///
/// The top-level `expiration` must be an ISO 8601 timestamp after `signing_time`.
/// The credential must be valid at signing time and any credential expiration
/// must be strictly later than the policy expiration. Credentials carrying a
/// session token must have a known expiration in [`Credential::expires_in`].
///
/// Pass the [`CryptoProvider`] selected for this operation. Callers using a
/// [`Context`](reqsign_core::Context) can pass `context.crypto_provider()?`.
///
/// # Errors
///
/// Returns `RequestInvalid` for an invalid region or policy expiration, and
/// `CredentialInvalid` for missing or expired signing material or insufficient
/// credential lifetime. Propagates errors from the crypto provider.
///
/// [S3 POST policy]: https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-HTTPPOSTConstructPolicy.html
pub fn sign_s3_post_policy(
    provider: &dyn CryptoProvider,
    policy: &str,
    credential: &Credential,
    region: &str,
    signing_time: Timestamp,
) -> Result<S3PostPolicyFields> {
    if !credential.is_valid_at(signing_time) {
        return Err(Error::credential_invalid(
            "AWS credential is missing signing keys or is expired at the signing time",
        ));
    }
    if let Some(token) = &credential.session_token {
        if token.is_empty() {
            return Err(Error::credential_invalid("AWS session token is empty"));
        }
        if credential.expires_in.is_none() {
            return Err(Error::credential_invalid(
                "AWS session credential expiration is required to sign an S3 POST policy",
            ));
        }
    }
    if region.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Error::request_invalid("invalid S3 POST signing region"));
    }

    let expiration = policy_expiration(policy)?;
    if expiration <= signing_time {
        return Err(Error::request_invalid(
            "S3 POST policy expiration must be after the signing time",
        ));
    }
    if !credential.is_valid_at(expiration) {
        return Err(Error::credential_invalid(
            "AWS credential must remain valid through the S3 POST policy expiration",
        ));
    }

    let encoded_policy = base64_encode(policy.as_bytes());
    let signature = sigv4_signature(
        provider,
        &credential.secret_access_key,
        signing_time,
        region,
        "s3",
        &encoded_policy,
    )?;
    let credential_scope = format!(
        "{}/{}/{region}/s3/aws4_request",
        credential.access_key_id,
        signing_time.format_date()
    );
    let mut fields = vec![
        ("Policy", encoded_policy),
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential_scope),
        ("X-Amz-Date", signing_time.format_iso8601()),
        ("X-Amz-Signature", signature),
    ];
    if let Some(token) = &credential.session_token {
        fields.push(("X-Amz-Security-Token", token.clone()));
    }

    Ok(S3PostPolicyFields { fields })
}

fn policy_expiration(policy: &str) -> Result<Timestamp> {
    #[derive(Deserialize)]
    struct PolicyExpiration {
        expiration: String,
    }

    let invalid_policy = || {
        Error::request_invalid(
            "S3 POST policy must be a JSON object with one string expiration field",
        )
    };
    // Serde can also deserialize a struct from a JSON array.
    if !policy.trim_start().starts_with('{') {
        return Err(invalid_policy());
    }
    let policy: PolicyExpiration = serde_json::from_str(policy).map_err(|_| invalid_policy())?;
    policy.expiration.parse().map_err(|_| {
        Error::request_invalid("S3 POST policy expiration must be an ISO 8601 timestamp")
    })
}

#[cfg(test)]
mod tests;
