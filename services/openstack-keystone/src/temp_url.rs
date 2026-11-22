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

use std::fmt::{self, Debug};
use std::str::FromStr;
use std::time::Duration;

use http::uri::Builder;
use http::{Method, Uri};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqsign_core::hash::{base64_encode, hmac_sha1, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use reqsign_core::{Context, Error, Result};

const TEMP_URL_AUTH_PARAMETERS: &[&str] = &[
    "temp_url_sig",
    "temp_url_expires",
    "temp_url_prefix",
    "temp_url_ip_range",
];

/// Hash algorithm used to sign a Swift TempURL.
///
/// The selected algorithm must also be listed in the cluster's
/// `tempurl.allowed_digests` capability. SHA-256 is the default because it is
/// supported by current clusters and produces a compact URL. Use SHA-1 only for
/// older clusters and SHA-512 when the deployment requires it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TempUrlHashAlgorithm {
    /// HMAC-SHA-1.
    Sha1,
    /// HMAC-SHA-256.
    #[default]
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TempUrlHashAlgorithm {
    /// Return the wire name used in the `temp_url_sig` algorithm tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl FromStr for TempUrlHashAlgorithm {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(Error::config_invalid(format!(
                "unsupported TempURL hash algorithm '{value}'; expected sha1, sha256, or sha512"
            ))),
        }
    }
}

/// A Swift account or container TempURL key.
///
/// This is the shared secret configured through
/// `X-Account-Meta-Temp-URL-Key` or `X-Container-Meta-Temp-URL-Key`. It is not
/// a Keystone identity token and must never be populated from `X-Auth-Token`.
#[derive(Clone)]
pub struct TempUrlKey {
    secret: String,
}

impl TempUrlKey {
    /// Create a TempURL key from its secret value.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

impl Debug for TempUrlKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempUrlKey")
            .field("secret", &Redact::from(&self.secret))
            .finish()
    }
}

impl From<&str> for TempUrlKey {
    fn from(secret: &str) -> Self {
        Self::new(secret)
    }
}

impl From<String> for TempUrlKey {
    fn from(secret: String) -> Self {
        Self::new(secret)
    }
}

/// Signs Swift object URLs with a TempURL key.
///
/// This path is deliberately separate from [`crate::RequestSigner`]: an
/// ordinary Swift request uses a Keystone `X-Auth-Token`, while a TempURL uses
/// an account or container key and embeds the derived signature in the query
/// string. The signer preserves the URI's scheme, authority, path, and existing
/// query parameters. The signature covers the request method, the absolute
/// expiration time, and the already-encoded URI path; it never covers the
/// query string.
///
/// The resulting URL contains authentication material. Treat it as a secret and
/// do not log or re-encode it.
#[derive(Clone, Debug)]
pub struct TempUrlSigner {
    key: TempUrlKey,
    algorithm: TempUrlHashAlgorithm,
}

impl TempUrlSigner {
    /// Create a signer with the given TempURL key and SHA-256.
    pub fn new(key: impl Into<TempUrlKey>) -> Self {
        Self {
            key: key.into(),
            algorithm: TempUrlHashAlgorithm::default(),
        }
    }

    /// Select the hash algorithm used for the signature.
    pub fn with_algorithm(mut self, algorithm: TempUrlHashAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Create a TempURL for an object request.
    ///
    /// `uri` must be the absolute, wire-ready object URL. Its path is signed
    /// exactly as supplied, so callers must percent-encode path segments before
    /// calling this method. Existing query parameters are preserved, but a URI
    /// that already contains a TempURL authentication parameter such as
    /// `temp_url_sig` is rejected. This method does not support prefix-based or
    /// IP-restricted TempURLs. Fractions of a second in `expires_in` are
    /// truncated to the whole-second `temp_url_expires` value.
    pub fn presign(
        &self,
        ctx: &Context,
        method: &Method,
        uri: &Uri,
        expires_in: Duration,
    ) -> Result<Uri> {
        let expires = expiration_from_now(expires_in)?;
        self.presign_with_expiration(ctx, method, uri, expires)
    }

    fn presign_with_expiration(
        &self,
        ctx: &Context,
        method: &Method,
        uri: &Uri,
        expires: i64,
    ) -> Result<Uri> {
        if self.key.secret.is_empty() {
            return Err(Error::config_invalid("TempURL key must not be empty"));
        }
        let Some(scheme) = uri.scheme_str() else {
            return Err(Error::request_invalid(
                "TempURL presign requires an absolute request URI",
            ));
        };
        let Some(authority) = uri.authority() else {
            return Err(Error::request_invalid(
                "TempURL presign requires an absolute request URI",
            ));
        };

        let query = uri.query().unwrap_or_default();
        validate_query(query)?;

        let path = if uri.path().is_empty() {
            "/"
        } else {
            uri.path()
        };
        let message = format!("{}\n{}\n{}", method.as_str(), expires, path);

        let provider = ctx.crypto_provider()?;
        let signature = match self.algorithm {
            TempUrlHashAlgorithm::Sha1 => format!(
                "sha1:{}",
                base64_encode(&hmac_sha1(
                    provider,
                    self.key.as_bytes(),
                    message.as_bytes()
                )?)
            ),
            TempUrlHashAlgorithm::Sha256 => format!(
                "sha256:{}",
                base64_encode(&hmac_sha256(
                    provider,
                    self.key.as_bytes(),
                    message.as_bytes()
                )?)
            ),
            TempUrlHashAlgorithm::Sha512 => format!(
                "sha512:{}",
                base64_encode(&provider.hmac_sha512(self.key.as_bytes(), message.as_bytes())?)
            ),
        };
        // Swift accepts an algorithm-prefixed base64 digest. Percent-encode the
        // whole value because standard base64 contains `+`, `/`, and `=`, and a
        // query parser would otherwise turn `+` into a space.
        let encoded_signature = utf8_percent_encode(&signature, NON_ALPHANUMERIC);
        let authentication = format!("temp_url_sig={encoded_signature}&temp_url_expires={expires}");
        let query = if query.is_empty() {
            authentication
        } else {
            format!("{query}&{authentication}")
        };
        let path_and_query = format!("{path}?{query}");

        Builder::new()
            .scheme(scheme)
            .authority(authority.as_str())
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| Error::unexpected("failed to build TempURL URI").with_source(e))
    }
}

fn expiration_from_now(expires_in: Duration) -> Result<i64> {
    let seconds = i64::try_from(expires_in.as_secs())
        .map_err(|_| Error::request_invalid("TempURL expiration is too large"))?;
    Timestamp::now()
        .as_second()
        .checked_add(seconds)
        .ok_or_else(|| Error::request_invalid("TempURL expiration is out of range"))
}

fn validate_query(query: &str) -> Result<()> {
    for pair in query.split('&') {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        if TEMP_URL_AUTH_PARAMETERS
            .iter()
            .any(|parameter| name.eq_ignore_ascii_case(parameter))
        {
            return Err(Error::request_invalid(format!(
                "request query already contains TempURL authentication parameter: {name}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::crypto::CryptoProvider;
    use reqsign_crypto_rustcrypto::RustCryptoProvider;

    fn ctx() -> Context {
        Context::new().with_crypto(RustCryptoProvider::new())
    }

    fn uri(value: &str) -> Uri {
        value.parse().expect("test URI must parse")
    }

    // The SHA-256 digest in this test is the example from the OpenStack Swift
    // temporary URL middleware documentation. The base64 form is derived from
    // that published hex digest.
    #[test]
    fn signs_first_party_sha256_vector() {
        let signer = TempUrlSigner::new("mykey");
        let signed = signer
            .presign_with_expiration(
                &ctx(),
                &Method::GET,
                &uri("https://swift.example.com/v1/AUTH_account/container/object"),
                1512508563,
            )
            .expect("presign must succeed");

        assert_eq!(
            signed.query(),
            Some(
                "temp_url_sig=sha256%3Acy%2FKw2irsQx4pMvpXD%2BrfzEVhFMr93mr1QdOE8vouIs%3D&temp_url_expires=1512508563"
            )
        );
    }

    // These digests were calculated independently with the canonical
    // `METHOD\nEXPIRES\nPATH` input.
    #[test]
    fn signs_sha1_and_sha512_vectors() {
        let uri = uri("https://swift.example.com/v1/AUTH_account/container/object");

        let sha1 = TempUrlSigner::new("mykey")
            .with_algorithm(TempUrlHashAlgorithm::Sha1)
            .presign_with_expiration(&ctx(), &Method::GET, &uri, 1512508563)
            .expect("SHA-1 presign must succeed");
        assert_eq!(
            sha1.query(),
            Some("temp_url_sig=sha1%3AqD3PBYeoRUK18jp4B8OP9LyqaSQ%3D&temp_url_expires=1512508563")
        );

        let sha512 = TempUrlSigner::new("mykey")
            .with_algorithm(TempUrlHashAlgorithm::Sha512)
            .presign_with_expiration(&ctx(), &Method::GET, &uri, 1512508563)
            .expect("SHA-512 presign must succeed");
        assert_eq!(
            sha512.query(),
            Some(
                "temp_url_sig=sha512%3AFV%2FkcQtXVbzr3sQV%2BsX%2BSCAxMVs%2FnoJegKuf%2FsPXxpNrTP349WJcgxmr0xnfnZXtcXV0dv5dPI9pw15cOGQL%2Fw%3D%3D&temp_url_expires=1512508563"
            )
        );
    }

    #[test]
    fn signs_wire_path_and_preserves_existing_query() {
        let signer = TempUrlSigner::new("mykey");
        let signed = signer
            .presign_with_expiration(
                &ctx(),
                &Method::PUT,
                &uri(
                    "https://swift.example.com/v1/AUTH_account/container/a%20b?filename=My+Test+File.pdf",
                ),
                1700000000,
            )
            .expect("presign must succeed");

        assert_eq!(signed.path(), "/v1/AUTH_account/container/a%20b");
        assert_eq!(
            signed.query(),
            Some(
                "filename=My+Test+File.pdf&temp_url_sig=sha256%3APvuzD4Kbm5iFj6n0Pm1grIs2dYFuyoOpSwBN0FHSQxY%3D&temp_url_expires=1700000000"
            )
        );
    }

    #[test]
    fn query_does_not_change_the_signature() {
        let signer = TempUrlSigner::new("mykey");
        let plain = signer
            .presign_with_expiration(
                &ctx(),
                &Method::GET,
                &uri("https://swift.example.com/v1/AUTH_account/container/object"),
                1512508563,
            )
            .expect("presign must succeed");
        let with_query = signer
            .presign_with_expiration(
                &ctx(),
                &Method::GET,
                &uri("https://swift.example.com/v1/AUTH_account/container/object?filename=a"),
                1512508563,
            )
            .expect("presign must succeed");

        let plain_signature = plain
            .query()
            .expect("plain URL has a query")
            .split('&')
            .next()
            .expect("plain URL has a signature");
        let query_signature = with_query
            .query()
            .expect("custom URL has a query")
            .split('&')
            .nth(1)
            .expect("custom URL has a signature");
        assert_eq!(plain_signature, query_signature);
    }

    #[test]
    fn rejects_existing_temp_url_authentication() {
        let signer = TempUrlSigner::new("mykey");

        for parameter in TEMP_URL_AUTH_PARAMETERS {
            let uri = uri(&format!(
                "https://swift.example.com/v1/AUTH_account/container/object?{parameter}=old"
            ));
            let error = signer
                .presign_with_expiration(&ctx(), &Method::GET, &uri, 1512508563)
                .expect_err("existing authentication must be rejected");

            assert_eq!(error.kind(), reqsign_core::ErrorKind::RequestInvalid);
            assert!(error.to_string().contains(parameter));
        }
    }

    #[test]
    fn rejects_empty_key() {
        let error = TempUrlSigner::new("")
            .presign_with_expiration(
                &ctx(),
                &Method::GET,
                &uri("https://swift.example.com/v1/AUTH_account/container/object"),
                1512508563,
            )
            .expect_err("empty key must be rejected");

        assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
    }

    #[test]
    fn requires_an_absolute_uri() {
        let error = TempUrlSigner::new("mykey")
            .presign_with_expiration(
                &ctx(),
                &Method::GET,
                &uri("/v1/AUTH_account/container/object"),
                1512508563,
            )
            .expect_err("relative URI must be rejected");

        assert_eq!(error.kind(), reqsign_core::ErrorKind::RequestInvalid);
    }

    #[test]
    fn requires_a_crypto_provider() {
        let error = TempUrlSigner::new("mykey")
            .presign(
                &Context::new(),
                &Method::GET,
                &uri("https://swift.example.com/v1/AUTH_account/container/object"),
                Duration::from_secs(60),
            )
            .expect_err("missing provider must fail");

        assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
    }

    #[test]
    fn sha512_failure_is_reported() {
        #[derive(Debug)]
        struct MinimalProvider;

        impl CryptoProvider for MinimalProvider {
            fn sha1(&self, _input: &[u8]) -> Result<[u8; 20]> {
                Ok([0; 20])
            }

            fn sha256(&self, _input: &[u8]) -> Result<[u8; 32]> {
                Ok([0; 32])
            }

            fn hmac_sha1(&self, _key: &[u8], _input: &[u8]) -> Result<[u8; 20]> {
                Ok([0; 20])
            }

            fn hmac_sha256(&self, _key: &[u8], _input: &[u8]) -> Result<[u8; 32]> {
                Ok([0; 32])
            }
        }

        let context = Context::new().with_crypto(MinimalProvider);
        let error = TempUrlSigner::new("mykey")
            .with_algorithm(TempUrlHashAlgorithm::Sha512)
            .presign(
                &context,
                &Method::GET,
                &uri("https://swift.example.com/v1/AUTH_account/container/object"),
                Duration::from_secs(60),
            )
            .expect_err("unsupported SHA-512 must fail");

        assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
        assert!(error.to_string().contains("HMAC-SHA512"));
    }

    #[test]
    fn debug_output_redacts_the_key() {
        let signer = TempUrlSigner::new(TempUrlKey::new("top-secret-tempurl-key"));

        let debug = format!("{signer:?}");
        assert!(
            !debug.contains("top-secret-tempurl-key"),
            "key leaked: {debug}"
        );
        assert!(debug.contains("***"), "key must be redacted: {debug}");
    }

    #[test]
    fn parses_supported_algorithms() {
        assert_eq!(
            TempUrlHashAlgorithm::from_str("SHA256").expect("supported"),
            TempUrlHashAlgorithm::Sha256
        );
        assert!(
            TempUrlHashAlgorithm::from_str("md5").is_err(),
            "MD5 must remain unsupported"
        );
    }
}
