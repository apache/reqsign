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

use std::fmt::Write;
use std::time::Duration;

use http::{HeaderValue, Uri, header};
use log::debug;
use percent_encoding::{AsciiSet, percent_decode_str, utf8_percent_encode};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::time::Timestamp;
use reqsign_core::{Result, SigningRequest};

use crate::constants::{
    AWS_QUERY_ENCODE_SET, AWS_URI_ENCODE_SET, X_AMZ_CONTENT_SHA_256, X_AMZ_DATE,
    X_AMZ_S3_SESSION_TOKEN, X_AMZ_SECURITY_TOKEN,
};
use crate::{Credential, PercentEncodingMode};

static AWS_URI_DOUBLE_ENCODE_SET: AsciiSet = AWS_URI_ENCODE_SET.remove(b'/');

const MAX_PRESIGN_LIFETIME: Duration = Duration::from_secs(604_800);

/// Build the canonical request shared by AWS SigV4-family algorithms.
pub fn canonical_request_string(
    request: &SigningRequest,
    canonical_query: &[(String, String)],
) -> Result<String> {
    canonical_request_string_with_encoding(request, canonical_query, PercentEncodingMode::Single)
}

/// Build an AWS canonical request with the selected URI percent-encoding mode.
///
/// The mode only affects the canonical URI, not the request's wire URI or query.
/// Canonical header values have leading and trailing ASCII spaces trimmed and
/// runs of ASCII spaces collapsed. Repeated values are joined with commas in
/// request order.
pub fn canonical_request_string_with_encoding(
    request: &SigningRequest,
    canonical_query: &[(String, String)],
    percent_encoding_mode: PercentEncodingMode,
) -> Result<String> {
    let mut output = String::with_capacity(256);

    writeln!(output, "{}", request.method)
        .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write method: {e}")))?;
    writeln!(
        output,
        "{}",
        canonical_uri_with_encoding(&request.path, percent_encoding_mode)?
    )
    .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write encoded path: {e}")))?;
    writeln!(
        output,
        "{}",
        canonical_query
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&")
    )
    .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write query: {e}")))?;

    let signed_headers = request.header_name_to_vec_sorted();
    for name in &signed_headers {
        output.push_str(name);
        output.push(':');
        for (index, value) in request.headers.get_all(*name).into_iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let value = value.to_str().map_err(|e| {
                reqsign_core::Error::request_invalid("invalid signed header value").with_source(e)
            })?;
            let mut segments = value.split(' ').filter(|segment| !segment.is_empty());
            if let Some(first) = segments.next() {
                output.push_str(first);
                for segment in segments {
                    output.push(' ');
                    output.push_str(segment);
                }
            }
        }
        output.push('\n');
    }
    writeln!(output)
        .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write newline: {e}")))?;
    writeln!(output, "{}", signed_headers.join(";")).map_err(|e| {
        reqsign_core::Error::unexpected(format!("failed to write signed headers: {e}"))
    })?;

    if request.headers.get(X_AMZ_CONTENT_SHA_256).is_none() {
        write!(output, "UNSIGNED-PAYLOAD").map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to write unsigned payload: {e}"))
        })?;
    } else {
        write!(
            output,
            "{}",
            request.headers[X_AMZ_CONTENT_SHA_256]
                .to_str()
                .map_err(|e| {
                    reqsign_core::Error::unexpected(format!("invalid header value: {e}"))
                })?
        )
        .map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to write content sha256: {e}"))
        })?;
    }

    Ok(output)
}

/// Add headers shared by AWS SigV4-family algorithms.
///
/// When `Host` is absent, derive it from the URI authority and omit the
/// scheme's default port for HTTP and HTTPS.
///
/// Session tokens always use the standard AWS `x-amz-security-token` header.
/// Service-specific representations, such as the S3 Express CreateSession
/// token, are selected by the signing service configuration rather than
/// inferred from the request authority.
pub fn canonicalize_headers(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
) -> Result<()> {
    canonicalize_headers_inner(request, credential, expires_in, now, X_AMZ_SECURITY_TOKEN)
}

/// Add SigV4 headers while always using the standard AWS session-token header.
///
/// This is the explicit standard-token entry point for shared callers. S3
/// Express callers that need the CreateSession representation select it from
/// their signing service configuration.
#[doc(hidden)]
pub fn canonicalize_headers_with_standard_session_token(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
) -> Result<()> {
    canonicalize_headers_inner(request, credential, expires_in, now, X_AMZ_SECURITY_TOKEN)
}

fn canonicalize_headers_inner(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    session_token_header: &'static str,
) -> Result<()> {
    if !request.headers.contains_key(header::HOST) {
        let host = match (request.scheme.as_str(), request.authority.port_u16()) {
            ("http", Some(80)) | ("https", Some(443)) => request.authority.host(),
            _ => request.authority.as_str(),
        };
        request.headers.insert(
            header::HOST,
            host.parse().map_err(|e| {
                reqsign_core::Error::unexpected(format!(
                    "failed to parse authority as header value: {e}"
                ))
            })?,
        );
    }

    if expires_in.is_some() {
        return Ok(());
    }

    if request.headers.get(X_AMZ_DATE).is_none() {
        let value = HeaderValue::try_from(now.format_iso8601()).map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to create date header: {e}"))
        })?;
        request.headers.insert(X_AMZ_DATE, value);
    }

    if request.headers.get(X_AMZ_CONTENT_SHA_256).is_none() {
        request.headers.insert(
            X_AMZ_CONTENT_SHA_256,
            HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
    }

    if let Some(token) = &credential.session_token {
        let mut value = HeaderValue::from_str(token).map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to create security token header: {e}"))
        })?;
        value.set_sensitive(true);

        request.headers.insert(session_token_header, value);
    }

    Ok(())
}

/// Encode and sort the complete canonical query.
pub fn canonicalize_query(
    request: &SigningRequest,
    authentication_query: &[(String, String)],
) -> Vec<(String, String)> {
    let mut query = request
        .query
        .iter()
        .chain(authentication_query)
        .map(|(key, value)| {
            (
                utf8_percent_encode(key, &AWS_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(value, &AWS_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect::<Vec<_>>();
    query.sort();
    query
}

/// Encode a wire-ready path with the default single-encoding behavior.
pub fn canonical_uri(path: &str) -> Result<String> {
    canonical_uri_with_encoding(path, PercentEncodingMode::Single)
}

/// Encode a wire-ready path for use in an AWS canonical request.
///
/// This does not normalize path segments or modify the original wire path.
pub fn canonical_uri_with_encoding(
    path: &str,
    percent_encoding_mode: PercentEncodingMode,
) -> Result<String> {
    if percent_encoding_mode == PercentEncodingMode::Double {
        // The input is already the caller's encoded wire path. Do not decode it:
        // doing so would lose percent-escape spelling and reject non-UTF-8 bytes.
        return Ok(utf8_percent_encode(path, &AWS_URI_DOUBLE_ENCODE_SET).to_string());
    }

    // Keep the existing single-encoding behavior, including escape normalization
    // and rejection of percent-encoded non-UTF-8 bytes, for S3 compatibility.
    path.split('/')
        .map(|segment| {
            let decoded = percent_decode_str(segment).decode_utf8().map_err(|e| {
                reqsign_core::Error::request_invalid("failed to decode URI path segment")
                    .with_source(e)
            })?;
            Ok(utf8_percent_encode(&decoded, &AWS_URI_ENCODE_SET).to_string())
        })
        .collect::<Result<Vec<_>>>()
        .map(|segments| segments.join("/"))
}

/// Append encoded query pairs without rewriting existing wire query bytes.
pub fn append_query_pairs(uri: &Uri, pairs: &[(String, String)]) -> Result<Uri> {
    let mut pairs = pairs
        .iter()
        .map(|(key, value)| {
            (
                utf8_percent_encode(key, &AWS_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(value, &AWS_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect::<Vec<_>>();
    pairs.sort();
    let fragment = pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    append_query_fragment(uri, &fragment)
}

/// Append an encoded query fragment without rewriting existing wire query bytes.
pub fn append_query_fragment(uri: &Uri, fragment: &str) -> Result<Uri> {
    if fragment.is_empty() {
        return Ok(uri.clone());
    }

    let mut value = uri.to_string();
    if uri.query().is_none() {
        value.push('?');
    } else if !value.ends_with('?') && !value.ends_with('&') {
        value.push('&');
    }
    value.push_str(fragment);

    value.parse().map_err(|e| {
        reqsign_core::Error::request_invalid("failed to append signing query").with_source(e)
    })
}

/// Service-selected options for the shared SigV4 request implementation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct SigV4SigningOptions<'a> {
    /// AWS signing service name.
    pub service: &'a str,
    /// AWS signing region.
    pub region: &'a str,
    /// Canonical URI percent-encoding mode.
    pub percent_encoding_mode: PercentEncodingMode,
    /// Whether the signing service selected the S3 Express CreateSession token.
    pub uses_s3_express_session_token: bool,
}

/// Validate a caller-supplied AWS presigned URL lifetime.
///
/// AWS query authentication writes `X-Amz-Expires` in whole seconds and accepts
/// values from 1 through 604800 (seven days).
#[doc(hidden)]
pub fn validate_presign_lifetime(expires_in: Option<Duration>) -> Result<()> {
    let Some(expires_in) = expires_in else {
        return Ok(());
    };

    let seconds = expires_in.as_secs();
    if seconds == 0 || seconds > MAX_PRESIGN_LIFETIME.as_secs() {
        return Err(reqsign_core::Error::request_invalid(
            "AWS SigV4 presigned URL lifetime must be between 1 and 604800 seconds",
        ));
    }

    Ok(())
}

/// Sign a wire-ready request with AWS Signature Version 4.
///
/// This is the shared implementation used by the public SigV4 signer and by
/// reqsign's internal STS operations. `expires_in` selects query-string
/// authentication and the signature deadline; `None` selects header
/// authentication for a request that must complete within the standard
/// operation headroom.
#[doc(hidden)]
pub fn sign_request_parts(
    provider: &dyn CryptoProvider,
    req: &mut http::request::Parts,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    options: SigV4SigningOptions<'_>,
) -> Result<()> {
    use reqsign_core::SigningCredential;

    let required_until = now.saturating_add(expires_in.unwrap_or(Duration::from_secs(10)));
    if !credential.is_valid_at(required_until) {
        return Err(reqsign_core::Error::credential_invalid(
            "credential expires before the requested signing operation deadline",
        ));
    }
    validate_presign_lifetime(expires_in)?;

    let original_uri = req.uri.clone();
    let mut signed_req = SigningRequest::build(req)?;

    canonicalize_signing_headers(
        &mut signed_req,
        credential,
        expires_in,
        now,
        options.uses_s3_express_session_token,
    )?;
    let authentication_query = sigv4_authentication_query(
        &signed_req,
        credential,
        expires_in,
        now,
        options.service,
        options.region,
        options.uses_s3_express_session_token,
    );
    let canonical_query = canonicalize_query(&signed_req, &authentication_query);

    // build canonical request and string to sign.
    let creq = canonical_request_string_with_encoding(
        &signed_req,
        &canonical_query,
        options.percent_encoding_mode,
    )?;
    let encoded_req = reqsign_core::hash::hex_sha256(provider, creq.as_bytes())?;

    // Scope: "20220313/<region>/<service>/aws4_request"
    let scope = format!(
        "{}/{}/{}/aws4_request",
        now.format_date(),
        options.region,
        options.service
    );
    debug!("calculated scope: {scope}");

    // StringToSign:
    //
    // AWS4-HMAC-SHA256
    // 20220313T072004Z
    // 20220313/<region>/<service>/aws4_request
    // <hashed_canonical_request>
    let string_to_sign = {
        let mut f = String::new();
        writeln!(f, "AWS4-HMAC-SHA256").map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to write algorithm: {e}"))
        })?;
        writeln!(f, "{}", now.format_iso8601()).map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to write timestamp: {e}"))
        })?;
        writeln!(f, "{scope}")
            .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write scope: {e}")))?;
        write!(f, "{encoded_req}").map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to write encoded request: {e}"))
        })?;
        f
    };
    debug!("calculated string to sign: {string_to_sign}");

    let signing_key = generate_signing_key(
        provider,
        &credential.secret_access_key,
        now,
        options.region,
        options.service,
    )?;
    let signature =
        reqsign_core::hash::hex_hmac_sha256(provider, &signing_key, string_to_sign.as_bytes())?;

    let final_uri = if expires_in.is_some() {
        let unsigned_uri = append_query_pairs(&original_uri, &authentication_query)?;
        Some(append_query_fragment(
            &unsigned_uri,
            &format!("X-Amz-Signature={signature}"),
        )?)
    } else {
        let mut authorization = HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            credential.access_key_id,
            scope,
            signed_req.header_name_to_vec_sorted().join(";"),
            signature
        ))
        .map_err(|e| {
            reqsign_core::Error::unexpected(format!("failed to create authorization header: {e}"))
        })?;
        authorization.set_sensitive(true);

        signed_req
            .headers
            .insert(header::AUTHORIZATION, authorization);
        None
    };

    signed_req.apply(req)?;
    if let Some(uri) = final_uri {
        req.uri = uri;
    }
    Ok(())
}

/// Add shared SigV4 headers and apply the service-selected session token choice.
#[doc(hidden)]
pub fn canonicalize_signing_headers(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    uses_s3_express_session_token: bool,
) -> Result<()> {
    canonicalize_headers(request, credential, expires_in, now)?;

    if !uses_s3_express_session_token || expires_in.is_some() || credential.session_token.is_none()
    {
        return Ok(());
    }

    // Shared canonicalization writes the standard header. S3 Express selects
    // its representation from the signing service, so move the same sensitive
    // header value before the canonical request is built.
    if let Some(value) = request.headers.remove(X_AMZ_SECURITY_TOKEN) {
        request.headers.insert(X_AMZ_S3_SESSION_TOKEN, value);
    }

    Ok(())
}

#[doc(hidden)]
pub fn sigv4_authentication_query(
    ctx: &SigningRequest,
    cred: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    service: &str,
    region: &str,
    uses_s3_express_session_token: bool,
) -> Vec<(String, String)> {
    let mut query = Vec::new();
    if let Some(expire) = expires_in {
        query.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
        query.push((
            "X-Amz-Credential".into(),
            format!(
                "{}/{}/{}/{}/aws4_request",
                cred.access_key_id,
                now.format_date(),
                region,
                service
            ),
        ));
        query.push(("X-Amz-Date".into(), now.format_iso8601()));
        query.push(("X-Amz-Expires".into(), expire.as_secs().to_string()));
        query.push((
            "X-Amz-SignedHeaders".into(),
            ctx.header_name_to_vec_sorted().join(";"),
        ));

        if let Some(token) = &cred.session_token {
            let name = if uses_s3_express_session_token {
                "X-Amz-S3session-Token"
            } else {
                "X-Amz-Security-Token"
            };
            query.push((name.into(), token.into()));
        }
    }
    query
}

fn generate_signing_key(
    provider: &dyn CryptoProvider,
    secret: &str,
    time: Timestamp,
    region: &str,
    service: &str,
) -> Result<Vec<u8>> {
    let secret = format!("AWS4{secret}");
    let sign_date = reqsign_core::hash::hmac_sha256(
        provider,
        secret.as_bytes(),
        time.format_date().as_bytes(),
    )?;
    let sign_region =
        reqsign_core::hash::hmac_sha256(provider, sign_date.as_slice(), region.as_bytes())?;
    let sign_service =
        reqsign_core::hash::hmac_sha256(provider, sign_region.as_slice(), service.as_bytes())?;
    Ok(reqsign_core::hash::hmac_sha256(
        provider,
        sign_service.as_slice(),
        "aws4_request".as_bytes(),
    )?
    .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn canonical_headers_join_values_and_collapse_only_ascii_spaces() -> Result<()> {
        let mut parts = Request::get("https://example.com/")
            .header(header::HOST, "example.com")
            .header("x-meta", "  z   word  ")
            .header("x-meta", "   ")
            .header("x-meta", "  \ta   word\t  ")
            .header("x-meta", "")
            .body(())
            .expect("request must be valid")
            .into_parts()
            .0;
        let request = SigningRequest::build(&mut parts)?;

        assert_eq!(
            canonical_request_string(&request, &[])?,
            "GET\n/\n\nhost:example.com\nx-meta:z word,,\ta word\t,\n\nhost;x-meta\nUNSIGNED-PAYLOAD"
        );
        Ok(())
    }

    #[test]
    fn canonical_headers_treat_zero_padded_default_ports_as_default() -> Result<()> {
        let now = "2026-07-22T00:00:00Z".parse().expect("valid timestamp");
        for (uri, host) in [
            ("http://example.com:080/", "example.com"),
            ("https://[::1]:0443/", "[::1]"),
            ("https://[::1]:080/", "[::1]:080"),
        ] {
            let mut parts = Request::get(uri)
                .body(())
                .expect("valid URI")
                .into_parts()
                .0;
            let mut request = SigningRequest::build(&mut parts)?;
            canonicalize_headers(
                &mut request,
                &Credential::default(),
                Some(Duration::from_secs(60)),
                now,
            )?;
            assert_eq!(request.headers[header::HOST], host, "{uri}");
        }
        Ok(())
    }

    #[test]
    fn canonical_uri_encoding_modes() -> Result<()> {
        let cases = [
            ("/", "/", "/"),
            ("/a%25b", "/a%25b", "/a%2525b"),
            ("/a%2Fb", "/a%2Fb", "/a%252Fb"),
            ("/a%20b", "/a%20b", "/a%2520b"),
            ("/a%40b", "/a%40b", "/a%2540b"),
            ("/a%3Db", "/a%3Db", "/a%253Db"),
            ("/a@b=c", "/a%40b%3Dc", "/a%40b%3Dc"),
            ("/a%2fb%3d", "/a%2Fb%3D", "/a%252fb%253d"),
            ("/%7E/%41", "/~/A", "/%257E/%2541"),
            (
                "/%E4%B8%AD%E6%96%87",
                "/%E4%B8%AD%E6%96%87",
                "/%25E4%25B8%25AD%25E6%2596%2587",
            ),
            ("/a//./b/../c/", "/a//./b/../c/", "/a//./b/../c/"),
            ("/-._~AZaz09", "/-._~AZaz09", "/-._~AZaz09"),
        ];

        assert_eq!(PercentEncodingMode::default(), PercentEncodingMode::Single);
        for (wire_path, single, double) in cases {
            assert_eq!(canonical_uri(wire_path)?, single, "default: {wire_path}");
            assert_eq!(
                canonical_uri_with_encoding(wire_path, PercentEncodingMode::Single)?,
                single,
                "single: {wire_path}"
            );
            assert_eq!(
                canonical_uri_with_encoding(wire_path, PercentEncodingMode::Double)?,
                double,
                "double: {wire_path}"
            );
        }
        Ok(())
    }

    #[test]
    fn double_encoding_does_not_decode_non_utf8_escapes() -> Result<()> {
        for (wire_path, double) in [("/%FF", "/%25FF"), ("/%C3%28", "/%25C3%2528")] {
            assert!(canonical_uri(wire_path).is_err());
            assert!(canonical_uri_with_encoding(wire_path, PercentEncodingMode::Single).is_err());
            assert_eq!(
                canonical_uri_with_encoding(wire_path, PercentEncodingMode::Double)?,
                double
            );
        }
        Ok(())
    }

    #[test]
    fn encoding_changes_only_the_canonical_uri() -> Result<()> {
        let mut parts = Request::get("https://example.com/a%2Fb?key=%25")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .expect("request must be valid")
            .into_parts()
            .0;
        let original_uri = parts.uri.clone();
        let request = SigningRequest::build(&mut parts)?;
        let canonical_query = canonicalize_query(&request, &[]);
        let default = canonical_request_string(&request, &canonical_query)?;
        let single = canonical_request_string_with_encoding(
            &request,
            &canonical_query,
            PercentEncodingMode::Single,
        )?;
        let double = canonical_request_string_with_encoding(
            &request,
            &canonical_query,
            PercentEncodingMode::Double,
        )?;

        assert_eq!(default, single);
        assert_eq!(single.lines().nth(1), Some("/a%2Fb"));
        assert_eq!(double.lines().nth(1), Some("/a%252Fb"));
        assert_eq!(double, single.replacen("/a%2Fb", "/a%252Fb", 1));
        assert_eq!(request.path, "/a%2Fb");
        assert_eq!(parts.uri, original_uri);
        Ok(())
    }
}
