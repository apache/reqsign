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
use percent_encoding::{AsciiSet, percent_decode_str, utf8_percent_encode};
use reqsign_core::time::Timestamp;
use reqsign_core::{Result, SigningRequest};

use crate::constants::{
    AWS_QUERY_ENCODE_SET, AWS_URI_ENCODE_SET, X_AMZ_CONTENT_SHA_256, X_AMZ_DATE,
    X_AMZ_S3_SESSION_TOKEN, X_AMZ_SECURITY_TOKEN,
};
use crate::{Credential, PercentEncodingMode};

static AWS_URI_DOUBLE_ENCODE_SET: AsciiSet = AWS_URI_ENCODE_SET.remove(b'/');

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
        let mut value = request.headers[*name].clone();
        SigningRequest::header_value_normalize(&mut value);
        writeln!(
            output,
            "{}:{}",
            name,
            value.to_str().map_err(|e| {
                reqsign_core::Error::request_invalid("invalid signed header value").with_source(e)
            })?
        )
        .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write header: {e}")))?;
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
pub fn canonicalize_headers(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
) -> Result<()> {
    canonicalize_headers_inner(request, credential, expires_in, now, false)
}

/// Add SigV4 headers while always using the standard AWS session-token header.
///
/// S3 Express is the only supported AWS flow that uses
/// `x-amz-s3session-token`. Operations whose endpoint is configurable must not
/// infer that service semantic from an arbitrary hostname.
#[doc(hidden)]
pub fn canonicalize_headers_with_standard_session_token(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
) -> Result<()> {
    canonicalize_headers_inner(request, credential, expires_in, now, true)
}

fn canonicalize_headers_inner(
    request: &mut SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    force_standard_session_token: bool,
) -> Result<()> {
    if request.headers.get(header::HOST).is_none() {
        request.headers.insert(
            header::HOST,
            request.authority.as_str().parse().map_err(|e| {
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

        let is_s3_express = !force_standard_session_token
            && (request.authority.as_str().contains("s3express")
                || request.authority.as_str().contains("--x-s3"));
        if is_s3_express {
            request.headers.insert(X_AMZ_S3_SESSION_TOKEN, value);
        } else {
            request.headers.insert(X_AMZ_SECURITY_TOKEN, value);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

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
