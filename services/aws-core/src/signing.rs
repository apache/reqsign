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
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use reqsign_core::time::Timestamp;
use reqsign_core::{Result, SigningRequest};

use crate::Credential;
use crate::constants::{
    AWS_QUERY_ENCODE_SET, AWS_URI_ENCODE_SET, X_AMZ_CONTENT_SHA_256, X_AMZ_DATE,
    X_AMZ_S3_SESSION_TOKEN, X_AMZ_SECURITY_TOKEN,
};

/// Build the canonical request shared by AWS SigV4-family algorithms.
pub fn canonical_request_string(
    request: &SigningRequest,
    canonical_query: &[(String, String)],
) -> Result<String> {
    let mut output = String::with_capacity(256);

    writeln!(output, "{}", request.method)
        .map_err(|e| reqsign_core::Error::unexpected(format!("failed to write method: {e}")))?;
    writeln!(output, "{}", canonical_uri(&request.path)?).map_err(|e| {
        reqsign_core::Error::unexpected(format!("failed to write encoded path: {e}"))
    })?;
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

/// Encode a wire-ready path for use in an AWS canonical request.
pub fn canonical_uri(path: &str) -> Result<String> {
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

/// Sign a wire-ready request with AWS Signature Version 4.
///
/// This is the shared implementation used by the public SigV4 signer and by
/// reqsign's internal STS operations. `expires_in` selects query-string
/// authentication and the signature deadline; `None` selects header
/// authentication for a request that must complete within the standard
/// operation headroom.
#[doc(hidden)]
pub fn sign_request_parts(
    req: &mut http::request::Parts,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    service: &str,
    region: &str,
    use_standard_session_token: bool,
) -> Result<()> {
    use reqsign_core::SigningCredential;

    let required_until = now + expires_in.unwrap_or(Duration::from_secs(10));
    if !credential.is_valid_at(required_until) {
        return Err(reqsign_core::Error::credential_invalid(
            "credential expires before the requested signing operation deadline",
        ));
    }

    let original_uri = req.uri.clone();
    let mut signed_req = SigningRequest::build(req)?;

    if use_standard_session_token {
        canonicalize_headers_with_standard_session_token(
            &mut signed_req,
            credential,
            expires_in,
            now,
        )?;
    } else {
        canonicalize_headers(&mut signed_req, credential, expires_in, now)?;
    }
    let authentication_query = sigv4_authentication_query(
        &signed_req,
        credential,
        expires_in,
        now,
        service,
        region,
        use_standard_session_token,
    );
    let canonical_query = canonicalize_query(&signed_req, &authentication_query);

    let creq = canonical_request_string(&signed_req, &canonical_query)?;
    let encoded_req = reqsign_core::hash::hex_sha256(creq.as_bytes());

    // Scope: "20220313/<region>/<service>/aws4_request"
    let scope = format!("{}/{}/{}/aws4_request", now.format_date(), region, service);
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

    let signing_key = generate_signing_key(&credential.secret_access_key, now, region, service);
    let signature = reqsign_core::hash::hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

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

#[doc(hidden)]
pub fn sigv4_authentication_query(
    ctx: &SigningRequest,
    cred: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    service: &str,
    region: &str,
    use_standard_session_token: bool,
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
            let is_s3_express = !use_standard_session_token
                && (ctx.authority.as_str().contains("s3express")
                    || ctx.authority.as_str().contains("--x-s3"));
            let name = if is_s3_express {
                "X-Amz-S3session-Token"
            } else {
                "X-Amz-Security-Token"
            };
            query.push((name.into(), token.into()));
        }
    }
    query
}

fn generate_signing_key(secret: &str, time: Timestamp, region: &str, service: &str) -> Vec<u8> {
    let secret = format!("AWS4{secret}");
    let sign_date =
        reqsign_core::hash::hmac_sha256(secret.as_bytes(), time.format_date().as_bytes());
    let sign_region = reqsign_core::hash::hmac_sha256(sign_date.as_slice(), region.as_bytes());
    let sign_service = reqsign_core::hash::hmac_sha256(sign_region.as_slice(), service.as_bytes());
    reqsign_core::hash::hmac_sha256(sign_service.as_slice(), "aws4_request".as_bytes())
}
