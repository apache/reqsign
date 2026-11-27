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

use http::request::Parts;
use http::{HeaderMap, HeaderValue, header};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result};

use crate::constants::{X_AMZ_CONTENT_SHA_256, X_AMZ_DATE};
use crate::{Credential, EMPTY_STRING_SHA256};

use super::{SigV4RequestSignature, SigV4SigningOptions, sign_sigv4, validate_sigv4_request};

#[derive(Debug, PartialEq, Eq)]
enum StreamingMode {
    Signed,
    SignedWithTrailers,
    UnsignedWithTrailers,
}

/// Signing state for a single S3 `aws-chunked` upload.
///
/// The state is seeded by the signed request head and owns the material needed
/// to sign its body. It can outlive the request signer, credential, and context
/// passed to the head signing operation.
pub struct StreamingSigner {
    ctx: Context,
    mode: StreamingMode,
    seed: SigV4RequestSignature,
    previous_chunk_signature: Option<String>,
    finished_chunks: bool,
}

impl fmt::Debug for StreamingSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingSigner")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl StreamingSigner {
    /// Return the initial signature written to the `Authorization` header.
    pub fn seed_signature(&self) -> &str {
        &self.seed.signature
    }

    /// Sign the next chunk's data bytes and advance the signature chain on success.
    ///
    /// Pass the final zero-length chunk as an empty slice. A signed chain
    /// accepts no more chunks after that. The returned lowercase hex signature
    /// is borrowed until the next mutable use of this signer. Unsigned payloads
    /// return `None` for every chunk, including the zero-length chunk.
    pub fn sign_chunk(&mut self, chunk: &[u8]) -> Result<Option<&str>> {
        if self.mode == StreamingMode::UnsignedWithTrailers {
            return Ok(None);
        }
        if self.finished_chunks {
            return Err(Error::request_invalid(
                "the final AWS chunk is already signed",
            ));
        }

        let previous_signature = self
            .previous_chunk_signature
            .as_deref()
            .unwrap_or(self.seed_signature());
        // A successfully resolved Context keeps the same explicit binding or
        // observes the same write-once process-wide provider for the upload.
        let provider = self.ctx.crypto_provider()?;
        let hash = hex_sha256(provider, chunk)?;
        let signature = self.sign_payload(
            provider,
            "AWS4-HMAC-SHA256-PAYLOAD",
            previous_signature,
            format_args!("{EMPTY_STRING_SHA256}\n{hash}"),
        )?;

        self.finished_chunks = chunk.is_empty();
        Ok(Some(
            self.previous_chunk_signature.insert(signature).as_str(),
        ))
    }

    /// Sign the trailing headers using the final zero-length chunk's signature.
    ///
    /// Supply the actual trailer fields declared by `x-amz-trailer`. For signed
    /// trailers, use the returned lowercase hex value for `x-amz-trailer-signature`.
    /// Unsigned trailers return `None`. A stream using the signed mode without
    /// trailers, or a signed trailer before the final chunk, returns an error.
    pub fn sign_trailer(&self, trailers: &HeaderMap) -> Result<Option<String>> {
        match self.mode {
            StreamingMode::UnsignedWithTrailers => return Ok(None),
            StreamingMode::Signed => {
                return Err(Error::request_invalid(
                    "the AWS streaming payload mode does not include trailers",
                ));
            }
            StreamingMode::SignedWithTrailers => {}
        }

        let Some(final_signature) = self
            .previous_chunk_signature
            .as_deref()
            .filter(|_| self.finished_chunks)
        else {
            return Err(Error::request_invalid(
                "sign the final zero-length AWS chunk before signing trailers",
            ));
        };
        if trailers.is_empty() || trailers.contains_key("x-amz-trailer-signature") {
            return Err(Error::request_invalid(
                "AWS trailer signing requires trailing headers without the trailer signature",
            ));
        }

        // S3 signs a newline-terminated list of lowercase names and trimmed
        // values. Preserve the order of repeated names, as the AWS SDK does.
        let mut headers: Vec<_> = trailers.iter().collect();
        headers.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
        let mut canonical = String::new();
        for (name, value) in headers {
            let value = value.to_str().map_err(|e| {
                Error::request_invalid("invalid AWS trailing header value").with_source(e)
            })?;
            canonical.push_str(name.as_str());
            canonical.push(':');
            canonical.push_str(value.trim());
            canonical.push('\n');
        }

        let provider = self.ctx.crypto_provider()?;
        let hash = hex_sha256(provider, canonical.as_bytes())?;
        self.sign_payload(
            provider,
            "AWS4-HMAC-SHA256-TRAILER",
            final_signature,
            format_args!("{hash}"),
        )
        .map(Some)
    }

    fn sign_payload(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: &str,
        previous_signature: &str,
        hashes: fmt::Arguments<'_>,
    ) -> Result<String> {
        let string_to_sign = format!(
            "{algorithm}\n{}\n{}\n{previous_signature}\n{hashes}",
            self.seed.timestamp, self.seed.scope,
        );
        hex_hmac_sha256(provider, &self.seed.signing_key, string_to_sign.as_bytes())
    }
}

/// Sign a fresh S3 streaming request head and capture its signing state.
#[doc(hidden)]
pub fn sign_streaming_request_parts(
    ctx: &Context,
    req: &mut Parts,
    credential: &Credential,
    now: Timestamp,
    options: SigV4SigningOptions<'_>,
) -> Result<StreamingSigner> {
    let provider = ctx.crypto_provider()?;
    validate_sigv4_request(credential, None, now)?;
    if req.headers.contains_key(header::AUTHORIZATION) {
        return Err(Error::request_invalid(
            "AWS streaming signing requires a request without an Authorization header",
        ));
    }

    let mut hashes = req.headers.get_all(X_AMZ_CONTENT_SHA_256).iter();
    let mode = match (hashes.next().map(HeaderValue::as_bytes), hashes.next()) {
        (Some(b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"), None) => StreamingMode::Signed,
        (Some(b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"), None) => {
            StreamingMode::SignedWithTrailers
        }
        (Some(b"STREAMING-UNSIGNED-PAYLOAD-TRAILER"), None) => StreamingMode::UnsignedWithTrailers,
        _ => {
            return Err(Error::request_invalid(
                "AWS streaming signing requires one streaming x-amz-content-sha256 value",
            ));
        }
    };

    let mut dates = req.headers.get_all(X_AMZ_DATE).iter();
    if dates
        .next()
        .is_some_and(|date| date.as_bytes() != now.format_iso8601().as_bytes())
        || dates.next().is_some()
    {
        return Err(Error::request_invalid(
            "AWS streaming x-amz-date must match the signing time and occur only once",
        ));
    }

    let seed = sign_sigv4(provider, req, credential, None, now, options)?;
    Ok(StreamingSigner {
        ctx: ctx.clone(),
        mode,
        seed,
        previous_chunk_signature: None,
        finished_chunks: false,
    })
}
