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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode,
};
use aws_sigv4::sign::v4;
use http::request::Parts;
use http::{HeaderMap, Request, header};
use reqsign_aws_v4::{Credential, RequestSigner};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ErrorKind};
use reqsign_crypto_rustcrypto::RustCryptoProvider;

const SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
const CHECKSUM_TRAILER: &str = "x-amz-checksum-crc32c";

const SIGNED_SEED: &str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
const SIGNED_CHUNKS: [&str; 3] = [
    "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
    "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
    "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
];
const SIGNED_TRAILER_SEED: &str =
    "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e";
const SIGNED_TRAILER_CHUNKS: [&str; 3] = [
    "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
    "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
    "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
];
const TRAILER_SIGNATURE: &str = "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435";

fn example_time() -> reqsign_core::Result<Timestamp> {
    Timestamp::parse_datetime_utc("2013-05-24T00:00:00")
}

fn example_credentials() -> Credential {
    // Public SigV4 example credentials from the S3 documentation.
    Credential {
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        ..Default::default()
    }
}

fn example_head(mode: &str) -> Result<Parts> {
    let request = Request::put("https://s3.amazonaws.com/examplebucket/chunkObject.txt")
        .header(header::CONTENT_ENCODING, "aws-chunked")
        .header("x-amz-content-sha256", mode)
        .header("x-amz-decoded-content-length", "66560")
        .header("x-amz-storage-class", "REDUCED_REDUNDANCY");
    let request = if mode == SIGNED {
        request.header(header::CONTENT_LENGTH, "66824")
    } else {
        // The published trailer vector omits Content-Length in its canonical request.
        request.header("x-amz-trailer", CHECKSUM_TRAILER)
    };
    Ok(request.body(())?.into_parts().0)
}

fn example_trailers() -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        CHECKSUM_TRAILER,
        header::HeaderValue::from_static("sOO8/Q=="),
    );
    trailers
}

#[test]
fn published_s3_streaming_signatures() -> Result<()> {
    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html
    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming-trailers.html
    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let signer = RequestSigner::new("s3", "us-east-1").with_time(example_time()?);
    let credential = example_credentials();
    let first_chunk = vec![b'a'; 65_536];
    let second_chunk = vec![b'a'; 1024];
    let trailers = example_trailers();

    for (mode, seed, chunk_signatures, trailer_signature) in [
        (SIGNED, SIGNED_SEED, SIGNED_CHUNKS, None),
        (
            SIGNED_TRAILER,
            SIGNED_TRAILER_SEED,
            SIGNED_TRAILER_CHUNKS,
            Some(TRAILER_SIGNATURE),
        ),
    ] {
        let mut head = example_head(mode)?;
        let mut stream = signer.sign_streaming_request(&ctx, &mut head, &credential)?;
        let authorization = &head.headers[header::AUTHORIZATION];
        assert!(authorization.is_sensitive());
        assert!(
            authorization
                .to_str()?
                .ends_with(&format!("Signature={seed}"))
        );
        assert_eq!(head.headers["x-amz-date"], "20130524T000000Z");
        assert_eq!(stream.seed_signature(), seed);

        for (chunk, expected) in [first_chunk.as_slice(), second_chunk.as_slice(), &[]]
            .into_iter()
            .zip(chunk_signatures)
        {
            assert_eq!(stream.sign_chunk(chunk)?, Some(expected));
        }

        if let Some(expected) = trailer_signature {
            assert_eq!(stream.sign_trailer(&trailers)?.as_deref(), Some(expected));
        } else {
            assert_eq!(
                stream.sign_trailer(&trailers).unwrap_err().kind(),
                ErrorKind::RequestInvalid
            );
        }
    }
    Ok(())
}

#[test]
fn unsigned_s3_express_trailer_authenticates_only_the_head() -> Result<()> {
    let now = example_time()? + Duration::from_secs(86_401);
    let region = "us-east-2";
    let service = "s3express";
    let session_token = "invented-create-session-token";
    let credential = Credential {
        access_key_id: "fixture-access-key".to_string(),
        secret_access_key: "fixture-secret-key".to_string(),
        session_token: Some(session_token.to_string()),
        expires_in: Some(now + Duration::from_secs(60)),
    };
    let mut head = Request::put("https://bucket.s3express-use2-az1.us-east-2.amazonaws.com/key")
        .header(header::CONTENT_ENCODING, "aws-chunked")
        .header("x-amz-content-sha256", UNSIGNED_TRAILER)
        .header("x-amz-decoded-content-length", "8")
        .header("x-amz-trailer", CHECKSUM_TRAILER)
        .body(())?
        .into_parts()
        .0;
    let sdk_seed = {
        let identity = Credentials::new(
            &credential.access_key_id,
            &credential.secret_access_key,
            credential.session_token.clone(),
            None,
            "offline-fixture",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.session_token_name_override = Some("x-amz-s3session-token");
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(service)
            .time(now.as_system_time())
            .settings(settings)
            .build()?;
        let signable = SignableRequest::new(
            head.method.as_str(),
            head.uri.to_string(),
            head.headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
            SignableBody::StreamingUnsignedPayloadTrailer,
        )?;
        aws_sigv4::http_request::sign(signable, &params.into())?
            .signature()
            .to_owned()
    };

    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let mut stream = RequestSigner::new(service, region)
        .with_time(now)
        .sign_streaming_request(&ctx, &mut head, &credential)?;
    assert_eq!(stream.seed_signature(), sdk_seed);
    let authorization = &head.headers[header::AUTHORIZATION];
    assert!(authorization.is_sensitive());
    assert!(
        authorization
            .to_str()?
            .ends_with(&format!("Signature={sdk_seed}"))
    );
    assert_eq!(head.headers["x-amz-content-sha256"], UNSIGNED_TRAILER);
    assert_eq!(head.headers["x-amz-s3session-token"], session_token);
    assert!(head.headers["x-amz-s3session-token"].is_sensitive());
    assert_eq!(stream.sign_chunk(b"unsigned")?, None);
    assert_eq!(stream.sign_chunk(&[])?, None);
    assert_eq!(stream.sign_trailer(&example_trailers())?, None);
    Ok(())
}

#[derive(Debug)]
struct FailNextMac {
    fail: Arc<AtomicBool>,
    backend: RustCryptoProvider,
}

impl CryptoProvider for FailNextMac {
    fn sha1(&self, input: &[u8]) -> reqsign_core::Result<[u8; 20]> {
        self.backend.sha1(input)
    }

    fn sha256(&self, input: &[u8]) -> reqsign_core::Result<[u8; 32]> {
        self.backend.sha256(input)
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> reqsign_core::Result<[u8; 20]> {
        self.backend.hmac_sha1(key, input)
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> reqsign_core::Result<[u8; 32]> {
        if self.fail.swap(false, Ordering::Relaxed) {
            return Err(Error::unexpected("injected HMAC failure"));
        }
        self.backend.hmac_sha256(key, input)
    }
}

#[test]
fn uploads_keep_independent_chains_and_allow_retrying_a_failed_chunk() -> Result<()> {
    let now = example_time()?;
    let credential = example_credentials();
    let signer = RequestSigner::new("s3", "us-east-1").with_time(now);
    let fail = Arc::new(AtomicBool::new(false));
    let (mut stream, mut other) = {
        let ctx = Context::new().with_crypto(FailNextMac {
            fail: fail.clone(),
            backend: RustCryptoProvider::new(),
        });
        let mut head = example_head(SIGNED_TRAILER)?;
        head.headers.insert(
            "x-amz-date",
            header::HeaderValue::from_static("20130524T000000Z"),
        );
        let stream = signer.sign_streaming_request(&ctx, &mut head, &credential)?;
        let mut other_head = example_head(SIGNED_TRAILER)?;
        other_head.uri = "https://s3.amazonaws.com/examplebucket/other".parse()?;
        let other = signer.sign_streaming_request(&ctx, &mut other_head, &credential)?;
        (stream, other)
    };
    assert_ne!(stream.seed_signature(), other.seed_signature());
    let first_chunk = vec![b'a'; 65_536];
    assert_eq!(
        stream.sign_chunk(&first_chunk)?,
        Some(SIGNED_TRAILER_CHUNKS[0])
    );
    assert_ne!(
        other.sign_chunk(&first_chunk)?,
        Some(SIGNED_TRAILER_CHUNKS[0])
    );
    assert_eq!(
        stream.sign_chunk(&vec![b'a'; 1024])?,
        Some(SIGNED_TRAILER_CHUNKS[1])
    );

    let trailers = example_trailers();
    let error = stream.sign_trailer(&trailers).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert!(error.to_string().contains("final zero-length AWS chunk"));

    fail.store(true, Ordering::Relaxed);
    let error = stream.sign_chunk(&[]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(error.to_string().contains("injected HMAC failure"));
    assert_eq!(stream.sign_chunk(&[])?, Some(SIGNED_TRAILER_CHUNKS[2]));
    assert_eq!(
        stream.sign_trailer(&trailers)?.as_deref(),
        Some(TRAILER_SIGNATURE)
    );
    assert_eq!(
        stream.sign_chunk(b"later").unwrap_err().kind(),
        ErrorKind::RequestInvalid
    );

    let debug = format!("{stream:?}");
    let signing_key = v4::generate_signing_key(
        &credential.secret_access_key,
        now.as_system_time(),
        "us-east-1",
        "s3",
    );
    assert!(!debug.contains(stream.seed_signature()));
    assert!(!debug.contains(SIGNED_TRAILER_CHUNKS[2]));
    assert!(!debug.contains(&format!("{:?}", signing_key.as_ref())));
    assert!(!debug.contains(&hex::encode(signing_key)));
    Ok(())
}

#[test]
fn streaming_head_rejects_inconsistent_signing_inputs_atomically() -> Result<()> {
    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let now = example_time()?;
    let signer = RequestSigner::new("s3", "us-east-1").with_time(now);
    let mut credential = example_credentials();
    for (name, value) in [
        ("x-amz-content-sha256", SIGNED_TRAILER),
        ("x-amz-date", "20130523T235959Z"),
    ] {
        let mut head = example_head(SIGNED)?;
        head.headers
            .append(name, header::HeaderValue::from_static(value));
        let original = head.clone();
        let error = signer
            .sign_streaming_request(&ctx, &mut head, &credential)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert!(error.to_string().contains(name));
        assert_eq!(head.headers, original.headers);
        assert_eq!(head.uri, original.uri);
    }

    credential.expires_in = Some(now + Duration::from_secs(10));
    let mut head = example_head(SIGNED)?;
    let original = head.clone();
    let error = signer
        .sign_streaming_request(&ctx, &mut head, &credential)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(head.headers, original.headers);
    assert_eq!(head.uri, original.uri);
    Ok(())
}
