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

use super::{assert_provider_reads_probe, create_test_context};
use log::warn;
use reqsign_core::time::Timestamp;
use reqsign_core::{ErrorKind, ProvideCredential, Result};
use reqsign_google::TokenCredentialProvider;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The last whole second jiff can represent. A saturated relative expiry must
// land here rather than panicking in `Timestamp + Duration`.
const MAX_JIFF_UNIX_SECOND: i64 = 253_402_207_200;

fn temp_token_file() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!("reqsign-google-token-{nanos}.txt"))
}

#[tokio::test]
async fn test_token_credential_provider_inline() -> Result<()> {
    let ctx = create_test_context();
    let expires_at = Timestamp::now() + Duration::from_secs(3600);
    let provider = TokenCredentialProvider::new("test-access-token").with_expires_at(expires_at);

    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided");

    assert!(credential.has_token());
    assert!(credential.has_valid_token());

    let token = credential.token.as_ref().unwrap();
    assert_eq!("test-access-token", token.access_token);
    assert_eq!(Some(expires_at), token.expires_at);

    Ok(())
}

#[tokio::test]
async fn test_token_credential_provider_from_path() -> Result<()> {
    let path = temp_token_file();
    fs::write(&path, "test-access-token\n").expect("token file must be written");

    let ctx = create_test_context();
    let provider = TokenCredentialProvider::from_path(path.to_string_lossy())
        .with_expires_in(Duration::from_secs(3600));

    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided");

    fs::remove_file(&path).expect("token file must be removed");

    assert!(credential.has_token());
    assert!(credential.has_valid_token());

    let token = credential.token.as_ref().unwrap();
    assert_eq!("test-access-token", token.access_token);
    assert!(token.expires_at.is_some());

    Ok(())
}

#[tokio::test]
async fn test_token_credential_provider_relative_expiry_saturates_for_inline_and_file_tokens()
-> Result<()> {
    let ctx = create_test_context();

    let inline = TokenCredentialProvider::new("inline-access-token")
        .with_expires_in(Duration::MAX)
        .provide_credential(&ctx)
        .await?
        .expect("inline credential must be provided");
    let inline_token = inline
        .token
        .as_ref()
        .expect("inline credential must contain a token");
    assert_eq!("inline-access-token", inline_token.access_token);
    assert_eq!(
        Some(MAX_JIFF_UNIX_SECOND),
        inline_token
            .expires_at
            .map(|expires_at| expires_at.as_second())
    );

    let path = temp_token_file();
    fs::write(&path, "file-access-token\n").expect("token file must be written");
    let result = TokenCredentialProvider::from_path(path.to_string_lossy())
        .with_expires_in(Duration::MAX)
        .provide_credential(&ctx)
        .await;
    fs::remove_file(&path).expect("token file must be removed");

    let file = result?.expect("file credential must be provided");
    let file_token = file
        .token
        .as_ref()
        .expect("file credential must contain a token");
    assert_eq!("file-access-token", file_token.access_token);
    assert_eq!(
        Some(MAX_JIFF_UNIX_SECOND),
        file_token
            .expires_at
            .map(|expires_at| expires_at.as_second())
    );

    Ok(())
}

#[tokio::test]
async fn test_token_credential_provider_relative_expiry_preserves_error_order() {
    let ctx = create_test_context();

    let err = TokenCredentialProvider::new("   ")
        .with_expires_in(Duration::MAX)
        .provide_credential(&ctx)
        .await
        .expect_err("empty inline token must fail before expiry is used");
    assert_eq!(ErrorKind::CredentialInvalid, err.kind());
    assert!(err.to_string().contains("access token is empty"));

    let missing = temp_token_file();
    let err = TokenCredentialProvider::from_path(missing.to_string_lossy())
        .with_expires_in(Duration::MAX)
        .provide_credential(&ctx)
        .await
        .expect_err("missing token file must fail before expiry is used");
    assert_eq!(ErrorKind::Unexpected, err.kind());
    assert!(err.to_string().contains("failed to read file"));

    let invalid_utf8 = temp_token_file();
    fs::write(&invalid_utf8, [0xff, 0xfe]).expect("token file must be written");
    let result = TokenCredentialProvider::from_path(invalid_utf8.to_string_lossy())
        .with_expires_in(Duration::MAX)
        .provide_credential(&ctx)
        .await;
    fs::remove_file(&invalid_utf8).expect("token file must be removed");

    let err = result.expect_err("invalid UTF-8 must fail before expiry is used");
    assert_eq!(ErrorKind::Unexpected, err.kind());
    assert!(err.to_string().contains("invalid UTF-8 in token file"));
}

#[tokio::test]
async fn test_token_credential_provider_empty_token() {
    let ctx = create_test_context();
    let provider = TokenCredentialProvider::new("   ");

    let err = provider
        .provide_credential(&ctx)
        .await
        .expect_err("empty token must fail");
    assert_eq!(ErrorKind::CredentialInvalid, err.kind());
}

#[tokio::test]
async fn test_token_credential_provider_live() -> Result<()> {
    if std::env::var("REQSIGN_GOOGLE_TEST_TOKEN").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_TOKEN is not set, skipped");
        return Ok(());
    }

    let access_token = std::env::var("REQSIGN_GOOGLE_ACCESS_TOKEN")
        .expect("REQSIGN_GOOGLE_ACCESS_TOKEN must be set");
    let provider =
        TokenCredentialProvider::new(access_token).with_expires_in(Duration::from_secs(1800));
    assert_provider_reads_probe(provider, create_test_context()).await
}
