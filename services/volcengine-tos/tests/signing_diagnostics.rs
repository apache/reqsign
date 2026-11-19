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

mod common;

use std::sync::{Mutex, Once};
use std::time::Duration;

use http::header::AUTHORIZATION;
use reqsign_core::SignRequest;
use reqsign_volcengine_tos::{Credential, RequestSigner};

const ACCESS_KEY_ID: &str = "synthetic-volcengine-access-key-id";
const SECRET_ACCESS_KEY: &str = "synthetic-volcengine-secret-access-key";
const SESSION_TOKEN: &str = "synthetic-volcengine-session-token";

static CAPTURED_LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static LOGGER: CapturingLogger = CapturingLogger;
static INIT_LOGGER: Once = Once::new();

struct CapturingLogger;

impl log::Log for CapturingLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        CAPTURED_LOGS
            .lock()
            .expect("captured logs lock poisoned")
            .push(record.args().to_string());
    }

    fn flush(&self) {}
}

fn start_log_capture() {
    INIT_LOGGER.call_once(|| {
        log::set_logger(&LOGGER).expect("test logger must be installed once");
        log::set_max_level(log::LevelFilter::Debug);
    });
    CAPTURED_LOGS
        .lock()
        .expect("captured logs lock poisoned")
        .clear();
}

fn captured_logs() -> String {
    CAPTURED_LOGS
        .lock()
        .expect("captured logs lock poisoned")
        .join("\n")
}

fn signature_from_authorization(authorization: &str) -> &str {
    authorization
        .split_once("Signature=")
        .expect("authorization must contain a signature")
        .1
}

fn signature_from_query(uri: &str) -> &str {
    uri.split_once("X-Tos-Signature=")
        .expect("presigned URI must contain a signature")
        .1
        .split('&')
        .next()
        .expect("signature must be terminated by the query separator")
}

#[tokio::test]
async fn signing_diagnostics_redact_credential_material() -> anyhow::Result<()> {
    let credential =
        Credential::new(ACCESS_KEY_ID, SECRET_ACCESS_KEY).with_session_token(SESSION_TOKEN);
    let signer = RequestSigner::new("cn-beijing");

    start_log_capture();
    let mut parts = http::Request::get("https://bucket.tos-cn-beijing.volces.com/object")
        .body(())?
        .into_parts()
        .0;
    signer
        .sign_request(
            &crate::common::test_context(),
            &mut parts,
            Some(&credential),
            None,
        )
        .await?;

    let authorization = parts.headers[AUTHORIZATION].to_str()?.to_string();
    let signature = signature_from_authorization(&authorization);
    let token = parts.headers["x-tos-security-token"].to_str()?;

    assert_eq!(token, SESSION_TOKEN);
    assert!(parts.headers[AUTHORIZATION].is_sensitive());
    assert!(parts.headers["x-tos-security-token"].is_sensitive());

    let logs = captured_logs();
    assert!(logs.contains("string to sign: TOS4-HMAC-SHA256"));
    assert!(logs.contains("authorization: TOS4-HMAC-SHA256 Credential="));
    for secret in [ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, signature] {
        assert!(
            !logs.contains(secret),
            "signing logs must not contain credential material: {secret}"
        );
    }

    let debug = format!("{parts:?}");
    for secret in [ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, signature] {
        assert!(
            !debug.contains(secret),
            "signed request Debug must not contain credential material: {secret}"
        );
    }

    start_log_capture();
    let mut parts = http::Request::get("https://bucket.tos-cn-beijing.volces.com/object")
        .body(())?
        .into_parts()
        .0;
    signer
        .sign_request(
            &crate::common::test_context(),
            &mut parts,
            Some(&credential),
            Some(Duration::from_secs(3600)),
        )
        .await?;

    let uri = parts.uri.to_string();
    let signature = signature_from_query(&uri);
    assert!(uri.contains(&format!("X-Tos-Security-Token={SESSION_TOKEN}")));

    let logs = captured_logs();
    assert!(logs.contains("string to sign: TOS4-HMAC-SHA256"));
    for secret in [ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, signature] {
        assert!(
            !logs.contains(secret),
            "presigning logs must not contain credential material: {secret}"
        );
    }

    Ok(())
}
