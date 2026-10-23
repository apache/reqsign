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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use reqsign_core::{
    Context, Error, HttpSend, OsEnv, ProvideCredential, Result, Signer, SigningCredential,
    StaticEnv,
};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_openstack_keystone::{
    Credential, DefaultCredentialProvider, EnvCredentialProvider, KeystoneCredentialProvider,
    RequestSigner,
};

const AUTH_URL: &str = "https://keystone.example.com/v3";
const SUBJECT_TOKEN: &str = "subject-token-value";
const SWIFT_PUBLIC_URL: &str = "https://swift.example.com/v1/AUTH_test";
const SWIFT_INTERNAL_URL: &str = "http://swift-internal:8080/v1/AUTH_test";

/// A catalog as Keystone returns it for a project scoped token. The internal
/// endpoint only carries `region_id`, the field Keystone fills in since v3.2;
/// the public endpoint still carries the deprecated `region` as well.
const SCOPED_CATALOG: &str = r#"[
  {
    "type": "object-store",
    "endpoints": [
      {
        "interface": "public",
        "url": "https://swift.example.com/v1/AUTH_test",
        "region_id": "RegionOne",
        "region": "RegionOne"
      },
      {
        "interface": "internal",
        "url": "http://swift-internal:8080/v1/AUTH_test",
        "region_id": "RegionOne"
      }
    ]
  },
  {
    "type": "identity",
    "endpoints": [
      {
        "interface": "public",
        "url": "https://keystone.example.com/v3",
        "region_id": "RegionOne"
      }
    ]
  }
]"#;

/// Mock Keystone that records the requests a provider sends and replies with a
/// scripted token response.
#[derive(Clone, Debug)]
struct MockKeystone {
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
    status: StatusCode,
    subject_token: Option<&'static str>,
    expires_at: Option<&'static str>,
    catalog: &'static str,
    transport_error: Option<&'static str>,
}

impl MockKeystone {
    fn scoped() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            status: StatusCode::CREATED,
            subject_token: Some(SUBJECT_TOKEN),
            expires_at: Some("2126-01-01T00:00:00.000000Z"),
            catalog: SCOPED_CATALOG,
            transport_error: None,
        }
    }

    fn unscoped() -> Self {
        Self {
            catalog: "[]",
            ..Self::scoped()
        }
    }

    fn without_expiration() -> Self {
        Self {
            expires_at: None,
            ..Self::scoped()
        }
    }

    fn without_subject_token() -> Self {
        Self {
            subject_token: None,
            ..Self::scoped()
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            subject_token: None,
            ..Self::scoped()
        }
    }

    fn transport_failure() -> Self {
        Self {
            transport_error: Some("connection refused"),
            ..Self::scoped()
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("lock poisoned").len()
    }

    fn last_request(&self) -> Request<Bytes> {
        self.requests
            .lock()
            .expect("lock poisoned")
            .last()
            .expect("provider must send a request")
            .clone()
    }
}

impl HttpSend for MockKeystone {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        self.requests.lock().expect("lock poisoned").push(request);

        if let Some(message) = self.transport_error {
            return Err(Error::unexpected(message));
        }

        let expires_at = match self.expires_at {
            Some(expires_at) => format!("\"{expires_at}\""),
            None => "null".to_string(),
        };
        let body = format!(
            r#"{{"token":{{"expires_at":{expires_at},"catalog":{}}}}}"#,
            self.catalog
        );

        let mut response = Response::builder().status(self.status);
        if let Some(subject_token) = self.subject_token {
            response = response.header("X-Subject-Token", subject_token);
        }

        Ok(response
            .body(Bytes::from(body))
            .expect("response must build"))
    }
}

fn scoped_provider(auth_url: &str) -> KeystoneCredentialProvider {
    KeystoneCredentialProvider::new(auth_url)
        .with_username("testuser")
        .with_password("testpass")
        .with_user_domain_name("Default")
        .with_project_name("testproject")
        .with_project_domain_name("Default")
}

fn envs(envs: impl IntoIterator<Item = (&'static str, &'static str)>) -> HashMap<String, String> {
    envs.into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[tokio::test]
async fn keystone_provider_authenticates_and_returns_catalog() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new().with_http_send(mock.clone());

    let credential = scoped_provider(AUTH_URL)
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert_eq!(SUBJECT_TOKEN, credential.token);
    assert!(credential.is_valid(), "credential must be valid");
    assert!(credential.expires_at.is_some(), "expires_at must be set");

    assert_eq!(
        Some(SWIFT_PUBLIC_URL),
        credential.endpoint("object-store", "public")
    );
    assert_eq!(
        Some(SWIFT_INTERNAL_URL),
        credential.endpoint_in_region("object-store", "internal", "RegionOne")
    );
    assert_eq!(
        None,
        credential.endpoint_in_region("object-store", "public", "RegionTwo")
    );

    let request = mock.last_request();
    assert_eq!(http::Method::POST, request.method());
    assert_eq!(format!("{AUTH_URL}/auth/tokens"), request.uri().to_string());
    assert_eq!(
        "application/json",
        request.headers()["content-type"].to_str().unwrap()
    );

    let body: serde_json::Value =
        serde_json::from_slice(request.body()).expect("auth request must be JSON");
    assert_eq!("password", body["auth"]["identity"]["methods"][0]);
    assert_eq!(
        "testuser",
        body["auth"]["identity"]["password"]["user"]["name"]
    );
    assert_eq!(
        "Default",
        body["auth"]["identity"]["password"]["user"]["domain"]["name"]
    );
    assert_eq!("testproject", body["auth"]["scope"]["project"]["name"]);
}

#[tokio::test]
async fn keystone_provider_rejects_bad_credentials() {
    let mock = MockKeystone::unauthorized();
    let ctx = Context::new().with_http_send(mock);

    let result = scoped_provider(AUTH_URL).provide_credential(&ctx).await;
    assert!(result.is_err(), "bad password must fail");
}

#[tokio::test]
async fn keystone_provider_requires_subject_token() {
    let mock = MockKeystone::without_subject_token();
    let ctx = Context::new().with_http_send(mock);

    let err = scoped_provider(AUTH_URL)
        .provide_credential(&ctx)
        .await
        .expect_err("a token response without X-Subject-Token must fail");
    assert!(
        err.to_string().contains("X-Subject-Token"),
        "error must mention the missing header, got: {err}"
    );
}

#[tokio::test]
async fn keystone_provider_reports_transport_errors() {
    let mock = MockKeystone::transport_failure();
    let ctx = Context::new().with_http_send(mock);

    let result = scoped_provider(AUTH_URL).provide_credential(&ctx).await;
    assert!(result.is_err(), "transport errors must not be swallowed");
}

#[tokio::test]
async fn keystone_provider_skips_without_credentials() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new().with_http_send(mock.clone());

    let credential = KeystoneCredentialProvider::new(AUTH_URL)
        .provide_credential(&ctx)
        .await
        .expect("missing credentials must not error");

    assert!(credential.is_none(), "missing credentials must skip");
    assert_eq!(0, mock.request_count(), "no request must be sent");
}

#[tokio::test]
async fn token_without_expiration_is_usable() {
    let mock = MockKeystone::without_expiration();
    let ctx = Context::new().with_http_send(mock);

    let credential = scoped_provider(AUTH_URL)
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(credential.expires_at.is_none());
    assert!(credential.is_valid(), "a token without expiry stays valid");
}

#[tokio::test]
async fn unscoped_token_has_empty_catalog() {
    let mock = MockKeystone::unscoped();
    let ctx = Context::new().with_http_send(mock);

    let credential = KeystoneCredentialProvider::new(AUTH_URL)
        .with_username("testuser")
        .with_password("testpass")
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!credential.token.is_empty());
    assert!(credential.is_valid());
    assert!(
        credential.service_catalog.is_empty(),
        "unscoped tokens carry no catalog"
    );
    assert_eq!(None, credential.endpoint("object-store", "public"));
}

#[tokio::test]
async fn env_provider_reads_standard_openstack_variables() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: envs([
                ("OS_AUTH_URL", AUTH_URL),
                ("OS_USERNAME", "testuser"),
                ("OS_PASSWORD", "testpass"),
                ("OS_USER_DOMAIN_NAME", "Example"),
                ("OS_PROJECT_NAME", "testproject"),
            ]),
        });

    let credential = EnvCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert_eq!(SUBJECT_TOKEN, credential.token);

    // Without OS_PROJECT_DOMAIN_NAME the project domain follows the user domain.
    let body: serde_json::Value =
        serde_json::from_slice(mock.last_request().body()).expect("auth request must be JSON");
    assert_eq!(
        "Example",
        body["auth"]["identity"]["password"]["user"]["domain"]["name"]
    );
    assert_eq!(
        "Example",
        body["auth"]["scope"]["project"]["domain"]["name"]
    );
    assert_eq!("testproject", body["auth"]["scope"]["project"]["name"]);
}

#[tokio::test]
async fn env_provider_defaults_to_the_default_domain() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: envs([
                ("OS_AUTH_URL", AUTH_URL),
                ("OS_USERNAME", "testuser"),
                ("OS_PASSWORD", "testpass"),
            ]),
        });

    let credential = EnvCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");
    assert_eq!(SUBJECT_TOKEN, credential.token);

    let body: serde_json::Value =
        serde_json::from_slice(mock.last_request().body()).expect("auth request must be JSON");
    assert_eq!(
        "Default",
        body["auth"]["identity"]["password"]["user"]["domain"]["name"]
    );
    assert!(
        body["auth"]["scope"].is_null(),
        "without OS_PROJECT_NAME the token stays unscoped"
    );
}

#[tokio::test]
async fn env_provider_skips_without_variables() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

    let credential = EnvCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("missing variables must not error");

    assert!(credential.is_none());
    assert_eq!(0, mock.request_count(), "no request must be sent");
}

#[tokio::test]
async fn default_provider_uses_the_env_provider() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: envs([
                ("OS_AUTH_URL", AUTH_URL),
                ("OS_USERNAME", "testuser"),
                ("OS_PASSWORD", "testpass"),
                ("OS_PROJECT_NAME", "testproject"),
            ]),
        });

    let credential = DefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert_eq!(SUBJECT_TOKEN, credential.token);
    assert_eq!(
        Some(SWIFT_PUBLIC_URL),
        credential.endpoint("object-store", "public")
    );
}

#[tokio::test]
async fn signer_signs_with_the_token_and_reuses_it() {
    let mock = MockKeystone::scoped();
    let ctx = Context::new().with_http_send(mock.clone());

    let signer = Signer::new(ctx, scoped_provider(AUTH_URL), RequestSigner);

    let mut first = http::Request::builder()
        .method("GET")
        .uri(format!("{SWIFT_PUBLIC_URL}/container/object"))
        .body(())
        .unwrap()
        .into_parts()
        .0;
    signer
        .sign(&mut first, None)
        .await
        .expect("signing must succeed");

    let mut second = http::Request::builder()
        .method("PUT")
        .uri(format!("{SWIFT_PUBLIC_URL}/container/other"))
        .body(())
        .unwrap()
        .into_parts()
        .0;
    signer
        .sign(&mut second, None)
        .await
        .expect("signing must succeed");

    assert_eq!(SUBJECT_TOKEN, first.headers["x-auth-token"]);
    assert_eq!(SUBJECT_TOKEN, second.headers["x-auth-token"]);
    assert!(
        first.headers["x-auth-token"].is_sensitive(),
        "the token header must be marked sensitive"
    );
    assert_eq!(
        1,
        mock.request_count(),
        "the second sign must reuse the cached token"
    );
}

/// Integration test against a real Keystone service.
///
/// Requires:
/// - REQSIGN_OPENSTACK_KEYSTONE_TEST=on
/// - OS_AUTH_URL
/// - OS_USERNAME
/// - OS_PASSWORD
/// - OS_USER_DOMAIN_NAME (optional, defaults to "Default")
/// - OS_PROJECT_NAME (optional)
#[tokio::test]
async fn test_real_keystone_env_credential_provider() {
    let _ = dotenvy::dotenv();
    let _ = env_logger::builder().is_test(true).try_init();

    if std::env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST").unwrap_or_default() != "on" {
        return;
    }

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let credential: Credential = EnvCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!credential.token.is_empty(), "token must not be empty");
    assert!(credential.is_valid(), "credential must be valid");

    println!("Token obtained successfully");
    println!("Expires at: {:?}", credential.expires_at);
    println!(
        "Service catalog entries: {}",
        credential.service_catalog.len()
    );

    for entry in &credential.service_catalog {
        println!("  Service: {}", entry.service_type);
        for endpoint in &entry.endpoints {
            println!(
                "    {} ({:?}): {}",
                endpoint.interface,
                endpoint.region_name(),
                endpoint.url
            );
        }
    }
}
