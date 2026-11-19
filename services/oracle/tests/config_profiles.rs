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
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::header::{AUTHORIZATION, DATE};
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, ErrorKind, FileRead, ProvideCredential, Result, Signer, StaticEnv,
};
use reqsign_oracle::{
    ConfigFileCredentialProvider, Credential, DefaultCredentialProvider, RequestSigner,
};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{RsaPrivateKey, RsaPublicKey};

const CONFIG_PATH: &str = "/synthetic/oci/config";
const DEFAULT_KEY: &str = "/synthetic/keys/default.pem";
const FIELDS: [&str; 4] = ["tenancy", "user", "key_file", "fingerprint"];
const DEFAULT_VALUES: [&str; 4] = [
    "default-tenancy",
    "default-user",
    DEFAULT_KEY,
    "default-fingerprint",
];

// Only these in-memory files exist; tests cannot fall through to ~/.oci or the network.
#[derive(Clone, Default)]
struct Files {
    contents: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    reads: Arc<Mutex<Vec<String>>>,
}

impl std::fmt::Debug for Files {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Files").finish_non_exhaustive()
    }
}

impl Files {
    fn insert(&self, path: &str, content: impl Into<Vec<u8>>) {
        self.contents
            .lock()
            .unwrap()
            .insert(path.into(), content.into());
    }

    fn reads(&self) -> Vec<String> {
        self.reads.lock().unwrap().clone()
    }
}

impl FileRead for Files {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.reads.lock().unwrap().push(path.into());
        self.contents
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| Error::unexpected("synthetic file does not exist"))
    }
}

fn section(name: &str, values: &[Option<&str>; 4]) -> String {
    let mut result = format!("[{name}]\n");
    for (field, value) in FIELDS.into_iter().zip(values) {
        if let Some(value) = value {
            result.push_str(&format!("{field}={value}\n"));
        }
    }
    result
}

fn defaults() -> String {
    section("DEFAULT", &DEFAULT_VALUES.map(Some))
}

fn context(config: &str, profile: Option<&str>) -> (Context, Files) {
    let files = Files::default();
    files.insert(CONFIG_PATH, config.as_bytes().to_vec());
    let mut envs = HashMap::from([("OCI_CONFIG_FILE".into(), CONFIG_PATH.into())]);
    if let Some(profile) = profile {
        envs.insert("OCI_PROFILE".into(), profile.into());
    }
    let ctx = Context::new()
        .with_file_read(files.clone())
        .with_env(StaticEnv {
            home_dir: Some("/synthetic/home".into()),
            envs,
        });
    (ctx, files)
}

async fn load(ctx: &Context) -> Credential {
    ConfigFileCredentialProvider::new()
        .provide_credential(ctx)
        .await
        .expect("config must load")
        .expect("profile must resolve to credentials")
}

fn values(credential: &Credential) -> [&str; 4] {
    [
        &credential.tenancy,
        &credential.user,
        &credential.key_file,
        &credential.fingerprint,
    ]
}

#[tokio::test]
async fn named_profile_inherits_each_missing_field() {
    for missing in 0..FIELDS.len() {
        let overrides = [
            "selected-tenancy",
            "selected-user",
            "/selected.pem",
            "selected-fingerprint",
        ];
        let mut selected = overrides.map(Some);
        selected[missing] = None;
        let config = defaults() + &section("ADMIN", &selected);
        let (ctx, files) = context(&config, Some("ADMIN"));

        let credential = load(&ctx).await;
        let mut expected = overrides;
        expected[missing] = DEFAULT_VALUES[missing];
        assert_eq!(values(&credential), expected, "missing {}", FIELDS[missing]);
        assert_eq!(files.reads(), [CONFIG_PATH]);
    }
}

#[tokio::test]
async fn empty_named_profile_inherits_all_defaults() {
    let (ctx, _) = context(&(defaults() + "[ADMIN]\n"), Some("ADMIN"));
    assert_eq!(values(&load(&ctx).await), DEFAULT_VALUES);
}

#[tokio::test]
async fn complete_named_profile_overrides_defaults_and_works_without_them() {
    let expected = [
        "selected-tenancy",
        "selected-user",
        "/selected.pem",
        "selected-fingerprint",
    ];
    for prefix in [String::new(), defaults()] {
        let config = prefix + &section("ADMIN", &expected.map(Some));
        let (ctx, _) = context(&config, Some("ADMIN"));
        assert_eq!(values(&load(&ctx).await), expected);
    }
}

#[tokio::test]
async fn default_profile_is_selected_implicitly_or_explicitly() {
    let config = defaults() + "[ADMIN]\nuser=other-user\n";
    for profile in [None, Some("DEFAULT")] {
        let (ctx, _) = context(&config, profile);
        let before = Timestamp::now();
        let credential = load(&ctx).await;
        assert_eq!(values(&credential), DEFAULT_VALUES);
        let refresh_at = credential
            .expires_in
            .expect("file credentials must be refreshed");
        assert!(refresh_at >= before + Duration::from_secs(600));
        assert!(refresh_at <= Timestamp::now() + Duration::from_secs(600));
    }
}

#[tokio::test]
async fn missing_profile_does_not_fall_back_to_default_or_other_profiles() -> Result<()> {
    let config = defaults() + "[ADMIN]\nuser=other-user\n";
    for profile in ["MISSING", "admin", "default"] {
        let (ctx, _) = context(&config, Some(profile));
        assert!(
            ConfigFileCredentialProvider::new()
                .provide_credential(&ctx)
                .await?
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn missing_fields_are_not_inherited_from_sibling_or_general_sections() -> Result<()> {
    for missing in 0..FIELDS.len() {
        let mut incomplete = DEFAULT_VALUES.map(Some);
        incomplete[missing] = None;
        let general = format!("{}=general-value\n", FIELDS[missing]);
        let config = general
            + &section("DEFAULT", &incomplete)
            + &section("SIBLING", &DEFAULT_VALUES.map(Some))
            + "[ADMIN]\n";
        let (ctx, _) = context(&config, Some("ADMIN"));
        assert!(
            ConfigFileCredentialProvider::new()
                .provide_credential(&ctx)
                .await?
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn explicit_empty_values_are_not_replaced_by_defaults() {
    for empty in 0..FIELDS.len() {
        let mut selected = [None; 4];
        selected[empty] = Some("");
        let (ctx, _) = context(&(defaults() + &section("ADMIN", &selected)), Some("ADMIN"));
        let credential = load(&ctx).await;
        let mut expected = DEFAULT_VALUES;
        expected[empty] = "";
        assert_eq!(values(&credential), expected);
    }
}

#[tokio::test]
async fn key_paths_preserve_literal_backslashes_and_quotes() {
    for key_file in [
        r"C:\new\test\api_key.pem",
        r"\\server\tenant\api_key.pem",
        r"keys\new\test.pem",
        r#"/keys/owner's api_key.pem"#,
        r#"/keys/"quoted"/api_key.pem"#,
    ] {
        for inherited in [false, true] {
            let mut base = DEFAULT_VALUES.map(Some);
            base[2] = Some(key_file);
            let config = section("DEFAULT", &base) + if inherited { "[ADMIN]\n" } else { "" };
            let (ctx, _) = context(&config, inherited.then_some("ADMIN"));
            assert_eq!(load(&ctx).await.key_file, key_file);
        }
    }
}

#[tokio::test]
async fn home_expansion_applies_after_profile_resolution() {
    for inherited in [false, true] {
        let mut base = DEFAULT_VALUES.map(Some);
        base[2] = Some("~/.oci/default.pem");
        let selected = if inherited {
            "[ADMIN]\n"
        } else {
            "[ADMIN]\nkey_file=~/.oci/admin.pem\n"
        };
        let (ctx, _) = context(&(section("DEFAULT", &base) + selected), Some("ADMIN"));
        let expected = ctx
            .expand_home_dir(if inherited {
                "~/.oci/default.pem"
            } else {
                "~/.oci/admin.pem"
            })
            .unwrap();
        assert_eq!(load(&ctx).await.key_file, expected);
    }
}

#[tokio::test]
async fn provider_rereads_selected_profile_and_defaults() {
    let (ctx, files) = context(&(defaults() + "[ADMIN]\n"), Some("ADMIN"));
    assert_eq!(load(&ctx).await.user, "default-user");
    files.insert(
        CONFIG_PATH,
        (defaults() + "[ADMIN]\nuser=rotated-user\n").into_bytes(),
    );
    assert_eq!(load(&ctx).await.user, "rotated-user");
    let changed = defaults().replace("default-tenancy", "rotated-tenancy") + "[ADMIN]\n";
    files.insert(CONFIG_PATH, changed.into_bytes());
    assert_eq!(load(&ctx).await.tenancy, "rotated-tenancy");
    assert_eq!(files.reads(), [CONFIG_PATH, CONFIG_PATH, CONFIG_PATH]);
}

#[tokio::test]
async fn unreadable_files_and_incomplete_profiles_remain_absent() -> Result<()> {
    for config in ["", "[DEFAULT]\n", "[ADMIN]\nuser=only-user\n"] {
        let (ctx, _) = context(config, Some("ADMIN"));
        assert!(
            ConfigFileCredentialProvider::new()
                .provide_credential(&ctx)
                .await?
                .is_none()
        );
    }
    let (ctx, files) = context(&defaults(), None);
    files.contents.lock().unwrap().clear();
    assert!(
        ConfigFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn malformed_config_remains_a_configuration_error() {
    let (ctx, _) = context("[DEFAULT\nuser=broken\n", None);
    let error = ConfigFileCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
}

#[tokio::test]
async fn home_directory_is_only_required_for_tilde_paths() -> Result<()> {
    let files = Files::default();
    files.insert(CONFIG_PATH, defaults().into_bytes());
    let ctx = Context::new()
        .with_file_read(files.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([("OCI_CONFIG_FILE".into(), CONFIG_PATH.into())]),
        });
    assert_eq!(values(&load(&ctx).await), DEFAULT_VALUES);

    files.insert(
        CONFIG_PATH,
        (defaults() + "[ADMIN]\nkey_file=~/.oci/admin.pem\n").into_bytes(),
    );
    let ctx = ctx.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([
            ("OCI_CONFIG_FILE".into(), CONFIG_PATH.into()),
            ("OCI_PROFILE".into(), "ADMIN".into()),
        ]),
    });
    assert!(
        ConfigFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .is_err()
    );

    let reads = files.reads();
    let ctx = ctx.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::new(),
    });
    assert!(
        ConfigFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .is_err()
    );
    assert_eq!(files.reads(), reads);
    Ok(())
}

#[tokio::test]
async fn default_chain_loads_inherited_profile_and_respects_removed_slot() -> Result<()> {
    let (ctx, files) = context(&(defaults() + "[ADMIN]\nuser=admin-user\n"), Some("ADMIN"));
    let credential = DefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await?
        .unwrap();
    assert_eq!(credential.user, "admin-user");
    assert_eq!(credential.tenancy, "default-tenancy");
    let reads = files.reads();
    assert!(
        DefaultCredentialProvider::builder()
            .no_config_file()
            .build()
            .provide_credential(&ctx)
            .await?
            .is_none()
    );
    assert_eq!(files.reads(), reads);
    Ok(())
}

#[tokio::test]
async fn inherited_profile_produces_a_verifiable_signed_request() -> anyhow::Result<()> {
    let key = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let (ctx, files) = context(&(defaults() + "[ADMIN]\nuser=admin-user\n"), Some("ADMIN"));
    files.insert(
        DEFAULT_KEY,
        key.to_pkcs8_pem(LineEnding::LF)?.as_bytes().to_vec(),
    );
    let mut parts = http::Request::get("https://iaas.example.com/instances?name=a%2Fb&name=c+d")
        .header("x-original", "preserved")
        .body(())?
        .into_parts()
        .0;
    let original_uri = parts.uri.clone();

    Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner::new())
        .sign(&mut parts, None)
        .await?;

    assert_eq!(parts.uri, original_uri);
    assert_eq!(parts.headers["x-original"], "preserved");
    let authorization = parts.headers[AUTHORIZATION].to_str()?;
    assert!(authorization.contains("keyId=\"default-tenancy/admin-user/default-fingerprint\""));
    let signature = authorization
        .split("signature=\"")
        .nth(1)
        .and_then(|value| value.strip_suffix('"'))
        .expect("signature must exist");
    let signature = STANDARD.decode(signature)?;
    let signature = Signature::try_from(signature.as_slice())?;
    let signing_input = format!(
        "date: {}\n(request-target): get {}\nhost: {}",
        parts.headers[DATE].to_str()?,
        original_uri.path_and_query().unwrap(),
        original_uri.authority().unwrap()
    );
    VerifyingKey::<Sha256>::new(RsaPublicKey::from(&key))
        .verify(signing_input.as_bytes(), &signature)?;
    assert_eq!(files.reads(), [CONFIG_PATH, DEFAULT_KEY]);
    Ok(())
}
