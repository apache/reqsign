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

use crate::{
    AccountSasConfig, AccountSasGrant, AccountSasGranter, AccountSasPermissions,
    AccountSasResourceTypes, AccountSasServices, AccountSasVersion, Credential, RequestSigner,
    SasIpRange, SasProtocol, StaticCredentialProvider,
};
use reqsign_core::hash;
use reqsign_core::time::Timestamp;
use reqsign_core::{ErrorKind, GrantCredential, Granter, Signer};
use std::net::Ipv4Addr;
use std::time::Duration;

// The public Azurite emulator account from src/blob/utils/constants.ts.
const AZURITE_ACCOUNT: &str = "devstoreaccount1";
const AZURITE_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const ACCOUNT: &str = "account";
const NOW: &str = "2099-01-01T00:00:01.500Z";
const MINUTE: Duration = Duration::from_secs(60);
const LIST_CONTAINERS: AccountSasGrant = AccountSasGrant::new(
    AccountSasServices::BLOB,
    AccountSasResourceTypes::SERVICE,
    AccountSasPermissions::LIST,
);

fn time(value: &str) -> Timestamp {
    value.parse().expect("fixture timestamp must parse")
}

fn fixture_key() -> String {
    hash::base64_encode(&(0_u8..64).collect::<Vec<_>>())
}

fn sas_parts(credential: &Credential) -> (&str, Timestamp) {
    match credential {
        Credential::SasToken {
            token,
            expires_at: Some(expiry),
        } => (token, *expiry),
        other => panic!("expected an expiring SAS credential, got {other:?}"),
    }
}

#[tokio::test]
async fn matches_azurite_account_sas_signature_vectors() {
    // Azurite's "generateAccountSASQueryParameters should generate correct hashes".
    // https://github.com/Azure/Azurite/blob/a4087a2b6e1a776863bf5f918baea899d4bb6553/tests/blob/sas.test.ts#L118-L181
    let source = Credential::with_shared_key(AZURITE_ACCOUNT, AZURITE_KEY);
    let start = "2022-04-16T06:31:48Z";
    let expiry = "2022-04-17T06:31:48Z";
    let grant = AccountSasGrant::new(
        AccountSasServices::FILE
            | AccountSasServices::QUEUE
            | AccountSasServices::TABLE
            | AccountSasServices::BLOB,
        AccountSasResourceTypes::OBJECT
            | AccountSasResourceTypes::CONTAINER
            | AccountSasResourceTypes::SERVICE,
        AccountSasPermissions::PROCESS
            | AccountSasPermissions::UPDATE
            | AccountSasPermissions::CREATE
            | AccountSasPermissions::ADD
            | AccountSasPermissions::LIST
            | AccountSasPermissions::DELETE
            | AccountSasPermissions::WRITE
            | AccountSasPermissions::READ,
    );
    let config = AccountSasConfig::new(AZURITE_ACCOUNT)
        .with_start(time(start))
        .with_ip(SasIpRange::range(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST).unwrap())
        .with_protocol(SasProtocol::HttpsAndHttp);
    let context = crate::test_context();

    for (version, signature) in [
        ("2016-05-31", "bTjnB+yT4DkYQcmMfpedew72/KdvTMuz29uatYuWYME="),
        ("2018-11-09", "zty6+wJgp86CuAlzq9w/+avVwjoEHgBOTXXmN7xAyio="),
        ("2020-12-06", "QB5jKCJTqn7jcPidkkXAazBQBL6VDMY7HumUIM78ROE="),
    ] {
        let config = config
            .clone()
            .with_version(AccountSasVersion::new(version).unwrap());
        let credential = AccountSasGranter::new(config, grant)
            .with_time(time(start))
            .grant_credential(&context, &source, Some(Duration::from_secs(86_400)))
            .await
            .expect("Azurite grant vector must sign");
        let (token, expires_at) = sas_parts(&credential);
        assert_eq!(expires_at, time(expiry));
        let query: Vec<_> = form_urlencoded::parse(token.as_bytes()).collect();
        let expected = [
            ("sv", version),
            ("ss", "btqf"),
            ("srt", "sco"),
            ("sp", "rwdlacup"),
            ("st", start),
            ("se", expiry),
            ("sip", "0.0.0.0-255.255.255.255"),
            ("spr", "https,http"),
            ("sig", signature),
        ];
        assert_eq!(query.len(), expected.len());
        for (name, value) in expected {
            assert!(
                query
                    .iter()
                    .any(|(key, actual)| key == name && actual == value),
                "Azure {version} query field {name} must match the Azurite vector"
            );
        }
    }
}

#[tokio::test]
async fn grants_a_signed_encryption_scope_and_rounds_the_validity_window() {
    let now = time(NOW);
    let config = AccountSasConfig::new(ACCOUNT)
        .with_start(time("2099-01-01T00:00:00.750Z"))
        .with_ip(SasIpRange::address(Ipv4Addr::new(198, 51, 100, 10)))
        .with_encryption_scope("archive-scope");
    let grant = AccountSasGrant::new(
        AccountSasServices::BLOB
            | AccountSasServices::TABLE
            | AccountSasServices::QUEUE
            | AccountSasServices::FILE,
        AccountSasResourceTypes::SERVICE
            | AccountSasResourceTypes::CONTAINER
            | AccountSasResourceTypes::OBJECT,
        AccountSasPermissions::SET_IMMUTABILITY_POLICY
            | AccountSasPermissions::FILTER_BY_TAGS
            | AccountSasPermissions::TAGS
            | AccountSasPermissions::PROCESS
            | AccountSasPermissions::UPDATE
            | AccountSasPermissions::CREATE
            | AccountSasPermissions::ADD
            | AccountSasPermissions::LIST
            | AccountSasPermissions::PERMANENT_DELETE
            | AccountSasPermissions::DELETE_VERSION
            | AccountSasPermissions::DELETE
            | AccountSasPermissions::WRITE
            | AccountSasPermissions::READ,
    );
    let operation = AccountSasGranter::new(config, grant).with_time(now);
    let source = Credential::with_shared_key(ACCOUNT, &fixture_key());
    let output = operation
        .grant_credential(
            &crate::test_context(),
            &source,
            Some(Duration::from_millis(1_750)),
        )
        .await
        .expect("scoped Account SAS must sign");
    let (token, expires_at) = sas_parts(&output);

    assert_eq!(expires_at, time("2099-01-01T00:00:03Z"));
    // Independently calculated with Python hmac.digest over the REST string-to-sign.
    // The permission order follows Azure.Storage.Common's AccountSasPermissions.
    // https://github.com/Azure/azure-sdk-for-net/blob/6a395c10a9a3126661bed9958a864f3c4487d39c/sdk/storage/Azure.Storage.Common/src/Sas/AccountSasPermissions.cs#L107-L162
    assert_eq!(
        token,
        "sv=2020-12-06&ss=btqf&srt=sco&sp=rwdxylacuptfi&se=2099-01-01T00%3A00%3A03Z&spr=https&st=2099-01-01T00%3A00%3A01Z&sip=198.51.100.10&ses=archive-scope&sig=rePd%2Bur9hUMiqLtw5sXxoKz56pqMnqNX7pbEjukTfmI%3D"
    );
}

#[tokio::test]
async fn granter_returns_an_account_sas_for_the_existing_request_signer() {
    let now = time(NOW);
    let ctx = crate::test_context();
    let source = StaticCredentialProvider::new_shared_key(ACCOUNT, &fixture_key());
    let operation =
        AccountSasGranter::new(AccountSasConfig::new(ACCOUNT), LIST_CONTAINERS).with_time(now);
    let credential = Granter::new(ctx.clone(), source, operation)
        .grant(Some(MINUTE))
        .await
        .expect("core granter must return a usable Account SAS");
    let (token, expires_at) = sas_parts(&credential);
    assert_eq!(expires_at, time("2099-01-01T00:01:01Z"));
    // Independently calculated with Python hmac.digest, with empty st, sip, and ses lines.
    assert_eq!(
        token,
        "sv=2020-12-06&ss=b&srt=s&sp=l&se=2099-01-01T00%3A01%3A01Z&spr=https&sig=mJwu3NK%2BUCB0Ys4CPnOaCb/jrCBdHDzIjuzrJBiIbZ4%3D"
    );
    assert!(!format!("{credential:?}").contains("sig="));

    let mut request = http::Request::get("https://account.blob.core.windows.net/?comp=list")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    Signer::new(
        ctx,
        StaticCredentialProvider::new_sas_token_expires_at(token, expires_at),
        RequestSigner::new().with_time(now),
    )
    .sign(&mut request, None)
    .await
    .expect("existing signer must apply the Account SAS");
    assert_eq!(request.uri.query().unwrap(), format!("comp=list&{token}"));
}

#[tokio::test]
async fn requires_a_valid_shared_key_for_the_configured_account() {
    let context = crate::test_context();
    let operation = AccountSasGranter::new(AccountSasConfig::new(ACCOUNT), LIST_CONTAINERS)
        .with_time(time(NOW));
    for (source, diagnostic) in [
        (
            Credential::with_bearer_token("test-bearer", None),
            "requires a Shared Key",
        ),
        (
            Credential::with_sas_token("sv=test&sig=test-sas"),
            "requires a Shared Key",
        ),
        (
            Credential::with_shared_key("otheraccount", &fixture_key()),
            "account does not match",
        ),
        (
            Credential::with_shared_key(ACCOUNT, "test-key%%%"),
            "source key is invalid",
        ),
        (
            Credential::with_shared_key(ACCOUNT, "YQ=="),
            "source key is invalid",
        ),
        (
            Credential::with_shared_key(ACCOUNT, ""),
            "source key is invalid",
        ),
    ] {
        let err = operation
            .grant_credential(&context, &source, Some(MINUTE))
            .await
            .expect_err("invalid source must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert!(err.to_string().contains(diagnostic), "{err}");
        assert!(!format!("{err:?}").contains("test-key%%%"));
    }

    let invalid_account = "account\nname";
    let source = Credential::with_shared_key(invalid_account, &fixture_key());
    let err = AccountSasGranter::new(AccountSasConfig::new(invalid_account), LIST_CONTAINERS)
        .with_time(time(NOW))
        .grant_credential(&context, &source, Some(MINUTE))
        .await
        .expect_err("invalid account name must fail even when the source matches");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
}

#[tokio::test]
async fn rejects_each_empty_authority_set_before_signing() {
    let source = Credential::with_shared_key(ACCOUNT, &fixture_key());
    let config = AccountSasConfig::new(ACCOUNT);
    let cases = [
        (
            AccountSasGrant::new(
                AccountSasServices::default(),
                AccountSasResourceTypes::SERVICE,
                AccountSasPermissions::LIST,
            ),
            "requires services",
        ),
        (
            AccountSasGrant::new(
                AccountSasServices::BLOB,
                AccountSasResourceTypes::default(),
                AccountSasPermissions::LIST,
            ),
            "requires resource types",
        ),
        (
            AccountSasGrant::new(
                AccountSasServices::BLOB,
                AccountSasResourceTypes::SERVICE,
                AccountSasPermissions::default(),
            ),
            "requires permissions",
        ),
    ];
    for (grant, diagnostic) in cases {
        let err = AccountSasGranter::new(config.clone(), grant)
            .with_time(time(NOW))
            .grant_credential(&crate::test_context(), &source, Some(MINUTE))
            .await
            .expect_err("empty Account SAS scope must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert!(err.to_string().contains(diagnostic), "{err}");
    }
}

#[tokio::test]
async fn rejects_unusable_validity_windows() {
    let context = crate::test_context();
    let source = Credential::with_shared_key(ACCOUNT, &fixture_key());
    let config = AccountSasConfig::new(ACCOUNT);
    for (lifetime, start, diagnostic) in [
        (None, None, "explicit positive lifetime"),
        (Some(Duration::ZERO), None, "explicit positive lifetime"),
        (
            Some(Duration::from_millis(400)),
            None,
            "future wire timestamp",
        ),
        (Some(Duration::MAX), None, "exceeds the wire time range"),
        (
            Some(Duration::from_secs(1_000_000_000_000)),
            None,
            "exceeds the wire time range",
        ),
        (
            Some(MINUTE),
            Some("2099-01-01T00:01:01Z"),
            "start time must be before its expiration",
        ),
        (
            Some(MINUTE),
            Some("2099-01-01T00:01:02Z"),
            "start time must be before its expiration",
        ),
        (
            Some(MINUTE),
            Some("2099-01-01T00:00:01.250Z"),
            "start time must not be in the future",
        ),
    ] {
        let mut config = config.clone();
        if let Some(start) = start {
            config = config.with_start(time(start));
        }
        let err = AccountSasGranter::new(config, LIST_CONTAINERS)
            .with_time(time(NOW))
            .grant_credential(&context, &source, lifetime)
            .await
            .expect_err("invalid Account SAS validity window must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert!(err.to_string().contains(diagnostic), "{err}");
    }
}

#[test]
fn accepts_documented_account_sas_versions() {
    assert_eq!(
        AccountSasVersion::new("2015-04-05").unwrap().as_str(),
        "2015-04-05"
    );
    assert_eq!(
        AccountSasVersion::new("2026-10-06").unwrap().as_str(),
        "2026-10-06"
    );
    for version in ["2015-02-21", "2020-12-05", "2020-2-10", "9999-01-01"] {
        let err = AccountSasVersion::new(version).expect_err("unsupported version must fail");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    }
}

#[tokio::test]
async fn rejects_unsupported_encryption_scopes() {
    let context = crate::test_context();
    let source = Credential::with_shared_key(ACCOUNT, &fixture_key());
    let config = AccountSasConfig::new(ACCOUNT);
    for scope in [
        "",
        "ab",
        "UPPER",
        "-scope",
        "scope-",
        "double--dash",
        "scope\nname",
        "scope&x=1",
        &"s".repeat(64),
    ] {
        let err =
            AccountSasGranter::new(config.clone().with_encryption_scope(scope), LIST_CONTAINERS)
                .with_time(time(NOW))
                .grant_credential(&context, &source, Some(MINUTE))
                .await
                .expect_err("invalid scope name must fail");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert!(
            err.to_string()
                .contains("invalid Azure encryption scope name")
        );
    }

    let scoped = config.with_encryption_scope("archive-scope");
    let legacy = scoped
        .clone()
        .with_version(AccountSasVersion::new("2020-10-02").unwrap());
    let err = AccountSasGranter::new(legacy, LIST_CONTAINERS)
        .with_time(time(NOW))
        .grant_credential(&context, &source, Some(MINUTE))
        .await
        .expect_err("legacy signing format cannot bind an encryption scope");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(err.to_string().contains("requires version 2020-12-06"));

    let files = AccountSasGrant::new(
        AccountSasServices::FILE,
        AccountSasResourceTypes::OBJECT,
        AccountSasPermissions::WRITE,
    );
    let err = AccountSasGranter::new(scoped, files)
        .with_time(time(NOW))
        .grant_credential(&context, &source, Some(MINUTE))
        .await
        .expect_err("encryption scope requires Blob Storage");
    assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    assert!(
        err.to_string()
            .contains("requires the Blob Storage service")
    );
}
