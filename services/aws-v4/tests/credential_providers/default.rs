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

use super::{assert_credentials_work, create_test_context};
use log::info;
use reqsign_aws_v4::DefaultCredentialProvider;
use reqsign_core::ProvideCredential;
use std::env;

#[tokio::test]
async fn test_default_credential_provider_live() {
    if env::var("REQSIGN_AWS_V4_TEST_DEFAULT").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_DEFAULT not set, skipping");
        return;
    }

    let ctx = create_test_context();
    let credential = DefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("DefaultCredentialProvider should succeed")
        .expect("DefaultCredentialProvider should return credentials");
    assert_credentials_work(&ctx, &credential).await;
}

#[tokio::test]
async fn test_default_provider_role_chain_is_consumed_by_signer() {
    use bytes::Bytes;
    use http::{Request, Response, StatusCode, header};
    use reqsign_aws_v4::RequestSigner;
    use reqsign_core::{FileRead, HttpSend, Signer, StaticEnv};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Files(Mutex<HashMap<String, Vec<u8>>>);

    impl FileRead for Files {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            self.0
                .lock()
                .expect("lock poisoned")
                .get(path)
                .cloned()
                .ok_or_else(|| reqsign_core::Error::unexpected("file not found"))
        }
    }

    #[derive(Debug)]
    struct Http {
        request: Mutex<Option<Request<Bytes>>>,
    }

    impl HttpSend for Http {
        async fn http_send(
            &self,
            request: Request<Bytes>,
        ) -> reqsign_core::Result<Response<Bytes>> {
            *self.request.lock().expect("lock poisoned") = Some(request);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Bytes::from_static(
                    b"<AssumeRoleResponse><AssumeRoleResult><Credentials>\
                      <AccessKeyId>ASIAOPERATOR0000001</AccessKeyId>\
                      <SecretAccessKey>operator-secret</SecretAccessKey>\
                      <SessionToken>operator-token</SessionToken>\
                      <Expiration>2099-11-09T13:34:41Z</Expiration>\
                      </Credentials></AssumeRoleResult></AssumeRoleResponse>",
                ))
                .expect("response must build"))
        }
    }

    let files = Files::default();
    files.0.lock().expect("lock poisoned").insert(
        "/config".to_owned(),
        b"[profile operator]\n\
          role_arn = arn:aws:iam::111122223333:role/Operator\n\
          source_profile = static-source\n\
          role_session_name = operator-session\n\
          region = us-east-1\n\
          \n\
          [profile static-source]\n\
          aws_access_key_id = ASIASOURCE0000000001\n\
          aws_secret_access_key = source-secret\n"
            .to_vec(),
    );
    let http = Http {
        request: Mutex::new(None),
    };
    let ctx = crate::common::test_context()
        .with_file_read(files)
        .with_http_send(http)
        .with_env(StaticEnv {
            home_dir: Some("/home".into()),
            envs: HashMap::from([
                ("AWS_CONFIG_FILE".to_owned(), "/config".to_owned()),
                (
                    "AWS_SHARED_CREDENTIALS_FILE".to_owned(),
                    "/credentials".to_owned(),
                ),
                ("AWS_PROFILE".to_owned(), "operator".to_owned()),
            ]),
        });
    let signer = Signer::new(
        ctx,
        DefaultCredentialProvider::new(),
        RequestSigner::new("s3", "us-east-1"),
    );
    let mut request = http::Request::get("https://bucket.s3.us-east-1.amazonaws.com/object")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut request, None)
        .await
        .expect("signer must consume the role-chain credential");

    let authorization = request.headers[header::AUTHORIZATION]
        .to_str()
        .expect("authorization must be text");
    assert!(authorization.contains("Credential=ASIAOPERATOR0000001/"));
    assert_eq!(request.headers["x-amz-security-token"], "operator-token");
}
