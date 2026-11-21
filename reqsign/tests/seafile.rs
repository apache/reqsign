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

#![cfg(feature = "seafile")]

use reqsign::seafile::StaticCredentialProvider;
use reqsign::{Context, Error, FileRead, Result, StaticEnv};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Clone, Default, Debug)]
struct MockFileRead {
    content: Arc<StdMutex<Option<Vec<u8>>>>,
}

impl FileRead for MockFileRead {
    async fn file_read(&self, _path: &str) -> Result<Vec<u8>> {
        self.content
            .lock()
            .expect("file lock")
            .clone()
            .ok_or_else(|| Error::unexpected("mock file does not exist"))
    }
}

fn context(content: Option<&str>) -> Context {
    Context::new()
        .with_file_read(MockFileRead {
            content: Arc::new(StdMutex::new(
                content.map(|value| value.as_bytes().to_vec()),
            )),
        })
        .with_env(StaticEnv {
            home_dir: Some(PathBuf::from("/home/seafile")),
            envs: HashMap::new(),
        })
}

#[tokio::test]
async fn facade_default_signer_reads_the_seaf_cli_token() -> Result<()> {
    let signer = reqsign::seafile::default_signer(context(Some(
        "[account]\nserver = https://files.example.com\ntoken = facade-cli-token\n",
    )));
    let mut parts = http::Request::get("https://files.example.com/api2/repos/")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await?;

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Token facade-cli-token");
    assert!(authorization.is_sensitive());
    Ok(())
}

#[tokio::test]
async fn facade_static_override_replaces_a_stale_authorization_header() -> Result<()> {
    let signer = reqsign::seafile::default_signer(context(None))
        .with_credential_provider(StaticCredentialProvider::new("facade-static-token"));
    let mut parts = http::Request::get("https://files.example.com/api2/repos/")
        .header(http::header::AUTHORIZATION, "Bearer stale")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Token facade-static-token"
    );
    Ok(())
}
