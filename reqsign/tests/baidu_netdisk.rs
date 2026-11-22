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

#![cfg(feature = "baidu-netdisk")]

use reqsign::baidu_netdisk::{StaticCredentialProvider, default_signer};
use reqsign::{Context, Result};

#[tokio::test]
async fn default_signer_uses_an_explicit_static_token() -> Result<()> {
    let signer = default_signer(Context::new(), String::from("fabricated-token"));
    let mut request = http::Request::get(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=meta&path=%2Fapps%2FMyApp",
    )
    .body(())
    .expect("request must build")
    .into_parts()
    .0;

    signer.sign(&mut request, None).await?;

    assert_eq!(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=meta&path=%2Fapps%2FMyApp&access_token=fabricated-token",
        request.uri.to_string()
    );

    Ok(())
}

#[tokio::test]
async fn default_signer_can_replace_the_static_provider() -> Result<()> {
    let signer = default_signer(Context::new(), "unused-token")
        .with_credential_provider(StaticCredentialProvider::new("rotated-token"));
    let mut request = http::Request::get("https://pan.baidu.com/rest/2.0/xpan/file")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer.sign(&mut request, None).await?;

    assert_eq!(
        "https://pan.baidu.com/rest/2.0/xpan/file?access_token=rotated-token",
        request.uri.to_string()
    );

    Ok(())
}
