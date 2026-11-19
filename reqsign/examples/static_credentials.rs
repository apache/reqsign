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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ANCHOR: static
    use reqsign::aws::{self, StaticCredentialProvider};
    let signer = aws::default_signer("s3", "us-east-1").with_credential_provider(
        StaticCredentialProvider::new("AKIDEXAMPLE", "example-secret-key"),
    );
    // ANCHOR_END: static

    // ANCHOR: chain
    let provider = reqsign::aws::DefaultCredentialProvider::new().push_front(
        StaticCredentialProvider::new("AKIDEXAMPLE", "example-secret-key"),
    );
    // ANCHOR_END: chain
    let _custom_chain_signer =
        aws::default_signer("s3", "us-east-1").with_credential_provider(provider);

    let mut req = http::Request::get("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())?
        .into_parts()
        .0;
    signer.sign(&mut req, None).await?;
    assert!(req.headers.contains_key("authorization"));
    Ok(())
}
