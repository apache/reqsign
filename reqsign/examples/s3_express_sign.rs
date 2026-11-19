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

use reqsign::aws::{
    self, DefaultCredentialProvider, S3ExpressSessionGrant, S3ExpressSessionMode,
    S3ExpressSessionProvider,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = S3ExpressSessionProvider::new(
        "my-bucket--usw2-az1--x-s3",
        DefaultCredentialProvider::new(),
    )
    .with_region("us-west-2")
    .with_grant(S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadOnly));
    let signer = aws::default_signer("s3express", "us-west-2").with_credential_provider(provider);
    let mut req = http::Request::get(
        "https://my-bucket--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com/object",
    )
    .body(())?
    .into_parts()
    .0;
    // The signer caches the session with its expiration and refreshes as needed.
    signer.sign(&mut req, None).await?;
    Ok(())
}
