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
    DefaultCredentialProvider, S3ExpressSessionConfig, S3ExpressSessionGrant,
    S3ExpressSessionGranter, S3ExpressSessionMode,
};
use reqsign::{Granter, default_context};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = S3ExpressSessionConfig::from_bucket("my-bucket--usw2-az1--x-s3", "us-west-2")?;
    let grant = S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadOnly);
    let granter = Granter::new(
        default_context(),
        DefaultCredentialProvider::new(),
        S3ExpressSessionGranter::new(config, grant),
    );
    let scoped = granter.grant(None).await?;
    // Keep the entire credential, including expires_in, when passing it on.
    assert!(scoped.expires_in.is_some());
    Ok(())
}
