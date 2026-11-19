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

use reqsign::aws;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let signer = aws::default_signer("s3", "us-east-1");
    let mut req = http::Request::get("https://s3.amazonaws.com/my-bucket/report.csv")
        .body(())?
        .into_parts()
        .0;
    signer
        .sign(&mut req, Some(Duration::from_secs(3600)))
        .await?;
    // Share req.uri over a trusted channel; it contains authentication material.
    assert!(req.uri.query().is_some());
    Ok(())
}
