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

use crate::imds::ImdsClient;
use bytes::Bytes;
use futures::future::{Either, select};
use reqsign_core::{Context, Error, Result};
use std::time::Duration;

/// Discovers an EC2 region without obtaining IAM credentials.
///
/// Uses IMDSv2 only: one token request followed by `meta-data/placement/region`.
/// `AWS_EC2_METADATA_DISABLED=true` disables discovery. Endpoint precedence is
/// explicit endpoint, `AWS_EC2_METADATA_SERVICE_ENDPOINT`, then the IPv4 metadata
/// endpoint (or IPv6 when `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE=IPv6`).
///
/// The runtime-independent timer also supports browser timers on wasm32.
/// The entire discovery has a default two-second deadline with no retries. HTTP
/// requests use the supplied Context. Timeout cancels the in-flight HTTP future;
/// the HTTP adapter must cooperate with cancellation and must not block polling.
#[derive(Debug, Clone)]
pub struct IMDSv2RegionProvider {
    client: ImdsClient,
    timeout: Duration,
}

impl Default for IMDSv2RegionProvider {
    fn default() -> Self {
        Self {
            client: ImdsClient::new(),
            timeout: Duration::from_secs(2),
        }
    }
}

impl IMDSv2RegionProvider {
    /// Create a region provider with a two-second deadline.
    pub fn new() -> Self {
        Self::default()
    }
    /// Override the metadata service endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.client = self.client.with_endpoint(endpoint);
        self
    }
    /// Set the deadline for the whole discovery, including the token request.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    /// Return the EC2 region, or `None` when metadata is disabled.
    ///
    /// Transport errors, non-success responses, empty/invalid region responses, and
    /// deadline expiry return errors. No credentials or instance role are required.
    pub async fn resolve_region(&self, ctx: &Context) -> Result<Option<String>> {
        if crate::imds::disabled(ctx) {
            return Ok(None);
        }
        let discovery = Box::pin(self.discover(ctx));
        match select(discovery, futures_timer::Delay::new(self.timeout)).await {
            Either::Left((result, _)) => result.map(Some),
            Either::Right(_) => {
                Err(Error::unexpected("IMDS region discovery timed out").set_retryable(true))
            }
        }
    }

    async fn discover(&self, ctx: &Context) -> Result<String> {
        let token = self.client.load_ec2_metadata_token(ctx).await?;
        let endpoint = self.client.get_endpoint(ctx);
        let request = http::Request::builder()
            .uri(format!(
                "{}/latest/meta-data/placement/region",
                endpoint.trim_end_matches('/')
            ))
            .header("x-aws-ec2-metadata-token", token)
            .body(Bytes::new())
            .map_err(|_| Error::request_invalid("failed to build IMDS region request"))?;
        let response = ctx.http_send(request).await?;
        if response.status() != http::StatusCode::OK {
            return Err(Error::unexpected("failed to fetch IMDS region")
                .with_context(format!("status: {}", response.status())));
        }
        let region = std::str::from_utf8(response.body())
            .map_err(|_| Error::unexpected("invalid IMDS region response"))?
            .trim();
        if region.is_empty()
            || !region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::unexpected("invalid IMDS region response"));
        }
        Ok(region.to_owned())
    }
}
