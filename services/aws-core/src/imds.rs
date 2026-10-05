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

use crate::provide_credential::utils::parse_imds_error;
use bytes::Bytes;
use http::Method;
use http::header::CONTENT_LENGTH;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct ImdsClient {
    endpoint: Option<String>,
    token: Arc<Mutex<(String, String, Timestamp)>>,
}

impl Default for ImdsClient {
    fn default() -> Self {
        Self {
            endpoint: None,
            token: Arc::new(Mutex::new((
                String::new(),
                String::new(),
                Timestamp::default(),
            ))),
        }
    }
}

impl ImdsClient {
    /// Create a new `ImdsClient` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the endpoint for the metadata service.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}

impl ImdsClient {
    pub(crate) fn get_endpoint(&self, ctx: &Context) -> String {
        // First check configured endpoint, then environment, then default
        self.endpoint.clone().unwrap_or_else(|| {
            ctx.env_var("AWS_EC2_METADATA_SERVICE_ENDPOINT")
                .unwrap_or_else(|| {
                    if ctx
                        .env_var("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE")
                        .is_some_and(|v| v.eq_ignore_ascii_case("IPv6"))
                    {
                        "http://[fd00:ec2::254]".into()
                    } else {
                        "http://169.254.169.254".into()
                    }
                })
        })
    }

    pub(crate) async fn load_ec2_metadata_token(&self, ctx: &Context) -> Result<String> {
        let endpoint = self.get_endpoint(ctx);
        {
            let (cached_endpoint, token, expires_in) =
                self.token.lock().expect("lock poisoned").clone();
            if cached_endpoint == endpoint && expires_in > Timestamp::now() {
                return Ok(token);
            }
        }

        let url = format!("{}/latest/api/token", endpoint.trim_end_matches('/'));
        let req = http::Request::builder()
            .uri(&url)
            .method(Method::PUT)
            .header(CONTENT_LENGTH, "0")
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
            .body(Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build IMDS token request")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
            })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to connect to IMDS")
                .with_source(e)
                .with_context(format!("endpoint: {endpoint}"))
                .with_context("hint: check if running on EC2 instance")
                .set_retryable(true)
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(parse_imds_error(
                "fetch_imds_token",
                resp.status(),
                resp.body(),
            ));
        }
        let ec2_token = resp.into_body();
        // Refresh ten minutes before the token expires.
        let expires_in = Timestamp::now() + Duration::from_secs(21600) - Duration::from_secs(600);

        {
            *self.token.lock().expect("lock poisoned") = (endpoint, ec2_token.clone(), expires_in);
        }

        Ok(ec2_token)
    }
}

impl std::fmt::Debug for ImdsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImdsClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

pub(crate) fn disabled(ctx: &Context) -> bool {
    ctx.env_var("AWS_EC2_METADATA_DISABLED")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}
