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

use reqsign_core::{Context, OsEnv};

#[cfg(feature = "default-crypto")]
use reqsign_crypto_rustcrypto::RustCryptoProvider;

#[cfg(not(target_arch = "wasm32"))]
use reqsign_command_execute_tokio::TokioCommandExecute;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

/// Create a Context with default implementations.
///
/// This function returns a Context configured with:
/// - `TokioCommandExecute` for command execution (non-WASM only)
/// - `TokioFileRead` for file reading (non-WASM only)
/// - `ReqwestHttpSend` for HTTP requests
/// - `OsEnv` for environment variable access
/// - `RustCryptoProvider` bound to the context when `default-crypto` is enabled
///   and no process-wide provider is installed at construction time
///
/// This makes `reqsign` examples and default signers usable without installation
/// boilerplate. It does not touch the process-wide registration. An application
/// that wants to choose a process-wide provider installs it before constructing
/// facade contexts; a context that already binds RustCrypto keeps that binding.
/// An explicit `Context::with_crypto` binding always wins. Integrating middleware
/// must leave provider installation to the application.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
///
/// // Use the context directly
/// let response = ctx.http_send(http::Request::builder()
///     .uri("https://api.example.com")
///     .body(bytes::Bytes::new())?)
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// You can replace any component by chaining method calls:
///
/// ```no_run
/// # async fn example() -> reqsign_core::Result<()> {
/// // Example: Replace with a custom environment implementation
/// use reqsign_core::StaticEnv;
/// use std::collections::HashMap;
///
/// let mut envs = HashMap::new();
/// envs.insert("AWS_ACCESS_KEY_ID".to_string(), "my-key".to_string());
///
/// let ctx = reqsign::default_context()
///     .with_env(StaticEnv { envs, home_dir: None });
/// # Ok(())
/// # }
/// ```
pub fn default_context() -> Context {
    #[cfg(not(target_arch = "wasm32"))]
    let ctx = Context::new()
        .with_command_execute(TokioCommandExecute)
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    #[cfg(target_arch = "wasm32")]
    let ctx = Context::new()
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    #[cfg(feature = "default-crypto")]
    let ctx = if reqsign_core::crypto::get_default().is_none() {
        ctx.with_crypto(RustCryptoProvider::new())
    } else {
        ctx
    };

    ctx
}
