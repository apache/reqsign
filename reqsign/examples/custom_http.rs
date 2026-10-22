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

use bytes::Bytes;
use reqsign::{Context, HttpSend, Result};

// Implement this adapter over your own transport, such as browser fetch().
#[derive(Debug)]
struct MyHttpSend;

impl HttpSend for MyHttpSend {
    async fn http_send(&self, _req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        todo!("drive the request through your own transport")
    }
}

fn main() {
    // This example only assembles the context; implement http_send before use.
    let _ctx = Context::new().with_http_send(MyHttpSend);
}
