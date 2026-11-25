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

mod support;

use std::sync::Arc;

use reqsign_core::Context;
use reqsign_core::crypto::CryptoProvider;
use support::crypto_arc::{ALL_CRYPTO_METHODS, MarkerProvider, assert_all_forwarded};

const CRYPTO_SOURCE: &str = include_str!("../src/crypto.rs");
const TRAIT_HEADER: &str = "pub trait CryptoProvider: Debug + Send + Sync + 'static {";
const ARC_IMPL_HEADER: &str = "impl<T: CryptoProvider + ?Sized> CryptoProvider for Arc<T> {";

#[test]
fn arc_forwards_every_method_of_a_dyn_provider() {
    let marker = Arc::new(MarkerProvider::new());
    let provider: Arc<dyn CryptoProvider> = marker.clone();

    assert_all_forwarded::<Arc<dyn CryptoProvider>>(&provider);

    assert_eq!(marker.recorded_calls(), ALL_CRYPTO_METHODS);
}

#[test]
fn context_with_crypto_accepts_an_arc_dyn_provider() {
    let marker = Arc::new(MarkerProvider::new());
    let provider: Arc<dyn CryptoProvider> = marker.clone();

    let context = Context::new().with_crypto(provider);
    let resolved = context
        .crypto_provider()
        .expect("the explicit Arc provider must resolve");

    assert_all_forwarded::<dyn CryptoProvider>(resolved);

    assert_eq!(marker.recorded_calls(), ALL_CRYPTO_METHODS);
}

#[test]
fn arc_impl_covers_every_crypto_provider_method() {
    let mut trait_methods = block_lines(CRYPTO_SOURCE, TRAIT_HEADER)
        .into_iter()
        .filter_map(top_level_method_name)
        .collect::<Vec<_>>();
    trait_methods.sort_unstable();

    let forwarded_methods = forwarding_methods(CRYPTO_SOURCE, ARC_IMPL_HEADER);
    let mut impl_methods = forwarded_methods
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    impl_methods.sort_unstable();
    assert_eq!(
        trait_methods, impl_methods,
        "the Arc<T> CryptoProvider impl must forward exactly the trait methods"
    );

    for (name, body) in forwarded_methods {
        let expected = format!("(**self).{name}(");
        assert!(
            body.contains(&expected),
            "the Arc<T> forwarding method `{name}` must call `{expected}`"
        );
    }

    let mut marker_methods = ALL_CRYPTO_METHODS.to_vec();
    marker_methods.sort_unstable();
    assert_eq!(
        trait_methods, marker_methods,
        "update MarkerProvider and ALL_CRYPTO_METHODS when CryptoProvider gains a method"
    );
}

fn block_lines<'a>(source: &'a str, header: &str) -> Vec<&'a str> {
    let header_start = source
        .find(header)
        .unwrap_or_else(|| panic!("missing source block: {header}"));
    let body_start = source[header_start..]
        .find('\n')
        .expect("the source block header must end with a newline")
        + header_start
        + 1;

    source[body_start..]
        .lines()
        .take_while(|line| *line != "}")
        .collect()
}

fn top_level_method_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("    fn ")?;
    let name_end = rest.find('(')?;
    Some(&rest[..name_end])
}

fn forwarding_methods<'a>(source: &'a str, header: &str) -> Vec<(&'a str, String)> {
    let mut methods: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut current: Option<(&str, Vec<&str>)> = None;

    for line in block_lines(source, header) {
        if let Some(name) = top_level_method_name(line) {
            if let Some((name, lines)) = current.take() {
                methods.push((name, lines));
            }
            current = Some((name, vec![line]));
        } else if let Some((_, lines)) = current.as_mut() {
            lines.push(line);
        }
    }
    if let Some((name, lines)) = current {
        methods.push((name, lines));
    }

    methods
        .into_iter()
        .map(|(name, lines)| (name, lines.join("\n")))
        .collect()
}
