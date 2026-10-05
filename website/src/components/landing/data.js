/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Content model for the landing page. All copy and catalog data lives here so
// the section components stay presentational. Hero statistics and the provider
// grid derive from data/providers.json — the capability
// catalog. CI checks its structure; maintainers verify capability semantics.
// Code samples are included from compiled examples under reqsign/examples/.

import catalog from "../../../data/providers.json";

import { codeSnippet } from "../../code-snippets";
import customHttpCode from "!!raw-loader!@site/../reqsign/examples/custom_http.rs";
import awsCode from "!!raw-loader!@site/../reqsign/examples/aws.rs";
import azureCode from "!!raw-loader!@site/../reqsign/examples/azure.rs";
import googleCode from "!!raw-loader!@site/../reqsign/examples/google.rs";
import staticCredentialsCode from "!!raw-loader!@site/../reqsign/examples/static_credentials.rs";
import customContextCode from "!!raw-loader!@site/../reqsign/examples/custom_context.rs";
import presignCode from "!!raw-loader!@site/../reqsign/examples/presign.rs";
import s3ExpressGrantCode from "!!raw-loader!@site/../reqsign/examples/s3_express_grant.rs";

export const REPO_URL = "https://github.com/apache/reqsign";
export const DOCS_URL = "/docs/getting-started/";
export const PROVIDERS_URL = "/docs/providers/";
export const DISCORD_URL = "https://discord.gg/XQy8yGR2dg";
export const OPENDAL_URL = "https://opendal.apache.org/";

export const providers = catalog.providers;

// Derived, not hand-written: the numbers on the page are the catalog's.
const granterCount = providers.reduce(
  (n, p) => n + p.credential_granting.length,
  0
);
const wasmCount = providers.filter((p) => p.wasm.supported).length;

export const heroStats = [
  { value: `${providers.length}`, label: "signing providers" },
  { value: `${granterCount}`, label: "granting operations" },
  { value: `${wasmCount}`, label: "WASM-ready providers" },
  { value: "0", label: "vendor SDKs required" },
];

// Hero quickstart tabs. Only providers with a compiled facade example under
// reqsign/examples/ appear here — do not add a tab without adding the example.
export const codeSamples = [
  {
    id: "aws",
    label: "AWS",
    language: "rust",
    install: "$ cargo add reqsign --features aws",
    code: codeSnippet(awsCode, "quickstart"),
  },
  {
    id: "azure",
    label: "Azure",
    language: "rust",
    install: "$ cargo add reqsign --features azure",
    code: codeSnippet(azureCode, "quickstart"),
  },
  {
    id: "google",
    label: "Google",
    language: "rust",
    install: "$ cargo add reqsign --features google",
    code: codeSnippet(googleCode, "quickstart"),
  },
];

export const valueProps = [
  {
    index: "01",
    title: "Signing without a full SDK",
    body: "Build requests with plain http types, sign them in place, and send with any client. Encoded URIs, atomic request mutation, and expiration follow explicit, documented contracts.",
  },
  {
    index: "02",
    title: "Credentials that fit the provider",
    body: "Every provider keeps its own credential semantics. Default chains cover environment, config files, instance metadata, OIDC federation, CLIs, and credential processes.",
  },
  {
    index: "03",
    title: "Scoped access you can grant",
    body: "One Granter abstraction covers S3 Access Grants, S3 Express sessions, Azure user delegation SAS, and GCP Credential Access Boundary — downscoping that vendor SDKs rarely unify.",
  },
  {
    index: "04",
    title: "A runtime you control",
    body: "Context makes file reading, HTTP sending, environment, and command execution pluggable. Swap Tokio and reqwest for your own runtime, or compile to WebAssembly.",
  },
];

// The public composition contract, not an implementation diagram.
export const howItWorks = [
  {
    index: "01",
    title: "Build",
    body: "Construct the request with the http crate's plain types — reqsign never wraps your HTTP client.",
  },
  {
    index: "02",
    title: "Load or grant",
    body: "Resolve credentials through the provider's default chain, your own ProvideCredential, or a Granter that downscopes them first.",
  },
  {
    index: "03",
    title: "Sign, then send",
    body: "One sign call mutates the request head atomically — headers or query string — and hands it back for any client to send.",
  },
];

// Capability explorer. Runnable snippets come from compiled examples; each doc link lands on the guide that owns the topic.
export const capabilityThemes = [
  {
    title: "Default signer",
    blurb: "One call wires the default context and credential chain.",
    doc: "/docs/getting-started/#every-provider-one-pattern",
    code: codeSnippet(staticCredentialsCode, "static"),
  },
  {
    title: "Custom assembly",
    blurb: "Pick every component of the signer explicitly.",
    doc: "/docs/architecture/#where-to-plug-in",
    code: codeSnippet(customContextCode),
  },
  {
    title: "Presigning",
    blurb: "Produce query-authenticated URLs you can hand out.",
    doc: "/docs/guides/presigning/",
    code: codeSnippet(presignCode),
  },
  {
    title: "Credential granting",
    blurb: "Downscope credentials before a request is ever signed.",
    doc: "/docs/guides/granting/",
    code: codeSnippet(s3ExpressGrantCode),
  },
  {
    title: "Custom context & WASM",
    blurb: "Bring your own runtime — down to wasm32-unknown-unknown.",
    doc: "/docs/guides/custom-runtimes/#wasm",
    code: codeSnippet(customHttpCode),
  },
];

// Verified adoption. Reqsign does not keep a logo wall: an entry requires a
// public, auditable direct dependency on reqsign in the adopter's own
// manifest (OpenDAL's per-service crates; uv's Cargo.toml).
export const adoption = [
  {
    name: "Apache OpenDAL™",
    href: OPENDAL_URL,
    claim:
      "signs every cloud storage request — S3, GCS, Azure Blob, COS, TOS, and more — through Reqsign.",
  },
  {
    name: "uv",
    href: "https://github.com/astral-sh/uv",
    claim:
      "the Python package manager, authenticates to AWS, Azure, and Google Cloud with Reqsign.",
  },
];
