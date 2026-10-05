<!--
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
-->

# Reqsign Website

The Apache Reqsign™ website — a [Docusaurus](https://docusaurus.io/) site
targeting `https://reqsign.apache.org/`.

## Development

```bash
pnpm install
pnpm start        # dev server
pnpm build        # production build into build/
pnpm serve        # serve the production build locally
```

Requires Node ≥ 24.17 and pnpm 11 (`corepack enable`).

## Checks

```bash
cargo check -p reqsign --examples --all-features # from the repository root
pnpm validate-providers      # crate, feature, page, and source-path consistency
pnpm build                   # also fails on broken internal links
pnpm check-external-assets   # no third-party runtime assets (run after build)
```

## Layout

| Path | Purpose |
| --- | --- |
| `data/providers.json` | Provider capability catalog — structural references are checked in CI; behavioral claims require source review |
| `docs/` | Concept, guide, contract, compatibility, and provider documentation |
| `docs/providers/` | One page per provider: capability facts render from the catalog via `ProviderFacts`; provider-specific prose lives in the MDX. The validator requires a page per catalog entry |
| `src/pages/` | Landing page, `/download`, `/community` |
| `src/components/landing/` | Landing sections and content model |
| `src/components/providers/` | `ProviderFacts` and `ProvidersMatrix`, the catalog-rendering components embedded in docs pages |
| `plugins/remark-include-code.js` | Includes real repository files into docs code blocks |
| `scripts/` | Catalog validator and external-asset check |
| `DESIGN_SYSTEM.md` | Visual language: shared skeleton + Reqsign identity |
| `UPSTREAM_DESIGN.md` | Provenance and sync procedure for design reused from the OpenDAL website |

## Editing rules

- **Provider capabilities** change in `data/providers.json` (with source
  refs), and related guide prose must be updated together. Run the validator.
  It checks structure, not signing behavior, chain order, or WASM support;
  review those claims against their source and existing service tests.
- **Code snippets** in docs come from compiled sources via
  ` ```rust file=path/to/file.rs ` fences where possible; landing snippets
  import those same files through `raw-loader`. Keep runnable examples under
  `reqsign/examples/`; CI compiles them with all facade features.
- **Design changes** to shared-skeleton styles should go through the sync
  procedure in `UPSTREAM_DESIGN.md`; Reqsign-identity overrides (accent,
  stroke motif, wordmark) are documented there and never synced.

## Environment variables

| Variable | Effect |
| --- | --- |
| `REQSIGN_WEBSITE_URL` | Overrides the canonical site URL |
| `REQSIGN_WEBSITE_BASE_URL` | Overrides `baseUrl` (fallback deployments) |
| `REQSIGN_WEBSITE_STAGING=true` | Marks the build as staging: sets `noIndex` |

## Deployment

The Website workflow validates pull requests and uploads a `website` artifact.
Only a successful build of `main` (a push or a manual workflow dispatch) can
publish. The deploy job receives `contents: write` and pushes the validated
artifact to `asf-site` with the repository's `GITHUB_TOKEN`; PR builds retain
read-only repository permissions.

The artifact includes `.asf.yaml` at its root with `publish.whoami: asf-site`.
ASF's publishing service watches that branch and serves it at
<https://reqsign.apache.org/>. This follows the
[ASF project website deployment mechanism](https://infra.apache.org/project-site).
No GitHub Pages environment, personal access token, or external hosting account
is required.

After merging, inspect the Website run's build and deploy jobs, then verify
that the homepage, `/docs/getting-started/`, and `/sitemap.xml` are available on
the canonical host. A successful push to `asf-site` confirms artifact publication,
not completion of ASF's asynchronous serving and CDN update. If the first
publication does not appear, confirm the `reqsign.apache.org` site mapping with
ASF Infra and inspect the generated branch's `.asf.yaml`.

To republish, run the Website workflow manually on `main`. To roll back content,
revert the source change on `main` and let the same workflow rebuild and publish.
Do not manually dispatch a feature branch expecting it to update production;
the deploy job is restricted to `main`.
