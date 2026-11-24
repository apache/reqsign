# reqsign-github

GitHub.com token discovery and request signing for Reqsign.

The default credential chain reads `GH_TOKEN` before `GITHUB_TOKEN` through
`Context`. When the context has a command executor, it resolves the active
stored account with `gh config get user --host github.com`, then reads that
account's token with
`gh auth token --hostname github.com --user <user> --no-refresh`. The explicit
user prevents `GH_TOKEN` or `GITHUB_TOKEN` in the child process environment
from shadowing the stored credential. Safe stored-token discovery requires
GitHub CLI 2.40.0 or newer.

The default slots stop at the first error instead of silently selecting a
different identity. A malformed environment token, an invalid prepended or
static provider, or a GitHub CLI error or malformed CLI output fails signing;
the chain does not fall back to anonymous access. Only an absent credential
reaches the explicit anonymous slot: no command executor, a missing `gh`
executable, no stored account, or an explicit `no oauth token found` response.
Add a `CommandExecute` adapter to the context to enable GitHub CLI discovery;
without one, that slot yields no credential.

`--no-refresh` keeps discovery read-only and is used on GitHub CLI 2.103.0 and
newer. Older supported versions do not refresh when printing a stored token, so
the provider retries without the flag only after the CLI reports that specific
flag as unknown. Run `gh auth refresh` separately when the stored token has
expired, then recreate the signer so it loads the renewed token.

`RequestSigner` adds a sensitive `Authorization: Bearer` header for a token
credential and removes any existing `Authorization` header for an explicit
anonymous credential, so a reused request cannot carry stale authentication
material. Other headers and the URI are unchanged. It does not add or replace
`User-Agent` (GitHub requires the caller to send one), `Accept`, or
`X-GitHub-Api-Version`, and it rejects `expires_in` because GitHub has no query
authentication. GitHub credentials in this crate carry no expiration and
signing writes no protocol time, so signing has no clock dependency.

The built-in providers discover GitHub.com credentials only. They ignore
`GH_HOST`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_ENTERPRISE_TOKEN`; use
`StaticCredentialProvider` or a custom provider for GitHub Enterprise Server.
`GH_TOKEN` and `GITHUB_TOKEN` are interpreted as the GitHub CLI's GitHub.com
token; pass the intended token explicitly when you use multiple hosts. The
signer does not restrict the request host, so caller-supplied credentials may
be used with another GitHub host. A token carries the host and scopes or
repository permissions assigned by GitHub; Reqsign neither requests nor
inspects them. The caller owns the HTTP client and its redirect policy, and must
not forward the signed header to another host.

On `wasm32-unknown-unknown`, environment, static, and anonymous signing work
without a JavaScript clock. GitHub CLI discovery requires a `CommandExecute`
adapter and is unavailable in bare WASM runtimes.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_github::{DefaultCredentialProvider, RequestSigner};

# async fn example() -> reqsign_core::Result<()> {
// Add a CommandExecute adapter to enable GitHub CLI discovery.
let context = Context::new().with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner,
);

let mut req = http::Request::get("https://api.github.com/repos/apache/reqsign")
    .header("user-agent", "my-application")
    .header("x-github-api-version", "2022-11-28")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

For an explicit token, replace the default provider:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_github::{RequestSigner, StaticCredentialProvider};

# fn example(context: Context) -> Result<()> {
let signer = Signer::new(
    context,
    StaticCredentialProvider::new("github-token"),
    RequestSigner,
);
# let _ = signer;
# Ok(())
# }
```

The builder supports positive slots and matching removals:

```rust,no_run
use reqsign_github::DefaultCredentialProvider;

let provider = DefaultCredentialProvider::builder()
    .no_env()
    .no_gh_cli()
    .build();
```

With both token slots removed, the provider falls back to anonymous public
access. Add `.no_anonymous()` to remove that fallback as well.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
