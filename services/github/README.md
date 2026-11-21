# reqsign-github

GitHub.com token discovery and request signing for Reqsign.

The default credential chain reads `GH_TOKEN` before `GITHUB_TOKEN` through
`Context`. When the context has a command executor, it then reads the stored
GitHub.com token with `gh auth token --hostname github.com --no-refresh`.
Discovery is scoped to GitHub.com, runs the CLI directly instead of through a
shell, and does not parse the CLI's configuration files; the CLI remains the
source of truth for account and host selection. It does not refresh or rewrite
the CLI credential store; run `gh auth refresh` separately when the stored token
has expired, then recreate the signer so it loads the renewed token. If no token
is found, the chain ends with an explicit anonymous credential for public
resources.

`RequestSigner` adds only a sensitive `Authorization: Bearer` header. It does
not add or replace `User-Agent` (GitHub requires the caller to send one),
`Accept`, or `X-GitHub-Api-Version`, and it rejects `expires_in` because GitHub
has no query authentication.

This crate targets `https://api.github.com`. It ignores `GH_HOST`,
`GH_ENTERPRISE_TOKEN`, and `GITHUB_ENTERPRISE_TOKEN`; use
`StaticCredentialProvider` or a custom provider for GitHub Enterprise Server.
`GH_TOKEN` and `GITHUB_TOKEN` are interpreted as the GitHub CLI's GitHub.com
token; pass the intended token explicitly when you use multiple hosts. A token
carries the host and scopes or repository permissions assigned by GitHub;
Reqsign neither requests nor inspects them. The caller owns the HTTP client and
its redirect policy, and must not forward the signed header to another host.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_github::{DefaultCredentialProvider, RequestSigner};

# async fn example() -> reqsign_core::Result<()> {
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
