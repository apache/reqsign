# reqsign-b2

Backblaze B2 Native API authentication for reqsign.

The crate exchanges a B2 application key for a Native API authorization token
with [`b2_authorize_account`](https://www.backblaze.com/apidocs/b2-authorize-account),
keeps the returned Native API and download base URLs on the credential, and signs
requests with the required `Authorization` header.

## Quick Start

```rust,no_run
use reqsign_b2::{DefaultCredentialProvider, RequestSigner};
use reqsign_core::{Context, OsEnv, Result, Signer};
use reqsign_http_send_reqwest::ReqwestHttpSend;

# async fn main() -> Result<()> {
let context = Context::new()
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);

let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner,
);

let mut request = http::Request::get(
    "https://api001.backblazeb2.com/b2api/v4/b2_list_buckets?accountId=account-id",
)
.body(())
.unwrap()
.into_parts()
.0;

signer.sign(&mut request, None).await?;
# Ok(())
# }
```

The default chain reads `B2_APPLICATION_KEY_ID` and `B2_APPLICATION_KEY`, the
variables used by the official B2 command line tools, and sends them to
`https://api.backblazeb2.com/b2api/v4/b2_authorize_account` with HTTP Basic
authentication. API v4 supports Multi-Bucket Application Keys. The default
source and prepended providers fail closed: a provider error is returned to
the caller instead of falling through, so a retryable `b2_authorize_account`
failure stays retryable.

Use `AccountAuthorizationCredentialProvider` for an explicit application key, or
`StaticCredentialProvider` when the caller already has an authorization token and
its base URLs:

```rust
use reqsign_b2::{Credential, StaticCredentialProvider};

let credential = Credential::new(
    "authorization-token",
    "https://api001.backblazeb2.com",
    "https://f001.backblazeb2.com",
);
let provider = StaticCredentialProvider::new(credential);
```

## Credential lifetime

B2 caps an authorization token at 24 hours. The provider also reads
`applicationKeyExpirationTimestamp`, expressed in milliseconds since the Unix
epoch, and keeps the earlier deadline. `Signer` refreshes the token before it
expires and reuses it across requests.

B2 returns key restrictions such as capabilities, bucket allow-lists, and name
prefixes. B2 enforces them when the token is used, so they are not part of the
credential and do not need to be checked while signing.

## Scope

The signer covers requests authorized by the Native API account token. Bucket
and file dependent operations remain with the caller: `b2_get_upload_url`,
`b2_get_upload_part_url`, and `b2_get_download_authorization` return or require
different authorization values, and the S3-compatible API uses a different
signing protocol. Part size recommendations and `s3ApiUrl` are likewise caller
concerns.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
