# reqsign-aliyun-drive

Aliyun Drive Open Platform OAuth credentials and request signing for
[Reqsign](../README.md).

This crate provides:

- `Credential`, a redacted access token with an optional absolute expiration.
- `StaticCredentialProvider` for a caller-managed access token.
- `RefreshCredentialProvider` for Aliyun Drive's JSON refresh-token exchange,
  including serialized refresh-token rotation.
- `RequestSigner`, which inserts `Authorization: Bearer <token>`.
- `DefaultCredentialProvider`, an empty default chain because Aliyun Drive
  documents no ambient CLI, SDK, environment, or file credential contract.

The drive ID, file paths, upload URLs, request bodies, and storage API requests
stay with the caller. The first-party storage API requires a caller-supplied
`User-Agent`; the signer does not add or replace it.

## Refresh endpoint

Aliyun Drive uses a vendor-specific JSON body rather than the RFC 6749
form-encoded refresh request:

```text
POST https://openapi.alipan.com/oauth/access_token
Content-Type: application/json
User-Agent: reqsign-aliyun-drive/<version>

{"client_id":"...","client_secret":"...","grant_type":"refresh_token","refresh_token":"..."}
```

All three confidential-client credentials are required. Public clients use the
official PKCE flow, which returns a 30-day access token without a refresh token;
supply that access token through `StaticCredentialProvider`.

The response returns `access_token`, `token_type`, `expires_in`, and a new
single-use `refresh_token`. A provider keeps only the latest refresh token in
memory, clones share it, and exchanges are serialized. Tokens are never
persisted, and there is no getter or persistence callback. After a successful
exchange, restarting with the originally configured refresh token may fail
because that token was consumed. Restart with a fresh authorized grant, or
manage and persist the exchange in the application and supply an access token.
Access-token caching is provided by `reqsign_core::Signer`.

## License

Licensed under the Apache License, Version 2.0.
