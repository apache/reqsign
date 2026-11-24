# Backblaze B2 Tests

The suite runs without a B2 account. Provider behavior comes from a mock
`HttpSend` injected into the `Context`, which records the authorization request
reqsign sends and returns a scripted B2 response. This keeps the tests
deterministic and lets them assert the exact request method, URL, and Basic
authorization header.

## Test Structure

```text
tests/
├── credential_providers.rs   # Account exchange, providers, signer, caching
└── wasm.rs                   # Public signing with the JavaScript clock
```

The tests cover the v4 account authorization exchange, application key expiry,
error redaction, environment discovery, static credentials, default-chain
overrides, request-target preservation, and credential caching. `wasm.rs` runs
the public signing path with static and expiring credentials under
`wasm-bindgen-test` in Node.
