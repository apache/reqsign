# OpenStack Keystone Tests

The suite runs without any external service. Provider behaviour comes from a
mock `HttpSend` injected into the `Context`, which records the authentication
request reqsign sends and replies with a scripted Keystone response. This keeps
the tests deterministic and lets them assert on the exact wire payload. Static
token and `OS_AUTH_TOKEN` tests use a `Context` without an HTTP adapter so a
Keystone request would fail the test; the password fallback still uses the mock.
TempURL tests use published and independently calculated HMAC vectors with a
RustCrypto `CryptoProvider`; no Swift service is contacted.

## Test Structure

```text
tests/
├── catalog_lookup.rs         # Catalog and endpoint lookup
├── credential_providers.rs   # Providers, catalog lookup, and signer behaviour
└── temp_url.rs               # Public TempURL presign contract
```

## Live Tests

`test_real_keystone_env_credential_provider` authenticates against a real
Keystone v3 deployment and is skipped unless these variables are set:

- `REQSIGN_OPENSTACK_KEYSTONE_TEST=on`
- `OS_AUTH_URL`
- `OS_USERNAME`
- `OS_PASSWORD`
- `OS_USER_DOMAIN_NAME` (optional, defaults to `Default`)
- `OS_PROJECT_NAME` (optional)
