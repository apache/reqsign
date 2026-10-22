# OpenStack Keystone Tests

The suite runs without any external service. Provider behaviour comes from a
mock `HttpSend` injected into the `Context`, which records the authentication
request reqsign sends and replies with a scripted Keystone response. This keeps
the tests deterministic and lets them assert on the exact wire payload.

## Test Structure

```text
tests/
└── credential_providers.rs   # Providers, catalog lookup, and signer behaviour
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
