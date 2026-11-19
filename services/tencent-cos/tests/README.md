# Tencent COS Integration Tests

## Test Files

| File | Coverage |
| --- | --- |
| `main.rs` | Request signing with static credentials. Gated live tests require `REQSIGN_TENCENT_COS_TEST=on` and COS access-key configuration. |
| `credential_chain.rs` | Credential-chain ordering and error behavior without network access. |
| `web_identity_live.rs` | Live `AssumeRoleWithWebIdentityCredentialProvider` coverage. |

## Live Web Identity Coverage

`web_identity_live.rs` invokes `AssumeRoleWithWebIdentityCredentialProvider`
with the provider's own environment contract. The provider reads a GitHub OIDC
token from `TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE` and exchanges it at
`sts.tencentcloudapi.com`. The test then uses the returned temporary credential
to GET one private COS object. It fails when the object is publicly readable,
when the credential has no `x-cos-security-token` header, or when COS rejects
the read.

### Trust Boundary

The `test_web_identity_provider` job in
`.github/workflows/tencent_cos.yml` runs only for pushes to `main` and for pull
requests from branches in `apache/reqsign` by actors other than
`dependabot[bot]`. Fork pull requests, dependabot pull requests, and runs without
the configuration below are reported as a skipped job by `check_live_config`;
they never mint an OIDC token. That job has `contents: read` and
`id-token: write`, and the workflow declares `permissions: {}`, so no other job
holds a token.

The OIDC token is written to `$RUNNER_TEMP/tencent-web-identity-token` with mode
`0600`, registered with `core.setSecret`, and is never exported to the
environment, printed, or uploaded. This test uses no long-lived Tencent Cloud
key.

### Required Configuration

The live job reads non-secret repository variables:

| Variable | Meaning |
| --- | --- |
| `REQSIGN_TENCENT_LIVE_ROLE_ARN` | CAM role that STS returns credentials for. |
| `REQSIGN_TENCENT_LIVE_PROVIDER_ID` | CAM OIDC identity provider ID passed to `AssumeRoleWithWebIdentity`. |
| `REQSIGN_TENCENT_LIVE_REGION` | COS region, for example `ap-guangzhou`. |
| `REQSIGN_TENCENT_LIVE_OBJECT_URL` | Full URL of the private object the test reads. |

These are identifiers rather than credentials, so they belong in repository
variables like the AWS live tests' `REQSIGN_AWS_LIVE_*` variables. When any of
them is missing, the job is skipped with an `::warning::`, so an unconfigured
repository never reports a green live-provider result.

### Cloud-Side Setup

The live job needs the following resources before any of its configuration can
be set:

1. A CAM OIDC identity provider for the GitHub Actions issuer.
2. A role whose trust policy accepts only the audience
   `sts.tencentcloudapi.com` and the GitHub subject claims for this repository:
   `repo:apache/reqsign:ref:refs/heads/main` for pushes and
   `repo:apache/reqsign:pull_request` for pull requests from branches in this
   repository.
3. A policy that allows only `cos:GetObject` on the test object's path. The test
   never lists, writes, or deletes objects.
4. One private object, then the four repository variables above.

### Running Locally

```bash
export REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY=on
export TENCENTCLOUD_REGION=ap-guangzhou
export TENCENTCLOUD_ROLE_ARN=...
export TENCENTCLOUD_PROVIDER_ID=...
export TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE=/path/to/github-oidc-token
export REQSIGN_TENCENT_COS_OBJECT_URL=https://.../private-object
cargo test -p reqsign-tencent-cos --test web_identity_live -- --no-capture
```

Without `REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY=on` the test returns early and
passes, matching the other live tests in this crate. With the gate on, missing
configuration is a test failure rather than a skip.
