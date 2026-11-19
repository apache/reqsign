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

Without `REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY=on` the test returns early and
passes, matching the other live tests in this crate. With the gate on, missing
configuration is a test failure that names every unset variable.

## Where Live Tests Run

`.github/workflows/tencent_cos_live.yml` owns all cloud access. It runs on
pushes to `main` and on a manual `workflow_dispatch` of `main`, and its jobs
skip any other ref. `.github/workflows/tencent_cos.yml` runs offline tests for
pushes and pull requests and has no job with `id-token: write`, so the pull
request workflow itself never requests a GitHub OIDC token.

Pull request YAML is not a trust boundary: a pull request can change a
workflow file and request a token. The CAM role described below therefore
accepts only the `refs/heads/main` subject, so a run from any other ref fails
at STS even if its workflow asks for a token.

## Trust Boundary

The live job requests an OIDC token with an explicit audience and sets these
claims:

| Claim | Value |
| --- | --- |
| `iss` | `https://token.actions.githubusercontent.com` |
| `aud` | `sts.tencentcloudapi.com` |
| `sub` | `repo:apache@47359/reqsign@469069490:ref:refs/heads/main` |

Apache Reqsign has immutable OIDC subject claims enabled, so the subject uses
the owner and repository IDs rather than only their names. A
`pull_request`-triggered run gets
`repo:apache@47359/reqsign@469069490:pull_request`, and a run from another branch
gets that branch in place of `refs/heads/main`; the CAM role rejects both. The
live job does not use a GitHub environment, which would replace the ref part of
the subject with the environment name.

The token is written to `$RUNNER_TEMP/tencent-web-identity-token` with mode
`0600`, registered with `core.setSecret`, never exported to the environment,
never printed, and removed at the end of the job. The job holds only
`contents: read` and `id-token: write`; the workflow declares `permissions: {}`.

## Required Configuration

The live workflow reads four non-secret repository variables:

| Variable | Meaning |
| --- | --- |
| `REQSIGN_TENCENT_LIVE_ROLE_ARN` | CAM role ARN, `qcs::cam::uin/<uin>:roleName/<name>`. |
| `REQSIGN_TENCENT_LIVE_PROVIDER_ID` | CAM OIDC identity provider name, passed to STS as `ProviderId`. |
| `REQSIGN_TENCENT_LIVE_REGION` | COS region, for example `ap-guangzhou`. |
| `REQSIGN_TENCENT_LIVE_OBJECT_URL` | `https://` URL of the private object the test reads. |

When none is set, `check_live_config` warns and the live job is skipped, so an
unconfigured repository never reports a passing live-provider result. When only
some are set, `check_live_config` fails and names the missing variables. It also
rejects a role ARN that is not a CAM role ARN and an object URL that is not
HTTPS.

## Cloud-Side Setup

The workflow cannot grant itself access. These resources define the boundary and
must exist before the variables are set:

1. A CAM OIDC identity provider. Use `https://token.actions.githubusercontent.com`
   as the provider URL (the token issuer) and `sts.tencentcloudapi.com` as a
   client ID (the token audience). Enable public-key auto-rotation, or upload
   GitHub's current signing keys.
2. A CAM role with this trust policy, where `<owner-uin>` is the account's
   owner UIN and `<provider-name>` is the provider name above. The role session
   duration must allow at least 7200 seconds, the provider's default STS
   duration, and console login stays disabled.

```json
{
  "version": "2.0",
  "statement": [
    {
      "action": "name/sts:AssumeRoleWithWebIdentity",
      "effect": "allow",
      "principal": {
        "federated": ["qcs::cam::uin/<owner-uin>:oidc-provider/<provider-name>"]
      },
      "condition": {
        "string_equal": {
          "oidc:iss": "https://token.actions.githubusercontent.com",
          "oidc:aud": "sts.tencentcloudapi.com",
          "oidc:sub": "repo:apache@47359/reqsign@469069490:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

3. A policy that allows one read action on one object, where `<appid>` is the
   COS APPID and `<bucket>` includes the APPID suffix:

```json
{
  "version": "2.0",
  "statement": [
    {
      "action": ["name/cos:GetObject"],
      "effect": "allow",
      "resource": ["qcs::cos:<region>:uid/<appid>:<bucket>/<object-key>"]
    }
  ]
}
```

The role cannot list, write, or delete objects, and the job needs no long-lived
Tencent Cloud key. Changing the repository's OIDC subject setting changes the
`sub` claim; the trust condition then stops matching and STS rejects the
exchange instead of accepting a broader identity.

## Verifying Activation

After the resources exist and the variables are set, a push to `main` or a
manual run of `Tencent COS Live Test` on `main` proves the full exchange. Its
signed request succeeds only when the provider returned a temporary credential
that STS issued for the role and COS accepted for `cos:GetObject`. The job also
checks that the object is not publicly readable. A skipped live job proves
nothing; `check_live_config` warns when the variables are absent.

To run the test locally, provide a token for the same issuer, audience, role,
and subject, then:

```bash
export REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY=on
export TENCENTCLOUD_REGION=ap-guangzhou
export TENCENTCLOUD_ROLE_ARN=...
export TENCENTCLOUD_PROVIDER_ID=...
export TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE=/path/to/github-oidc-token
export REQSIGN_TENCENT_COS_OBJECT_URL=https://.../private-object
cargo test -p reqsign-tencent-cos --test web_identity_live -- --no-capture
```

## References

- GitHub OIDC claims and subject formats:
  <https://docs.github.com/en/actions/reference/security/oidc>
- Repository OIDC subject customization:
  <https://docs.github.com/en/rest/actions/oidc>
- Tencent CAM OIDC role SSO:
  <https://cloud.tencent.com/document/product/598/96013>
- Tencent CAM role trust conditions (`oidc:iss`, `oidc:aud`, `oidc:sub`):
  <https://cloud.tencent.com/document/product/598/19381>
- Tencent CAM OIDC identity provider:
  <https://cloud.tencent.com/document/product/598/93430>
- `AssumeRoleWithWebIdentity`:
  <https://cloud.tencent.com/document/product/1312/73070>
- COS CAM actions and resource formats:
  <https://cloud.tencent.com/document/product/436/31923>
