# reqsign-aws-v4a

`reqsign-aws-v4a` provides AWS Signature Version 4A request signing for
[`reqsign`](https://crates.io/crates/reqsign).

SigV4a uses ECDSA P-256 signatures and a signing region set, allowing one
signed request to be accepted in multiple AWS regions. See the
[AWS SigV4a signing documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

```rust
use reqsign_aws_v4a::{RequestSigner, SigningRegionSet};

let region_set = SigningRegionSet::new("us-east-1,us-west-2")?;
let signer = RequestSigner::new("s3", region_set);
# Ok::<(), reqsign_core::Error>(())
```

Credential providers and shared AWS types are re-exported from
`reqsign-aws-core`.

## Canonical URI Encoding

`RequestSigner` follows the AWS service rules by default: `s3` and `s3express`
use `PercentEncodingMode::Single`, and every other service uses
`PercentEncodingMode::Double` (the `aws-sigv4` default). Call
`with_percent_encoding_mode` to override the inferred mode for a custom or
self-hosted endpoint:

```rust
use reqsign_aws_v4a::{PercentEncodingMode, RequestSigner, SigningRegionSet};

let signer = RequestSigner::new("my-custom-service", SigningRegionSet::new("*")?)
    .with_percent_encoding_mode(PercentEncodingMode::Single);
# Ok::<(), reqsign_core::Error>(())
```

The input URI must already be wire-ready. Double applies one additional encoding
pass to its original path without decoding it: `/a%20b` becomes `/a%2520b` only in
the canonical request. The outgoing path is unchanged, literal `/` separators are
preserved, and path normalization and payload hashing are unaffected. Single
keeps the existing per-segment decode/re-encode behavior, including escape
normalization and rejection of percent-encoded invalid UTF-8.
