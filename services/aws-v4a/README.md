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

`RequestSigner` defaults to `PercentEncodingMode::Single` for compatibility with
existing S3 callers. Both header signing and presigning can opt into Double:

```rust
use reqsign_aws_v4a::{PercentEncodingMode, RequestSigner, SigningRegionSet};

let signer = RequestSigner::new("execute-api", SigningRegionSet::new("*")?)
    .with_percent_encoding_mode(PercentEncodingMode::Double);
# Ok::<(), reqsign_core::Error>(())
```

The input URI must already be wire-ready. Double applies one additional encoding
pass to its original path without decoding it: `/a%20b` becomes `/a%2520b` only in
the canonical request. The outgoing path is unchanged, literal `/` separators are
preserved, and path normalization and payload hashing are unaffected. Single
keeps the existing per-segment decode/re-encode behavior, including escape
normalization and rejection of percent-encoded invalid UTF-8. Neither the service
name nor the endpoint automatically selects a mode.
