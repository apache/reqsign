# reqsign-aws-v4a

`reqsign-aws-v4a` provides AWS Signature Version 4A request signing for
[`reqsign`](https://crates.io/crates/reqsign).

SigV4a uses ECDSA P-256 signatures and a signing region set, allowing one
signed request to be accepted in multiple AWS regions. See the
[AWS SigV4a signing documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

> Signing needs a `CryptoProvider` resolved through the `Context`: bind one with
> `Context::with_crypto`, install a process-wide default, or use a facade
> `default_context()` (which binds RustCrypto when the global slot is empty). A
> bare `Context::new()` starts unbound. See
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

```rust
use reqsign_aws_v4a::{RequestSigner, SigningRegionSet};

let region_set = SigningRegionSet::new("us-east-1,us-west-2")?;
let signer = RequestSigner::new("s3", region_set);
# Ok::<(), reqsign_core::Error>(())
```

Credential providers and shared AWS types are re-exported from
`reqsign-aws-core`. Use [`SharedConfig::load`] to read the configured SigV4a
signing region set. When [`Profile::sigv4a_signing_region_set`] returns a value,
pass it to [`SigningRegionSet::new`].

## Canonical URI

The signer defaults to `PercentEncodingMode::Single` and
`UriPathNormalizationMode::Disabled` for every service, including S3. Configure
encoding and path normalization independently to match the signing service.
The example enables both settings for a service that requires them.

```rust
use reqsign_aws_v4a::{
    PercentEncodingMode, RequestSigner, SigningRegionSet, UriPathNormalizationMode,
};

let signer = RequestSigner::new("execute-api", SigningRegionSet::new("*")?)
    .with_percent_encoding_mode(PercentEncodingMode::Double)
    .with_uri_path_normalization_mode(UriPathNormalizationMode::Enabled);
# Ok::<(), reqsign_core::Error>(())
```

Both header signing and presigning use these settings to compute the canonical
path. Supply the final wire-ready URI. With normalization enabled, literal `.`
and `..` segments are resolved and repeated slashes are collapsed before encoding.
The outgoing URI keeps its original path and existing query bytes.

Double encodes the path without decoding its escapes. In the canonical request,
`/a%20b` becomes `/a%2520b`, a literal `@` becomes `%40`, and an existing `%40`
becomes `%2540`. Literal `/` separators are preserved. Single retains Reqsign's
per-segment decode/re-encode behavior, including normalization of escape spelling
and rejection of percent-encoded invalid UTF-8.
