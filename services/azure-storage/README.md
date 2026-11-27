# reqsign-azure-storage

Azure Storage signing support for reqsign.

This crate signs requests for Blob, File, Queue, and Table Storage. It supports
shared key, SAS token, and Azure AD bearer token credentials.

> Signing needs a `CryptoProvider` resolved through the `Context`: bind one with
> `Context::with_crypto`, install a process-wide default, or use a facade
> `default_context()` (which binds RustCrypto when the global slot is empty). A
> bare `Context::new()` starts unbound. See
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

## Quick Start

```rust
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use anyhow::Result;
use reqsign_azure_storage::{DefaultCredentialProvider, RequestSigner};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> Result<()> {
    let ctx = Context::new().with_crypto(RustCryptoProvider::new())
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default());

    let signer = Signer::new(
        ctx,
        DefaultCredentialProvider::new(),
        RequestSigner::new(),
    );

    let mut req = http::Request::get(
        "https://mystorageaccount.blob.core.windows.net/container/blob",
    )
    .body(())
    .unwrap()
    .into_parts()
    .0;

    signer.sign(&mut req, None).await?;
    Ok(())
}
```

## Default Credential Chain

`DefaultCredentialProvider::new()` uses this chain:

1. `env`
2. `azure_cli` (`non-wasm32` only)
3. `client_certificate` (`non-wasm32` only)
4. `client_secret`
5. `azure_pipelines`
6. `workload_identity`
7. `imds`

Use `DefaultCredentialProvider::builder()` to customize slot participation.

```rust
use reqsign_azure_storage::{
    ClientSecretCredentialProvider, DefaultCredentialProvider,
};

let provider = DefaultCredentialProvider::builder()
    .no_env()
    .client_secret(
        ClientSecretCredentialProvider::new().with_tenant_id("tenant-id"),
    )
    .no_imds()
    .build();
```

## Environment Variables

Shared key:

```bash
export AZURE_STORAGE_ACCOUNT_NAME=mystorageaccount
export AZURE_STORAGE_ACCOUNT_KEY=base64encodedkey==
```

`AZURE_STORAGE_ACCOUNT` supplies the Shared Key account name when neither
`AZBLOB_ACCOUNT_NAME` nor `AZURE_STORAGE_ACCOUNT_NAME` is set.

SAS token:

```bash
export AZURE_STORAGE_SAS_TOKEN="sv=2021-06-08&ss=b&srt=sco&sp=rwdlacx..."
```

Client secret:

```bash
export AZURE_TENANT_ID=tenant-id
export AZURE_CLIENT_ID=client-id
export AZURE_CLIENT_SECRET=client-secret
```

### Client certificate

On native targets, set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
`AZURE_CLIENT_CERTIFICATE_PATH`. Use a PEM file containing an unencrypted
PKCS#8 or PKCS#1 RSA private key and its certificate. Put the leaf certificate
first, followed by any issuer certificates in chain order.

For Microsoft Entra Subject Name/Issuer authentication, set
`AZURE_CLIENT_SEND_CERTIFICATE_CHAIN=true` to include the public certificates
in the assertion's `x5c` header. The header is omitted by default.
`ClientCertificateCredentialProvider::with_send_certificate_chain` overrides
the environment setting, including when set to `false`.

### Managed identity

The default chain's `imds` slot uses the following endpoint precedence.

| Endpoint source | API version | Request headers |
| --- | --- | --- |
| `ImdsCredentialProvider::with_endpoint`, `AZBLOB_ENDPOINT`, or `AZURE_IMDS_ENDPOINT` | `2018-02-01` | `Metadata: true` and optional `X-IDENTITY-HEADER` from `AZURE_MSI_SECRET` |
| App Service, Functions, and Container Apps via `IDENTITY_ENDPOINT` | `2019-08-01` | `X-IDENTITY-HEADER` from `IDENTITY_HEADER` |
| Legacy App Service and Functions via `MSI_ENDPOINT` | `2017-09-01` | `secret` from `MSI_SECRET` |
| Azure VM IMDS | `2018-02-01` | `Metadata: true` |

A partial platform pair returns a configuration error from the managed identity
provider before it sends a request. The default chain continues to use its usual
provider error handling. `no_imds()` removes the entire slot.

To select a user-assigned identity, the provider uses the first configured ID in
the order `AZURE_OBJECT_ID`, `AZURE_CLIENT_ID`, `AZURE_MSI_RESOURCE_ID` (alias
`AZURE_MSI_RES_ID`). The legacy API requires `AZURE_CLIENT_ID` for user-assigned
identities.

The default token resource is `https://storage.azure.com/`. To specify a different
resource, supply the exact resource URI to `with_resource`, including any trailing
slash. Use the provider directly or pass it to the builder's `imds` slot.

[App Service and Functions](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity#rest-endpoint-reference) ·
[Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity#rest-endpoint-reference) ·
[Legacy App Service](https://github.com/MicrosoftDocs/azure-docs/blob/3bd05c243466cf0f111bb009a64b15443175d80b/articles/app-service/overview-managed-identity.md#using-the-rest-protocol) ·
[VM IMDS](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)

## Using Specific Providers

Use a single provider directly when you do not want the default chain:

```rust
use reqsign_azure_storage::{EnvCredentialProvider, StaticCredentialProvider};

let env_provider = EnvCredentialProvider::new();

let static_provider = StaticCredentialProvider::new_shared_key(
    "mystorageaccount",
    "base64encodedkey==",
);
```

## Use an Azure CLI session

On native targets, the default Azure CLI provider requests the Azure Storage
resource using `az account get-access-token`. It takes `AZURE_TENANT_ID` from the
context environment when set to a non-blank value. To select a tenant and scope
explicitly, supply the configured provider to your signer.

```rust
use reqsign::{azure, default_context, Signer};

let provider = azure::AzureCliCredentialProvider::new()
    .with_tenant_id("contoso.onmicrosoft.com")
    .with_scope("https://storage.azure.com/.default");
let signer = Signer::new(default_context(), provider, azure::RequestSigner::new());
```

`with_tenant_id` takes precedence over the environment. Use `with_resource` for a
resource URI. The last scope or resource setting selects the token target.

To use an existing Azure Developer CLI session, explicitly choose the `azd`
provider. It requests the Azure Storage scope by default and accepts a custom
scope via `with_scope`.

```rust
use reqsign::{azure, default_context, Signer};

let signer = Signer::new(
    default_context(),
    azure::AzureDeveloperCliCredentialProvider::new(),
    azure::RequestSigner::new(),
);
```

Use the facade with the `azure` and `default-context` features for these
examples. When supplying your own context, attach a `CommandExecute` adapter.

## Sign requests to Azurite and custom domains

Use `AddressingStyle::PathStyle` when the first URI path segment contains
the account, as in `http://127.0.0.1:10000/devstoreaccount1/container/blob`.
Shared Key uses the account from the credential and includes the entire encoded
path in the signature. Explicitly configured accounts must match the credential.
Blob Service SAS and User Delegation SAS generation remove the matched account
segment when deriving the SAS resource name. Both preserve the wire URI path.

```rust
use reqsign_azure_storage::{AddressingStyle, RequestSigner};

let request_signer = RequestSigner::new()
    .with_account_name("devstoreaccount1")
    .with_addressing_style(AddressingStyle::PathStyle);
```

For a custom domain that maps directly to an account, keep the default
`AddressingStyle::HostStyle` and set `with_account_name("mystorageaccount")`
for User Delegation SAS. The first path segment names the container. For
path-style User Delegation SAS, the explicit account is required and the key
request goes to the account path on the request's endpoint. Use a trusted
endpoint that accepts the bearer credential and supports Get User Delegation
Key. [Get User Delegation Key](https://learn.microsoft.com/en-us/rest/api/storageservices/get-user-delegation-key)

## Sign Table Storage requests with Shared Key

Use `RequestSigner::new().with_shared_key_mode(SharedKeyMode::Table)` and call
`Signer::sign` with `None`. Table signing uses the generated `x-ms-date` in the
five-line signature and includes only `comp` from the URI query. Supply the
Table operation's service and OData headers on the request.
[Authorize with Shared Key](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#table-service-shared-key-authorization)

## Grant an Account SAS

Use `AccountSasGranter` with a Shared Key for the configured account to issue a
SAS for selected services, resource types, and permissions. The operation signs
locally, requires an explicit positive lifetime, and defaults to HTTPS.
See the [Account SAS example](src/account_sas.rs) for `Granter` setup.

## Grant a Service SAS

Use a Shared Key source to mint an independently usable, expiration-aware SAS
for one typed container or blob grant:

```rust
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use std::time::Duration;

use reqsign_azure_storage::{
    ServiceSasBlobPermissions, ServiceSasConfig, ServiceSasGrant,
    ServiceSasGranter, StaticCredentialProvider,
};
use reqsign_core::{Context, Granter};

# async fn example() -> reqsign_core::Result<()> {
let grant = ServiceSasGrant::for_blob(
    "customer-data",
    "reports/current.csv",
    ServiceSasBlobPermissions::READ,
);
let credential = Granter::new(
    Context::new().with_crypto(RustCryptoProvider::new()),
    StaticCredentialProvider::new_shared_key(
        "mystorageaccount",
        "<base64-encoded 512-bit account key>",
    ),
    ServiceSasGranter::new(ServiceSasConfig::new("mystorageaccount"), grant),
)
.grant(Some(Duration::from_secs(900)))
.await?;
# let _ = credential;
# Ok(())
# }
```

The configured account must match the Shared Key source. The returned
`Credential::SasToken` can be supplied directly to the existing Azure
`RequestSigner`.

## Examples

Run the example:

```bash
cargo run --example blob_storage
```
