// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use crate::Context;
use crate::Error;
use crate::ProvideCredential;
use crate::ProvideCredentialDyn;
use crate::Result;
use crate::SignRequest;
use crate::SignRequestDyn;
use crate::SigningCredential;
use asyncband::mutex::Mutex;
use std::any::type_name;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Loads credentials and atomically signs request heads.
///
/// The service-specific [`SignRequest`] runs against a private candidate. Only the
/// candidate URI and headers are committed after successful signing.
#[derive(Clone)]
pub struct Signer<K: SigningCredential> {
    ctx: Context,
    loader: Arc<dyn ProvideCredentialDyn<Credential = K>>,
    builder: Arc<dyn SignRequestDyn<Credential = K>>,
    credential: Arc<CredentialCache<K>>,
}

/// Credential cache shared by clones of a [`Signer`].
///
/// Valid credentials are read from `current` without awaiting, so concurrent
/// signing doesn't serialize. `refresh` only serializes loading a new credential.
struct CredentialCache<K> {
    current: RwLock<Option<K>>,
    refresh: Mutex<()>,
}

impl<K> CredentialCache<K> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(None),
            refresh: Mutex::new(()),
        })
    }
}

impl<K: SigningCredential> Debug for Signer<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("credential_type", &type_name::<K>())
            .finish_non_exhaustive()
    }
}

impl<K: SigningCredential> Signer<K> {
    /// Create a new signer.
    pub fn new(
        ctx: Context,
        loader: impl ProvideCredential<Credential = K>,
        builder: impl SignRequest<Credential = K>,
    ) -> Self {
        Self {
            ctx,

            loader: Arc::new(loader),
            builder: Arc::new(builder),
            credential: CredentialCache::new(),
        }
    }

    /// Replace the context and create an isolated empty credential cache.
    pub fn with_context(mut self, ctx: Context) -> Self {
        self.ctx = ctx;
        self.credential = CredentialCache::new();
        self
    }

    /// Replace the credential provider while keeping context and request signer,
    /// and create an isolated empty credential cache.
    pub fn with_credential_provider(
        mut self,
        provider: impl ProvideCredential<Credential = K>,
    ) -> Self {
        self.loader = Arc::new(provider);
        self.credential = CredentialCache::new();
        self
    }

    /// Replace only the request signer, retaining the context, credential provider,
    /// and shared credential cache.
    pub fn with_request_signer(mut self, signer: impl SignRequest<Credential = K>) -> Self {
        self.builder = Arc::new(signer);
        self
    }

    /// Sign a wire-ready request head.
    ///
    /// The request URI must satisfy the input contract of the configured
    /// [`SignRequest`]. Built-in signers require an authority and expect path and query
    /// data to be percent-encoded exactly once before this call. Signing does not
    /// perform general-purpose URI encoding for the caller.
    ///
    /// If credential loading or request signing returns an error, `req` is unchanged.
    /// On success, only `req.uri` and `req.headers` may change; the method, version, and
    /// extensions retain their input values.
    ///
    /// `expires_in` is a service-specific validity input and does not universally
    /// select query authentication. The configured service signer and credential type
    /// determine how it is interpreted.
    ///
    /// Use [`Signer::credential_for`] and [`Signer::sign_with_credential`] when the
    /// credential supplies routing metadata for the request URI. This method may refresh
    /// the cached credential, which can differ from the credential that determined the
    /// URI.
    ///
    /// Cached credentials must be fresh according to [`SigningCredential::is_valid`]
    /// and usable through [`SignRequest::required_valid_until`]. A refreshed credential
    /// only needs to satisfy the exact operation deadline. Credential refresh is
    /// serialized per shared cache. A failed refresh is not cached, so the next waiting
    /// or later caller can retry. Provider errors are returned without internal retry or
    /// fallback to the previous cached credential. Request signing runs after refresh
    /// coordination has completed and remains concurrent.
    pub async fn sign(
        &self,
        req: &mut http::request::Parts,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let credential = self.credential_for(expires_in).await?;
        self.sign_candidate(req, &credential, expires_in).await
    }

    /// Load or reuse the credential for a requested signing operation.
    ///
    /// This uses the same serialized credential cache and validity checks as
    /// [`Signer::sign`]. It may load a new credential or refresh a stale cached one,
    /// and installs a successful result in the shared cache. The returned credential
    /// is usable through [`SigningCredential::is_valid_at`] for the timestamp returned
    /// by [`SignRequest::required_valid_until`] with `expires_in`.
    ///
    /// Call this before building a request URI when the service credential carries
    /// routing metadata, then pass the same credential to
    /// [`Signer::sign_with_credential`] so the URI and its authentication agree.
    pub async fn credential_for(&self, expires_in: Option<Duration>) -> Result<K> {
        if let Some(credential) = self.usable_cached(expires_in) {
            return Ok(credential);
        }

        let refresh = self.credential.refresh.lock().await;
        if let Some(credential) = self.usable_cached(expires_in) {
            return Ok(credential);
        }

        let credential = self
            .loader
            .provide_credential_dyn(&self.ctx)
            .await?
            .ok_or_else(|| {
                Error::credential_invalid("failed to load signing credential")
                    .with_context(format!("credential_type: {}", type_name::<K>()))
            })?;

        *self
            .credential
            .current
            .write()
            .expect("credential cache poisoned") = Some(credential.clone());
        drop(refresh);

        self.validate_refreshed_credential(credential, expires_in)
    }

    fn usable_cached(&self, expires_in: Option<Duration>) -> Option<K> {
        let current = self
            .credential
            .current
            .read()
            .expect("credential cache poisoned");
        current
            .as_ref()
            .filter(|credential| {
                credential.is_valid()
                    && credential.is_valid_at(
                        self.builder
                            .required_valid_until_dyn(credential, expires_in),
                    )
            })
            .cloned()
    }

    /// Sign a wire-ready request head with a caller-supplied credential.
    ///
    /// Use this with a credential obtained from [`Signer::credential_for`] when that
    /// credential determined the request URI. Normal [`Signer::sign`] may refresh the
    /// cached credential in between, so the supplied credential must be the one used to
    /// build the URI. This method never loads, refreshes, or stores a credential, and it
    /// does not modify the signer's credential cache.
    ///
    /// Only exact usability at the operation deadline from
    /// [`SignRequest::required_valid_until`] is required; the credential's proactive
    /// cache freshness does not matter. If [`SigningCredential::is_valid_at`] rejects
    /// that deadline, this method returns `CredentialInvalid` and leaves `req`
    /// unchanged. Call [`Signer::credential_for`] again and rebuild the URI if the
    /// credential must be replaced.
    ///
    /// The request URI and `expires_in` follow the same contracts as [`Signer::sign`].
    /// If signing returns an error, `req` is unchanged. On success, only `req.uri` and
    /// `req.headers` may change; the method, version, and extensions retain their input
    /// values.
    pub async fn sign_with_credential(
        &self,
        req: &mut http::request::Parts,
        credential: &K,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let required_until = self
            .builder
            .required_valid_until_dyn(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "supplied signing credential expires before the requested operation deadline",
            )
            .with_context(format!("credential_type: {}", type_name::<K>()))
            .with_context(format!("required_valid_until: {required_until}")));
        }

        self.sign_candidate(req, credential, expires_in).await
    }

    async fn sign_candidate(
        &self,
        req: &mut http::request::Parts,
        credential: &K,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let mut candidate = req.clone();
        self.builder
            .sign_request_dyn(&self.ctx, &mut candidate, Some(credential), expires_in)
            .await?;

        req.uri = candidate.uri;
        req.headers = candidate.headers;
        Ok(())
    }

    fn validate_refreshed_credential(
        &self,
        credential: K,
        expires_in: Option<Duration>,
    ) -> Result<K> {
        let required_until = self
            .builder
            .required_valid_until_dyn(&credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "refreshed signing credential expires before the requested operation deadline",
            )
            .with_context(format!("credential_type: {}", type_name::<K>()))
            .with_context(format!("required_valid_until: {required_until}")));
        }

        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;
    use crate::{ErrorKind, ProvideCredential, SignRequest, StaticEnv};
    use asyncband::oneshot;
    use futures::future::{join_all, pending};
    use futures::poll;
    use http::{HeaderValue, Method, Request, Version};
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Debug)]
    struct TestCredential;

    impl SigningCredential for TestCredential {
        fn is_valid(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct StaticProvider;

    impl ProvideCredential for StaticProvider {
        type Credential = TestCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(Some(TestCredential))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Extension(&'static str);

    #[derive(Debug)]
    struct MutatingSigner {
        fail: bool,
    }

    impl SignRequest for MutatingSigner {
        type Credential = TestCredential;

        async fn sign_request(
            &self,
            _ctx: &Context,
            req: &mut http::request::Parts,
            _credential: Option<&Self::Credential>,
            _expires_in: Option<Duration>,
        ) -> Result<()> {
            req.method = Method::POST;
            req.uri = "https://signed.example.com/result?auth=1"
                .parse()
                .expect("URI must parse");
            req.version = Version::HTTP_2;
            req.headers.clear();
            req.headers
                .insert("authorization", HeaderValue::from_static("signed"));
            req.extensions.insert(Extension("candidate"));

            if self.fail {
                Err(Error::unexpected("injected signing failure"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ExpiringCredential {
        generation: u8,
        fresh: bool,
        expires_at: Timestamp,
        required_until: Timestamp,
    }

    impl SigningCredential for ExpiringCredential {
        fn is_valid(&self) -> bool {
            self.fresh
        }

        fn is_valid_at(&self, timestamp: Timestamp) -> bool {
            self.expires_at > timestamp
        }
    }

    type ControlledResponse = Result<Option<ExpiringCredential>>;
    type ControlledProviderParts = (
        ControlledProvider,
        Arc<AtomicUsize>,
        Vec<oneshot::Sender<ControlledResponse>>,
    );

    #[derive(Debug)]
    struct SequenceProvider {
        responses: StdMutex<VecDeque<Result<Option<ExpiringCredential>>>>,
        calls: Arc<AtomicUsize>,
    }

    impl SequenceProvider {
        fn new(
            responses: impl IntoIterator<Item = Result<Option<ExpiringCredential>>>,
        ) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    responses: StdMutex::new(responses.into_iter().collect()),
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl ProvideCredential for SequenceProvider {
        type Credential = ExpiringCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .unwrap_or(Ok(None))
        }
    }

    struct ControlledProvider {
        responses: StdMutex<VecDeque<oneshot::Receiver<ControlledResponse>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Debug for ControlledProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ControlledProvider").finish_non_exhaustive()
        }
    }

    impl ControlledProvider {
        fn new(invocations: usize) -> ControlledProviderParts {
            let calls = Arc::new(AtomicUsize::new(0));
            let (senders, receivers) = (0..invocations)
                .map(|_| oneshot::channel())
                .unzip::<_, _, Vec<_>, VecDeque<_>>();
            (
                Self {
                    responses: StdMutex::new(receivers),
                    calls: calls.clone(),
                },
                calls,
                senders,
            )
        }
    }

    impl ProvideCredential for ControlledProvider {
        type Credential = ExpiringCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = self
                .responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .expect("controlled response must exist");
            response
                .await
                .map_err(|_| Error::unexpected("controlled response sender was dropped"))?
        }
    }

    struct ControlledRequestSigner {
        started: Arc<AtomicUsize>,
        releases: StdMutex<VecDeque<oneshot::Receiver<()>>>,
    }

    impl Debug for ControlledRequestSigner {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ControlledRequestSigner")
                .finish_non_exhaustive()
        }
    }

    impl ControlledRequestSigner {
        fn new(count: usize) -> (Self, Arc<AtomicUsize>, Vec<oneshot::Sender<()>>) {
            let started = Arc::new(AtomicUsize::new(0));
            let (senders, receivers) = (0..count)
                .map(|_| oneshot::channel())
                .unzip::<_, _, Vec<_>, VecDeque<_>>();
            (
                Self {
                    started: started.clone(),
                    releases: StdMutex::new(receivers),
                },
                started,
                senders,
            )
        }
    }

    impl SignRequest for ControlledRequestSigner {
        type Credential = ExpiringCredential;

        fn required_valid_until(
            &self,
            credential: &Self::Credential,
            _expires_in: Option<Duration>,
        ) -> Timestamp {
            credential.required_until
        }

        async fn sign_request(
            &self,
            _ctx: &Context,
            req: &mut http::request::Parts,
            credential: Option<&Self::Credential>,
            _expires_in: Option<Duration>,
        ) -> Result<()> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let release = self
                .releases
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .expect("signing release must exist");
            release
                .await
                .map_err(|_| Error::unexpected("signing release sender was dropped"))?;
            req.headers.insert(
                "x-credential-generation",
                credential
                    .expect("credential must be present")
                    .generation
                    .to_string()
                    .parse()?,
            );
            Ok(())
        }
    }

    struct CancellationProvider {
        calls: Arc<AtomicUsize>,
        credential: ExpiringCredential,
    }

    impl Debug for CancellationProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CancellationProvider")
                .finish_non_exhaustive()
        }
    }

    impl ProvideCredential for CancellationProvider {
        type Credential = ExpiringCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                pending::<()>().await;
            }
            Ok(Some(self.credential.clone()))
        }
    }

    const CREDENTIAL_SECRET: &str = "credential-secret-must-not-leak";

    #[derive(Clone, Debug)]
    struct SecretCredential {
        secret: &'static str,
    }

    impl SigningCredential for SecretCredential {
        fn is_valid(&self) -> bool {
            !self.secret.is_empty()
        }

        fn is_valid_at(&self, _timestamp: Timestamp) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct SecretProvider;

    impl ProvideCredential for SecretProvider {
        type Credential = SecretCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(Some(SecretCredential {
                secret: CREDENTIAL_SECRET,
            }))
        }
    }

    #[derive(Debug)]
    struct SecretRequestSigner;

    impl SignRequest for SecretRequestSigner {
        type Credential = SecretCredential;

        async fn sign_request(
            &self,
            _ctx: &Context,
            _req: &mut http::request::Parts,
            _credential: Option<&Self::Credential>,
            _expires_in: Option<Duration>,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct OperationSigner;

    impl SignRequest for OperationSigner {
        type Credential = ExpiringCredential;

        fn required_valid_until(
            &self,
            credential: &Self::Credential,
            _expires_in: Option<Duration>,
        ) -> Timestamp {
            credential.required_until
        }

        async fn sign_request(
            &self,
            _ctx: &Context,
            req: &mut http::request::Parts,
            credential: Option<&Self::Credential>,
            expires_in: Option<Duration>,
        ) -> Result<()> {
            let credential = credential.expect("credential must be present");
            if !credential.is_valid_at(self.required_valid_until(credential, expires_in)) {
                return Err(Error::credential_invalid(
                    "credential is not valid for operation",
                ));
            }
            req.headers.insert(
                "x-credential-generation",
                credential.generation.to_string().parse()?,
            );
            Ok(())
        }
    }

    fn request_parts() -> http::request::Parts {
        let mut parts = Request::get("https://example.com/original?x=%2F")
            .version(Version::HTTP_11)
            .header("x-original", "value")
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
        parts.extensions.insert(Extension("caller"));
        parts
    }

    fn set_cached_credential<K: SigningCredential>(signer: &Signer<K>, credential: K) {
        *signer
            .credential
            .current
            .write()
            .expect("credential cache poisoned") = Some(credential);
    }

    #[test]
    fn failure_leaves_entire_request_head_unchanged() {
        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: true },
        );
        let mut parts = request_parts();
        let original = parts.clone();

        let result = futures::executor::block_on(signer.sign(&mut parts, None));

        assert!(result.is_err());
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(
            parts.extensions.get::<Extension>(),
            original.extensions.get::<Extension>()
        );
    }

    #[test]
    fn success_commits_only_uri_and_headers() {
        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: false },
        );
        let mut parts = request_parts();
        let original = parts.clone();

        futures::executor::block_on(signer.sign(&mut parts, None)).expect("signing must succeed");

        assert_eq!(parts.method, original.method);
        assert_eq!(parts.version, original.version);
        assert_eq!(
            parts.extensions.get::<Extension>(),
            original.extensions.get::<Extension>()
        );
        assert_eq!(
            parts.uri,
            "https://signed.example.com/result?auth=1"
                .parse::<http::Uri>()
                .expect("URI must parse")
        );
        assert_eq!(
            parts.headers.get("authorization"),
            Some(&HeaderValue::from_static("signed"))
        );
        assert!(!parts.headers.contains_key("x-original"));
    }

    #[test]
    fn valid_cached_credential_does_not_wait_for_refresh_lock() {
        use futures::FutureExt;

        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: false },
        );
        futures::executor::block_on(signer.sign(&mut request_parts(), None))
            .expect("signing must succeed");

        let _refresh = signer
            .credential
            .refresh
            .try_lock()
            .expect("refresh lock must be free");
        let mut parts = request_parts();
        signer
            .sign(&mut parts, None)
            .now_or_never()
            .expect("signing with a valid cached credential must not wait")
            .expect("signing must succeed");
        assert_eq!(
            parts.headers.get("authorization"),
            Some(&HeaderValue::from_static("signed"))
        );
    }

    #[test]
    fn concurrent_cold_start_invokes_provider_once() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(500).expect("timestamp must be valid");
            let credential = ExpiringCredential {
                generation: 1,
                fresh: true,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let (provider, calls, mut responses) = ControlledProvider::new(1);
            let signer = Signer::new(Context::new(), provider, OperationSigner);
            let signers = (0..8).map(|_| signer.clone()).collect::<Vec<_>>();
            let mut requests = (0..8).map(|_| request_parts()).collect::<Vec<_>>();
            let mut batch = Box::pin(join_all(
                requests
                    .iter_mut()
                    .zip(signers.iter())
                    .map(|(request, signer)| signer.sign(request, None)),
            ));

            assert!(poll!(&mut batch).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 1);

            responses
                .remove(0)
                .send(Ok(Some(credential)))
                .expect("controlled response must be received");
            for result in batch.await {
                result.expect("concurrent cold-start signing must succeed");
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn concurrent_stale_refresh_invokes_provider_once() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(600).expect("timestamp must be valid");
            let cached = ExpiringCredential {
                generation: 1,
                fresh: false,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let refreshed = ExpiringCredential {
                generation: 2,
                fresh: true,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let (provider, calls, mut responses) = ControlledProvider::new(1);
            let signer = Signer::new(Context::new(), provider, OperationSigner);
            set_cached_credential(&signer, cached);
            let mut requests = (0..8).map(|_| request_parts()).collect::<Vec<_>>();
            let mut batch = Box::pin(join_all(
                requests
                    .iter_mut()
                    .map(|request| signer.sign(request, None)),
            ));

            assert!(poll!(&mut batch).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 1);

            responses
                .remove(0)
                .send(Ok(Some(refreshed)))
                .expect("controlled response must be received");
            for result in batch.await {
                result.expect("concurrent stale refresh must succeed");
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            for request in requests {
                assert_eq!(
                    request.headers.get("x-credential-generation"),
                    Some(&HeaderValue::from_static("2"))
                );
            }
        });
    }

    #[test]
    fn concurrent_refresh_failure_allows_waiter_retry() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(700).expect("timestamp must be valid");
            let refreshed = ExpiringCredential {
                generation: 2,
                fresh: true,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let (provider, calls, mut responses) = ControlledProvider::new(2);
            let signer = Signer::new(Context::new(), provider, OperationSigner);
            let mut requests = (0..8).map(|_| request_parts()).collect::<Vec<_>>();
            let mut batch = Box::pin(join_all(
                requests
                    .iter_mut()
                    .map(|request| signer.sign(request, None)),
            ));

            assert!(poll!(&mut batch).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 1);

            responses
                .remove(0)
                .send(Err(Error::rate_limited("injected refresh failure")
                    .with_context("refresh_generation: 1")))
                .expect("controlled failure must be received");

            assert!(poll!(&mut batch).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            responses
                .remove(0)
                .send(Ok(Some(refreshed)))
                .expect("controlled recovery must be received");

            let results = batch.await;
            let errors = results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .collect::<Vec<_>>();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].kind(), ErrorKind::RateLimited);
            assert_eq!(errors[0].to_string(), "injected refresh failure");
            assert_eq!(errors[0].context(), &["refresh_generation: 1"]);
            assert!(errors[0].is_retryable());
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 7);
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            let mut later_request = request_parts();
            signer
                .sign(&mut later_request, None)
                .await
                .expect("later caller must reuse the recovered credential");
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn refreshed_credential_is_checked_for_exact_operation_deadline() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(800).expect("timestamp must be valid");
            let credential = ExpiringCredential {
                generation: 1,
                fresh: true,
                expires_at: base + Duration::from_secs(10),
                required_until: base + Duration::from_secs(10),
            };
            let (provider, calls, mut responses) = ControlledProvider::new(1);
            let signer = Signer::new(Context::new(), provider, OperationSigner);
            let mut request = request_parts();
            let mut signing = Box::pin(signer.sign(&mut request, None));

            assert!(poll!(&mut signing).is_pending());
            responses
                .remove(0)
                .send(Ok(Some(credential)))
                .expect("controlled response must be received");
            let error = signing
                .await
                .expect_err("exact deadline must reject the credential");
            assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
            assert!(
                error
                    .to_string()
                    .contains("expires before the requested operation deadline")
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn distinct_credential_caches_do_not_block_each_other() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(900).expect("timestamp must be valid");
            let credential_a = ExpiringCredential {
                generation: 1,
                fresh: true,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let credential_b = ExpiringCredential {
                generation: 2,
                fresh: true,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let (provider_a, calls_a, mut responses_a) = ControlledProvider::new(1);
            let (provider_b, calls_b, mut responses_b) = ControlledProvider::new(1);
            let signer_a = Signer::new(Context::new(), provider_a, OperationSigner);
            let signer_b = Signer::new(Context::new(), provider_b, OperationSigner);
            let mut request_a = request_parts();
            let mut request_b = request_parts();
            let mut future_a = Box::pin(signer_a.sign(&mut request_a, None));
            let mut future_b = Box::pin(signer_b.sign(&mut request_b, None));

            assert!(poll!(&mut future_a).is_pending());
            assert!(poll!(&mut future_b).is_pending());
            assert_eq!(calls_a.load(Ordering::SeqCst), 1);
            assert_eq!(calls_b.load(Ordering::SeqCst), 1);

            responses_b
                .remove(0)
                .send(Ok(Some(credential_b)))
                .expect("second cache response must be received");
            future_b
                .await
                .expect("second cache must complete while first is blocked");
            assert!(poll!(&mut future_a).is_pending());

            responses_a
                .remove(0)
                .send(Ok(Some(credential_a)))
                .expect("first cache response must be received");
            future_a.await.expect("first cache must complete");
        });
    }

    #[test]
    fn request_signing_remains_concurrent_after_refresh() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(950).expect("timestamp must be valid");
            let credential = ExpiringCredential {
                generation: 1,
                fresh: true,
                expires_at: base + Duration::from_secs(30),
                required_until: base + Duration::from_secs(10),
            };
            let (provider, calls, mut responses) = ControlledProvider::new(1);
            let (request_signer, started, releases) = ControlledRequestSigner::new(8);
            let signer = Signer::new(Context::new(), provider, request_signer);
            let mut requests = (0..8).map(|_| request_parts()).collect::<Vec<_>>();
            let mut batch = Box::pin(join_all(
                requests
                    .iter_mut()
                    .map(|request| signer.sign(request, None)),
            ));

            assert!(poll!(&mut batch).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(started.load(Ordering::SeqCst), 0);
            responses
                .remove(0)
                .send(Ok(Some(credential)))
                .expect("controlled response must be received");

            assert!(poll!(&mut batch).is_pending());
            assert_eq!(started.load(Ordering::SeqCst), 8);
            for release in releases {
                release.send(()).expect("signing release must be received");
            }
            for result in batch.await {
                result.expect("concurrent request signing must succeed");
            }
        });
    }

    #[test]
    fn cache_sharing_and_reset_contract_is_preserved() {
        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: false },
        );
        let clone = signer.clone();
        let with_context = signer.clone().with_context(Context::new());
        let with_request_signer = signer
            .clone()
            .with_request_signer(MutatingSigner { fail: false });
        let with_provider = signer.clone().with_credential_provider(StaticProvider);

        assert!(Arc::ptr_eq(&signer.credential, &clone.credential));
        assert!(!Arc::ptr_eq(&signer.credential, &with_context.credential));
        assert!(Arc::ptr_eq(
            &signer.credential,
            &with_request_signer.credential
        ));
        assert!(!Arc::ptr_eq(&signer.credential, &with_provider.credential));
    }

    #[test]
    fn with_context_isolates_credential_cache() {
        #[derive(Debug)]
        struct EnvGenerationProvider {
            calls: Arc<AtomicUsize>,
            base: Timestamp,
        }

        impl ProvideCredential for EnvGenerationProvider {
            type Credential = ExpiringCredential;

            async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let generation = ctx
                    .env_var("GENERATION")
                    .expect("generation env must be set")
                    .parse::<u8>()
                    .expect("generation env must be u8");
                Ok(Some(ExpiringCredential {
                    generation,
                    fresh: true,
                    expires_at: self.base + Duration::from_secs(60),
                    required_until: self.base + Duration::from_secs(10),
                }))
            }
        }

        fn context_with_generation(generation: u8) -> Context {
            Context::new().with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([("GENERATION".to_string(), generation.to_string())]),
            })
        }

        futures::executor::block_on(async {
            let base = Timestamp::from_second(975).expect("timestamp must be valid");
            let calls = Arc::new(AtomicUsize::new(0));
            let signer_a = Signer::new(
                context_with_generation(1),
                EnvGenerationProvider {
                    calls: calls.clone(),
                    base,
                },
                OperationSigner,
            );

            let mut req_a = request_parts();
            signer_a
                .sign(&mut req_a, None)
                .await
                .expect("initial sign under context 1 must succeed");
            assert_eq!(req_a.headers["x-credential-generation"], "1");
            assert_eq!(calls.load(Ordering::SeqCst), 1);

            let signer_b = signer_a.clone().with_context(context_with_generation(2));
            let mut req_b = request_parts();
            signer_b
                .sign(&mut req_b, None)
                .await
                .expect("sign after with_context must reload under context 2");
            assert_eq!(req_b.headers["x-credential-generation"], "2");
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            let mut req_a_again = request_parts();
            signer_a
                .sign(&mut req_a_again, None)
                .await
                .expect("original signer must retain its isolated cache");
            assert_eq!(req_a_again.headers["x-credential-generation"], "1");
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn cancelled_refresh_releases_lock_and_waiter_retries() {
        futures::executor::block_on(async {
            let base = Timestamp::from_second(975).expect("timestamp must be valid");
            let calls = Arc::new(AtomicUsize::new(0));
            let provider = CancellationProvider {
                calls: calls.clone(),
                credential: ExpiringCredential {
                    generation: 2,
                    fresh: true,
                    expires_at: base + Duration::from_secs(30),
                    required_until: base + Duration::from_secs(10),
                },
            };
            let signer = Signer::new(Context::new(), provider, OperationSigner);
            let mut leader_request = request_parts();
            let mut waiter_request = request_parts();
            let mut leader = Box::pin(signer.sign(&mut leader_request, None));
            let mut waiter = Box::pin(signer.sign(&mut waiter_request, None));

            assert!(poll!(&mut leader).is_pending());
            assert!(poll!(&mut waiter).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            drop(leader);

            waiter
                .await
                .expect("waiter must retry after leader cancellation");
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(
                waiter_request.headers.get("x-credential-generation"),
                Some(&HeaderValue::from_static("2"))
            );
        });
    }

    #[test]
    fn credential_values_are_redacted_from_debug_and_validation_errors() {
        let signer = Signer::new(Context::new(), SecretProvider, SecretRequestSigner);
        let mut request = request_parts();
        let error = futures::executor::block_on(signer.sign(&mut request, None))
            .expect_err("unusable credential must fail validation");

        assert!(!format!("{signer:?}").contains(CREDENTIAL_SECRET));
        assert!(!format!("{error:?}").contains(CREDENTIAL_SECRET));
        assert!(!error.to_string().contains(CREDENTIAL_SECRET));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn signer_futures_remain_send_on_native_targets() {
        fn assert_send<T: Send>(_future: T) {}

        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: false },
        );
        let mut request = request_parts();
        let credential = TestCredential;
        assert_send(signer.credential_for(None));
        assert_send(signer.sign_with_credential(&mut request, &credential, None));
        assert_send(signer.sign(&mut request, None));
    }

    #[test]
    fn refreshes_cached_credential_for_operation_requirement() {
        let base = Timestamp::from_second(1_000).expect("timestamp must be valid");
        let cached = ExpiringCredential {
            generation: 1,
            fresh: true,
            expires_at: base + Duration::from_secs(20),
            required_until: base + Duration::from_secs(30),
        };
        let refreshed = ExpiringCredential {
            generation: 2,
            fresh: true,
            expires_at: base + Duration::from_secs(20),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) = SequenceProvider::new([Ok(Some(refreshed))]);
        let signer = Signer::new(Context::new(), provider, OperationSigner);
        set_cached_credential(&signer, cached);

        let mut parts = request_parts();
        futures::executor::block_on(signer.sign(&mut parts, None))
            .expect("refreshed credential must satisfy the recomputed requirement");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            parts.headers.get("x-credential-generation"),
            Some(&HeaderValue::from_static("2"))
        );
    }

    #[test]
    fn uses_refreshed_credential_that_is_usable_but_not_fresh() {
        let base = Timestamp::from_second(2_000).expect("timestamp must be valid");
        let credential = ExpiringCredential {
            generation: 1,
            fresh: false,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) =
            SequenceProvider::new([Ok(Some(credential.clone())), Ok(Some(credential))]);
        let signer = Signer::new(Context::new(), provider, OperationSigner);

        for _ in 0..2 {
            let mut parts = request_parts();
            futures::executor::block_on(signer.sign(&mut parts, None))
                .expect("usable refreshed credential must be accepted");
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn explicit_signing_uses_supplied_credential_without_loading_or_caching() {
        let base = Timestamp::from_second(1_100).expect("timestamp must be valid");
        let credential = ExpiringCredential {
            generation: 1,
            fresh: true,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) =
            SequenceProvider::new(std::iter::empty::<Result<Option<ExpiringCredential>>>());
        let signer = Signer::new(Context::new(), provider, OperationSigner);
        let mut parts = request_parts();
        let original_uri = parts.uri.clone();

        futures::executor::block_on(signer.sign_with_credential(&mut parts, &credential, None))
            .expect("supplied credential must sign without loading");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            parts.headers.get("x-credential-generation"),
            Some(&HeaderValue::from_static("1"))
        );
        assert_eq!(parts.uri, original_uri);
        assert!(
            signer
                .credential
                .current
                .read()
                .expect("credential cache poisoned")
                .is_none()
        );
    }

    #[test]
    fn explicit_signing_after_refresh_uses_original_routing_credential() {
        let base = Timestamp::from_second(1_200).expect("timestamp must be valid");
        let original = ExpiringCredential {
            generation: 1,
            fresh: false,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let refreshed = ExpiringCredential {
            generation: 2,
            fresh: true,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) =
            SequenceProvider::new([Ok(Some(original.clone())), Ok(Some(refreshed))]);
        let signer = Signer::new(Context::new(), provider, OperationSigner);

        let routing_credential = futures::executor::block_on(signer.credential_for(None))
            .expect("initial usable credential must load");
        assert_eq!(routing_credential.generation, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let signing_credential = futures::executor::block_on(signer.credential_for(None))
            .expect("non-fresh cached credential must refresh");
        assert_eq!(signing_credential.generation, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let routing_uri: http::Uri = format!(
            "https://example.com/generation/{}",
            routing_credential.generation
        )
        .parse()
        .expect("routing URI must parse");
        let mut parts = request_parts();
        parts.uri = routing_uri.clone();

        futures::executor::block_on(signer.sign_with_credential(
            &mut parts,
            &routing_credential,
            None,
        ))
        .expect("original credential must remain usable for its routing URI");

        assert_eq!(
            parts.headers.get("x-credential-generation"),
            Some(&HeaderValue::from_static("1"))
        );
        assert_eq!(parts.uri, routing_uri);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let mut later = request_parts();
        futures::executor::block_on(signer.sign(&mut later, None))
            .expect("refreshed credential must remain installed in the cache");
        assert_eq!(
            later.headers.get("x-credential-generation"),
            Some(&HeaderValue::from_static("2"))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn explicit_signing_rejects_credential_without_operation_validity() {
        let base = Timestamp::from_second(1_300).expect("timestamp must be valid");
        let credential = ExpiringCredential {
            generation: 1,
            fresh: true,
            expires_at: base + Duration::from_secs(10),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) =
            SequenceProvider::new(std::iter::empty::<Result<Option<ExpiringCredential>>>());
        let signer = Signer::new(Context::new(), provider, OperationSigner);
        let mut parts = request_parts();
        let original = parts.clone();

        let error =
            futures::executor::block_on(signer.sign_with_credential(&mut parts, &credential, None))
                .expect_err("credential at the exact deadline must be rejected");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert!(
            error
                .to_string()
                .contains("expires before the requested operation deadline")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(
            parts.extensions.get::<Extension>(),
            original.extensions.get::<Extension>()
        );
    }

    #[test]
    fn refresh_error_does_not_fall_back_and_caller_can_retry() {
        let base = Timestamp::from_second(3_000).expect("timestamp must be valid");
        let cached = ExpiringCredential {
            generation: 1,
            fresh: false,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let refreshed = ExpiringCredential {
            generation: 2,
            fresh: true,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) = SequenceProvider::new([
            Err(Error::unexpected("injected refresh failure")),
            Ok(Some(refreshed)),
        ]);
        let signer = Signer::new(Context::new(), provider, OperationSigner);
        set_cached_credential(&signer, cached);

        let mut parts = request_parts();
        let original = parts.clone();
        let err = futures::executor::block_on(signer.sign(&mut parts, None))
            .expect_err("refresh error must be returned");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        futures::executor::block_on(signer.sign(&mut parts, None))
            .expect("caller retry must attempt refresh again");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            parts.headers.get("x-credential-generation"),
            Some(&HeaderValue::from_static("2"))
        );
    }

    #[test]
    fn missing_refresh_does_not_fall_back_and_caller_can_retry() {
        let base = Timestamp::from_second(4_000).expect("timestamp must be valid");
        let cached = ExpiringCredential {
            generation: 1,
            fresh: false,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let refreshed = ExpiringCredential {
            generation: 2,
            fresh: true,
            expires_at: base + Duration::from_secs(30),
            required_until: base + Duration::from_secs(10),
        };
        let (provider, calls) = SequenceProvider::new([Ok(None), Ok(Some(refreshed))]);
        let signer = Signer::new(Context::new(), provider, OperationSigner);
        set_cached_credential(&signer, cached);
        let mut parts = request_parts();
        let original = parts.clone();

        let err = futures::executor::block_on(signer.sign(&mut parts, None))
            .expect_err("missing credential must fail");

        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);

        futures::executor::block_on(signer.sign(&mut parts, None))
            .expect("caller retry must attempt refresh again");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            parts.headers.get("x-credential-generation"),
            Some(&HeaderValue::from_static("2"))
        );
    }

    #[test]
    fn debug_is_opaque() {
        let signer = Signer::new(
            Context::new(),
            StaticProvider,
            MutatingSigner { fail: false },
        );
        set_cached_credential(&signer, TestCredential);

        let debug = format!("{signer:?}");
        assert!(debug.starts_with("Signer"));
        assert!(!debug.contains("StaticProvider"));
        assert!(!debug.contains("MutatingSigner"));
        assert!(!debug.contains("credential:"));
    }
}
