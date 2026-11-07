//! [`Client`]: requests by URL, from any executor.
//!
//! [`send`](crate::send) needs a [`Target`] and a reactor [`Handle`], which is
//! the right shape for a caller that owns its reactor. Most callers do not:
//! they are a handler on the server's reactor, a task on a nagoya pool, a
//! `block_on` at boot, or a test. A [`Client`] owns a reactor on a thread of
//! its own, so its futures complete under any of those: the socket makes
//! progress because that thread polls it, not because the caller's executor
//! does.
//!
//! It also caches up to 256 resolved targets, re-resolving after capacity
//! eviction or connection failure, and puts a deadline on every request.
//! The cache makes no DNS TTL promise.
//!
//! ```no_run
//! let client = nago_http::Client::global()?;
//! let response = nagoya::block_on(client.get("https://api.example.com/v1/thing", &[]))?;
//! assert!(response.is_success());
//! # Ok::<(), nago_http::Error>(())
//! ```

use std::collections::HashMap;
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nagoya::reactor::Reactor;

use crate::{Error, Request, Response, Target};

const MAX_RESOLVED_TARGETS: usize = 256;

type TargetKey = (bool, String, u16);

struct CachedTarget {
    target: Arc<Target>,
    inserted_at_ns: u64,
}

#[derive(Default)]
struct TargetCache {
    entries: HashMap<TargetKey, CachedTarget>,
}

impl TargetCache {
    fn get(&self, key: &TargetKey) -> Option<&Arc<Target>> {
        self.entries.get(key).map(|entry| &entry.target)
    }

    #[cfg(test)]
    fn insert(&mut self, key: TargetKey, target: Arc<Target>) {
        self.entries.insert(key, CachedTarget { target, inserted_at_ns: 0 });
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    fn contains_key(&self, key: &TargetKey) -> bool {
        self.entries.contains_key(key)
    }

    fn resolved_len(&self) -> usize {
        self.entries.values().filter(|entry| !entry.target.is_pinned()).count()
    }
}

#[cfg(test)]
type ResolveHook = std::sync::Arc<
    dyn Fn(String, u16, bool, u64) -> std::pin::Pin<Box<dyn Future<Output = Result<Target, Error>> + Send>>
        + Send
        + Sync,
>;

/// One request deadline covering DNS resolution, connect, TLS, and HTTP I/O.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests by URL, over a reactor this client runs on its own thread.
pub struct Client {
    tls_config: Option<std::sync::Arc<nago_rustls::rustls::ClientConfig>>,
    reactor: Reactor,
    /// Targets by (TLS, host, port). Resolved targets are retained up to
    /// `MAX_RESOLVED_TARGETS`, then re-resolved after capacity eviction or a
    /// connection failure. Pinned targets stay cached.
    targets: Mutex<TargetCache>,
    resolver: &'static nagoya::resolve::Resolver,
    #[cfg(test)]
    resolve_hook: Option<ResolveHook>,
    timeout: Duration,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Start a client and its reactor thread.
    ///
    /// Requires a process-default rustls crypto provider installed by the host.
    /// Default HTTPS uses it for an ECC-only first connection and can open one
    /// RSA-PSS verification retry for a matching handshake refusal. Returns a
    /// TLS error when no provider is installed, before starting the reactor.
    /// The first call initializes shared DNS workers, so make it during
    /// synchronous setup before entering a reactor callback.
    pub fn new() -> Result<Self, Error> {
        crate::require_crypto_provider()?;
        Self::start(None)
    }

    fn start(
        tls_config: Option<std::sync::Arc<nago_rustls::rustls::ClientConfig>>,
    ) -> Result<Self, Error> {
        let resolver = nagoya::resolve::Resolver::shared()
            .map_err(|err| Error::Io(format!("starting the DNS resolver: {err}")))?;
        let reactor =
            Reactor::start().map_err(|err| Error::Io(format!("starting the reactor: {err:?}")))?;
        Ok(Self {
            tls_config,
            reactor,
            targets: Mutex::new(TargetCache::default()),
            resolver,
            #[cfg(test)]
            resolve_hook: None,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// One client for the whole process, started on first use.
    /// First use initializes shared DNS workers synchronously, so call this
    /// during setup before entering a reactor callback.
    pub fn global() -> Result<&'static Self, Error> {
        static CLIENT: OnceLock<Client> = OnceLock::new();
        if let Some(client) = CLIENT.get() {
            return Ok(client);
        }
        let client = Self::new()?;
        // Losing a race to another first caller drops this one, which stops
        // its thread; the winner serves everyone.
        Ok(CLIENT.get_or_init(|| client))
    }

    /// Start a client with the caller's TLS policy. HTTPS uses this
    /// configuration as supplied and returns handshake errors without retrying
    /// with another verifier. No process-default provider is required: this
    /// configuration already carries its provider.
    /// The first call initializes shared DNS workers, so make it during
    /// synchronous setup before entering a reactor callback.
    pub fn with_tls_config(
        config: std::sync::Arc<nago_rustls::rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        Self::start(Some(config))
    }

    /// Give DNS resolution and network I/O this much time in total.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send `method` to `url` (`https://` or `http://`) with `headers` and an
    /// optional `(content type, body)`, and read the whole response.
    ///
    /// The path and query are sent as the URL has them, so they must already be
    /// percent-encoded. Errors never carry the path or query, which is where
    /// some APIs put their credentials.
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<Response, Error> {
        let deadline_ns = nagoya::time::now_ns().saturating_add(
            u64::try_from(self.timeout.as_nanos()).unwrap_or(u64::MAX),
        );
        let url = Url::parse(url)?;
        if nagoya::time::now_ns() >= deadline_ns {
            return Err(timeout_error(&url, self.timeout));
        }
        let target = self.target(&url, deadline_ns).await?;
        if nagoya::time::now_ns() >= deadline_ns {
            return Err(timeout_error(&url, self.timeout));
        }
        let mut request = Request::new(method, url.path_and_query);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some((content_type, body)) = body {
            request = request.body(content_type, body);
        }
        let handle = self.reactor.handle();
        let exchange = async {
            let connection = crate::open_with_tls_config(&target, &handle, self.tls_config.clone()).await?;
            connection.send(request).await
        };
        let mut exchange = Box::pin(exchange);
        let mut timer = Box::pin(nagoya::sleep_until(deadline_ns));
        let result = poll_fn(|cx| {
            if nagoya::time::now_ns() >= deadline_ns {
                return std::task::Poll::Ready(None);
            }
            match exchange.as_mut().poll(cx) {
                std::task::Poll::Ready(result) => {
                    return std::task::Poll::Ready(if nagoya::time::now_ns() >= deadline_ns {
                        None
                    } else {
                        Some(result)
                    });
                }
                std::task::Poll::Pending => {}
            }
            if timer.as_mut().poll(cx).is_ready() || nagoya::time::now_ns() >= deadline_ns {
                std::task::Poll::Ready(None)
            } else {
                std::task::Poll::Pending
            }
        })
        .await
        .unwrap_or_else(|| Err(timeout_error(&url, self.timeout)));
        // A host that could not be reached may have moved: forget its address,
        // so the next request resolves it again.
        if !target.is_pinned()
            && let Err(Error::Connect(_) | Error::Tls(_) | Error::Io(_) | Error::Timeout(_)) =
                &result
        {
            let mut cache = self.targets.lock().expect("not poisoned");
            let key = (url.tls, url.host.to_string(), url.port);
            forget_target_if_current(&mut cache, &key, &target);
        }
        result
    }

    /// `GET url`.
    pub async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response, Error> {
        self.send("GET", url, headers, None).await
    }

    /// `POST url` with a body of `content_type`.
    pub async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Response, Error> {
        self.send("POST", url, headers, Some((content_type, body)))
            .await
    }

    async fn target(&self, url: &Url<'_>, deadline_ns: u64) -> Result<Arc<Target>, Error> {
        let key = (url.tls, url.host.to_string(), url.port);
        let cached = { self.targets.lock().expect("not poisoned").get(&key).cloned() };
        if let Some(target) = cached {
            if nagoya::time::now_ns() < deadline_ns {
                return Ok(target);
            }
            return Err(timeout_error(url, self.timeout));
        }
        #[cfg(test)]
        let resolved = if let Some(resolve) = &self.resolve_hook {
            resolve(url.host.to_string(), url.port, url.tls, deadline_ns).await?
        } else {
            Target::resolve_until(self.resolver, url.host, url.port, url.tls, deadline_ns).await?
        };
        #[cfg(not(test))]
        let resolved = Target::resolve_until(self.resolver, url.host, url.port, url.tls, deadline_ns).await?;
        let target = Arc::new(resolved);
        if nagoya::time::now_ns() >= deadline_ns {
            return Err(timeout_error(url, self.timeout));
        }
        let mut cache = self.targets.lock().expect("not poisoned");
        cache_resolved_target(&mut cache, key, target, nagoya::time::now_ns(), deadline_ns)
            .ok_or_else(|| timeout_error(url, self.timeout))
    }
}

fn cache_resolved_target(
    cache: &mut TargetCache,
    key: TargetKey,
    target: Arc<Target>,
    now_ns: u64,
    deadline_ns: u64,
) -> Option<Arc<Target>> {
    if now_ns >= deadline_ns {
        return None;
    }
    if let Some(existing) = cache.get(&key) {
        return Some(existing.clone());
    }
    if !target.is_pinned() && cache.resolved_len() >= MAX_RESOLVED_TARGETS {
        let oldest = cache
            .entries
            .iter()
            .filter(|(_, entry)| !entry.target.is_pinned())
            .min_by_key(|(_, entry)| entry.inserted_at_ns)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            cache.entries.remove(&oldest);
        }
    }
    cache.entries.insert(key, CachedTarget { target: target.clone(), inserted_at_ns: now_ns });
    Some(target)
}

fn forget_target_if_current(
    cache: &mut TargetCache,
    key: &TargetKey,
    failed: &Arc<Target>,
) {
    if !failed.is_pinned()
        && cache.get(key).is_some_and(|current| Arc::ptr_eq(current, failed))
    {
        cache.entries.remove(key);
    }
}

fn timeout_error(url: &Url<'_>, timeout: Duration) -> Error {
    Error::Timeout(format!("{} did not answer within {}s", url.host, timeout.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn malformed_ports_do_not_echo_input() {
        for (authority, port) in [
            ("example.test", "PORT_MARKER"),
            ("example.test", ""),
            ("example.test", "65536"),
            ("[2001:db8::1]", "PORT_MARKER"),
            ("[2001:db8::1]", ""),
            ("[2001:db8::1]", "65536"),
        ] {
            let input = format!("https://{authority}:{port}/PATH_MARKER?QUERY_MARKER");
            let error = Url::parse(&input).expect_err("port must be rejected");
            assert!(matches!(&error, Error::Url(detail) if detail == "bad port"));

            let display = error.to_string();
            let debug = format!("{error:?}");
            for marker in ["PORT_MARKER", "PATH_MARKER", "QUERY_MARKER"] {
                assert!(!display.contains(marker), "display leaked {marker}");
                assert!(!debug.contains(marker), "debug leaked {marker}");
            }
        }
    }

    #[test]
    fn valid_ports_preserve_url_parts() {
        for (input, expected_tls, expected_host, expected_port) in [
            ("http://example.test/path?query", false, "example.test", 80),
            ("https://example.test/path?query", true, "example.test", 443),
            ("http://example.test:8080/path?query", false, "example.test", 8080),
            ("https://[2001:db8::1]:8443/path?query", true, "2001:db8::1", 8443),
        ] {
            let parsed = Url::parse(input).expect("valid URL");
            assert_eq!(parsed.tls, expected_tls);
            assert_eq!(parsed.host, expected_host);
            assert_eq!(parsed.port, expected_port);
            assert_eq!(parsed.path_and_query, "/path?query");
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) {
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    }

    #[test]
    fn client_keeps_a_pinned_target_after_connect_fails() {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let _ = ps_rustcrypto::provider().install_default();
        let client = Client::new().unwrap();
        let key = (false, "example.com".to_string(), port);
        let target = Target::pinned(
            "example.com",
            port,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            false,
        )
        .unwrap();
        client.targets.lock().unwrap().insert(key.clone(), Arc::new(target));
        let url = format!("http://example.com:{port}/");

        let first = nagoya::block_on(nagoya::timeout(
            Duration::from_secs(2),
            client.get(&url, &[]),
        ))
        .expect("client request deadline");
        assert!(matches!(first, Err(Error::Connect(_))));
        assert!(
            client
                .targets
                .lock()
                .unwrap()
                .get(&key)
                .is_some_and(|target| target.is_pinned())
        );

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
                .expect("write response");
            release_rx.recv().expect("test releases listener");
        });

        let second = nagoya::block_on(nagoya::timeout(
            Duration::from_secs(2),
            client.get(&url, &[]),
        ))
        .expect("client request deadline")
        .expect("the cached pinned address is still used");
        assert_eq!(second.body, b"body");
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }


    #[test]
    fn client_forgets_a_seeded_unpinned_target_after_refused_connect() {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let _ = ps_rustcrypto::provider().install_default();
        let client = Client::new().unwrap();
        let key = (false, "127.0.0.1".to_string(), port);
        let target = Target::from_addrs(
            "127.0.0.1",
            port,
            false,
            vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), port)],
        )
        .unwrap();
        client.targets.lock().unwrap().insert(key.clone(), Arc::new(target));
        let url = format!("http://127.0.0.1:{port}/");
        let result = nagoya::block_on(nagoya::timeout(
            Duration::from_secs(2),
            client.get(&url, &[]),
        ))
        .expect("client request deadline");
        assert!(matches!(result, Err(Error::Connect(_))));
        assert!(!client.targets.lock().unwrap().contains_key(&key));
    }

    #[test]
    fn cold_resolver_path_resolves_localhost_separately() {
        let _ = ps_rustcrypto::provider().install_default();
        let client = Client::new().unwrap();
        let deadline = nagoya::time::now_ns().saturating_add(2_000_000_000);
        let target = nagoya::block_on(async {
            loop {
                if nagoya::time::now_ns() >= deadline {
                    return Err(Error::Timeout("localhost resolver admission exceeded the fixture deadline".into()));
                }
                match Target::resolve_until(client.resolver, "localhost", 80, false, deadline).await {
                    Ok(target) => return Ok(target),
                    Err(Error::Resolve(message)) if message == "bounded DNS admission is busy" => {
                        let retry_at = nagoya::time::now_ns().saturating_add(1_000_000).min(deadline);
                        nagoya::sleep_until(retry_at).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .expect("localhost resolution admitted within the fixture deadline");
        assert_eq!(target.host(), "localhost");
        assert!(!target.addrs.is_empty());
    }

    #[test]
    fn one_budget_covers_delayed_dns_and_stalled_loopback_transport() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept loopback request");
            accepted_tx.send(()).expect("signal accepted connection");
            release_rx.recv().expect("test releases stalled server");
        });

        let _ = ps_rustcrypto::provider().install_default();
        let mut client = Client::new().unwrap().with_timeout(Duration::from_millis(800));
        let dns_ready_ns = nagoya::time::now_ns().saturating_add(500_000_000);
        client.resolve_hook = Some(std::sync::Arc::new(move |host, target_port, tls, deadline| {
            Box::pin(async move {
                nagoya::sleep_until(dns_ready_ns).await;
                assert!(nagoya::time::now_ns() < deadline);
                Target::from_addrs(
                    &host,
                    target_port,
                    tls,
                    vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), target_port)],
                )
            })
        }));
        let started = std::time::Instant::now();
        let result = nagoya::block_on(client.get(&format!("http://delayed.test:{port}/"), &[]));
        assert!(matches!(result, Err(Error::Timeout(_))));
        assert!(started.elapsed() < Duration::from_millis(1_200), "deadline was reset after DNS");
        accepted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("delayed DNS completed and request reached stalled transport");
        release_tx.send(()).unwrap();
        server.join().unwrap();
        assert!(!client.targets.lock().unwrap().contains_key(&(false, "delayed.test".into(), port)));
    }

    #[test]
    fn expired_resolver_answer_cannot_populate_client_cache() {
        let _ = ps_rustcrypto::provider().install_default();
        let mut client = Client::new().unwrap().with_timeout(Duration::from_millis(100));
        client.resolve_hook = Some(std::sync::Arc::new(|host, port, tls, deadline| {
            Box::pin(async move {
                nagoya::sleep_until(deadline.saturating_add(50_000_000)).await;
                Target::from_addrs(
                    &host,
                    port,
                    tls,
                    vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), port)],
                )
            })
        }));
        let result = nagoya::block_on(client.get("http://late.example/", &[]));
        assert!(matches!(result, Err(Error::Timeout(_))));
        assert!(!client.targets.lock().unwrap().contains_key(&(false, "late.example".into(), 80)));
    }

    #[test]
    fn stale_transport_failure_cannot_remove_replacement_target() {
        let key = (false, "replace.example".to_string(), 80);
        let old = Arc::new(Target::from_addrs(
            "replace.example", 80, false,
            vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), 80)],
        ).unwrap());
        let replacement = Arc::new(Target::from_addrs(
            "replace.example", 80, false,
            vec![nagoya::reactor::Addr::V4(Ipv4Addr::UNSPECIFIED.octets(), 80)],
        ).unwrap());
        let mut cache = TargetCache::default();
        cache.entries.insert(key.clone(), CachedTarget { target: replacement.clone(), inserted_at_ns: 1 });
        forget_target_if_current(&mut cache, &key, &old);
        assert!(cache.get(&key).is_some_and(|current| Arc::ptr_eq(current, &replacement)));
    }

    #[test]
    fn resolved_target_cache_is_bounded_and_preserves_pinned_targets() {
        let mut cache = TargetCache::default();
        let pinned_key = (false, "pinned.example".to_string(), 80);
        let pinned = Arc::new(Target::pinned(
            "pinned.example", 80, &[IpAddr::V4(Ipv4Addr::LOCALHOST)], false,
        ).unwrap());
        cache.insert(pinned_key.clone(), pinned.clone());

        for index in 0..MAX_RESOLVED_TARGETS {
            let host = format!("{index}.example");
            let key = (false, host.clone(), 80);
            let target = Arc::new(Target::from_addrs(
                &host, 80, false,
                vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), 80)],
            ).unwrap());
            assert!(cache_resolved_target(&mut cache, key, target, index as u64 + 1, u64::MAX).is_some());
        }
        assert_eq!(cache.resolved_len(), MAX_RESOLVED_TARGETS);

        let new_key = (false, "new.example".to_string(), 80);
        let new_target = Arc::new(Target::from_addrs(
            "new.example", 80, false,
            vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), 80)],
        ).unwrap());
        assert!(cache_resolved_target(&mut cache, new_key.clone(), new_target, 10_000, u64::MAX).is_some());
        assert_eq!(cache.resolved_len(), MAX_RESOLVED_TARGETS);
        assert!(cache.get(&pinned_key).is_some_and(|target| Arc::ptr_eq(target, &pinned)));
        assert!(!cache.contains_key(&(false, "0.example".to_string(), 80)));
        assert!(cache.contains_key(&new_key));
    }

    #[test]
    fn concurrent_same_key_resolutions_keep_the_first_cached_arc() {
        let key = (false, "same.example".to_string(), 80);
        let first = Arc::new(Target::from_addrs(
            "same.example", 80, false,
            vec![nagoya::reactor::Addr::V4(Ipv4Addr::LOCALHOST.octets(), 80)],
        ).unwrap());
        let later = Arc::new(Target::from_addrs(
            "same.example", 80, false,
            vec![nagoya::reactor::Addr::V4(Ipv4Addr::UNSPECIFIED.octets(), 80)],
        ).unwrap());
        let mut cache = TargetCache::default();
        let admitted = cache_resolved_target(&mut cache, key.clone(), first.clone(), 10, 100).unwrap();
        let concurrent = cache_resolved_target(&mut cache, key.clone(), later, 11, 100).unwrap();
        assert!(Arc::ptr_eq(&admitted, &first));
        assert!(Arc::ptr_eq(&concurrent, &first));
        assert_eq!(cache.resolved_len(), 1);
    }

    #[test]
    fn zero_budget_returns_timeout_without_cache_mutation() {
        let _ = ps_rustcrypto::provider().install_default();
        let client = Client::new().unwrap().with_timeout(Duration::ZERO);
        let result = nagoya::block_on(client.get("http://dns-must-not-run.invalid/", &[]));
        assert!(matches!(result, Err(Error::Timeout(_))));
        assert!(client.targets.lock().unwrap().is_empty());
    }

    #[test]
    fn send_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let _ = ps_rustcrypto::provider().install_default();
        let client = Client::new().unwrap();
        assert_send(client.send("GET", "http://127.0.0.1/", &[], None));
    }
}

/// The parts of a URL a request needs.
#[derive(Debug, PartialEq, Eq)]
struct Url<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path_and_query: &'a str,
}

impl<'a> Url<'a> {
    fn parse(url: &'a str) -> Result<Self, Error> {
        if url.contains('#') || url.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(Error::Url("invalid URL characters".into()));
        }
        // Only the scheme and host are named in errors: the path and query can
        // carry credentials.
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(Error::Url("the scheme must be https:// or http://".into()));
        };
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path_and_query) = rest.split_at(authority_end);
        let path_and_query = match path_and_query {
            "" => "/",
            p if p.starts_with('?') => {
                return Err(Error::Url(
                    "a query needs a path before it: write /?".into(),
                ));
            }
            p => p,
        };
        if authority.contains('@') {
            return Err(Error::Url(
                "credentials in the URL are not supported".into(),
            ));
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            // IPv6: [addr] or [addr]:port
            let (host, after) = bracketed
                .split_once(']')
                .ok_or_else(|| Error::Url("unclosed [ in the host".into()))?;
            let port = match after.strip_prefix(':') {
                Some(port) => parse_port(port)?,
                None if after.is_empty() => default_port,
                None => return Err(Error::Url(format!("unexpected text after [{host}]"))),
            };
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, parse_port(port)?),
                None => (authority, default_port),
            }
        };
        if host.is_empty() {
            return Err(Error::Url("the URL has no host".into()));
        }
        Ok(Self {
            tls,
            host,
            port,
            path_and_query,
        })
    }
}

fn parse_port(port: &str) -> Result<u16, Error> {
    port.parse()
        .map_err(|_| Error::Url("bad port".into()))
}
