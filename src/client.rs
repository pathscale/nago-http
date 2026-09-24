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
//! It also resolves each host once and keeps the answer, and puts a deadline
//! on every request, which is what each backend was otherwise writing for
//! itself around [`send`](crate::send).
//!
//! ```no_run
//! let client = nago_http::Client::global()?;
//! let response = nagoya::block_on(client.get("https://api.example.com/v1/thing", &[]))?;
//! assert!(response.is_success());
//! # Ok::<(), nago_http::Error>(())
//! ```

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use nagoya::reactor::Reactor;

use crate::{Error, Request, Response, Target, send};

/// How long a request may take, connect to last byte, unless
/// [`Client::with_timeout`] says otherwise. The APIs this is for answer in
/// milliseconds; a request still going after this is a dead connection.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests by URL, over a reactor this client runs on its own thread.
pub struct Client {
    reactor: Reactor,
    /// Resolved hosts, by (TLS, host, port). Resolution blocks, so it happens
    /// once per host rather than once per request.
    targets: Mutex<HashMap<(bool, String, u16), Target>>,
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
    /// Also installs rustls' `ring` provider as the process default if none
    /// is installed yet: nago-rustls builds its configuration from the process
    /// default, and a request made before anything installed one would panic.
    pub fn new() -> Result<Self, Error> {
        let _ = nago_rustls::rustls::crypto::ring::default_provider().install_default();
        let reactor =
            Reactor::start().map_err(|err| Error::Io(format!("starting the reactor: {err:?}")))?;
        Ok(Self {
            reactor,
            targets: Mutex::new(HashMap::new()),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// One client for the whole process, started on first use.
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

    /// Give every request this much time, connect to last byte.
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
        let url = Url::parse(url)?;
        let target = self.target(&url)?;
        let mut request = Request::new(method, url.path_and_query);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some((content_type, body)) = body {
            request = request.body(content_type, body);
        }
        let handle = self.reactor.handle();
        match nagoya::timeout(self.timeout, send(&target, &handle, request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(format!(
                "{} did not answer within {}s",
                url.host,
                self.timeout.as_secs()
            ))),
        }
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

    fn target(&self, url: &Url<'_>) -> Result<Target, Error> {
        let key = (url.tls, url.host.to_string(), url.port);
        if let Some(target) = self.targets.lock().expect("not poisoned").get(&key) {
            return Ok(target.clone());
        }
        let target = if url.tls {
            Target::resolve(url.host, url.port)?
        } else {
            Target::resolve_plain(url.host, url.port)?
        };
        self.targets
            .lock()
            .expect("not poisoned")
            .insert(key, target.clone());
        Ok(target)
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
        .map_err(|_| Error::Url(format!("bad port {port}")))
}
