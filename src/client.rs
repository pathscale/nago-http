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
    /// Targets by (TLS, host, port). Resolved targets are resolved once per
    /// host and again after a connection failure; pinned targets stay cached.
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
        let result = match nagoya::timeout(self.timeout, send(&target, &handle, request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(format!(
                "{} did not answer within {}s",
                url.host,
                self.timeout.as_secs()
            ))),
        };
        // A host that could not be reached may have moved: forget its address,
        // so the next request resolves it again.
        if !target.is_pinned()
            && let Err(Error::Connect(_) | Error::Tls(_) | Error::Io(_) | Error::Timeout(_)) =
                &result
        {
            self.targets.lock().expect("not poisoned").remove(&(
                url.tls,
                url.host.to_string(),
                url.port,
            ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::thread;

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

        let client = Client::new().unwrap();
        let key = (false, "example.com".to_string(), port);
        let target = Target::pinned(
            "example.com",
            port,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            false,
        )
        .unwrap();
        client.targets.lock().unwrap().insert(key.clone(), target);
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
                .is_some_and(Target::is_pinned)
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
    fn client_forgets_an_unpinned_target_after_connect_fails() {
        let client = Client::new().unwrap();
        let url = "http://127.0.0.1:1/";
        let result = nagoya::block_on(nagoya::timeout(
            Duration::from_secs(2),
            client.get(url, &[]),
        ))
        .expect("client request deadline");
        assert!(matches!(result, Err(Error::Connect(_))));
        assert!(
            !client
                .targets
                .lock()
                .unwrap()
                .contains_key(&(false, "127.0.0.1".to_string(), 1,))
        );
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
