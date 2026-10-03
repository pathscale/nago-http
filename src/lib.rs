//! A small HTTP/1.1 client over nagoya and nago-rustls.
//!
//! For the outbound calls a backend makes to someone else's API: a secrets
//! store at boot, a bot platform, a payment gateway. One request per
//! connection, `Connection: close`, a body framed by `Content-Length` or
//! `chunked`, and nothing else. Those callers send a request now and then, not
//! a stream of them, so connection reuse would be complexity bought for nothing.
//!
//! TLS is nago-rustls, which is rustls on `ring`, trusting the webpki roots.
//! No tokio, no OpenSSL, no C.
//!
//! ```no_run
//! use nagoya::reactor::{Reactor, block_on_with};
//!
//! let target = nago_http::Target::resolve("api.example.com", 443)?;
//! let reactor = Reactor::local()?;
//! let handle = reactor.handle();
//! let response = block_on_with(&reactor, nago_http::send(
//!     &target,
//!     &handle,
//!     nago_http::Request::get("/v1/thing").header("Accept", "application/json"),
//! ))?;
//! assert!(response.is_success());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Resolving is separate, and synchronous
//!
//! [`Target::resolve`] is `getaddrinfo`, which blocks its thread. Call it before
//! the reactor is driven, or on a thread whose reactor serves nothing else: a
//! lookup inside a running reactor stalls every socket on it for as long as
//! the resolver takes.
//!
//! # Timeouts
//!
//! [`send`] imposes none: wrap it in [`nagoya::timeout`] with whatever budget
//! the API deserves. [`Client`] gives every request a deadline, 30 s unless
//! [`Client::with_timeout`] says otherwise.

use core::fmt;

use nago_rustls::TlsSession;
use nago_rustls::rustls::ClientConnection;
use nago_rustls::rustls_pki_types::ServerName;
use nagoya::io::Stream;
use nagoya::reactor::{Addr, Handle, TcpStream, connect_any, resolve};

mod client;
pub use client::{Client, DEFAULT_TIMEOUT};
pub use nago_rustls::rustls;

/// Largest response this will buffer. The APIs this is for answer in
/// kilobytes; anything near this is a fault, not a payload.
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// A host and the addresses used to reach it.
#[derive(Clone, Debug)]
pub struct Target {
    host: String,
    port: u16,
    addrs: Vec<Addr>,
    tls: bool,
    pinned: bool,
}

impl Target {
    /// Resolve `host`, to be reached over TLS. Blocks the calling thread for
    /// the lookup.
    pub fn resolve(host: &str, port: u16) -> Result<Self, Error> {
        Self::resolve_with(host, port, true)
    }

    /// Resolve `host`, to be reached over plain TCP: for a local stand-in of a
    /// service (a loopback S3, a test double), not for anything a credential
    /// crosses the network to. Blocks the calling thread for the lookup.
    pub fn resolve_plain(host: &str, port: u16) -> Result<Self, Error> {
        Self::resolve_with(host, port, false)
    }

    fn resolve_with(host: &str, port: u16, tls: bool) -> Result<Self, Error> {
        let addrs = resolve(host, port).map_err(|err| Error::Resolve(err.to_string()))?;
        if addrs.is_empty() {
            return Err(Error::Resolve(format!("{host} has no addresses")));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            addrs,
            tls,
            pinned: false,
        })
    }

    /// Dial `addrs` at `port`. Do not resolve `host`.
    ///
    /// `host` is the TLS server name and the `Host` header, using the same
    /// rules as [`Target::resolve`]. The supplied address order is preserved.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Url`] when `host` or `addrs` is empty, or when `port`
    /// is zero.
    pub fn pinned(
        host: &str,
        port: u16,
        addrs: &[std::net::IpAddr],
        tls: bool,
    ) -> Result<Self, Error> {
        if host.is_empty() {
            return Err(Error::Url("the target has no host".into()));
        }
        if addrs.is_empty() {
            return Err(Error::Url("the target has no addresses".into()));
        }
        if port == 0 {
            return Err(Error::Url("the target port is zero".into()));
        }
        let addrs = addrs
            .iter()
            .map(|address| match address {
                std::net::IpAddr::V4(address) => Addr::V4(address.octets(), port),
                std::net::IpAddr::V6(address) => Addr::V6(address.octets(), port),
            })
            .collect();
        Ok(Self {
            host: host.to_string(),
            port,
            addrs,
            tls,
            pinned: true,
        })
    }

    /// Whether this target uses caller-supplied addresses rather than DNS.
    pub fn is_pinned(&self) -> bool {
        self.pinned
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// The `Host` header value: an IPv6 address in brackets, and the port only
    /// when it is not the scheme's default (443, or 80 in plain).
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// One request. Build with [`Request::get`] or [`Request::post`].
#[derive(Clone, Debug)]
pub struct Request<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: Option<(&'a str, &'a [u8])>,
    max_body: Option<usize>,
}

impl<'a> Request<'a> {
    /// `path` is the path and query, already percent-encoded.
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: None,
            max_body: None,
        }
    }

    pub fn get(path: &'a str) -> Self {
        Self::new("GET", path)
    }

    pub fn post(path: &'a str) -> Self {
        Self::new("POST", path)
    }

    pub fn header(mut self, name: &'a str, value: &'a str) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Set the body and its `Content-Type`. `Content-Length` is added for you.
    pub fn body(mut self, content_type: &'a str, body: &'a [u8]) -> Self {
        self.body = Some((content_type, body));
        self
    }

    /// Return after this many response body bytes are available.
    ///
    /// The returned body is truncated to the limit. A limit above
    /// [`MAX_RESPONSE`] is reduced to that maximum; a limit of zero returns
    /// as soon as the headers are complete. Without this setting, the whole
    /// framed body is read and exceeding [`MAX_RESPONSE`] returns
    /// [`Error::TooLarge`].
    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = Some(max_body);
        self
    }

    fn encode(&self, host: &str) -> Vec<u8> {
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
            self.method, self.path
        );
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        let body: &[u8] = match self.body {
            Some((content_type, body)) => {
                head.push_str(&format!(
                    "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
                    body.len()
                ));
                body
            }
            // A request that could carry a body says it has none: some
            // servers refuse a bodyless POST without Content-Length.
            None if ["POST", "PUT", "PATCH"]
                .iter()
                .any(|m| self.method.eq_ignore_ascii_case(m)) =>
            {
                head.push_str("Content-Length: 0\r\n");
                &[]
            }
            None => &[],
        };
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The first header named `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What went wrong, and where. Never carries the request path, which is where
/// some APIs put their credentials.
#[derive(Debug)]
pub enum Error {
    Resolve(String),
    Connect(String),
    Tls(String),
    Io(String),
    /// The peer answered something that is not HTTP/1.1 this client reads.
    Protocol(String),
    TooLarge,
    /// The request did not finish within the [`Client`]'s deadline.
    Timeout(String),
    /// The URL given to a [`Client`] could not be used.
    Url(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(detail) => write!(f, "DNS resolution failed: {detail}"),
            Self::Connect(detail) => write!(f, "TCP connect failed: {detail}"),
            Self::Tls(detail) => write!(f, "TLS failed: {detail}"),
            Self::Io(detail) => write!(f, "connection failed: {detail}"),
            Self::Protocol(detail) => write!(f, "malformed response: {detail}"),
            Self::TooLarge => write!(f, "response exceeded {MAX_RESPONSE} bytes"),
            Self::Timeout(detail) => write!(f, "timed out: {detail}"),
            Self::Url(detail) => write!(f, "unusable URL: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

/// Establish TCP and, when selected by the target, complete the TLS handshake.
/// This dials only the addresses stored in `target` and never resolves its host.
pub async fn open(target: &Target, handle: &Handle) -> Result<Connection, Error> {
    open_with_tls_config(target, handle, None).await
}

/// Open with the caller's TLS policy. `None` retains the default policy.
pub async fn open_with_tls_config(
    target: &Target,
    handle: &Handle,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
) -> Result<Connection, Error> {
    let name = if target.tls {
        Some(
            ServerName::try_from(target.host.clone())
                .map_err(|_| Error::Tls(format!("invalid server name {}", target.host)))?,
        )
    } else {
        None
    };
    let session = name
        .map(|name| {
            ClientConnection::new(
                tls_config.unwrap_or_else(nago_rustls::default_client_config),
                name,
            )
            .map_err(|err| Error::Tls(err.to_string()))
        })
        .transpose()?;
    let stream = connect_any(&target.addrs, handle)
        .await
        .map_err(|err| Error::Connect(format!("{}: {err}", target.host)))?;
    let stream = if let Some(session) = session {
        let mut tls = TlsSession::client(stream, session);
        tls.handshake()
            .await
            .map_err(|err| Error::Tls(format!("handshake with {}: {err:?}", target.host)))?;
        ConnectionStream::Tls(tls)
    } else {
        ConnectionStream::Plain(stream)
    };
    Ok(Connection {
        stream,
        host: target.host.clone(),
        host_header: target.host_header(),
    })
}

enum ConnectionStream {
    Plain(TcpStream),
    Tls(TlsSession<TcpStream>),
}

/// An established connection. A connection sends one request and one response.
pub struct Connection {
    stream: ConnectionStream,
    host: String,
    host_header: String,
}

impl Connection {
    /// Send one request, read one response, and consume the connection.
    pub async fn send(self, request: Request<'_>) -> Result<Response, Error> {
        let bytes = request.encode(&self.host_header);
        let head = request.method.eq_ignore_ascii_case("HEAD");
        match self.stream {
            ConnectionStream::Plain(mut stream) => {
                exchange(&mut stream, &self.host, &bytes, head, request.max_body).await
            }
            ConnectionStream::Tls(mut tls) => {
                let response = exchange(&mut tls, &self.host, &bytes, head, request.max_body).await;
                let _ = tls.close().await;
                response
            }
        }
    }
}

/// Send one request over a fresh connection (TLS unless the target was
/// resolved with [`Target::resolve_plain`]). By default, read the whole body;
/// [`Request::max_body`] returns once its body limit is available.
pub async fn send(
    target: &Target,
    handle: &Handle,
    request: Request<'_>,
) -> Result<Response, Error> {
    open(target, handle).await?.send(request).await
}

/// Write `request` and read until a complete response or requested body prefix
/// has arrived.
async fn exchange<S: Stream>(
    stream: &mut S,
    host: &str,
    request: &[u8],
    head: bool,
    max_body: Option<usize>,
) -> Result<Response, Error> {
    stream
        .write_all(request)
        .await
        .map_err(|err| Error::Io(format!("writing to {host}: {err:?}")))?;

    let mut buffer = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(response) = parse_response_with_limit(&buffer, false, head, max_body)? {
            return Ok(response);
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|err| Error::Io(format!("reading from {host}: {err:?}")))?;
        if read == 0 {
            return parse_response_with_limit(&buffer, true, head, max_body)?.ok_or_else(|| {
                Error::Protocol(format!("{host} closed the connection mid-response"))
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
        if max_body.is_none() && buffer.len() > MAX_RESPONSE {
            return Err(Error::TooLarge);
        }
        if max_body.is_some() && response_headers_too_large(&buffer) {
            return Err(Error::TooLarge);
        }
    }
}

/// Parse a complete response out of `buffer`, or `None` if more is needed.
///
/// `at_eof` says the peer has closed: a body framed by neither length nor
/// chunking ends there, and one that is framed but short is an error.
/// `head_request` says the request was HEAD, whose response has no body; 1xx, 204 and 304
/// never do either (RFC 9112 section 6.3).
#[cfg(test)]
fn parse_response(
    buffer: &[u8],
    at_eof: bool,
    head_request: bool,
) -> Result<Option<Response>, Error> {
    parse_response_with_limit(buffer, at_eof, head_request, None)
}

fn response_headers_too_large(buffer: &[u8]) -> bool {
    match find(buffer, b"\r\n\r\n") {
        Some(head_end) => head_end + 4 > MAX_RESPONSE,
        None => buffer.len() > MAX_RESPONSE,
    }
}

fn parse_response_with_limit(
    buffer: &[u8],
    at_eof: bool,
    head_request: bool,
    max_body: Option<usize>,
) -> Result<Option<Response>, Error> {
    let protocol = |detail: &str| Error::Protocol(detail.to_string());
    let Some(head_end) = find(buffer, b"\r\n\r\n") else {
        if at_eof {
            return Err(protocol("connection closed before the headers ended"));
        }
        return Ok(None);
    };
    let head =
        std::str::from_utf8(&buffer[..head_end]).map_err(|_| protocol("headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| Error::Protocol(format!("bad status line: {status_line}")))?;

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::Protocol(format!("bad Content-Length: {value}")))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
        headers.push((name.to_string(), value.to_string()));
    }

    let body = &buffer[head_end + 4..];
    let bodiless = head_request || (100..200).contains(&status) || status == 204 || status == 304;
    let cap = max_body.map(|limit| limit.min(MAX_RESPONSE));
    let body = if bodiless {
        Vec::new()
    } else if chunked {
        match decode_chunked(body, cap)? {
            Some(body) => body,
            None if at_eof => return Err(protocol("connection closed inside a chunked body")),
            None => return Ok(None),
        }
    } else if let Some(length) = content_length {
        if let Some(cap) = cap {
            if body.len() >= cap && length >= cap {
                body[..cap].to_vec()
            } else if body.len() < length {
                if at_eof {
                    return Err(protocol("connection closed before the body ended"));
                }
                return Ok(None);
            } else {
                body[..length].to_vec()
            }
        } else if body.len() < length {
            if at_eof {
                return Err(protocol("connection closed before the body ended"));
            }
            return Ok(None);
        } else {
            body[..length].to_vec()
        }
    } else if let Some(cap) = cap {
        if body.len() >= cap {
            body[..cap].to_vec()
        } else if at_eof {
            body.to_vec()
        } else {
            return Ok(None);
        }
    } else if at_eof {
        body.to_vec()
    } else {
        return Ok(None);
    };
    Ok(Some(Response {
        status,
        headers,
        body,
    }))
}

/// Decode a chunked body, or `None` if the terminating chunk or requested
/// decoded body prefix has not arrived.
fn decode_chunked(mut input: &[u8], cap: Option<usize>) -> Result<Option<Vec<u8>>, Error> {
    let mut body = Vec::new();
    if cap == Some(0) {
        return Ok(Some(body));
    }
    loop {
        let Some(line_end) = find(input, b"\r\n") else {
            return Ok(None);
        };
        let size_field = std::str::from_utf8(&input[..line_end])
            .map_err(|_| Error::Protocol("chunk size is not UTF-8".to_string()))?;
        let size_hex = size_field.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| Error::Protocol(format!("bad chunk size: {size_field}")))?;
        input = &input[line_end + 2..];
        if size == 0 {
            // Trailers are not read; the terminator is enough.
            return Ok(Some(body));
        }
        if let Some(cap) = cap {
            let remaining = cap.saturating_sub(body.len());
            if size > remaining {
                if input.len() < remaining {
                    return Ok(None);
                }
                body.extend_from_slice(&input[..remaining]);
                return Ok(Some(body));
            }
            if input.len() < size {
                return Ok(None);
            }
            body.extend_from_slice(&input[..size]);
            if body.len() == cap {
                return Ok(Some(body));
            }
            if input.len() < size + 2 {
                return Ok(None);
            }
            input = &input[size + 2..];
        } else {
            if input.len() < size + 2 {
                return Ok(None);
            }
            body.extend_from_slice(&input[..size]);
            input = &input[size + 2..];
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
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
        request
    }

    #[test]
    fn pinned_rejects_empty_host_empty_addrs_and_port_zero() {
        let address = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert!(matches!(
            Target::pinned("", 80, &address, false),
            Err(Error::Url(_))
        ));
        assert!(matches!(
            Target::pinned("localhost", 80, &[], false),
            Err(Error::Url(_))
        ));
        assert!(matches!(
            Target::pinned("localhost", 0, &address, false),
            Err(Error::Url(_))
        ));
    }

    #[test]
    fn pinned_dials_the_given_address_and_puts_the_hostname_in_host() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("write response");
            request
        });

        let target = Target::pinned(
            "example.com",
            port,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            false,
        )
        .unwrap();
        let reactor = nagoya::reactor::Reactor::local().unwrap();
        let handle = reactor.handle();
        let response = nagoya::reactor::block_on_with(
            &reactor,
            send(&target, &handle, Request::get("/pinned")),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        let request = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(request.starts_with(&format!(
            "GET /pinned HTTP/1.1\r\nHost: example.com:{port}\r\n"
        )));
    }

    #[test]
    fn pinned_connect_failure_is_connect_and_a_second_attempt_stays_pinned() {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let target = Target::pinned(
            "this-name-does-not-resolve.invalid",
            port,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            false,
        )
        .unwrap();
        let reactor = nagoya::reactor::Reactor::local().unwrap();
        let handle = reactor.handle();
        for _ in 0..2 {
            let result = nagoya::reactor::block_on_with(
                &reactor,
                nagoya::timeout(
                    Duration::from_secs(2),
                    send(&target, &handle, Request::get("/")),
                ),
            )
            .unwrap();
            assert!(matches!(result, Err(Error::Connect(_))));
            assert!(target.is_pinned());
        }
    }

    #[test]
    fn pinned_tls_sni_is_the_hostname_while_the_dial_is_the_address() {
        let _ = nago_rustls::rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut flight = [0; 5];
            stream.read_exact(&mut flight).expect("TLS record header");
            let length = usize::from(u16::from_be_bytes([flight[3], flight[4]]));
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).expect("TLS ClientHello");
            flight.into_iter().chain(payload).collect::<Vec<_>>()
        });

        let target = Target::pinned(
            "pinned.example",
            port,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            true,
        )
        .unwrap();
        let reactor = nagoya::reactor::Reactor::local().unwrap();
        let handle = reactor.handle();
        let result = nagoya::reactor::block_on_with(
            &reactor,
            nagoya::timeout(
                Duration::from_secs(2),
                send(&target, &handle, Request::get("/")),
            ),
        )
        .unwrap();
        assert!(matches!(result, Err(Error::Tls(_))));
        let flight = server.join().unwrap();
        assert!(
            flight
                .windows(b"pinned.example".len())
                .any(|window| window == b"pinned.example")
        );
    }

    #[test]
    fn max_body_returns_the_status_without_waiting_for_the_rest() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n0123456789abcdef")
                .expect("write response prefix");
            release_rx.recv().expect("test releases stalled peer");
        });

        let target =
            Target::pinned("127.0.0.1", port, &[IpAddr::V4(Ipv4Addr::LOCALHOST)], false).unwrap();
        let reactor = nagoya::reactor::Reactor::local().unwrap();
        let handle = reactor.handle();
        let response = nagoya::reactor::block_on_with(
            &reactor,
            nagoya::timeout(
                Duration::from_secs(2),
                send(&target, &handle, Request::get("/").max_body(16)),
            ),
        )
        .unwrap()
        .expect("body cap returns before the peer completes its body");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"0123456789abcdef");
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn content_length_body_waits_for_every_byte() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
        assert!(parse_response(partial, false, false).unwrap().is_none());
        assert!(parse_response(partial, true, false).is_err());

        let full = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Id: 7\r\n\r\nhello";
        let response = parse_response(full, false, false).unwrap().unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header("x-id"), Some("7"));
    }

    #[test]
    fn chunked_body_is_reassembled() {
        let raw = b"HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n";
        let response = parse_response(raw, false, false).unwrap().unwrap();
        assert_eq!(response.status, 502);
        assert!(!response.is_success());
        assert_eq!(response.body, b"wikipedia");

        let unfinished = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n";
        assert!(parse_response(unfinished, false, false).unwrap().is_none());
    }

    #[test]
    fn unframed_body_ends_at_eof() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nall of it";
        assert!(parse_response(raw, false, false).unwrap().is_none());
        assert_eq!(
            parse_response(raw, true, false).unwrap().unwrap().body,
            b"all of it"
        );
    }

    #[test]
    fn request_carries_host_length_and_close() {
        let bytes = Request::post("/x?y=1")
            .header("Authorization", "Bearer t")
            .body("application/json", b"{}")
            .encode("api.example.com:8443");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /x?y=1 HTTP/1.1\r\nHost: api.example.com:8443\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains("Authorization: Bearer t\r\n"));
        assert!(text.ends_with("Content-Length: 2\r\n\r\n{}"));
    }

    #[test]
    #[ignore = "reaches the network"]
    fn a_real_https_round_trip() {
        let target = Target::resolve("api.telegram.org", 443).unwrap();
        let reactor = nagoya::reactor::Reactor::local().unwrap();
        let handle = reactor.handle();
        let response = nagoya::reactor::block_on_with(
            &reactor,
            send(&target, &handle, Request::get("/bot0:x/getMe")),
        )
        .unwrap();
        assert_eq!(response.status, 401);
        assert!(response.header("content-type").unwrap().contains("json"));
    }
}
