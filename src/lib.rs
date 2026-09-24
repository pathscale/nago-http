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
use nagoya::reactor::{Addr, Handle, connect_any, resolve};

mod client;
pub use client::{Client, DEFAULT_TIMEOUT};

/// Largest response this will buffer. The APIs this is for answer in
/// kilobytes; anything near this is a fault, not a payload.
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// A host, resolved.
#[derive(Clone, Debug)]
pub struct Target {
    host: String,
    port: u16,
    addrs: Vec<Addr>,
    tls: bool,
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
        })
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
}

impl<'a> Request<'a> {
    /// `path` is the path and query, already percent-encoded.
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: None,
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

/// Send one request over a fresh connection (TLS unless the target was
/// resolved with [`Target::resolve_plain`]) and read the whole response.
pub async fn send(
    target: &Target,
    handle: &Handle,
    request: Request<'_>,
) -> Result<Response, Error> {
    let host = &target.host;
    let stream = connect_any(&target.addrs, handle)
        .await
        .map_err(|err| Error::Connect(format!("{host}: {err}")))?;
    let bytes = request.encode(&target.host_header());
    // A response to HEAD has no body, whatever Content-Length says.
    let head = request.method.eq_ignore_ascii_case("HEAD");
    if !target.tls {
        let mut stream = stream;
        return exchange(&mut stream, host, &bytes, head).await;
    }
    let name = ServerName::try_from(host.clone())
        .map_err(|_| Error::Tls(format!("invalid server name {host}")))?;
    let session = ClientConnection::new(nago_rustls::default_client_config(), name)
        .map_err(|err| Error::Tls(err.to_string()))?;
    let mut tls = TlsSession::client(stream, session);
    tls.handshake()
        .await
        .map_err(|err| Error::Tls(format!("handshake with {host}: {err:?}")))?;
    let response = exchange(&mut tls, host, &bytes, head).await;
    let _ = tls.close().await;
    response
}

/// Write `request` and read until a whole response has arrived.
async fn exchange<S: Stream>(
    stream: &mut S,
    host: &str,
    request: &[u8],
    head: bool,
) -> Result<Response, Error> {
    stream
        .write_all(request)
        .await
        .map_err(|err| Error::Io(format!("writing to {host}: {err:?}")))?;

    let mut buffer = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(response) = parse_response(&buffer, false, head)? {
            return Ok(response);
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|err| Error::Io(format!("reading from {host}: {err:?}")))?;
        if read == 0 {
            return parse_response(&buffer, true, head)?.ok_or_else(|| {
                Error::Protocol(format!("{host} closed the connection mid-response"))
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_RESPONSE {
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
fn parse_response(
    buffer: &[u8],
    at_eof: bool,
    head_request: bool,
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
    let body = if bodiless {
        Vec::new()
    } else if chunked {
        match decode_chunked(body)? {
            Some(body) => body,
            None if at_eof => return Err(protocol("connection closed inside a chunked body")),
            None => return Ok(None),
        }
    } else if let Some(length) = content_length {
        if body.len() < length {
            if at_eof {
                return Err(protocol("connection closed before the body ended"));
            }
            return Ok(None);
        }
        body[..length].to_vec()
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

/// Decode a chunked body, or `None` if the terminating chunk has not arrived.
fn decode_chunked(mut input: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut body = Vec::new();
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
        if input.len() < size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
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
