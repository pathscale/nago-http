//! A small HTTP/1.1 client over nagoya and nago-rustls.
//!
//! For the outbound calls a backend makes to someone else's API: a secrets
//! store at boot, a bot platform, a payment gateway. One request per
//! connection, `Connection: close`, a body framed by `Content-Length` or
//! `chunked`, and nothing else. Those callers send a request now and then, not
//! a stream of them, so connection reuse would be complexity bought for nothing.
//!
//! TLS is nago-rustls with the process-default rustls provider selected by the
//! host and webpki roots on default paths. Default HTTPS first verifies ECC
//! chains and can retry one new connection with verify-only RSA-PSS after a
//! matching handshake refusal. Caller-supplied configs stay in force, and the
//! library never installs a provider. No tokio, no OpenSSL, no C.
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

use nago_rustls::rustls::ClientConnection;
use nago_rustls::rustls_pki_types::ServerName;
use nago_rustls::TlsSession;
use nagoya::io::Stream;
use nagoya::reactor::{connect_any, resolve, Addr, Handle, TcpStream};

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
        Self::from_addrs(host, port, tls, addrs)
    }

    fn from_addrs(host: &str, port: u16, tls: bool, addrs: Vec<Addr>) -> Result<Self, Error> {
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

    pub(crate) async fn resolve_until(
        resolver: &nagoya::resolve::Resolver,
        host: &str,
        port: u16,
        tls: bool,
        deadline_ns: u64,
    ) -> Result<Self, Error> {
        let addrs = resolver
            .resolve_until(host, port, deadline_ns)
            .await
            .map_err(|error| match error {
                nagoya::resolve::ResolveUntilError::Deadline => {
                    Error::Timeout(format!("DNS for {host} exceeded the request deadline"))
                }
                nagoya::resolve::ResolveUntilError::Busy => Error::Resolve(
                    "bounded DNS admission is busy".into(),
                ),
                nagoya::resolve::ResolveUntilError::Closed => Error::Resolve(
                    "bounded DNS resolver is unavailable".into(),
                ),
                nagoya::resolve::ResolveUntilError::Resolve(error) => {
                    Error::Resolve(error.to_string())
                }
            })?;
        Self::from_addrs(host, port, tls, addrs)
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
#[derive(Clone)]
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

#[derive(Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").finish_non_exhaustive()
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
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

pub(crate) fn require_crypto_provider() -> Result<(), Error> {
    rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| {
            Error::Tls(
                "no process-default rustls crypto provider installed; the host must call CryptoProvider::install_default before using default TLS".into(),
            )
        })
        .map(|_| ())
}

/// Establish TCP and, when selected by the target, complete the TLS handshake.
/// Default HTTPS requires the host's process-default provider. It first uses
/// ECC-only verification and opens one new connection with verify-only
/// RSA-PSS when the handshake error matches the fallback policy. This dials
/// only the addresses stored in `target` and never resolves its host.
pub async fn open(target: &Target, handle: &Handle) -> Result<Connection, Error> {
    open_with_tls_config(target, handle, None).await
}

/// Open with the caller's TLS policy. `None` uses the host's process-default
/// provider and default roots, with one RSA-PSS retry for matching handshake
/// errors. Supplied configs are used as provided, with no verifier retry. Plain
/// TCP and supplied configs do not require a process-default provider.
pub async fn open_with_tls_config(
    target: &Target,
    handle: &Handle,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
) -> Result<Connection, Error> {
    if !target.tls {
        let stream = connect_any(&target.addrs, handle)
            .await
            .map_err(|err| Error::Connect(format!("{}: {err}", target.host)))?;
        return Ok(Connection {
            stream: ConnectionStream::Plain(stream),
            host: target.host.clone(),
            host_header: target.host_header(),
        });
    }

    if let Some(tls_config) = tls_config {
        return open_tls_with_config(target, handle, tls_config)
            .await
            .map_err(|(error, _)| error);
    }

    require_crypto_provider()?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // ClientConfig::builder uses the host's process-default provider. The
    // ECC-only verifier uses ps-rustcrypto's provider for certificate checks.
    let verifier = ps_rustcrypto::policy::EccOnlyVerifier::new(roots.clone())
        .map_err(|err| Error::Tls(err.to_string()))?;
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    match open_tls_with_config(target, handle, std::sync::Arc::new(config)).await {
        Ok(connection) => Ok(connection),
        Err((error, false)) => Err(error),
        Err((_, true)) => {
            let verifier = ps_rustcrypto::fallback::rsa_fallback_ct_verifier(roots.clone(), roots)
                .map_err(|err| Error::Tls(err.to_string()))?;
            let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                ps_rustcrypto::provider_with_rsa_pss(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|err| Error::Tls(err.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
            open_tls_with_config(target, handle, std::sync::Arc::new(config))
                .await
                .map_err(|(error, _)| error)
        }
    }
}

async fn open_tls_with_config(
    target: &Target,
    handle: &Handle,
    tls_config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<Connection, (Error, bool)> {
    let name = ServerName::try_from(target.host.clone()).map_err(|_| {
        (
            Error::Tls(format!("invalid server name {}", target.host)),
            false,
        )
    })?;
    let session = ClientConnection::new(tls_config, name)
        .map_err(|err| (Error::Tls(err.to_string()), false))?;
    let stream = connect_any(&target.addrs, handle)
        .await
        .map_err(|err| (Error::Connect(format!("{}: {err}", target.host)), false))?;
    let mut tls = TlsSession::client(stream, session);
    if let Err(err) = tls.handshake().await {
        let retry = tls
            .tls_error()
            .is_some_and(ps_rustcrypto::fallback::wants_rsa_fallback);
        return Err((
            Error::Tls(format!("handshake with {}: {err:?}", target.host)),
            retry,
        ));
    }
    Ok(Connection {
        stream: ConnectionStream::Tls(tls),
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
        let token = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        };
        let value = |s: &str| s.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f));
        if !token(request.method)
            || !request.path.starts_with('/')
            || request.path.contains(['#', '\\'])
            || !request.path.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || !value(&self.host_header)
            || request.headers.iter().any(|(name, val)| {
                !token(name)
                    || !value(val)
                    || ["host", "connection", "content-length", "transfer-encoding"]
                        .iter()
                        .any(|reserved| name.eq_ignore_ascii_case(reserved))
            })
            || request
                .body
                .is_some_and(|(content_type, _)| !value(content_type))
        {
            return Err(Error::Protocol("invalid request head".into()));
        }
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
    let mut parser = ResponseParser::new(max_body);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(response) = parser.advance(&buffer, false, head)? {
            return Ok(response);
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|err| Error::Io(format!("reading from {host}: {err:?}")))?;
        if read == 0 {
            return parser.advance(&buffer, true, head)?.ok_or_else(|| {
                Error::Protocol(format!("{host} closed the connection mid-response"))
            });
        }
        append_wire_bytes(&mut buffer, &chunk[..read])?;
    }
}

#[derive(Clone, Copy, Debug)]
enum BodyFraming {
    Bodiless,
    Fixed(usize),
    CloseDelimited,
    Chunked,
}

/// Per-exchange parser. All offsets are absolute positions in the append-only wire buffer.
struct ResponseParser {
    head_start: usize,
    head_scan: usize,
    status: u16,
    headers: Vec<(String, String)>,
    body_start: usize,
    framing: Option<BodyFraming>,
    cap: Option<usize>,
    body: Vec<u8>,
    chunk_scan: usize,
    chunk_cursor: usize,
    chunk_payload_end: Option<usize>,
    chunk_suffix_pending: bool,
    trailers_pending: bool,
    #[cfg(test)]
    delimiter_candidates: usize,
    #[cfg(test)]
    head_parses: usize,
    #[cfg(test)]
    payload_appended: usize,
}

impl ResponseParser {
    fn new(max_body: Option<usize>) -> Self {
        Self {
            head_start: 0,
            head_scan: 0,
            status: 0,
            headers: Vec::new(),
            body_start: 0,
            framing: None,
            cap: max_body.map(|limit| limit.min(MAX_RESPONSE)),
            body: Vec::new(),
            chunk_scan: 0,
            chunk_cursor: 0,
            chunk_payload_end: None,
            chunk_suffix_pending: false,
            trailers_pending: false,
            #[cfg(test)]
            delimiter_candidates: 0,
            #[cfg(test)]
            head_parses: 0,
            #[cfg(test)]
            payload_appended: 0,
        }
    }

    fn advance(
        &mut self,
        buffer: &[u8],
        at_eof: bool,
        head_request: bool,
    ) -> Result<Option<Response>, Error> {
        let protocol = |detail: &str| Error::Protocol(detail.to_string());
        while self.framing.is_none() {
            let (head_end, _scanned) =
                find_from(buffer, b"\r\n\r\n", &mut self.head_scan, 3, self.head_start);
            #[cfg(test)]
            {
                self.delimiter_candidates += _scanned;
            }
            if let Some(end) = head_end {
                self.parse_head(buffer, end, head_request)?;
            } else {
                if at_eof {
                    return Err(protocol("connection closed before the headers ended"));
                }
                return Ok(None);
            }
        }
        let framing = *self.framing.as_ref().expect("head framing is initialized");
        match framing {
            BodyFraming::Bodiless => Ok(Some(self.response(Vec::new()))),
            BodyFraming::Fixed(length) => {
                let target = self.cap.map_or(length, |cap| length.min(cap));
                let available = buffer.len().saturating_sub(self.body_start);
                if available >= target {
                    Ok(Some(self.response(
                        buffer[self.body_start..self.body_start + target].to_vec(),
                    )))
                } else if at_eof {
                    Err(protocol("connection closed before the body ended"))
                } else {
                    Ok(None)
                }
            }
            BodyFraming::CloseDelimited => {
                let available = buffer.len().saturating_sub(self.body_start);
                if let Some(cap) = self.cap {
                    if available >= cap {
                        return Ok(Some(self.response(
                            buffer[self.body_start..self.body_start + cap].to_vec(),
                        )));
                    }
                }
                if at_eof {
                    Ok(Some(self.response(buffer[self.body_start..].to_vec())))
                } else {
                    Ok(None)
                }
            }
            BodyFraming::Chunked => self.advance_chunked(buffer, at_eof),
        }
    }

    fn parse_head(
        &mut self,
        buffer: &[u8],
        head_end: usize,
        head_request: bool,
    ) -> Result<(), Error> {
        let protocol = |detail: &str| Error::Protocol(detail.to_string());
        let head = std::str::from_utf8(&buffer[self.head_start..head_end])
            .map_err(|_| protocol("headers are not UTF-8"))?;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut status_parts = status_line.splitn(3, ' ');
        let version = status_parts.next().unwrap_or_default();
        let code = status_parts.next().unwrap_or_default();
        let reason = status_parts.next();
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
            || code.len() != 3
            || !code.bytes().all(|byte| byte.is_ascii_digit())
            || reason.is_none()
            || !reason.unwrap_or_default().bytes().all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
        {
            return Err(protocol("malformed HTTP/1.x status line"));
        }
        let status = code.parse::<u16>().map_err(|_| protocol("invalid status code"))?;
        if !(100..=599).contains(&status) {
            return Err(protocol("status code is outside the HTTP range"));
        }
        if status == 101 {
            return Err(protocol("switching protocols is unsupported"));
        }
        let interim = status < 200;
        let mut content_length = None;
        let mut chunked = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(protocol("malformed response header"));
            };
            if !is_http_token(name)
                || !value.bytes().all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
            {
                return Err(protocol("malformed response header"));
            }
            let framing_value = value.trim_matches([' ', '\t']);
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() || chunked {
                    return Err(protocol("ambiguous response framing"));
                }
                if framing_value.is_empty() || !framing_value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(protocol("invalid Content-Length"));
                }
                content_length = Some(
                    framing_value
                        .parse::<usize>()
                        .map_err(|_| protocol("invalid Content-Length"))?,
                );
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if version == "HTTP/1.0" {
                    return Err(protocol("Transfer-Encoding on HTTP/1.0 response"));
                }
                if chunked || content_length.is_some() || !framing_value.eq_ignore_ascii_case("chunked") {
                    return Err(protocol("unsupported response framing"));
                }
                chunked = true;
            }
            if !interim {
                self.headers.push((name.to_string(), value.trim().to_string()));
            }
        }
        #[cfg(test)]
        {
            self.head_parses += 1;
        }
        if interim {
            self.head_start = head_end + 4;
            return Ok(());
        }
        self.status = status;
        self.body_start = head_end + 4;
        self.chunk_cursor = self.body_start;
        self.chunk_scan = self.body_start;
        let bodiless = head_request
            || self.status == 204
            || self.status == 304;
        self.framing = Some(if bodiless {
            BodyFraming::Bodiless
        } else if chunked {
            BodyFraming::Chunked
        } else if let Some(length) = content_length {
            BodyFraming::Fixed(length)
        } else {
            BodyFraming::CloseDelimited
        });
        Ok(())
    }

    fn advance_chunked(&mut self, buffer: &[u8], at_eof: bool) -> Result<Option<Response>, Error> {
        let protocol = |detail: &str| Error::Protocol(detail.to_string());
        if self.cap == Some(0) {
            return Ok(Some(self.response(Vec::new())));
        }
        loop {
            if self.chunk_suffix_pending {
                let suffix_end = self.chunk_cursor.saturating_add(2);
                if buffer.len() < suffix_end {
                    if at_eof {
                        return Err(protocol("connection closed inside a chunked body"));
                    }
                    return Ok(None);
                }
                if &buffer[self.chunk_cursor..suffix_end] != b"\r\n" {
                    return Err(protocol("chunk data is not followed by CRLF"));
                }
                self.chunk_cursor = suffix_end;
                self.chunk_suffix_pending = false;
                self.chunk_scan = self.chunk_cursor;
            }
            if self.trailers_pending {
                let line_start = self.chunk_cursor;
                let (line_end, _scanned) = find_from(buffer, b"\r\n", &mut self.chunk_scan, 1, line_start);
                #[cfg(test)]
                { self.delimiter_candidates += _scanned; }
                check_chunk_line_limit(buffer, line_start, line_end)?;
                let Some(line_end) = line_end else {
                    if at_eof { return Err(protocol("connection closed before chunk trailers ended")); }
                    return Ok(None);
                };
                if line_end == line_start {
                    let body = std::mem::take(&mut self.body);
                    return Ok(Some(self.response(body)));
                }
                let line = std::str::from_utf8(&buffer[line_start..line_end])
                    .map_err(|_| protocol("chunk trailer is not UTF-8"))?;
                let Some((name, value)) = line.split_once(':') else {
                    return Err(protocol("malformed chunk trailer"));
                };
                if !is_http_token(name)
                    || !value.bytes().all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
                    || ["content-length", "transfer-encoding", "host"]
                        .iter().any(|forbidden| name.eq_ignore_ascii_case(forbidden))
                {
                    return Err(protocol("malformed or forbidden chunk trailer"));
                }
                // Validate and consume trailers without promoting them into the
                // original header block (which callers may use for policy).
                self.chunk_cursor = line_end + 2;
                self.chunk_scan = self.chunk_cursor;
                continue;
            }
            if let Some(end) = self.chunk_payload_end {
                if let Some(cap) = self.cap {
                    let remaining = cap.saturating_sub(self.body.len());
                    let payload_len = end - self.chunk_cursor;
                    if payload_len > remaining {
                        if buffer.len().saturating_sub(self.chunk_cursor) < remaining {
                            if at_eof {
                                return Err(protocol("connection closed inside a chunked body"));
                            }
                            return Ok(None);
                        }
                        self.append_payload(buffer, self.chunk_cursor, remaining);
                        let body = std::mem::take(&mut self.body);
                        return Ok(Some(self.response(body)));
                    }
                }
                if buffer.len() < end {
                    if at_eof {
                        return Err(protocol("connection closed inside a chunked body"));
                    }
                    return Ok(None);
                }
                self.append_payload(buffer, self.chunk_cursor, end - self.chunk_cursor);
                self.chunk_cursor = end;
                self.chunk_payload_end = None;
                self.chunk_suffix_pending = true;
                if self.cap.is_some_and(|cap| self.body.len() == cap) {
                    let body = std::mem::take(&mut self.body);
                    return Ok(Some(self.response(body)));
                }
                continue;
            }
            let line_start = self.chunk_cursor;
            let (line_end, _scanned) =
                find_from(buffer, b"\r\n", &mut self.chunk_scan, 1, line_start);
            #[cfg(test)]
            {
                self.delimiter_candidates += _scanned;
            }
            check_chunk_line_limit(buffer, line_start, line_end)?;
            let Some(line_end) = line_end else {
                if at_eof {
                    return Err(protocol("connection closed inside a chunked body"));
                }
                return Ok(None);
            };
            let size = parse_chunk_size(&buffer[line_start..line_end])
                .ok_or_else(|| protocol("invalid chunk size or extension"))?;
            if size > MAX_RESPONSE || size.checked_add(2).is_none() {
                return Err(Error::TooLarge);
            }
            self.chunk_cursor = line_end + 2;
            self.chunk_scan = self.chunk_cursor;
            if size == 0 {
                self.trailers_pending = true;
                continue;
            }
            self.chunk_payload_end = self.chunk_cursor.checked_add(size);
            if self.chunk_payload_end.is_none() {
                return Err(Error::TooLarge);
            }
        }
    }

    fn append_payload(&mut self, buffer: &[u8], start: usize, length: usize) {
        self.body.extend_from_slice(&buffer[start..start + length]);
        #[cfg(test)]
        {
            self.payload_appended += length;
        }
    }

    fn response(&self, body: Vec<u8>) -> Response {
        Response {
            status: self.status,
            headers: self.headers.clone(),
            body,
        }
    }
}

fn check_chunk_line_limit(buffer: &[u8], start: usize, end: Option<usize>) -> Result<(), Error> {
    let length = if let Some(end) = end {
        end - start
    } else {
        let pending = &buffer[start..];
        // A final CR may be the first byte of the line delimiter.
        pending.strip_suffix(b"\r").unwrap_or(pending).len()
    };
    if length > 1024 {
        return Err(Error::TooLarge);
    }
    Ok(())
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let hex_end = line
        .iter()
        .position(|byte| !byte.is_ascii_hexdigit())
        .unwrap_or(line.len());
    let size = usize::from_str_radix(std::str::from_utf8(&line[..hex_end]).ok()?, 16).ok()?;

    let mut extension = line[hex_end..].iter().copied().peekable();
    let is_space = |byte: &u8| matches!(byte, b' ' | b'\t');
    let is_token = |byte: &u8| is_http_token_byte(*byte);
    while extension.peek().is_some() {
        while extension.next_if(is_space).is_some() {}
        extension.next_if_eq(&b';')?;
        while extension.next_if(is_space).is_some() {}
        extension.next_if(is_token)?;
        while extension.next_if(is_token).is_some() {}

        // Whitespace after a name belongs to the following '=' or ';'.
        let had_space = extension.next_if(is_space).is_some();
        while extension.next_if(is_space).is_some() {}
        if extension.next_if_eq(&b'=').is_some() {
            while extension.next_if(is_space).is_some() {}
            if extension.next_if_eq(&b'"').is_some() {
                loop {
                    let byte = match extension.next()? {
                        b'"' => break,
                        b'\\' => extension.next()?,
                        byte => byte,
                    };
                    if byte != b'\t' && (byte < b' ' || byte == 0x7f) {
                        return None;
                    }
                }
            } else {
                extension.next_if(is_token)?;
                while extension.next_if(is_token).is_some() {}
            }
        } else if had_space && extension.peek().is_none() {
            return None;
        }
    }
    Some(size)
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_http_token_byte)
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&byte) || byte == 0x60
}

fn find_from(
    haystack: &[u8],
    needle: &[u8],
    cursor: &mut usize,
    overlap: usize,
    floor: usize,
) -> (Option<usize>, usize) {
    let start = (*cursor).min(haystack.len());
    if needle.is_empty() {
        return (Some(start.max(floor)), 0);
    }
    let scan_start = start.saturating_sub(overlap).max(floor);
    let mut scanned = 0;
    if haystack.len() >= needle.len() && scan_start <= haystack.len() - needle.len() {
        for i in scan_start..=haystack.len() - needle.len() {
            scanned += 1;
            if &haystack[i..i + needle.len()] == needle {
                *cursor = i + needle.len();
                return (Some(i), scanned);
            }
        }
    }
    *cursor = haystack.len();
    (None, scanned)
}

#[cfg(test)]
fn parse_response(
    buffer: &[u8],
    at_eof: bool,
    head_request: bool,
) -> Result<Option<Response>, Error> {
    parse_response_with_limit(buffer, at_eof, head_request, None)
}

#[cfg(test)]
fn parse_response_with_limit(
    buffer: &[u8],
    at_eof: bool,
    head_request: bool,
    max_body: Option<usize>,
) -> Result<Option<Response>, Error> {
    ResponseParser::new(max_body).advance(buffer, at_eof, head_request)
}

fn append_wire_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_RESPONSE.saturating_sub(buffer.len()) {
        return Err(Error::TooLarge);
    }
    buffer.extend_from_slice(bytes);
    Ok(())
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
        let _ = ps_rustcrypto::provider().install_default();
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
        assert!(flight
            .windows(b"pinned.example".len())
            .any(|window| window == b"pinned.example"));
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
    fn incremental_chunk_parser_is_linear_across_one_byte_feeds() {
        let raw = b"HTTP/1.1 200 OK\r\nX-First: a\r\nTransfer-Encoding: chunked\r\nX-Last: b\r\n\r\n3;ext=yes\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let mut parser = ResponseParser::new(None);
        let mut wire = Vec::new();
        let mut fragmented = None;
        let mut previous_head_scan = 0;
        let mut previous_chunk_scan = 0;
        for byte in raw {
            wire.push(*byte);
            let parsed = parser.advance(&wire, false, false).unwrap();
            assert!(parser.head_scan >= previous_head_scan);
            assert!(parser.chunk_scan >= previous_chunk_scan);
            previous_head_scan = parser.head_scan;
            previous_chunk_scan = parser.chunk_scan;
            if parsed.is_some() {
                fragmented = parsed;
                break;
            }
        }
        let response = fragmented.expect("one-byte feed completes at zero chunk");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers,
            vec![
                ("X-First".into(), "a".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
                ("X-Last".into(), "b".into())
            ]
        );
        assert_eq!(response.body, b"abcde");
        assert_eq!(parser.head_parses, 1);
        assert_eq!(parser.payload_appended, 5);
        assert!(parser.delimiter_candidates > 0);
        assert!(parser.delimiter_candidates <= raw.len() * 5);

        let mut coalesced = ResponseParser::new(None);
        let expected = coalesced.advance(raw, false, false).unwrap().unwrap();
        assert_eq!(expected.status, response.status);
        assert_eq!(expected.headers, response.headers);
        assert_eq!(expected.body, response.body);
        assert_eq!(coalesced.head_parses, 1);
        assert_eq!(coalesced.payload_appended, 5);
        assert!(coalesced.delimiter_candidates <= raw.len() * 5);
    }

    #[test]
    fn chunk_prefix_completes_inside_payload_or_at_its_boundary() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n";
        let mut inside = ResponseParser::new(Some(2));
        assert!(inside.advance(head, false, false).unwrap().is_none());
        assert_eq!(
            inside
                .advance(&[head.as_slice(), b"ab"].concat(), false, false)
                .unwrap()
                .unwrap()
                .body,
            b"ab"
        );

        let mut boundary = ResponseParser::new(Some(4));
        assert!(boundary.advance(head, false, false).unwrap().is_none());
        assert_eq!(
            boundary
                .advance(&[head.as_slice(), b"abcd"].concat(), false, false)
                .unwrap()
                .unwrap()
                .body,
            b"abcd"
        );

        let valid_head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            ResponseParser::new(Some(0))
                .advance(valid_head, false, false)
                .unwrap()
                .unwrap()
                .body,
            b""
        );
    }

    #[test]
    fn chunk_suffix_waits_across_fragmented_payload_crlf() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut parser = ResponseParser::new(None);
        let mut wire = head.to_vec();
        wire.extend_from_slice(b"3\r\na\r\n");
        assert!(parser.advance(&wire, false, false).unwrap().is_none());
        wire.extend_from_slice(b"\r\n0\r\n");
        assert!(parser.advance(&wire, false, false).unwrap().is_none());
        wire.extend_from_slice(b"\r\n");
        assert_eq!(
            parser.advance(&wire, false, false).unwrap().unwrap().body,
            b"a\r\n"
        );
    }

    #[test]
    fn incremental_parser_preserves_eof_and_framing_errors() {
        assert!(matches!(
            ResponseParser::new(None).advance(b"HTTP/1.1 200 OK\r\nX: y", true, false),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            ResponseParser::new(None).advance(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
                true,
                false
            ),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            ResponseParser::new(None).advance(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\na",
                true,
                false
            ),
            Err(Error::Protocol(_))
        ));
        let bodiless = ResponseParser::new(None).advance(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            false,
            false,
        );
        assert!(matches!(bodiless, Err(Error::Protocol(_))));
        assert_eq!(
            ResponseParser::new(None)
                .advance(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
                    false,
                    true
                )
                .unwrap()
                .unwrap()
                .body,
            b""
        );
    }

    #[test]
    fn strict_response_framing_rejects_bad_suffix_and_trailers() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let bad_suffix = [head.as_slice(), b"1\r\nxX0\r\n\r\n"].concat();
        assert!(matches!(parse_response(&bad_suffix, false, false), Err(Error::Protocol(_))));

        let incomplete = [head.as_slice(), b"0\r\nX-End: yes\r\n"].concat();
        assert!(parse_response(&incomplete, false, false).unwrap().is_none());
        assert!(matches!(parse_response(&incomplete, true, false), Err(Error::Protocol(_))));

        let malformed = [head.as_slice(), b"0\r\nnot-a-field\r\n\r\n"].concat();
        assert!(matches!(parse_response(&malformed, false, false), Err(Error::Protocol(_))));

        let valid = [head.as_slice(), b"1\r\nx\r\n0\r\nX-End: yes\r\n\r\n"].concat();
        let response = parse_response(&valid, false, false).unwrap().unwrap();
        assert_eq!(response.body, b"x");
        assert_eq!(response.header("x-end"), None);
    }

    #[test]
    fn strict_response_status_line_rejects_invalid_version_and_upgrade() {
        for raw in [
            &b"HTTP/9.9 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
        ] {
            assert!(matches!(parse_response(raw, false, false), Err(Error::Protocol(_))));
        }
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(parse_response(valid, false, false).unwrap().unwrap().body, b"ok");
        let legacy = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(parse_response(legacy, false, false).unwrap().unwrap().body, b"ok");
    }

    #[test]
    fn informational_heads_are_consumed_before_the_final_response() {
        let interim = b"HTTP/1.1 100 Continue\r\nX-First: interim\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n";
        let final_response = b"HTTP/1.1 200 OK\r\nX-First: final\r\nContent-Length: 2\r\n\r\nok";
        let raw = [interim.as_slice(), final_response.as_slice()].concat();

        let mut parser = ResponseParser::new(None);
        for end in 1..raw.len() {
            assert!(parser.advance(&raw[..end], false, false).unwrap().is_none());
        }
        let fragmented = parser.advance(&raw, false, false).unwrap().unwrap();
        let coalesced = parse_response(&raw, false, false).unwrap().unwrap();
        for response in [fragmented, coalesced] {
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"ok");
            assert_eq!(response.header("x-first"), Some("final"));
            assert_eq!(response.header("link"), None);
            assert_eq!(response.headers.len(), 2);
        }
        assert_eq!(parser.head_start, interim.len());
        assert_eq!(parser.head_parses, 3);
        assert!(parser.delimiter_candidates <= raw.len());
        assert!(parse_response_with_limit(interim, false, false, Some(0))
            .unwrap()
            .is_none());
        assert!(matches!(
            parse_response(interim, true, false),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn http_10_rejects_transfer_encoding_and_accepts_close_delimiting() {
        let chunked = b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(matches!(
            parse_response(chunked, false, false),
            Err(Error::Protocol(_))
        ));

        let close = b"HTTP/1.0 200 OK\r\n\r\nok";
        assert!(parse_response(close, false, false).unwrap().is_none());
        assert_eq!(parse_response(close, true, false).unwrap().unwrap().body, b"ok");
    }

    #[test]
    fn framing_values_require_http_numeric_and_extension_syntax() {
        for value in ["+1", "-1", "", "\u{a0}1", "1\u{a0}", "\u{FF11}", "1 0"] {
            let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\nx");
            assert!(matches!(
                parse_response(raw.as_bytes(), false, false),
                Err(Error::Protocol(_))
            ), "accepted Content-Length {value:?}");
        }
        let fixed = b"HTTP/1.1 200 OK\r\nContent-Length: \t01\t \r\n\r\nx";
        assert_eq!(parse_response(fixed, false, false).unwrap().unwrap().body, b"x");

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        for line in [
            "+1", "-1", "", " 1", "\u{a0}1", "1\u{a0}", "0x1", "1 ",
            "1;", "1;=yes", "1;ext=", "1;ext=a b", "1;ext ", "1;ext=ok ",
            "1;ext=\"unterminated", "1;ext=\"a\\", "1;ext=\"a\"extra",
            "1;ext=a\nb", "1;ext=\"a\rb\"", "1;ext=\"a\\\nb\"",
            "1;ext=\"a\x7fb\"",
        ] {
            let raw = [head.as_slice(), line.as_bytes(), b"\r\nx\r\n0\r\n\r\n"].concat();
            assert!(matches!(
                parse_response(&raw, false, false),
                Err(Error::Protocol(_))
            ), "accepted chunk line {line:?}");
        }
        let valid = b"1 \t; flag ; ext \t= \t\"a;\\\"b\\\\c\";word=abc\r\nx\r\n0;last=\"\"\r\n\r\n";
        let raw = [head.as_slice(), valid.as_slice()].concat();
        assert_eq!(parse_response(&raw, false, false).unwrap().unwrap().body, b"x");
    }

    #[test]
    fn wire_limit_is_checked_before_prefix_parsing() {
        let interim = "HTTP/1.1 103 Early Hints\r\n\r\n";
        let placeholder = format!("{interim}HTTP/1.1 200 OK\r\nContent-Length: 00000000\r\n\r\n");
        let body_len = MAX_RESPONSE - placeholder.len();
        let head = format!("{interim}HTTP/1.1 200 OK\r\nContent-Length: {body_len:08}\r\n\r\n").into_bytes();
        assert_eq!(head.len(), placeholder.len());
        let mut exact_wire = head.clone();
        exact_wire.resize(MAX_RESPONSE, b'x');

        let mut exact = Vec::new();
        let mut exact_parser = ResponseParser::new(Some(body_len));
        while exact.len() < MAX_RESPONSE - 1 {
            let start = exact.len();
            let end = (start + 16 * 1024).min(MAX_RESPONSE - 1);
            append_wire_bytes(&mut exact, &exact_wire[start..end]).unwrap();
            assert!(exact_parser
                .advance(&exact, false, false)
                .unwrap()
                .is_none());
        }
        assert_eq!(exact.len(), MAX_RESPONSE - 1);
        append_wire_bytes(&mut exact, &exact_wire[MAX_RESPONSE - 1..MAX_RESPONSE]).unwrap();
        let response = exact_parser.advance(&exact, false, false).unwrap().unwrap();
        assert_eq!(response.body.as_slice(), &exact_wire[head.len()..]);

        let mut over = Vec::new();
        let mut over_parser = ResponseParser::new(Some(body_len));
        while over.len() < MAX_RESPONSE - 1 {
            let start = over.len();
            let end = (start + 16 * 1024).min(MAX_RESPONSE - 1);
            append_wire_bytes(&mut over, &exact_wire[start..end]).unwrap();
            assert!(over_parser.advance(&over, false, false).unwrap().is_none());
        }
        assert_eq!(over.len(), MAX_RESPONSE - 1);
        let overread = [exact_wire[MAX_RESPONSE - 1], b'y'];
        assert!(matches!(
            append_wire_bytes(&mut over, &overread),
            Err(Error::TooLarge)
        ));
    }
    #[test]
    fn chunk_line_limits_are_independent_of_delimiter_fragmentation() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        for (prefix, line_prefix, suffix) in [
            (&b""[..], &b"1;ext="[..], &b"x\r\n0\r\n\r\n"[..]),
            (&b"0\r\n"[..], &b"X-Trailer:"[..], &b"\r\n"[..]),
        ] {
            for length in [1024, 1025] {
                let mut raw = [head.as_slice(), prefix, line_prefix].concat();
                raw.resize(head.len() + prefix.len() + length, b'a');
                let line_end = raw.len();
                raw.extend_from_slice(b"\r\n");
                raw.extend_from_slice(suffix);

                let mut parser = ResponseParser::new(None);
                let before_cr = parser.advance(&raw[..line_end], false, false);
                let mut parser_at_cr = ResponseParser::new(None);
                let after_cr = parser_at_cr.advance(&raw[..line_end + 1], false, false);
                let coalesced = parse_response(&raw, false, false);
                if length == 1024 {
                    assert!(before_cr.unwrap().is_none());
                    assert!(parser.advance(&raw[..line_end + 1], false, false).unwrap().is_none());
                    assert!(after_cr.unwrap().is_none());
                    let fragmented = parser.advance(&raw, false, false).unwrap().unwrap();
                    let coalesced = coalesced.unwrap().unwrap();
                    assert_eq!(fragmented.body, coalesced.body);
                    assert_eq!(fragmented.header("x-trailer"), None);
                } else {
                    for result in [before_cr, after_cr, coalesced] {
                        assert!(matches!(result, Err(Error::TooLarge)));
                    }
                }
            }
        }
    }

    #[test]
    fn chunk_size_line_guards_remain_bounded() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut long_line = head.to_vec();
        long_line.extend(vec![b'a'; 1025]);
        assert!(matches!(
            ResponseParser::new(None).advance(&long_line, false, false),
            Err(Error::TooLarge)
        ));
        let mut complete_long_line = long_line;
        complete_long_line.extend_from_slice(b"\r\n");
        assert!(matches!(
            ResponseParser::new(None).advance(&complete_long_line, false, false),
            Err(Error::TooLarge)
        ));
        let size_line = format!("{:x}\r\n", MAX_RESPONSE + 1);
        let oversized = [head.as_slice(), size_line.as_bytes()].concat();
        assert!(matches!(
            ResponseParser::new(None).advance(&oversized, false, false),
            Err(Error::TooLarge)
        ));
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
