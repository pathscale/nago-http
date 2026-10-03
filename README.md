# nago-http

A small HTTP/1.1 client over [nagoya](https://github.com/pathscale/nagoya) and
[nago-rustls](https://github.com/pathscale/nago-rustls). No tokio, no OpenSSL,
no C.

It is for the outbound calls a backend makes to someone else's API: a secrets
store at boot, a bot platform, a payment gateway. One request per connection,
`Content-Length` or `chunked` bodies, and nothing else.

Callers with a private trust policy can use `Client::with_tls_config(Arc<ClientConfig>)`
or `open_with_tls_config(target, handle, Some(config))`. HTTPS uses that policy
without adding system or default WebPKI roots. The URL hostname remains the SNI
and certificate verification name, including for pinned socket addresses. The
original constructors keep their default policy for other consumers.

Most callers want a `Client`: requests by URL, from any executor. It runs its own
reactor on a thread of its own, resolves each host once, and gives every request
a deadline (30 s unless `with_timeout` says otherwise).

```rust
let client = nago_http::Client::global()?;
let response = client
    .post("https://api.example.com/v1/thing", &[], "application/json", br#"{"a":1}"#)
    .await?;
```

`https://` goes over TLS; `http://` is plain TCP, for a local stand-in such as a
loopback S3, never for a credential crossing the network. `HEAD`, 1xx, 204 and 304
responses have no body, whatever `Content-Length` says.

To drive the reactor yourself, give `Target::pinned` the addresses you already
have, then call `send`:

```rust
use nagoya::reactor::{Reactor, block_on_with};

let addresses = [std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 17))];
let target = nago_http::Target::pinned("api.example.com", 443, &addresses, true)?;
let reactor = Reactor::local()?;
let handle = reactor.handle();
let response = block_on_with(&reactor, nago_http::send(
    &target,
    &handle,
    nago_http::Request::post("/v1/thing").body("application/json", br#"{"a":1}"#),
))?;
```

`open` dials only the addresses stored in its `Target`; it does not look up the
host name. A pinned target already in a `Client` cache stays there after a
failed connection. Resolved targets continue to be looked up again after a
connection failure.

`send` imposes no timeout; wrap it in `nagoya::timeout`.

## License

MIT or Apache-2.0, at your option.
