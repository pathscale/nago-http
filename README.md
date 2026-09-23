# nago-http

A small HTTP/1.1 client over [nagoya](https://github.com/pathscale/nagoya) and
[nago-rustls](https://github.com/pathscale/nago-rustls). No tokio, no OpenSSL,
no C.

It is for the outbound calls a backend makes to someone else's API: a secrets
store at boot, a bot platform, a payment gateway. One request per connection,
`Content-Length` or `chunked` bodies, and nothing else.

```rust
use nagoya::reactor::{Reactor, block_on_with};

let target = nago_http::Target::resolve("api.example.com", 443)?; // blocks: do it first
let reactor = Reactor::local()?;
let handle = reactor.handle();
let response = block_on_with(&reactor, nago_http::send(
    &target,
    &handle,
    nago_http::Request::post("/v1/thing").body("application/json", br#"{"a":1}"#),
))?;
```

No timeouts are imposed; wrap the call in `nagoya::timeout`.

## License

MIT or Apache-2.0, at your option.
