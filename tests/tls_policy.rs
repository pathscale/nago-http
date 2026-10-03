use nago_http::{Client, Target, rustls};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    time::Duration,
};

#[test]
fn injected_client_and_open_verify_the_chain_and_hostname() {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = identity.cert.der().clone();
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der())
                    .into(),
            )
            .unwrap(),
    );
    for (host, approved) in [
        ("localhost", true),
        ("127.0.0.1", true),
        ("localhost", false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = server.clone();
        let worker = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut tls =
                rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), socket);
            let mut request = [0u8; 4096];
            if tls.read(&mut request).is_ok() {
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tls.flush();
            }
        });
        let mut roots = rustls::RootCertStore::empty();
        if approved {
            roots.add(cert.clone()).unwrap();
        }
        let config = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let client = Client::with_tls_config(config.clone())
            .unwrap()
            .with_timeout(Duration::from_secs(5));
        let result =
            nagoya::block_on(client.get(&format!("https://{host}:{}/", address.port()), &[]));
        if host == "localhost" && approved {
            assert_eq!(result.unwrap().body, b"ok");
        } else {
            assert!(matches!(result, Err(nago_http::Error::Tls(_))));
        }
        worker.join().unwrap();

        // The lower-level entry point must use the same supplied policy.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = server.clone();
        let worker = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut tls =
                rustls::StreamOwned::new(rustls::ServerConnection::new(server).unwrap(), socket);
            let _ = tls.read(&mut [0u8; 1]);
        });
        let target = Target::pinned(host, address.port(), &[address.ip()], true).unwrap();
        let reactor = nagoya::reactor::Reactor::local().unwrap();
        let result = nagoya::reactor::block_on_with(
            &reactor,
            nago_http::open_with_tls_config(&target, &reactor.handle(), Some(config)),
        );
        assert_eq!(result.is_ok(), host == "localhost" && approved);
        drop(result);
        worker.join().unwrap();
    }
}
