use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use nago_http::Client;

#[test]
fn put_writes_a_large_body_to_a_slow_reader() {
    const BODY_SIZE: usize = 16 * 1024 * 1024;
    const CHUNK_SIZE: usize = 16 * 1024;

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");

        // Let the sender fill its socket buffer before the server starts
        // draining it, then keep the receive rate low enough to require
        // repeated writable notifications.
        thread::sleep(Duration::from_millis(100));

        let mut request = Vec::with_capacity(CHUNK_SIZE);
        let mut chunk = [0u8; CHUNK_SIZE];
        let header_end = loop {
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
            let read = stream.read(&mut chunk).expect("read request header");
            assert_ne!(read, 0, "client closed before sending request headers");
            request.extend_from_slice(&chunk[..read]);
        };

        let headers = std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
        assert!(headers.starts_with("PUT /snapshot HTTP/1.1\r\n"));
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim())
            })
            .expect("Content-Length header")
            .parse::<usize>()
            .expect("numeric Content-Length");
        assert_eq!(content_length, BODY_SIZE);

        let mut received = request.len() - header_end;
        assert!(request[header_end..].iter().all(|byte| *byte == 0xA5));
        while received < content_length {
            let read = stream.read(&mut chunk).expect("read request body");
            assert_ne!(read, 0, "client closed before sending the full body");
            assert!(chunk[..read].iter().all(|byte| *byte == 0xA5));
            received += read;
            thread::sleep(Duration::from_millis(2));
        }

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("write response");
        received
    });

    let client = Client::new()
        .expect("client")
        .with_timeout(Duration::from_secs(10));
    let body = vec![0xA5; BODY_SIZE];
    let url = format!("http://{address}/snapshot");
    let response = nagoya::block_on(client.send(
        "PUT",
        &url,
        &[],
        Some(("application/octet-stream", &body)),
    ))
    .expect("large PUT");

    assert_eq!(response.status, 200);
    assert_eq!(server.join().expect("server thread"), BODY_SIZE);
}
