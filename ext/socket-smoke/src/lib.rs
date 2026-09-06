//! Socket-bind smoke — the Windows diagnostic for the extension
//! listener failure (WSAENOTSOCK 10038 / bind refusal from the Ruby
//! process). These tests exercise the same transport crates and the
//! same bind paths the extension uses, but in a plain Rust process.
//! A green run here next to a red Ruby-side bind isolates the fault
//! to the Ruby embedding environment rather than windows-gnu socket
//! support. See `cargo test --manifest-path ext/socket-smoke/Cargo.toml`.

#[cfg(test)]
use std::net::{TcpListener, TcpStream};

use std::io::{Read, Write};

// Link the transport registry statics into this binary exactly as
// the extension does, so tcp:// and noise:// resolve.
extern crate confium_net_noise as _noise_link;
extern crate confium_net_tcp as _tcp_link;

#[test]
fn std_tcp_listener_binds_and_echoes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("std bind");
    let addr = listener.local_addr().expect("local_addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).expect("read");
        stream.write_all(&buf[..n]).expect("write");
    });

    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(b"ping").expect("client write");
    let mut buf = [0u8; 8];
    let n = client.read(&mut buf).expect("client read");
    assert_eq!(&buf[..n], b"ping");
    server.join().expect("server thread");
}

#[test]
fn registry_tcp_listener_binds() {
    confium_net::listen("tcp://127.0.0.1:0")
        .inspect_err(|e| panic!("registry tcp bind: {e}"))
        .ok();
}

#[test]
fn registry_noise_listener_binds() {
    confium_net::listen("noise://127.0.0.1:0")
        .inspect_err(|e| panic!("registry noise bind: {e}"))
        .ok();
}

#[test]
fn registry_tcp_round_trip() {
    // Probe-rebind: reserve a port with std, release it, then listen
    // on it through the registry. On Windows a refusal here is itself
    // diagnostic (the Ruby specs observe exactly that).
    let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let mut listener = confium_net::listen(&format!("tcp://127.0.0.1:{port}"))
        .unwrap_or_else(|e| panic!("registry bind on {port}: {e}"));

    let sender = std::thread::spawn(move || {
        let mut conn = confium_net::connect(&format!("tcp://127.0.0.1:{port}"))
            .unwrap_or_else(|e| panic!("connect: {e}"));
        conn.send(b"frame-1").expect("send");
    });

    let transport = listener.accept().unwrap_or_else(|e| panic!("accept: {e}"));
    let mut session = confium_net::io::TransportIo::new(transport);
    let mut buf = [0u8; 16];
    let n = session.read(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"frame-1");
    sender.join().expect("sender thread");
}
