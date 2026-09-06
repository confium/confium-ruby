//! Windows winsock diagnostics for the extension listener bind failure
//! (WSAENOTSOCK 10038 inside the Ruby process; passes in a plain Rust
//! process on the same runner — see ext/socket-smoke).
//!
//! Two probes run once at extension load, before any other winsock
//! consumer in the process can interfere:
//!
//! 1. WSAStartup(2.2) — and the reference is deliberately NEVER
//!    released. Ruby's own exit path and other native extensions call
//!    WSACleanup; if the process-wide startup count ever drains to
//!    zero, every existing socket dies and new ones fail with
//!    WSAENOTSOCK/WSANOTINITIALISED. Holding one reference pins the
//!    winsock instance for the extension's lifetime.
//! 2. A raw std TcpListener bind on 127.0.0.1:0 — logged to stderr so
//!    the state of winsock AT LOAD TIME is visible in every CI log.

#![cfg(windows)]

use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

static PROBED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WsaData) -> i32;
    fn socket(af: i32, ty: i32, protocol: i32) -> usize;
    fn WSASocketW(
        af: i32,
        ty: i32,
        protocol: i32,
        lpProtocolInfo: *const u8,
        g: i32,
        dwFlags: u32,
    ) -> usize;
    fn bind(s: usize, name: *const u8, namelen: i32) -> i32;
    fn connect(s: usize, name: *const u8, namelen: i32) -> i32;
    fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
    fn setsockopt(s: usize, level: i32, name: i32, value: *const u8, len: i32) -> i32;
    fn listen(s: usize, backlog: i32) -> i32;
    fn getsockname(s: usize, name: *mut u8, namelen: *mut i32) -> i32;
    fn accept(s: usize, addr: *mut u8, addrlen: *mut i32) -> usize;
    fn closesocket(s: usize) -> i32;
    fn WSAGetLastError() -> i32;
}

#[repr(C)]
struct WsaData {
    w_version: u16,
    w_high_version: u16,
    i_max_sockets: u16,
    i_max_u_dp_dg: u16,
    lp_vendor_info: *mut u8,
    sz_description: [u8; 257],
    sz_system_status: [u8; 129],
}

/// Run the winsock probes once. Idempotent; safe to call from init.
pub fn probe() {
    if PROBED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut data = WsaData {
        w_version: 0,
        w_high_version: 0,
        i_max_sockets: 0,
        i_max_u_dp_dg: 0,
        lp_vendor_info: std::ptr::null_mut(),
        sz_description: [0; 257],
        sz_system_status: [0; 129],
    };
    // SAFETY: WSAData is a plain C struct; the pointer is valid for the
    // call duration. The startup reference is intentionally leaked.
    let rc = unsafe { WSAStartup(0x0202, &mut data) };
    let w_hi = data.w_version >> 8;
    let w_lo = data.w_version & 0xff;
    let h_hi = data.w_high_version >> 8;
    let h_lo = data.w_high_version & 0xff;
    eprintln!("confium-winsock: WSAStartup(2.2) rc={rc} ver={w_hi}.{w_lo} high={h_hi}.{h_lo}");

    probe_raw_winsock();
    probe_wsa_socket_variants();
    probe_address_resolution_split();

    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            let addr = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|e| format!("<local_addr failed: {e}>"));
            eprintln!("confium-winsock: init-time bind OK ({addr})");
        }
        Err(e) => {
            eprintln!("confium-winsock: init-time bind FAILED: {e}");
        }
    }
}

/// Step-level raw winsock discrimination: create a socket via FFI,
/// bind it via FFI, close it. If these succeed where the std bind
/// fails, the fault is in the std windows-gnu socket path inside the
/// Ruby process; if the FFI socket() itself fails, the process-level
/// winsock state is poisoned (no library code of ours involved).
fn probe_raw_winsock() {
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const IPPROTO_TCP: i32 = 6;
    const INVALID: usize = usize::MAX;

    // sockaddr_in: family=AF_INET, port=0 (ephemeral), addr=127.0.0.1
    let mut addr = [0u8; 16];
    addr[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    addr[4..8].copy_from_slice(&[127, 0, 0, 1]);

    // SAFETY: plain winsock calls; the sockaddr outlives both calls.
    let handle = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
    if handle == INVALID {
        let err = unsafe { WSAGetLastError() };
        eprintln!("confium-winsock: raw socket() FAILED wsagetlasterror={err}");
        return;
    }
    eprintln!("confium-winsock: raw socket() handle={handle:#x}");

    let rc = unsafe { bind(handle, addr.as_ptr(), 16) };
    if rc != 0 {
        let err = unsafe { WSAGetLastError() };
        eprintln!("confium-winsock: raw bind() rc={rc} wsagetlasterror={err}");
    } else {
        eprintln!("confium-winsock: raw bind() OK");
    }
    unsafe { closesocket(handle) };
}

/// Probe (e): Rust std creates sockets with `WSASocketW` (not the
/// plain `socket()` above). Round (d) showed raw `socket()`+`bind()`
/// succeed while std's bind fails — so call `WSASocketW` exactly as
/// std does, across its flag variants, and bind each result. Whichever
/// variant reproduces the 10038 identifies the failing entry point.
fn probe_wsa_socket_variants() {
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const IPPROTO_TCP: i32 = 6;
    const INVALID: usize = usize::MAX;
    const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;

    let variants: [(&str, u32); 3] = [
        ("overlapped", WSA_FLAG_OVERLAPPED),
        ("overlapped|no_handle_inherit", WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT),
        ("flags=0", 0),
    ];

    for (label, flags) in variants {
        let mut addr = [0u8; 16];
        addr[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        addr[4..8].copy_from_slice(&[127, 0, 0, 1]);

        // SAFETY: plain winsock calls; the sockaddr outlives both.
        let s = unsafe { WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, std::ptr::null(), 0, flags) };
        if s == INVALID {
            let err = unsafe { WSAGetLastError() };
            eprintln!("confium-winsock: WSASocketW[{label}] FAILED wsagetlasterror={err}");
            continue;
        }
        let rc = unsafe { bind(s, addr.as_ptr(), 16) };
        if rc != 0 {
            let err = unsafe { WSAGetLastError() };
            eprintln!("confium-winsock: WSASocketW[{label}] handle={s:#x} bind rc={rc} wsagetlasterror={err}");
        } else {
            eprintln!("confium-winsock: WSASocketW[{label}] handle={s:#x} bind OK");
        }
        unsafe { closesocket(s) };
    }
}

/// Probe (f): split std's bind path into its two halves. std's
/// `TcpListener::bind("host:port")` resolves the string (GetAddrInfoW)
/// before creating the socket; binding a pre-parsed `SocketAddr`
/// skips resolution entirely. If the SocketAddr form works while the
/// string form fails, the fault is std's address resolution inside
/// the Ruby process, and the fix is for confium-net-tcp to parse
/// hosts itself. Also exercised: a complete raw listener (bind +
/// listen + getsockname) and a std CLIENT connect to it, to see
/// whether any std net path works in-process.
fn probe_address_resolution_split() {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::TcpStream;

    // 1) std bind via pre-parsed SocketAddr (no getaddrinfo).
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    match TcpListener::bind(addr) {
        Ok(l) => eprintln!("confium-winsock: std bind[SocketAddr] OK ({})", l.local_addr().map(|a| a.to_string()).unwrap_or_default()),
        Err(e) => eprintln!("confium-winsock: std bind[SocketAddr] FAILED: {e}"),
    }

    // 2) std bind via &str (exercises GetAddrInfoW).
    match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => eprintln!("confium-winsock: std bind[str] OK ({})", l.local_addr().map(|a| a.to_string()).unwrap_or_default()),
        Err(e) => eprintln!("confium-winsock: std bind[str] FAILED: {e}"),
    }

    // 3) Full raw listener + std client connect to it.
    const AF_INET: i32 = 2;
    const INVALID: usize = usize::MAX;
    let mut saddr = [0u8; 16];
    saddr[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    saddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    // SAFETY: plain winsock calls; buffers outlive the calls.
    let s = unsafe { socket(AF_INET, 1, 6) };
    if s == INVALID {
        eprintln!("confium-winsock: probe-f socket FAILED {}", unsafe { WSAGetLastError() });
        return;
    }
    if unsafe { bind(s, saddr.as_ptr(), 16) } != 0 {
        eprintln!("confium-winsock: probe-f bind FAILED {}", unsafe { WSAGetLastError() });
        unsafe { closesocket(s) };
        return;
    }
    if unsafe { listen(s, 16) } != 0 {
        eprintln!("confium-winsock: probe-f listen FAILED {}", unsafe { WSAGetLastError() });
        unsafe { closesocket(s) };
        return;
    }
    let mut got = [0u8; 16];
    let mut gotlen: i32 = 16;
    let mut port: u16 = 0;
    if unsafe { getsockname(s, got.as_mut_ptr(), &mut gotlen) } == 0 {
        port = u16::from_be_bytes([got[2], got[3]]);
        eprintln!("confium-winsock: probe-f raw listener up on port {port}");
    }
    if port != 0 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(_) => eprintln!("confium-winsock: std client connect OK"),
            Err(e) => eprintln!("confium-winsock: std client connect FAILED: {e}"),
        }
        // Drain the accepted connection so the raw socket closes clean.
        let mut pa = [0u8; 16];
        let mut palen: i32 = 16;
        let acc = unsafe { accept(s, pa.as_mut_ptr(), &mut palen) };
        if acc != INVALID {
            unsafe { closesocket(acc) };
        }
    }
    unsafe { closesocket(s) };
}

/// Probe (g): the timeline bisect. Exposed to Ruby as
/// `Confium::Native.winsock_probe(tag)` so the spec harness can run
/// the full diagnostic sequence at chosen points (suite start, right
/// before a ceremony) and the CI log shows exactly WHEN each std net
/// operation degrades. Adds the comparator probe (f) lacked: a raw
/// FFI connect against a live listener, step by step, next to the
/// std connect — plus a UDP bind for type coverage.
///
/// Non-Windows builds get a no-op with the same signature so spec
/// code can call it unconditionally.
#[cfg(windows)]
pub fn probe_on_demand(tag: &str) {
    use std::io::Write;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::TcpStream;
    use std::net::UdpSocket;

    let log = |what: &str, r: Result<String, String>| match r {
        Ok(s) => eprintln!("confium-winsock[{tag}]: {what} OK ({s})"),
        Err(e) => eprintln!("confium-winsock[{tag}]: {what} FAILED: {e}"),
    };

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    log("std bind[SocketAddr]", TcpListener::bind(addr).and_then(|l| l.local_addr().map(|a| a.to_string())).map_err(|e| e.to_string()));
    log("std bind[str]", TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr().map(|a| a.to_string())).map_err(|e| e.to_string()));
    log("std udp bind", UdpSocket::bind("127.0.0.1:0").and_then(|s| s.local_addr().map(|a| a.to_string())).map_err(|e| e.to_string()));

    // Raw listener for the connect comparisons.
    let listener = raw_listener();
    let Some((ls, port)) = listener else {
        eprintln!("confium-winsock[{tag}]: raw listener setup FAILED");
        return;
    };

    // FFI connect with a plain socket().
    let c1 = ffi_connect(false, port);
    match c1 {
        Ok(()) => eprintln!("confium-winsock[{tag}]: FFI connect[socket()] OK"),
        Err(e) => eprintln!("confium-winsock[{tag}]: FFI connect[socket()] FAILED: {e}"),
    }
    // FFI connect with WSASocketW (overlapped), as std does.
    match ffi_connect(true, port) {
        Ok(()) => eprintln!("confium-winsock[{tag}]: FFI connect[WSASocketW] OK"),
        Err(e) => eprintln!("confium-winsock[{tag}]: FFI connect[WSASocketW] FAILED: {e}"),
    }
    // std connect, tuple form (resolution + socket + connect).
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(_) => eprintln!("confium-winsock[{tag}]: std connect[tuple] OK"),
        Err(e) => eprintln!("confium-winsock[{tag}]: std connect[tuple] FAILED: {e}"),
    }
    // std connect, pre-parsed SocketAddr (no resolution).
    match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)) {
        Ok(_) => eprintln!("confium-winsock[{tag}]: std connect[SocketAddr] OK"),
        Err(e) => eprintln!("confium-winsock[{tag}]: std connect[SocketAddr] FAILED: {e}"),
    }
    drain_accepted(ls);

    // Probe (h): the ceremonies showed std connect OK followed by
    // transport send failing 10038. Exercise the write paths next to
    // the reads: a std blocking write, and a raw FFI send.
    if let Some((ls2, port2)) = raw_listener() {
        match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port2)) {
            Ok(mut s) => match s.write_all(b"confium-probe") {
                Ok(()) => eprintln!("confium-winsock[{tag}]: std write_all OK"),
                Err(e) => eprintln!("confium-winsock[{tag}]: std write_all FAILED: {e}"),
            },
            Err(e) => eprintln!("confium-winsock[{tag}]: send-probe connect FAILED: {e}"),
        }
        drain_accepted(ls2);
    }
    if let Some((_ls3, port3)) = raw_listener() {
        match ffi_send_probe(port3) {
            Ok(()) => eprintln!("confium-winsock[{tag}]: FFI send OK"),
            Err(e) => eprintln!("confium-winsock[{tag}]: FFI send FAILED: {e}"),
        }
        drain_accepted(_ls3);
    }

    // Probe (i): every FAILING path (noise connect, coordinator
    // send/recv) calls set_read_timeout; no passing path does, and
    // none of the probes above ever set a timeout. Test std
    // set_read_timeout and the raw FFI setsockopt(SO_RCVTIMEO) next
    // to each other on a connected socket.
    if let Some((ls4, port4)) = raw_listener() {
        match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port4)) {
            Ok(mut s) => {
                match s.set_read_timeout(Some(std::time::Duration::from_secs(5))) {
                    Ok(()) => eprintln!("confium-winsock[{tag}]: std set_read_timeout OK"),
                    Err(e) => eprintln!("confium-winsock[{tag}]: std set_read_timeout FAILED: {e}"),
                }
                match s.write_all(b"probe-i") {
                    Ok(()) => eprintln!("confium-winsock[{tag}]: post-timeout write OK"),
                    Err(e) => eprintln!("confium-winsock[{tag}]: post-timeout write FAILED: {e}"),
                }
                let mut one = [0u8; 1];
                use std::io::Read;
                match s.read(&mut one) {
                    Ok(_) => eprintln!("confium-winsock[{tag}]: post-timeout read OK"),
                    Err(e) => eprintln!("confium-winsock[{tag}]: post-timeout read FAILED: {e}"),
                }
            }
            Err(e) => eprintln!("confium-winsock[{tag}]: probe-i connect FAILED: {e}"),
        }
        drain_accepted(ls4);
    }
    if let Some((ls5, port5)) = raw_listener() {
        match ffi_rcvtimeo_probe(port5) {
            Ok(()) => eprintln!("confium-winsock[{tag}]: FFI setsockopt[SO_RCVTIMEO] OK"),
            Err(e) => eprintln!("confium-winsock[{tag}]: FFI setsockopt[SO_RCVTIMEO] FAILED: {e}"),
        }
        drain_accepted(ls5);
    }
}

/// FFI socket + connect + setsockopt(SOL_SOCKET, SO_RCVTIMEO, ms) +
/// send + (short) recv — the exact call sequence the noise transport
/// and coordinator client use, via raw winsock.
#[cfg(windows)]
fn ffi_rcvtimeo_probe(port: u16) -> Result<(), String> {
    const AF_INET: i32 = 2;
    const SOL_SOCKET: i32 = 0xffff;
    const SO_RCVTIMEO: i32 = 0x1006;
    const INVALID: usize = usize::MAX;
    // SAFETY: plain winsock calls.
    let s = unsafe { socket(AF_INET, 1, 6) };
    if s == INVALID {
        return Err(format!("create {}", unsafe { WSAGetLastError() }));
    }
    let mut peer = [0u8; 16];
    peer[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    peer[2..4].copy_from_slice(&port.to_be_bytes());
    peer[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let rc = unsafe { connect(s, peer.as_ptr(), 16) };
    if rc != 0 {
        let err = unsafe { WSAGetLastError() };
        unsafe { closesocket(s) };
        return Err(format!("connect wsagetlasterror={err}"));
    }
    let ms: u32 = 5000;
    let rc = unsafe { setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &ms as *const u32 as *const u8, 4) };
    if rc != 0 {
        let err = unsafe { WSAGetLastError() };
        unsafe { closesocket(s) };
        return Err(format!("setsockopt wsagetlasterror={err}"));
    }
    let payload = b"probe-i";
    let sent = unsafe { send(s, payload.as_ptr(), payload.len() as i32, 0) };
    unsafe { closesocket(s) };
    if sent < 0 {
        Err(format!("send wsagetlasterror={}", unsafe { WSAGetLastError() }))
    } else {
        Ok(())
    }
}

/// FFI socket + connect + send, step by step.
#[cfg(windows)]
fn ffi_send_probe(port: u16) -> Result<(), String> {
    const AF_INET: i32 = 2;
    const INVALID: usize = usize::MAX;
    // SAFETY: plain winsock calls.
    let s = unsafe { socket(AF_INET, 1, 6) };
    if s == INVALID {
        return Err(format!("create {}", unsafe { WSAGetLastError() }));
    }
    let mut peer = [0u8; 16];
    peer[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    peer[2..4].copy_from_slice(&port.to_be_bytes());
    peer[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let rc = unsafe { connect(s, peer.as_ptr(), 16) };
    if rc != 0 {
        let err = unsafe { WSAGetLastError() };
        unsafe { closesocket(s) };
        return Err(format!("connect wsagetlasterror={err}"));
    }
    let payload = b"confium-probe";
    let sent = unsafe { send(s, payload.as_ptr(), payload.len() as i32, 0) };
    let err = if sent < 0 { unsafe { WSAGetLastError() } } else { 0 };
    unsafe { closesocket(s) };
    if sent < 0 {
        Err(format!("send wsagetlasterror={err}"))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn raw_listener() -> Option<(usize, u16)> {
    const AF_INET: i32 = 2;
    const INVALID: usize = usize::MAX;
    let mut saddr = [0u8; 16];
    saddr[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    saddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    // SAFETY: plain winsock calls; buffers outlive them.
    let s = unsafe { socket(AF_INET, 1, 6) };
    if s == INVALID {
        eprintln!("confium-winsock: raw_listener socket FAILED {}", unsafe { WSAGetLastError() });
        return None;
    }
    if unsafe { bind(s, saddr.as_ptr(), 16) } != 0 {
        eprintln!("confium-winsock: raw_listener bind FAILED {}", unsafe { WSAGetLastError() });
        unsafe { closesocket(s) };
        return None;
    }
    if unsafe { listen(s, 16) } != 0 {
        eprintln!("confium-winsock: raw_listener listen FAILED {}", unsafe { WSAGetLastError() });
        unsafe { closesocket(s) };
        return None;
    }
    let mut got = [0u8; 16];
    let mut gotlen: i32 = 16;
    if unsafe { getsockname(s, got.as_mut_ptr(), &mut gotlen) } != 0 {
        eprintln!("confium-winsock: raw_listener getsockname FAILED {}", unsafe { WSAGetLastError() });
        unsafe { closesocket(s) };
        return None;
    }
    let port = u16::from_be_bytes([got[2], got[3]]);
    Some((s, port))
}

#[cfg(windows)]
fn ffi_connect(wsa: bool, port: u16) -> Result<(), String> {
    const AF_INET: i32 = 2;
    const INVALID: usize = usize::MAX;
    // SAFETY: plain winsock calls.
    let s = if wsa {
        unsafe { WSASocketW(AF_INET, 1, 6, std::ptr::null(), 0, 0x01) }
    } else {
        unsafe { socket(AF_INET, 1, 6) }
    };
    if s == INVALID {
        return Err(format!("create {}", unsafe { WSAGetLastError() }));
    }
    let mut peer = [0u8; 16];
    peer[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    peer[2..4].copy_from_slice(&port.to_be_bytes());
    peer[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let rc = unsafe { connect(s, peer.as_ptr(), 16) };
    let err = if rc != 0 { unsafe { WSAGetLastError() } } else { 0 };
    unsafe { closesocket(s) };
    if rc != 0 {
        Err(format!("connect wsagetlasterror={err}"))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn drain_accepted(listener: usize) {
    const INVALID: usize = usize::MAX;
    let mut pa = [0u8; 16];
    let mut palen: i32 = 16;
    // SAFETY: plain winsock calls.
    let acc = unsafe { accept(listener, pa.as_mut_ptr(), &mut palen) };
    if acc != INVALID {
        unsafe { closesocket(acc) };
    }
    unsafe { closesocket(listener) };
}

/// No-op on non-Windows targets (the Ruby method exists everywhere so
/// spec code need not branch).
#[cfg(not(windows))]
pub fn probe_on_demand(_tag: &str) {}
