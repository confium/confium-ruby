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
    fn bind(s: usize, name: *const u8, namelen: i32) -> i32;
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

