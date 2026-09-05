//! Confium::Net — transport-level coordinator clients.
//!
//! Binds the registry-transport coordinator surface: a signer dials
//! the coordinator over any URL scheme the native library links
//! (tcp:// for local/trusted, noise:// for encrypted sessions with
//! key=/pinned= parameters), and a CoordinatorServer serves any
//! linked scheme. This is the transport half of multi-host signing;
//! the protocol half is Confium::TC::Session.

use magnus::{prelude::*, DataTypeFunctions, Error, Ruby, TypedData};

// Force the noise transport crate (and its `register_transport!`
// static) into the cdylib so the noise:// scheme resolves — the
// binding itself never names a symbol from it.
extern crate confium_net_noise as _noise_link;
extern crate confium_net_tcp as _tcp_link;

use confium_coordinator::coordinator::client::SignerClient as RustSignerClient;
use confium_coordinator::coordinator::net_server::CoordinatorServer as RustCoordinatorServer;

fn io_error(e: std::io::Error, operation: &str) -> Error {
    magnus::Error::new(
        magnus::exception::io_error(),
        format!("{operation}: {e}"),
    )
}

/// Confium::Net::SignerClient — a coordinator connection over a
/// registry transport URL.
#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Net::SignerClient", size)]
pub struct SignerClient {
    inner: std::cell::RefCell<RustSignerClient>,
}

impl SignerClient {
    fn initialize(ruby: &Ruby, url: String) -> Result<Self, Error> {
        let _ = ruby;
        let inner = RustSignerClient::connect_url(&url).map_err(|e| io_error(e, "SignerClient.new"))?;
        Ok(Self { inner: std::cell::RefCell::new(inner) })
    }

    fn register(&self, signer_id: String, quorum_id: String) -> Result<(), Error> {
        self.inner
            .borrow_mut()
            .register(&signer_id, &quorum_id)
            .map_err(|e| io_error(e, "register"))
    }

    fn create_session(
        &self,
        quorum_id: String,
        scheme: String,
        message: String,
        threshold: u32,
        num_parties: u32,
    ) -> Result<String, Error> {
        self.inner
            .borrow_mut()
            .create_session(&quorum_id, &scheme, message.as_bytes(), threshold, num_parties)
            .map_err(|e| io_error(e, "create_session"))
    }

    fn submit_commitment(&self, args: &[magnus::Value]) -> Result<(), Error> {
        let scanned = magnus::scan_args::scan_args::<(String, String, Vec<u8>), (), (), (), (), ()>(args)
            .map_err(|e| magnus::Error::new(magnus::exception::arg_error(), e.to_string()))?;
        let (session_id, signer_id, commitment) = scanned.required;
        self.inner
            .borrow_mut()
            .submit_commitment(&session_id, &signer_id, &commitment)
            .map_err(|e| io_error(e, "submit_commitment"))
    }

    fn submit_share(&self, args: &[magnus::Value]) -> Result<Option<Vec<u8>>, Error> {
        let scanned = magnus::scan_args::scan_args::<(String, String, Vec<u8>), (), (), (), (), ()>(args)
            .map_err(|e| magnus::Error::new(magnus::exception::arg_error(), e.to_string()))?;
        let (session_id, signer_id, share) = scanned.required;
        self.inner
            .borrow_mut()
            .submit_share(&session_id, &signer_id, &share)
            .map_err(|e| io_error(e, "submit_share"))
    }
}

/// Confium::Net::CoordinatorServer — serves coordinator sessions over
/// any linked transport scheme. Held in a Ruby object; the server
/// thread runs until the process exits.
#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Net::CoordinatorServer", size)]
pub struct CoordinatorServer {
    _bound: String,
}

impl CoordinatorServer {
    fn initialize(ruby: &Ruby, url: String) -> Result<Self, Error> {
        let _ = ruby;
        let server = RustCoordinatorServer::new(&url);
        let bound = server
            .start_url(&url)
            .map_err(|e| io_error(e, "CoordinatorServer.new"))?;
        Ok(Self { _bound: bound })
    }
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let net = parent.define_module("Net")?;

    let client = net.define_class("SignerClient", ruby.class_object())?;
    client.define_singleton_method("new", magnus::function!(SignerClient::initialize, 1))?;
    client.define_method("register", magnus::method!(SignerClient::register, 2))?;
    client.define_method(
        "create_session",
        magnus::method!(SignerClient::create_session, 5),
    )?;
    client.define_method(
        "submit_commitment",
        magnus::method!(SignerClient::submit_commitment, -1),
    )?;
    client.define_method("submit_share", magnus::method!(SignerClient::submit_share, -1))?;

    let server = net.define_class("CoordinatorServer", ruby.class_object())?;
    server.define_singleton_method("new", magnus::function!(CoordinatorServer::initialize, 1))?;

    Ok(())
}
