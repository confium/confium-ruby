//! confium_native — Rust native extension for the `confium` Ruby gem.
//!
//! Pattern follows parsanol-ruby: this cdylib is loaded by Ruby via
//! `rb_sys`, and exposes a `Confium::Native` submodule whose functions
//! are the Rust-backed implementation of the gem's API.

mod audit;
mod attributes;
mod composite;
mod deployment;
mod ers;
mod gvl;
mod openpgp_verify;
mod path;
mod pki;
mod store;
mod tc;
mod net;
mod ots;
mod tc_session;
mod transparency;
mod util;

#[cfg(windows)]
mod winsock;

use magnus::{function, Error, Module, Ruby};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn native_version() -> &'static str {
    VERSION
}

fn native_loaded() -> bool {
    true
}

/// `Confium::Native.winsock_probe(tag)` — run the winsock diagnostic
/// sequence at an arbitrary point (Windows only; no-op elsewhere).
/// Timeline bisect for the listener bind failure: call it at ext
/// load, suite start, and just before a ceremony to see exactly when
/// each std net operation degrades.
fn winsock_probe_fn(tag: String) -> Result<(), Error> {
    #[cfg(windows)]
    winsock::probe_on_demand(&tag);
    #[cfg(not(windows))]
    let _ = tag;
    Ok(())
}

fn core_version() -> &'static str {
    // Set by build.rs at compile time from Cargo.lock. Always matches the
    // confium-core crate version the extension was built against.
    env!("CONFIUM_CORE_VERSION")
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    #[cfg(windows)]
    winsock::probe();

    let confium = ruby.define_module("Confium")?;
    let native = confium.define_module("Native")?;
    native.define_module_function("version", function!(native_version, 0))?;
    native.define_module_function("loaded?", function!(native_loaded, 0))?;
    confium.define_module_function("core_version", function!(core_version, 0))?;
    native.define_module_function("winsock_probe", function!(winsock_probe_fn, 1))?;

    transparency::init(ruby, confium)?;
    let transparency = confium.define_module("Transparency")?;
    ots::init(ruby, transparency)?;
    openpgp_verify::init(ruby, confium)?;
    #[cfg(feature = "pgp")]
    openpgp_verify::init_pgp(ruby, &confium)?;
    composite::init(ruby, confium)?;
    attributes::init(ruby, confium)?;
    pki::init(ruby, confium)?;
    store::init(ruby, confium)?;
    path::init(ruby, confium)?;
    deployment::init(ruby, confium)?;
    tc::init(ruby, confium)?;
    tc_session::init(ruby, confium)?;
    net::init(ruby, confium)?;
    audit::init(ruby, confium)?;
    ers::init(ruby, confium)?;
    Ok(())
}
