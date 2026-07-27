//! confium_native — Rust native extension for the `confium` Ruby gem.
//!
//! Pattern follows parsanol-ruby: this cdylib is loaded by Ruby via
//! `rb_sys`, and exposes a `Confium::Native` submodule whose functions
//! are the Rust-backed implementation of the gem's API.

mod attributes;
mod composite;
mod deployment;
mod pki;
mod tc;
mod transparency;

use magnus::{function, Error, Module, Ruby};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn native_version() -> &'static str {
    VERSION
}

fn native_loaded() -> bool {
    true
}

fn core_version() -> &'static str {
    // confium-core doesn't expose its version at runtime; we hand-mirror
    // the workspace version the extension was built against.
    "0.2.0"
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let confium = ruby.define_module("Confium")?;
    let native = confium.define_module("Native")?;
    native.define_module_function("version", function!(native_version, 0))?;
    native.define_module_function("loaded?", function!(native_loaded, 0))?;
    confium.define_module_function("core_version", function!(core_version, 0))?;

    transparency::init(ruby, confium)?;
    composite::init(ruby, confium)?;
    attributes::init(ruby, confium)?;
    pki::init(ruby, confium)?;
    deployment::init(ruby, confium)?;
    tc::init(ruby, confium)?;
    Ok(())
}
