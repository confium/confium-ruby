//! Confium::OpenPGP — OpenPGP (RFC 9580) operations via bundled rnp-rs.
//!
//! Confium ships RNP functionality baked into the native extension.

use magnus::{exception, function, prelude::*, Error, Module, RModule, Ruby, TryConvert, Value};
use rnp::ops::ArmorType;
use rnp::{armor_bytes, dearmor_bytes};

use crate::util::{bytes_from_value, bytes_to_rstring};

/// Native: `Confium::OpenPGP._native_armor(data, type_str)` — 2 args.
/// The Ruby wrapper `Confium::OpenPGP.armor(data, type = MESSAGE)`
/// provides the default.
fn native_armor(ruby: &Ruby, data: Value, type_str: Value) -> Result<magnus::RString, Error> {
    let bytes = bytes_from_value(data)?;
    let ty = if type_str.is_nil() {
        ArmorType::Message
    } else {
        let s: String = TryConvert::try_convert(type_str)?;
        match s.as_str() {
            "public key" => ArmorType::PublicKey,
            "secret key" => ArmorType::SecretKey,
            "signature" => ArmorType::Signature,
            "cleartext signed message" | "cleartext" => ArmorType::Cleartext,
            _ => ArmorType::Message,
        }
    };
    let armored = armor_bytes(&bytes, ty)
        .map_err(|e| crate::util::parse_error(e.to_string(), "OpenPGP.armor", Some("openpgp"), None))?;
    Ok(bytes_to_rstring(ruby, &armored))
}

/// Native: `Confium::OpenPGP._native_dearmor(data)` — 1 arg.
fn native_dearmor(ruby: &Ruby, data: Value) -> Result<magnus::RString, Error> {
    let bytes = bytes_from_value(data)?;
    let raw = dearmor_bytes(&bytes)
        .map_err(|e| crate::util::parse_error(e.to_string(), "OpenPGP.dearmor", Some("openpgp"), None))?;
    Ok(bytes_to_rstring(ruby, &raw))
}

/// Initialize the `Confium::OpenPGP` module.
pub fn init(_ruby: &Ruby, parent: RModule) -> Result<(), Error> {
    let openpgp = parent.define_module("OpenPGP")?;

    openpgp.define_singleton_method("_native_armor", function!(native_armor, 2))?;
    openpgp.define_singleton_method("_native_dearmor", function!(native_dearmor, 1))?;

    openpgp.const_set("MESSAGE", "message")?;
    openpgp.const_set("PUBLIC_KEY", "public key")?;
    openpgp.const_set("SECRET_KEY", "secret key")?;
    openpgp.const_set("SIGNATURE", "signature")?;
    openpgp.const_set("CLEARTEXT", "cleartext signed message")?;

    Ok(())
}
