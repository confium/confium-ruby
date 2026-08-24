//! Confium::OpenPGP — OpenPGP (RFC 9580) signature verification via
//! the vendored librnp, behind the `pgp` cargo feature.
//!
//! Armor (encode/decode) is pure Ruby in lib/confium/openpgp.rb and
//! always available. This module adds verification only, and only
//! when the extension was built with `--features pgp`: the vendored
//! librnp brings a full Botan/json-c C/C++ build that default
//! (platform-gem) builds deliberately exclude.

use magnus::{Error, Module, RModule, Ruby, Value, function, prelude::*};

use crate::util::runtime;

fn stub_message(method: &str) -> String {
    format!(
        "Confium::OpenPGP.{} requires the pgp cargo feature — rebuild \
         the extension with --features pgp (platform gems build \
         default features)",
        method
    )
}

/// Registered when the extension builds WITHOUT the pgp feature:
/// `Confium::OpenPGP::PGP_AVAILABLE` is false and the verify methods
/// raise with instructions instead of pretending.
pub fn init(_ruby: &Ruby, parent: RModule) -> Result<(), Error> {
    let openpgp = parent.define_module("OpenPGP")?;
    let _ = openpgp.const_set("PGP_AVAILABLE", false);
    openpgp.define_singleton_method(
        "verify_detached",
        function!(
            move |_args: &[Value]| -> Result<Value, Error> {
                Err(runtime(stub_message("verify_detached")))
            },
            -1
        ),
    )?;
    openpgp.define_singleton_method(
        "verify",
        function!(
            move |_args: &[Value]| -> Result<Value, Error> { Err(runtime(stub_message("verify"))) },
            -1
        ),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// pgp feature implementation
// ---------------------------------------------------------------------------
#[cfg(feature = "pgp")]
mod pgp_impl {
    use super::*;
    use crate::util::{bytes_from_value, crypto_error, parse_error};

    fn result_to_hash(ruby: &Ruby, result: &rnp::VerifyResult) -> Result<Value, Error> {
        let hash = ruby.hash_new();
        let _ = hash.aset("any_valid", result.any_valid().unwrap_or(false));
        let _ = hash.aset(
            "signature_count",
            result.signature_count().unwrap_or(0) as i64,
        );
        let arr = ruby.ary_new();
        for s in result.iter_signatures() {
            let sh = ruby.hash_new();
            let _ = sh.aset("valid", s.status_is_valid());
            let _ = sh.aset("status", format!("{:?}", s.status()));
            let _ = sh.aset("key_id", s.keyid().unwrap_or_else(|_| "?".to_string()));
            let (created, expires) = s.times().unwrap_or((0, 0));
            let _ = sh.aset("creation_time", created as i64);
            let _ = sh.aset("expiration_time", expires as i64);
            if let Ok(alg) = s.hash() {
                let _ = sh.aset("hash", alg);
            }
            arr.push(sh)?;
        }
        let _ = hash.aset("signatures", arr);
        Ok(hash.as_value())
    }

    fn negative_result(ruby: &Ruby) -> Result<Value, Error> {
        // librnp reports a failed signature check as an error from
        // rnp_op_verify_execute; for a verifier API that is the
        // answer, not an exception.
        let hash = ruby.hash_new();
        let _ = hash.aset("any_valid", false);
        let _ = hash.aset("signature_count", 0 as i64);
        let _ = hash.aset("signatures", ruby.ary_new());
        Ok(hash.as_value())
    }

    fn ctx() -> Result<rnp::Context, Error> {
        rnp::Context::new().map_err(|e| crypto_error(e.to_string(), "OpenPGP", "openpgp"))
    }

    fn import_keys(context: &rnp::Context, keys: &[Value]) -> Result<(), Error> {
        for k in keys {
            let bytes = bytes_from_value(*k)?;
            context
                .import_keys(&bytes, rnp::LoadSaveFlags::PUBLIC)
                .map_err(|e| {
                    parse_error(e.to_string(), "OpenPGP key import", Some("openpgp"), None)
                })?;
        }
        Ok(())
    }

    /// `(message, signature, keys?)` → `(message, signature, keys)`
    fn split_args(
        args: &[Value],
        min: usize,
        method: &str,
    ) -> Result<(Value, Option<Value>, Vec<Value>), Error> {
        if args.len() < min || args.len() > min + 1 {
            return Err(crate::util::arg_error(format!(
                "Confium::OpenPGP.{}: wrong number of arguments (given {}, expected {}..{})",
                method,
                args.len(),
                min,
                min + 1
            )));
        }
        let keys = if args.len() == min + 1 {
            match <magnus::RArray as magnus::TryConvert>::try_convert(args[min]) {
                Ok(array) => array.into_iter().collect(),
                Err(_) => vec![args[min]],
            }
        } else {
            Vec::new()
        };
        Ok((args[0], args.get(1).copied(), keys))
    }

    pub fn verify_detached(args: &[Value]) -> Result<Value, Error> {
        let ruby = Ruby::get().map_err(|e| runtime(e.to_string()))?;
        let (message, signature, keys) = split_args(args, 2, "verify_detached")?;
        let msg = bytes_from_value(message)?;
        let sig = bytes_from_value(
            signature.ok_or_else(|| crate::util::arg_error("missing signature"))?,
        )?;

        let context = ctx()?;
        import_keys(&context, &keys)?;
        let result = match rnp::verify_detached(&context, &msg, &sig) {
            Ok(result) => result_to_hash(&ruby, &result)?,
            Err(e) if e.kind() == rnp::ErrorKind::SignatureInvalid => negative_result(&ruby)?,
            Err(e) => {
                return Err(parse_error(
                    e.to_string(),
                    "OpenPGP.verify_detached",
                    Some("openpgp"),
                    None,
                ));
            }
        };
        Ok(result)
    }

    pub fn verify(args: &[Value]) -> Result<Value, Error> {
        let ruby = Ruby::get().map_err(|e| runtime(e.to_string()))?;
        let (signed, _signature_ignored, keys) = split_args(args, 1, "verify")?;
        let msg = bytes_from_value(signed)?;

        let context = ctx()?;
        import_keys(&context, &keys)?;
        let result = match rnp::verify(&context, &msg) {
            Ok(result) => result_to_hash(&ruby, &result)?,
            Err(e) if e.kind() == rnp::ErrorKind::SignatureInvalid => negative_result(&ruby)?,
            Err(e) => {
                return Err(parse_error(
                    e.to_string(),
                    "OpenPGP.verify",
                    Some("openpgp"),
                    None,
                ));
            }
        };
        Ok(result)
    }
}

#[cfg(feature = "pgp")]
pub fn init_pgp(_ruby: &Ruby, parent: &RModule) -> Result<(), Error> {
    let openpgp = parent.define_module("OpenPGP")?;
    let _ = openpgp.const_set("PGP_AVAILABLE", true);
    openpgp.define_singleton_method("verify_detached", function!(pgp_impl::verify_detached, -1))?;
    openpgp.define_singleton_method("verify", function!(pgp_impl::verify, -1))?;
    Ok(())
}
