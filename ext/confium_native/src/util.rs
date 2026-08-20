//! Shared utilities for the confium-ruby native extension.
//!
//! DRY consolidation: a single `bytes_from_value` + size cap + string
//! conversion + typed-error helper shared by every subsystem module
//! (composite, pki, tc, transparency, deployment, attributes).

use magnus::prelude::*;
use magnus::{exception, Error, RHash, RString, Ruby, TryConvert, Value};

/// Maximum byte length for any input we accept from Ruby. Inputs larger
/// than this are rejected before they reach an allocator-capable codepath
/// (DoS guard). 1 MiB is generous for any current Confium operation
/// (cert bodies, sig material, JSON envelopes) and small enough to
/// prevent trivial memory-exhaustion attacks.
pub const MAX_INPUT_SIZE: usize = 1 << 20;

/// Convert a Ruby value to bytes. Accepts a binary `String` (any
/// encoding) or an `Array<Integer>`. Enforces a 1 MiB size cap.
pub fn bytes_from_value(v: Value) -> Result<Vec<u8>, Error> {
    if let Ok(s) = RString::try_convert(v) {
        // SAFETY: we treat the string's raw bytes as opaque cryptographic
        // input — we never interpret them as a UTF-8 string. Encoding is
        // irrelevant for hash input.
        let bytes = unsafe { s.as_slice() }.to_vec();
        enforce_size(bytes.len())?;
        return Ok(bytes);
    }
    let arr: Vec<i64> = Vec::<i64>::try_convert(v)?;
    enforce_size(arr.len())?;
    arr.into_iter()
        .map(|i| {
            if !(0..=255).contains(&i) {
                Err(Error::new(
                    exception::arg_error(),
                    format!("byte out of range 0..255: {i}"),
                ))
            } else {
                Ok(i as u8)
            }
        })
        .collect()
}

/// Reject a byte input larger than `MAX_INPUT_SIZE` with a clear
/// `ArgumentError`. Used at every byte-input boundary to prevent
/// memory-exhaustion attacks.
pub fn enforce_size(len: usize) -> Result<(), Error> {
    if len > MAX_INPUT_SIZE {
        return Err(Error::new(
            exception::arg_error(),
            format!("input size {0} exceeds max {MAX_INPUT_SIZE}", len),
        ));
    }
    Ok(())
}

/// Build a Ruby binary `String` from a byte slice. Avoids the UTF-8
/// round-trip in `RString::buf_new` + `cat` for already-binary input.
pub fn bytes_to_rstring(_ruby: &Ruby, bytes: &[u8]) -> RString {
    let s = RString::buf_new(0);
    s.cat(bytes);
    s
}

/// Construct a typed `Confium::*Error` instance with the given message
/// and details Hash, ready to be raised.
///
/// `subclass` is the Ruby class name under `Confium::` (e.g. "ThresholdError").
/// Falls back to `Confium::Error` if the subclass can't be resolved, then
/// to Ruby's `RuntimeError` if even the base class is unavailable.
///
/// ## Design
///
/// Each typed error class accepts `(message, details_hash)` positionally,
/// where `details_hash` is a plain Ruby Hash carrying the structured
/// fields (`have_count`, `need_count`, `algorithm`, etc.). The class's
/// initializer extracts its specific keys from the Hash and assigns them
/// to ivars exposed via `attr_reader`. This pattern survives Ruby 3's
/// removal of automatic positional-Hash-to-kwargs conversion.
///
/// ## Autoload caveat
///
/// The Ruby side registers error subclasses via `autoload`. We resolve
/// the constant by walking the path step by step (`Confium` →
/// `ThresholdError`) rather than `Object.const_get("Confium::ThresholdError")`,
/// because the latter does not trigger autoload.
pub fn confium_error(message: impl Into<String>, subclass: &str, details: RHash) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(exception::runtime_error(), message.into()),
    };
    let class = resolve_confium_subclass(&ruby, subclass);
    let msg: String = message.into();
    // Construct via `class.new(msg, details_hash)`. The typed subclasses
    // route the Hash through their initializer, which assigns ivars
    // exposed via attr_reader (have_count, need_count, etc.). If the
    // call fails for any reason we fall back to bare RuntimeError with
    // the original message so the binding stays usable.
    match class.funcall::<_, _, magnus::Exception>("new", (msg.as_str(), details)) {
        Ok(exc) => Error::from(exc),
        Err(_) => Error::new(exception::runtime_error(), msg),
    }
}

/// Resolve a `Confium::*Error` subclass by short name (e.g. "ThresholdError").
/// Walks the constant path segment by segment so autoload triggers
/// correctly. Falls back to `Confium::Error` if the named subclass is
/// missing, then to Ruby's `RuntimeError` if even the base class is
/// unavailable.
fn resolve_confium_subclass(ruby: &Ruby, subclass: &str) -> magnus::ExceptionClass {
    let confium_mod: magnus::RModule = match ruby
        .class_object()
        .const_get::<_, magnus::RModule>("Confium")
    {
        Ok(m) => m,
        Err(_) => return exception::runtime_error(),
    };
    confium_mod
        .const_get::<_, magnus::ExceptionClass>(subclass)
        .or_else(|_| confium_mod.const_get::<_, magnus::ExceptionClass>("Error"))
        .unwrap_or_else(|_| exception::runtime_error())
}

/// Build an empty `RHash` for the `details:` argument to a Confium
/// error. The Hash is owned by the Ruby GC; callers add keys via
/// `aset` before passing to [`confium_error`].
pub fn new_details(ruby: &Ruby) -> RHash {
    ruby.hash_new()
}

// ===== Typed error helpers (TODO 013) =====
// Each function builds a details Hash with the right shape for its
// error class, then delegates to confium_error(). Call sites pass
// only the domain-specific fields; :operation and :component are
// filled automatically.

#[allow(dead_code)]
pub fn parse_error(msg: impl Into<String>, operation: &str, format: Option<&str>, offset: Option<usize>) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(exception::runtime_error(), msg.into()),
    };
    let d = new_details(&ruby);
    let _ = d.aset("operation", operation);
    let _ = d.aset("component", "Confium");
    if let Some(f) = format { let _ = d.aset("format", f); }
    if let Some(o) = offset { let _ = d.aset("offset", o); }
    confium_error(msg, "ParseError", d)
}

#[allow(dead_code)]
pub fn validation_error(msg: impl Into<String>, operation: &str, param: &str, expected: &str, actual: &str) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(exception::runtime_error(), msg.into()),
    };
    let d = new_details(&ruby);
    let _ = d.aset("operation", operation);
    let _ = d.aset("param", param);
    let _ = d.aset("expected", expected);
    let _ = d.aset("actual", actual);
    confium_error(msg, "ValidationError", d)
}

#[allow(dead_code)]
pub fn verification_error(msg: impl Into<String>, operation: &str, signer_index: Option<usize>, algorithm: Option<&str>) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(exception::runtime_error(), msg.into()),
    };
    let d = new_details(&ruby);
    let _ = d.aset("operation", operation);
    if let Some(si) = signer_index { let _ = d.aset("signer_index", si); }
    if let Some(alg) = algorithm { let _ = d.aset("algorithm", alg); }
    confium_error(msg, "VerificationError", d)
}

#[allow(dead_code)]
pub fn crypto_error(msg: impl Into<String>, operation: &str, primitive: &str) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(exception::runtime_error(), msg.into()),
    };
    let d = new_details(&ruby);
    let _ = d.aset("operation", operation);
    let _ = d.aset("primitive", primitive);
    confium_error(msg, "CryptoError", d)
}

#[allow(dead_code)]
pub fn threshold_error(msg: impl Into<String>, operation: &str, have: usize, need: usize) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(exception::runtime_error(), msg.into()),
    };
    let d = new_details(&ruby);
    let _ = d.aset("operation", operation);
    let _ = d.aset("have_count", have);
    let _ = d.aset("need_count", need);
    confium_error(msg, "ThresholdError", d)
}
