//! Shared utilities for the confium-ruby native extension.
//!
//! DRY consolidation: a single `bytes_from_value` + size cap + string
//! conversion shared by every subsystem module (composite, pki, tc,
//! transparency, deployment, attributes).

use magnus::{exception, Error, RString, TryConvert, Value};

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
    if arr.len() > MAX_INPUT_SIZE {
        return Err(Error::new(
            exception::arg_error(),
            format!("array input size {0} exceeds max {MAX_INPUT_SIZE}", arr.len()),
        ));
    }
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
pub fn bytes_to_rstring(ruby: &magnus::Ruby, bytes: &[u8]) -> magnus::RString {
    let s = magnus::RString::buf_new(0);
    s.cat(bytes);
    s
}
