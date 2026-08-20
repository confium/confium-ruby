//! Confium::Audit — Ruby surface for audit logging.
//!
//! Stores the sink callback as a module-level instance variable on
//! Confium::Audit. The sink is a Ruby Proc that receives an audit
//! record Hash.
//!
//! In addition to the user-facing `record` function, this module
//! exposes `fire_event` for the rest of the native extension to
//! emit audit records from signing / verification entry points.
//! `fire_event` is best-effort: if no sink is configured, or the
//! sink raises, the calling operation still succeeds. Audit
//! failures must never break a signing ceremony.

use magnus::{exception, function, prelude::*, Error, Module, Ruby, Value};
use sha2::{Digest, Sha256};

const SINK_IVAR: &str = "@sink";

/// Best-effort audit event emitter. Called from signing / verification
/// entry points after the operation completes (whether successful or
/// not). Structured fields:
///
/// - `operation` — short slug like `"composite_sign"` or `"tc_cmp20_sign"`.
/// - `result` — `"success"` or `"failure"`.
/// - `algorithm` — optional algorithm identifier.
/// - `payload_hash` — hex SHA-256 of the signed/verified bytes (when
///   applicable; pass `None` if no payload is involved).
/// - `error` — optional error message on failure.
///
/// This function is intentionally silent on errors. If the sink
/// itself raises, the exception is logged to stderr but does not
/// propagate — the caller's crypto op has already succeeded.
pub(crate) fn fire_event(
    operation: &str,
    result: &str,
    algorithm: Option<&str>,
    payload: Option<&[u8]>,
    error: Option<&str>,
) {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return,
    };
    let audit_mod: magnus::RModule = match ruby
        .class_object()
        .const_get::<_, magnus::RModule>("Confium")
        .and_then(|m: magnus::RModule| m.const_get::<_, magnus::RModule>("Audit"))
    {
        Ok(m) => m,
        Err(_) => return,
    };
    let sink: Value = match audit_mod.ivar_get(SINK_IVAR) {
        Ok(v) => v,
        Err(_) => return,
    };
    if sink.is_nil() {
        return;
    }

    let payload_hex = payload
        .map(|bytes| {
            let mut h = Sha256::new();
            h.update(bytes);
            hex::encode(h.finalize())
        })
        .unwrap_or_default();

    let h = ruby.hash_new();
    let _ = h.aset("timestamp", chrono::Utc::now().to_rfc3339());
    let _ = h.aset("operation", operation);
    let _ = h.aset("result", result);
    let _ = h.aset("payload_hash", payload_hex);
    if let Some(a) = algorithm {
        let _ = h.aset("algorithm", a);
    }
    if let Some(e) = error {
        let _ = h.aset("error", e);
    }

    // The sink may be a Proc or any object responding to #call
    // (e.g. Confium::Audit::MemorySink). If it raises, log to stderr
    // but don't propagate — audit must not break signing.
    if let Err(e) = sink.funcall::<_, _, Value>("call", (h,)) {
        eprintln!("confium: audit sink raised (audit event dropped): {e:?}");
    }
}

/// Record an audit entry. Called from Ruby via Confium::Audit.record.
fn record(
    operation: String,
    payload_hash: String,
    result: String,
    actor: Option<String>,
    algorithm: Option<String>,
    error: Option<String>,
) -> Result<(), Error> {
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let audit_mod: magnus::RModule = ruby
        .class_object()
        .const_get("Confium")
        .and_then(|m: magnus::RModule| m.const_get("Audit"))
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;

    let sink: Value = audit_mod.ivar_get(SINK_IVAR)?;
    if sink.is_nil() {
        return Ok(());
    }

    let h = ruby.hash_new();
    let _ = h.aset("timestamp", chrono::Utc::now().to_rfc3339());
    let _ = h.aset("operation", operation);
    if let Some(a) = actor {
        let _ = h.aset("actor", a);
    }
    if let Some(alg) = algorithm {
        let _ = h.aset("algorithm", alg);
    }
    let _ = h.aset("payload_hash", payload_hash);
    let _ = h.aset("result", result);
    if let Some(e) = error {
        let _ = h.aset("error", e);
    }

    let _: Value = sink
        .funcall("call", (h,))
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    Ok(())
}

/// Set the global audit sink. `callback` is a Proc that receives a Hash
/// or nil to disable auditing.
fn set_sink(callback: Value) -> Result<(), Error> {
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let audit_mod: magnus::RModule = ruby
        .class_object()
        .const_get("Confium")
        .and_then(|m: magnus::RModule| m.const_get("Audit"))
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    audit_mod.ivar_set(SINK_IVAR, callback)?;
    Ok(())
}

/// Get the current audit sink (or nil if not set).
fn get_sink() -> Result<Value, Error> {
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let audit_mod: magnus::RModule = ruby
        .class_object()
        .const_get("Confium")
        .and_then(|m: magnus::RModule| m.const_get("Audit"))
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    audit_mod.ivar_get(SINK_IVAR)
}

/// Whether audit logging is enabled (a non-nil sink is set).
fn audit_enabled() -> Result<bool, Error> {
    let sink = get_sink()?;
    Ok(!sink.is_nil())
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let audit = parent.define_module("Audit")?;
    // Initialize the ivar to nil.
    audit.ivar_set(SINK_IVAR, ruby.qnil())?;
    audit.define_module_function("sink=", function!(set_sink, 1))?;
    audit.define_module_function("sink", function!(get_sink, 0))?;
    audit.define_module_function("enabled?", function!(audit_enabled, 0))?;
    audit.define_module_function("record", function!(record, 6))?;
    Ok(())
}
