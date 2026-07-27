//! Confium::Audit — Ruby surface for audit logging.
//!
//! Stores the sink callback as a module-level instance variable on
//! Confium::Audit. The sink is a Ruby Proc that receives an audit
//! record Hash.

use magnus::{exception, function, prelude::*, Error, Module, Object, RHash, Ruby, Value};

const SINK_IVAR: &str = "@sink";

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
