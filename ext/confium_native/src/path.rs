//! Confium::PKI::PathValidator — Ruby surface for `confium_pki::path`.
//!
//! Validates a certificate chain from leaf to trusted root. Checks
//! time validity at each link, basic constraints, and (when a
//! verifier is available) signature validity.

use chrono::Utc;
use confium_pki::{
    cert::Certificate as RustCert,
    path::{validate_path, CertPath},
    result::VerificationResult as PathVerificationResult,
};
use magnus::{function, method, prelude::*, DataTypeFunctions, Error, Module, Ruby, TypedData, Value};

/// Wraps a confium_pki::path::VerificationResult.
#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::PKI::PathValidationResult", size)]
pub struct PathResult {
    pub inner: PathVerificationResult,
}

impl PathResult {
    fn valid(&self) -> bool {
        self.inner.valid
    }

    fn checks_json(&self) -> String {
        let entries: Vec<String> = self
            .inner
            .checks
            .iter()
            .map(|c| format!("{:?}", c))
            .collect();
        format!("[{}]", entries.join(","))
    }

    fn check_count(&self) -> usize {
        self.inner.checks.len()
    }
}

/// Validate a certificate path (leaf -> intermediates -> root).
///
/// Ruby signature:
///   Confium::PKI::PathValidator.validate(
///     leaf: cert, intermediates: [cert, ...], root: cert, now: iso8601
///   )
///
/// All cert arguments are Confium::PKI::Certificate instances.
/// Returns a Confium::PKI::PathValidationResult.
fn validate(args: &[Value]) -> Result<magnus::typed_data::Obj<PathResult>, Error> {
    use magnus::scan_args;
    let scanned = scan_args::scan_args::<(Value, Value, Value), (Option<String>,), (), (), (), ()>(args)?;
    let leaf_value = scanned.required.0;
    let intermediates_value = scanned.required.1;
    let root_value = scanned.required.2;
    let now_iso8601 = scanned.optional.0;

    let leaf = extract_cert(leaf_value, "leaf")?;
    let root = extract_cert(root_value, "root")?;

    let intermediates = if intermediates_value.is_nil() {
        Vec::new()
    } else {
        let arr = magnus::RArray::try_convert(intermediates_value)
            .map_err(|e| crate::util::arg_error(e.to_string()))?;
        let mut out = Vec::with_capacity(arr.len());
        for v in arr.into_iter() {
            out.push(extract_cert(v, "intermediate")?);
        }
        out
    };

    let now = match now_iso8601 {
        Some(s) => chrono::DateTime::parse_from_rfc3339(&s)
            .map_err(|e| crate::util::arg_error(format!("invalid time: {e}")))?
            .with_timezone(&Utc),
        None => Utc::now(),
    };

    let path = CertPath {
        leaf: &leaf,
        intermediates: intermediates.iter().collect(),
        root: &root,
    };
    let result = validate_path(&path, now);

    let ruby = Ruby::get()
        .map_err(|e| crate::util::runtime(e.to_string()))?;
    Ok(ruby.obj_wrap(PathResult { inner: result }))
}

/// Extract a confium_pki::Certificate from a Ruby Confium::PKI::Certificate
/// instance. The Ruby object wraps an Obj<Certificate> whose inner field
/// holds the RustCert. We re-parse from DER to avoid lifetime issues.
fn extract_cert(value: Value, label: &str) -> Result<RustCert, Error> {
    // The Ruby Certificate object exposes #to_der which returns binary bytes.
    // We re-parse those bytes into a fresh RustCert.
    let der_value: Value = value
        .funcall("to_der", ())
        .map_err(|e| crate::util::parse_error(format!("{label}: cannot get DER: {e}"), "PathValidator.validate", Some("der"), None))?;
    let der = crate::util::bytes_from_value(der_value)?;
    RustCert::from_der(&der)
        .map_err(|e| crate::util::parse_error(format!("{label}: invalid DER: {e}"), "PathValidator.validate", Some("der"), None))
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let pki = parent.define_module("PKI")?;
    let validator = pki.define_module("PathValidator")?;
    validator.define_module_function("validate", function!(validate, -1))?;

    let result_class = pki.define_class("PathValidationResult", ruby.class_object())?;
    result_class.define_method("valid?", method!(PathResult::valid, 0))?;
    result_class.define_method("check_count", method!(PathResult::check_count, 0))?;
    result_class.define_method("checks_json", method!(PathResult::checks_json, 0))?;

    Ok(())
}
