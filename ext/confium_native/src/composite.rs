//! Confium::Composite — Ruby surface for `confium_composite`.
//!
//! Exposes PQ-migration composite signatures (Ed25519 + ML-DSA-65 etc.).
//!
//!   - `Confium::Composite::Signature` — a composite signature with multiple
//!     algorithm components over the same message. Wraps
//!     `confium_composite::CompositeSignature`.
//!   - `Confium::Composite.sign_ed25519(private_key_bytes, message)` —
//!     helper that builds a real Ed25519 component using
//!     `ed25519_dalek::SigningKey`.
//!   - `Confium::Composite::VerificationResult` — result of `#verify(message)`,
//!     with `#all_verified?` and `#per_component` accessors.

use confium_composite::{CompositeSignature, ComponentSignature, VerificationResult};
use ed25519_dalek::{Signer, SigningKey};
use magnus::{
    exception, function, method, prelude::*, typed_data::Obj, DataTypeFunctions, Error, IntoValue,
    Module, Object, RHash, Ruby, TryConvert, TypedData, Value,
};
use crate::util::{bytes_from_value, bytes_to_rstring};
use rand_core::OsRng;

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Composite::Signature", size)]
pub struct CompositeSig {
    inner: std::cell::RefCell<CompositeSignature>,
}

impl CompositeSig {
    fn new(components: Value) -> Result<Self, Error> {
        let comps = parse_components(components)?;
        Ok(Self {
            inner: std::cell::RefCell::new(CompositeSignature::new(comps)),
        })
    }

    fn component_count(&self) -> usize {
        self.inner.borrow().component_count()
    }

    fn algorithms(&self) -> Vec<String> {
        self.inner
            .borrow()
            .algorithms()
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn verify(&self, message: Value) -> Result<Obj<VerificationResultWrap>, Error> {
        let msg = bytes_from_value(message)?;
        let result = self
            .inner
            .borrow()
            .verify(&msg, |algorithm, public_key, m, signature| {
                // Built-in verifiers: Ed25519 + ECDSA-P256. Unknown
                // algorithms are reported as failed components.
                if algorithm == confium_composite::ED25519 {
                    confium_composite::ed25519_verifier(algorithm, public_key, m, signature)
                } else if algorithm == "ECDSA-P256" || algorithm == "ECDSA" {
                    p256_verifier(public_key, m, signature)
                } else {
                    Err(format!("unsupported algorithm: {algorithm}"))
                }
            })
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(VerificationResultWrap { inner: result }))
    }
}

/// Verify an ECDSA-P256 signature. `public_key` is the SEC1 uncompressed
/// (65-byte) or compressed (33-byte) verifying key. `signature` is the
/// DER-encoded ECDSA signature. SHA-256 is used as the digest.
fn p256_verifier(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    use p256::ecdsa::{VerifyingKey, Signature};
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| format!("invalid DER signature: {e}"))?;
    use p256::ecdsa::signature::Verifier;
    vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Composite::VerificationResult", size)]
pub struct VerificationResultWrap {
    inner: VerificationResult,
}

impl VerificationResultWrap {
    fn all_verified(&self) -> bool {
        self.inner.all_verified
    }

    fn per_component(&self) -> Result<Value, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let result = ruby.hash_new();
        for c in &self.inner.per_component {
            let entry = ruby.hash_new();
            entry.aset("algorithm", c.algorithm.clone())?;
            entry.aset("verified", c.verified)?;
            if let Some(err) = &c.error {
                entry.aset("error", err.clone())?;
            }
            result.aset(c.index, entry)?;
        }
        Ok(result.into_value_with(&ruby))
    }
}

/// Build a real Ed25519 component signature.
///
/// `Confium::Composite.sign_ed25519(private_key_bytes, message)` returns
/// a Hash with `algorithm`, `public_key`, `signature` keys.
fn sign_ed25519(ruby: &Ruby, private_key: Value, message: Value) -> Result<RHash, Error> {
    let pk_bytes = bytes_from_value(private_key)?;
    let msg = bytes_from_value(message)?;
    if pk_bytes.len() != 32 {
        return Err(Error::new(
            exception::arg_error(),
            format!("Ed25519 private key must be 32 bytes, got {}", pk_bytes.len()),
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let signing = SigningKey::from_bytes(&pk_arr);
    let component = confium_composite::build_ed25519_component(&signing, &msg)
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;

    let result = ruby.hash_new();
    result.aset("algorithm", component.algorithm)?;
    result.aset("public_key", bytes_to_rstring(ruby, &component.public_key))?;
    result.aset("signature", bytes_to_rstring(ruby, &component.signature))?;
    Ok(result)
}

/// Generate a fresh Ed25519 keypair.
///
/// `Confium::Composite.generate_ed25519_keypair` returns `[private_key, public_key]`
/// as binary strings (32 bytes each).
/// Build a real ECDSA-P256 component signature. Useful when the caller
/// holds a P-256 signing key and wants to participate in a composite
/// signature alongside e.g. Ed25519 or ML-DSA-65.
fn sign_p256(ruby: &Ruby, private_key: Value, message: Value) -> Result<RHash, Error> {
    let pk_bytes = bytes_from_value(private_key)?;
    let msg = bytes_from_value(message)?;
    if pk_bytes.len() != 32 {
        return Err(Error::new(
            exception::arg_error(),
            format!("P-256 private key must be 32 bytes, got {}", pk_bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_bytes);
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let signing = SigningKey::from_bytes(&arr.into())
        .map_err(|e| Error::new(exception::arg_error(), format!("invalid P-256 private key: {e}")))?;
    let sig: Signature = signing.try_sign(msg.as_slice()).map_err(|e| {
        Error::new(exception::runtime_error(), format!("sign error: {e}"))
    })?;
    let verifying = signing.verifying_key();
    let verifying_bytes: Vec<u8> = verifying.to_sec1_bytes().to_vec();
    let sig_bytes: Vec<u8> = sig.to_der().to_bytes().to_vec();
    let result = ruby.hash_new();
    result.aset("algorithm", "ECDSA-P256")?;
    result.aset("public_key", bytes_to_rstring(ruby, &verifying_bytes))?;
    result.aset("signature", bytes_to_rstring(ruby, &sig_bytes))?;
    Ok(result)
}

fn generate_ed25519_keypair(ruby: &Ruby) -> Result<RHash, Error> {
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    let result = ruby.hash_new();
    result.aset("private_key", bytes_to_rstring(ruby, &signing.to_bytes()))?;
    result.aset("public_key", bytes_to_rstring(ruby, &verifying.to_bytes()))?;
    Ok(result)
}

fn parse_components(value: Value) -> Result<Vec<ComponentSignature>, Error> {
    let arr = magnus::RArray::try_convert(value)?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr.each() {
        let h: RHash = RHash::try_convert(v?)?;
        let algorithm: String = h.fetch::<_, String>("algorithm")?;
        let public_key: Value = h.fetch::<_, Value>("public_key")?;
        let signature: Value = h.fetch::<_, Value>("signature")?;
        out.push(ComponentSignature {
            algorithm,
            public_key: bytes_from_value(public_key)?,
            signature: bytes_from_value(signature)?,
        });
    }
    Ok(out)
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let composite = parent.define_module("Composite")?;
    composite.define_module_function(
        "sign_ed25519",
        function!(sign_ed25519, 2),
    )?;
    composite.define_module_function(
        "sign_p256",
        function!(sign_p256, 2),
    )?;
    composite.define_module_function(
        "generate_ed25519_keypair",
        function!(generate_ed25519_keypair, 0),
    )?;

    let sig_class = composite.define_class("Signature", ruby.class_object())?;
    sig_class.define_singleton_method("new", function!(CompositeSig::new, 1))?;
    sig_class.define_method("component_count", method!(CompositeSig::component_count, 0))?;
    sig_class.define_method("algorithms", method!(CompositeSig::algorithms, 0))?;
    sig_class.define_method("verify", method!(CompositeSig::verify, 1))?;

    let result_class = composite.define_class("VerificationResult", ruby.class_object())?;
    result_class.define_method("all_verified?", method!(VerificationResultWrap::all_verified, 0))?;
    result_class.define_method("per_component", method!(VerificationResultWrap::per_component, 0))?;

    Ok(())
}
