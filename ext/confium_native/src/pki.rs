//! Confium::PKI — Ruby surface for `confium_pki`.
//!
//! Phase 1C scope:
//!   - `Confium::PKI::Certificate` — parse + inspect X.509 v3 certificates.
//!   - `Confium::PKI::CSR` — parse + serialize PKCS#10 certificate signing
//!     requests.
//!   - `Confium::PKI::CMS::SignedData` — JSON-backed CMS SignedData model.
//!
//! Verify + parse only on the Ruby side for v0.1.0; full certificate
//! *building* + signing lands in a follow-up once the Rust builder API
//! stabilizes (currently `confium_pki::cert::builder` is private).

use crate::util::{bytes_from_value, bytes_to_rstring, enforce_size};
use chrono::{DateTime, Utc};
use confium_pki::{
    cert::{Certificate as RustCert, CertificateSigningRequest as RustCsr},
    cms::{
        build_detached_signature, encode_signed_data_der, SignedData as RustSignedData,
    },
    xmldsig::{canonicalize, canonicalize_exclusive},
};
use magnus::{
    exception, function, method, prelude::*, typed_data::Obj, DataTypeFunctions, Error, Module,
    Object, RHash, RString, Ruby, TryConvert, TypedData, Value,
};

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::PKI::Certificate", size)]
pub struct Certificate {
    inner: RustCert,
}

impl Certificate {
    fn from_der(bytes: Value) -> Result<Obj<Self>, Error> {
        let der = bytes_from_value(bytes)?;
        let cert = RustCert::from_der(&der)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self { inner: cert }))
    }

    fn from_pem(pem: String) -> Result<Obj<Self>, Error> {
        enforce_size(pem.len())?;
        let cert = RustCert::from_pem(&pem)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self { inner: cert }))
    }

    fn to_der(&self) -> Result<RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(bytes_to_rstring(&ruby, &self.inner.to_der()))
    }

    fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    fn fingerprint_sha256(&self) -> String {
        self.inner.fingerprint_sha256()
    }

    fn serial_hex(&self) -> String {
        let bytes = self.inner.serial_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }

    fn not_before_iso8601(&self) -> String {
        let dt: DateTime<Utc> = self.inner.not_before_chrono();
        dt.to_rfc3339()
    }

    fn not_after_iso8601(&self) -> String {
        let dt: DateTime<Utc> = self.inner.not_after_chrono();
        dt.to_rfc3339()
    }

    fn valid_at(&self, iso8601: String) -> Result<bool, Error> {
        let now = DateTime::parse_from_rfc3339(&iso8601)
            .map_err(|e| Error::new(exception::arg_error(), format!("invalid ISO8601 time: {e}")))?
            .with_timezone(&Utc);
        Ok(self.inner.is_within_validity(now))
    }

    fn public_key_bytes(&self) -> Result<RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(bytes_to_rstring(&ruby, self.inner.public_key_bytes()))
    }
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::PKI::CSR", size)]
pub struct Csr {
    inner: RustCsr,
}

impl Csr {
    fn from_der(bytes: Value) -> Result<Obj<Self>, Error> {
        let der = bytes_from_value(bytes)?;
        let csr = RustCsr::from_der(&der)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self { inner: csr }))
    }

    fn from_pem(pem: String) -> Result<Obj<Self>, Error> {
        enforce_size(pem.len())?;
        let csr = RustCsr::from_pem(&pem)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self { inner: csr }))
    }

    fn to_der(&self) -> Result<RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(bytes_to_rstring(&ruby, &self.inner.to_der()))
    }

    fn to_pem(&self) -> String {
        self.inner.to_pem()
    }
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::PKI::CMS::SignedData", size)]
pub struct SignedData {
    inner: std::cell::RefCell<RustSignedData>,
}

impl SignedData {
    fn from_json(json: String) -> Result<Obj<Self>, Error> {
        enforce_size(json.len())?;
        let sd: RustSignedData = serde_json::from_str(&json)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(sd),
        }))
    }

    /// Build a detached CMS SignedData with one signer.
    ///
    /// Ruby signature:
    ///   SignedData.build_detached(signature, algorithm, certificates)
    ///
    /// - `signature`     — bytes (pre-computed signature over the payload)
    /// - `algorithm`     — string (signature algorithm OID)
    /// - `certificates`  — array of strings (DER cert bytes per signer)
    ///
    /// The caller signs the payload separately (typically via
    /// `Confium::Composite.sign_ed25519` or `Confium::TC::FrostP256.sign`)
    /// and passes the resulting signature bytes here. The first
    /// certificate's first 20 bytes become the SubjectKeyIdentifier per
    /// RFC 5652 §5.3.
    fn build_detached(
        signature: Value,
        algorithm: String,
        certificates: Value,
    ) -> Result<Obj<Self>, Error> {
        if signature.is_nil() {
            return Err(Error::new(
                exception::arg_error(),
                "signature is required",
            ));
        }
        if certificates.is_nil() {
            return Err(Error::new(
                exception::arg_error(),
                "certificates is required",
            ));
        }

        let sig_bytes = bytes_from_value(signature)?;
        enforce_size(sig_bytes.len())?;

        let certs_array: magnus::RArray = magnus::RArray::try_convert(certificates)?;
        let mut cert_ders = Vec::with_capacity(certs_array.len());
        for item in certs_array.each() {
            let v = item?;
            let der = bytes_from_value(v)?;
            enforce_size(der.len())?;
            cert_ders.push(der);
        }

        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let sd = build_detached_signature(Vec::new(), algorithm, sig_bytes, cert_ders)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(sd),
        }))
    }

    fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(&*self.inner.borrow())
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))
    }

    /// Encode this SignedData as DER bytes (RFC 5652 ContentInfo).
    ///
    /// The output is parseable by `openssl cms` / `openssl pkcs7` and
    /// any standards-compliant CMS consumer.
    fn to_der(&self) -> Result<RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let der = encode_signed_data_der(&self.inner.borrow())
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(bytes_to_rstring(&ruby, &der))
    }

    fn signer_count(&self) -> usize {
        self.inner.borrow().signer_count()
    }

    fn signing_time_iso8601(&self) -> Option<String> {
        self.inner.borrow().signing_time().map(|t| t.to_rfc3339())
    }

    fn content_type(&self) -> String {
        self.inner.borrow().encap_content_info.content_type.clone()
    }

    fn content(&self) -> Result<Option<Obj<CertWrapper>>, Error> {
        // Wrap the optional content bytes in a small value object so Ruby
        // can ask `.present?` / `.bytes` without juggling nil-vs-string.
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        match &self.inner.borrow().encap_content_info.content {
            Some(bytes) => {
                let wrapper = CertWrapper {
                    bytes: bytes.clone(),
                };
                Ok(Some(ruby.obj_wrap(wrapper)))
            }
            None => Ok(None),
        }
    }

    fn certificate_count(&self) -> usize {
        self.inner.borrow().certificates.len()
    }

    fn certificate_at(&self, index: usize) -> Result<RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        self.inner
            .borrow()
            .certificates
            .get(index)
            .map(|c| bytes_to_rstring(&ruby, c))
            .ok_or_else(|| {
                Error::new(
                    exception::index_error(),
                    format!("certificate index {index} out of range"),
                )
            })
    }

    /// Verify every signer's signature. Dispatches by signature algorithm
    /// OID found in each signer_info:
    ///   - 1.3.101.112 (Ed25519)        -> ed25519-dalek verifier
    ///   - 1.2.840.10045.4.3.2 (ECDSA-P256-SHA256) -> p256 verifier
    ///
    /// Simplification: assumes the first certificate in `certificates` is
    /// the signing cert for every signer. Production code should resolve
    /// by issuer+serial or subjectKeyIdentifier.
    fn verify_signatures(&self, payload: Value) -> Result<Obj<CmsVerificationResult>, Error> {
        use confium_pki::cms::verify_signed_data;
        let payload_bytes = bytes_from_value(payload)?;
        let sd = self.inner.borrow();
        let result = verify_signed_data(&sd, &payload_bytes, |_signer_index, pubkey_der, signed_bytes, signature| {
            // Inspect the algorithm via the first signer_info's signature_algorithm OID.
            let signer = sd.signer_infos.first().ok_or("no signer infos")?;
            let oid = &signer.signature_algorithm.oid;
            // Strip the DER-encoded public key down to raw key bytes.
            // For Ed25519 SPKI, the last 32 bytes are the raw key.
            // For ECDSA-P256 SPKI, the last 65 bytes are SEC1 uncompressed.
            if oid == "1.3.101.112" {
                // Ed25519.
                if pubkey_der.len() < 32 {
                    return Err("Ed25519 public key too short".into());
                }
                let pk_bytes = &pubkey_der[pubkey_der.len() - 32..];
                confium_composite::ed25519_verifier("Ed25519", pk_bytes, signed_bytes, signature)
            } else if oid == "1.2.840.10045.4.3.2" {
                // ECDSA-P256-SHA256.
                if pubkey_der.len() < 65 {
                    return Err("ECDSA-P256 public key too short".into());
                }
                let pk_bytes = &pubkey_der[pubkey_der.len() - 65..];
                // confium_composite doesn't have a p256 verifier; reuse the
                // one defined inline in composite.rs (re-implemented here).
                p256_verify_inline(pk_bytes, signed_bytes, signature)
            } else {
                Err(format!("unsupported signature algorithm OID: {oid}"))
            }
        }).map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(CmsVerificationResult { inner: result }))
    }
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::PKI::CMS::VerificationResult", size)]
pub struct CmsVerificationResult {
    pub inner: confium_pki::cms::VerificationResult,
}

impl CmsVerificationResult {
    fn all_verified(&self) -> bool {
        self.inner.all_verified
    }

    fn signer_count(&self) -> usize {
        self.inner.per_signer.len()
    }

    fn per_signer_json(&self) -> String {
        // Build JSON manually — the upstream SignerVerification doesn't
        // derive Serialize.
        let entries: Vec<String> = self.inner.per_signer.iter().map(|s| {
            let err = match &s.error {
                Some(e) => format!(",\"error\":{}", serde_json::to_string(e).unwrap_or_else(|_| "null".into())),
                None => String::new(),
            };
            format!(
                "{{\"signer_index\":{},\"verified\":{}{}}}",
                s.signer_index, s.verified, err
            )
        }).collect();
        format!("[{}]", entries.join(","))
    }
}

fn p256_verify_inline(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| format!("invalid DER signature: {e}"))?;
    vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::PKI::CMS::Content", size)]
pub struct CertWrapper {
    pub bytes: Vec<u8>,
}

impl CertWrapper {
    fn bytes(&self) -> Result<RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(bytes_to_rstring(&ruby, &self.bytes))
    }

    fn length(&self) -> usize {
        self.bytes.len()
    }
}

// ===== XMLDSig canonicalization (RFC 3076 + Exclusive C14N) =====

fn xmldsig_canonicalize(xml: String) -> Result<String, Error> {
    enforce_size(xml.len())?;
    canonicalize(&xml).map_err(|e| Error::new(exception::runtime_error(), e.to_string()))
}

fn xmldsig_canonicalize_exclusive(xml: String) -> Result<String, Error> {
    enforce_size(xml.len())?;
    canonicalize_exclusive(&xml).map_err(|e| Error::new(exception::runtime_error(), e.to_string()))
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let pki = parent.define_module("PKI")?;

    // Certificate
    let cert_class = pki.define_class("Certificate", ruby.class_object())?;
    cert_class.define_singleton_method("from_der", function!(Certificate::from_der, 1))?;
    cert_class.define_singleton_method("from_pem", function!(Certificate::from_pem, 1))?;
    cert_class.define_method("to_der", method!(Certificate::to_der, 0))?;
    cert_class.define_method("to_pem", method!(Certificate::to_pem, 0))?;
    cert_class.define_method("fingerprint_sha256", method!(Certificate::fingerprint_sha256, 0))?;
    cert_class.define_method("serial_hex", method!(Certificate::serial_hex, 0))?;
    cert_class.define_method("not_before", method!(Certificate::not_before_iso8601, 0))?;
    cert_class.define_method("not_after", method!(Certificate::not_after_iso8601, 0))?;
    cert_class.define_method("valid_at?", method!(Certificate::valid_at, 1))?;
    cert_class.define_method("public_key_bytes", method!(Certificate::public_key_bytes, 0))?;

    // CSR
    let csr_class = pki.define_class("CSR", ruby.class_object())?;
    csr_class.define_singleton_method("from_der", function!(Csr::from_der, 1))?;
    csr_class.define_singleton_method("from_pem", function!(Csr::from_pem, 1))?;
    csr_class.define_method("to_der", method!(Csr::to_der, 0))?;
    csr_class.define_method("to_pem", method!(Csr::to_pem, 0))?;

    // CMS submodule
    let cms = pki.define_module("CMS")?;
    let sd_class = cms.define_class("SignedData", ruby.class_object())?;
    sd_class.define_singleton_method("from_json", function!(SignedData::from_json, 1))?;
    sd_class.define_singleton_method("build_detached", function!(SignedData::build_detached, 3))?;
    sd_class.define_method("to_json", method!(SignedData::to_json, 0))?;
    sd_class.define_method("to_der", method!(SignedData::to_der, 0))?;
    sd_class.define_method("signer_count", method!(SignedData::signer_count, 0))?;
    sd_class.define_method("signing_time", method!(SignedData::signing_time_iso8601, 0))?;
    sd_class.define_method("content_type", method!(SignedData::content_type, 0))?;
    sd_class.define_method("content", method!(SignedData::content, 0))?;
    sd_class.define_method("certificate_count", method!(SignedData::certificate_count, 0))?;
    sd_class.define_method("certificate_at", method!(SignedData::certificate_at, 1))?;
    sd_class.define_method("verify_signatures", method!(SignedData::verify_signatures, 1))?;

    let verify_class = cms.define_class("VerificationResult", ruby.class_object())?;
    verify_class.define_method("all_verified?", method!(CmsVerificationResult::all_verified, 0))?;
    verify_class.define_method("signer_count", method!(CmsVerificationResult::signer_count, 0))?;
    verify_class.define_method("per_signer_json", method!(CmsVerificationResult::per_signer_json, 0))?;

    let content_class = cms.define_class("Content", ruby.class_object())?;
    content_class.define_method("bytes", method!(CertWrapper::bytes, 0))?;
    content_class.define_method("length", method!(CertWrapper::length, 0))?;
    content_class.define_method("size", method!(CertWrapper::length, 0))?;

    // XMLDSig submodule — Canonical XML (RFC 3076) and Exclusive C14N.
    let xmldsig = pki.define_module("XMLDSig")?;
    xmldsig.define_module_function("canonicalize", function!(xmldsig_canonicalize, 1))?;
    xmldsig.define_module_function("canonicalize_exclusive", function!(xmldsig_canonicalize_exclusive, 1))?;

    // Touch RHash to silence dead-code warning from import; the type is
    // used implicitly via Ruby Hash conversion paths.
    let _: Option<RHash> = None;

    Ok(())
}
