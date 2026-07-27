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

use chrono::{DateTime, Utc};
use confium_pki::{
    cert::{Certificate as RustCert, CertificateSigningRequest as RustCsr},
    cms::SignedData as RustSignedData,
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
        let sd: RustSignedData = serde_json::from_str(&json)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(sd),
        }))
    }

    fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(&*self.inner.borrow())
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))
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

fn bytes_from_value(v: Value) -> Result<Vec<u8>, Error> {
    use magnus::RString;
    if let Ok(s) = RString::try_convert(v) {
        return Ok(unsafe { s.as_slice() }.to_vec());
    }
    let arr: Vec<i64> = Vec::<i64>::try_convert(v)?;
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

fn bytes_to_rstring(_ruby: &Ruby, bytes: &[u8]) -> RString {
    let s = RString::buf_new(0);
    s.cat(bytes);
    s
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
    sd_class.define_method("to_json", method!(SignedData::to_json, 0))?;
    sd_class.define_method("signer_count", method!(SignedData::signer_count, 0))?;
    sd_class.define_method("signing_time", method!(SignedData::signing_time_iso8601, 0))?;
    sd_class.define_method("content_type", method!(SignedData::content_type, 0))?;
    sd_class.define_method("content", method!(SignedData::content, 0))?;
    sd_class.define_method("certificate_count", method!(SignedData::certificate_count, 0))?;
    sd_class.define_method("certificate_at", method!(SignedData::certificate_at, 1))?;

    let content_class = cms.define_class("Content", ruby.class_object())?;
    content_class.define_method("bytes", method!(CertWrapper::bytes, 0))?;
    content_class.define_method("length", method!(CertWrapper::length, 0))?;
    content_class.define_method("size", method!(CertWrapper::length, 0))?;

    // Touch RHash to silence dead-code warning from import; the type is
    // used implicitly via Ruby Hash conversion paths.
    let _: Option<RHash> = None;

    Ok(())
}
