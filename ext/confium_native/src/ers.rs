//! Confium::ERS — Evidence Record Syntax (RFC 4998) for long-term archival.

use confium_transparency::ers::{
    build_initial_evidence_record, renew_evidence_record, renewal_count,
    EvidenceRecord, HashAlgorithm,
};
use magnus::{
    exception, function, method, prelude::*, typed_data::Obj,
    DataTypeFunctions, Error, Module, Object, Ruby, TryConvert, TypedData, Value,
};

use crate::util::bytes_from_value;

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::ERS::EvidenceRecord", size)]
pub struct ErsRecord {
    inner: std::cell::RefCell<EvidenceRecord>,
}

impl ErsRecord {
    fn build_initial(args: &[Value]) -> Result<Obj<Self>, Error> {
        let first = args.first().ok_or_else(|| {
            Error::new(exception::arg_error(), "data_hash required")
        })?;
        let data_hash = bytes_from_value(*first)?;
        if data_hash.len() != 32 {
            return Err(Error::new(
                exception::arg_error(),
                format!("data_hash must be 32 bytes, got {}", data_hash.len()),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data_hash);
        let tsa_id: String = match args.get(1) {
            Some(v) => TryConvert::try_convert(*v)?,
            None => String::new(),
        };
        let token_bytes = match args.get(2) {
            Some(v) => bytes_from_value(*v)?,
            None => Vec::new(),
        };
        let record =
            build_initial_evidence_record(hash, HashAlgorithm::Sha256, tsa_id, token_bytes);
        let ruby = Ruby::get()
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(record),
        }))
    }

    fn renew(&self, args: &[Value]) -> Result<Obj<Self>, Error> {
        let first = args.first().ok_or_else(|| {
            Error::new(exception::arg_error(), "new_hash required")
        })?;
        let new_hash_bytes = bytes_from_value(*first)?;
        if new_hash_bytes.len() != 32 {
            return Err(Error::new(
                exception::arg_error(),
                format!("new_hash must be 32 bytes, got {}", new_hash_bytes.len()),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&new_hash_bytes);
        let tsa_id: String = match args.get(1) {
            Some(v) => TryConvert::try_convert(*v)?,
            None => String::new(),
        };
        let token_bytes = match args.get(2) {
            Some(v) => bytes_from_value(*v)?,
            None => Vec::new(),
        };
        let mut cloned = self.inner.borrow().clone();
        renew_evidence_record(&mut cloned, HashAlgorithm::Sha256, hash, tsa_id, token_bytes);
        let ruby = Ruby::get()
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(cloned),
        }))
    }

    fn renewal_count(&self) -> u32 {
        renewal_count(&self.inner.borrow())
    }
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let ers = parent.define_module("ERS")?;
    let cls = ers.define_class("EvidenceRecord", ruby.class_object())?;
    cls.define_singleton_method("build_initial", function!(ErsRecord::build_initial, -1))?;
    cls.define_method("renew", method!(ErsRecord::renew, -1))?;
    cls.define_method("renewal_count", method!(ErsRecord::renewal_count, 0))?;
    Ok(())
}
