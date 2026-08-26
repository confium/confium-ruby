//! Confium::Store — Ruby surface for `confium_store`.
//!
//! `Confium::Store::Keystore` opens a keystore by backend wire name
//! (`"memory"`, plus the remote-holding backends when the extension is
//! built with their features) and exposes the remote-sign path added
//! by the sign-with-handle contract:
//!
//!   ks = Confium::Store::Keystore.new("memory")
//!   ks.sign(key_id, algorithm, message)  # => binary String
//!
//! Local backends raise for `#sign` — remote signing is implemented by
//! the cloud KMS backends (`aws-kms`, `gcp-kms`, `azure-keyvault`),
//! which source builds opt into via cargo features.

use confium_store::Keystore as RustKeystore;
use magnus::{
    function, method, prelude::*, DataTypeFunctions, Error, Module, RHash, Ruby, TryConvert,
    TypedData, Value,
};

use crate::util::{bytes_from_value, bytes_to_rstring, confium_error, new_details};

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Store::Keystore", size)]
pub struct Keystore {
    inner: std::cell::RefCell<RustKeystore>,
}

fn store_error(e: confium_store::error::Error, operation: &str) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(magnus::exception::runtime_error(), e.to_string()),
    };
    let details = new_details(&ruby);
    let _ = details.aset("operation", operation);
    match &e {
        confium_store::error::Error::NotImplemented { what } => {
            let _ = details.aset("what", *what);
        }
        confium_store::error::Error::UnknownBackend { name } => {
            let _ = details.aset("backend", name.as_str());
        }
        _ => {}
    }
    confium_error(e.to_string(), "Error", details)
}

impl Keystore {
    fn initialize(ruby: &Ruby, args: &[Value]) -> Result<Self, Error> {
        let scanned = magnus::scan_args::scan_args::<(String,), (Option<RHash>,), (), (), (), ()>(args)
            .map_err(|e| crate::util::arg_error(e.to_string()))?;
        let backend = scanned.required.0;
        let mut options = confium_store::backend::Options::new();
        if let Some(hash) = scanned.optional.0 {
            hash.foreach(|k: Value, v: Value| {
                let key: String = <String as TryConvert>::try_convert(k)?;
                let value: String = <String as TryConvert>::try_convert(v)?;
                options.insert(key, value);
                Ok(magnus::r_hash::ForEach::Continue)
            })?;
        }
        let inner =
            RustKeystore::new(&backend, &options).map_err(|e| store_error(e, "Keystore.new"))?;
        let _ = ruby;
        Ok(Self {
            inner: std::cell::RefCell::new(inner),
        })
    }

    /// Sign `message` with the remotely-held key `key_id` under the
    /// provider algorithm name. Returns binary String signature bytes.
    fn sign(&self, args: &[Value]) -> Result<magnus::RString, Error> {
        let scanned = magnus::scan_args::scan_args::<(String, String), (Option<Value>,), (), (), (), ()>(args)
            .map_err(|e| crate::util::arg_error(e.to_string()))?;
        let (key_id, algorithm) = scanned.required;
        let message = scanned
            .optional
            .0
            .ok_or_else(|| crate::util::arg_error("Keystore#sign: message is required"))?;
        let bytes = bytes_from_value(message)?;
        let signature = self
            .inner
            .borrow()
            .sign("confium", "ruby", &key_id, &algorithm, &bytes)
            .map_err(|e| store_error(e, "Keystore#sign"))?;
        Ok(bytes_to_rstring(
            &Ruby::get().map_err(|e| crate::util::runtime(e.to_string()))?,
            &signature,
        ))
    }
}

/// The backend wire names registered at link time
/// (`Confium::Store.backends`).
fn backends() -> Result<Vec<String>, Error> {
    Ok(confium_store::backend::iter()
        .map(|b| b.name().to_string())
        .collect())
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let store = parent.define_module("Store")?;
    let class = store.define_class("Keystore", ruby.class_object())?;
    class.define_singleton_method("new", function!(Keystore::initialize, -1))?;
    class.define_method("sign", method!(Keystore::sign, -1))?;
    store.define_module_function("backends", function!(backends, 0))?;
    Ok(())
}
