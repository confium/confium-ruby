//! Confium::Attributes — Ruby surface for `confium_attributes`.
//!
//! Exposes the predicate DSL + evaluator for threshold-signing attribute
//! policies (e.g., "5-of-9 directors, spanning 3 regions").
//!
//!   - `Confium::Attributes.parse(expr)` — parse a DSL string into a
//!     `Confium::Attributes::Predicate`.
//!   - `Confium::Attributes::Predicate#satisfied_by?(signers)` — evaluate
//!     against a list of `Confium::Attributes::Signer`.
//!   - `Confium::Attributes::Signer` — a signer's attribute map, with
//!     `#add(key, value)`, `#has?(key)`, `#values(key)`.

use confium_attributes::{evaluate, parse as dsl_parse, Predicate, SignerAttributes};
use magnus::{
    exception, function, method, typed_data::Obj, DataTypeFunctions, Error, Module,
    Object, Ruby, TryConvert, TypedData, Value,
};

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Attributes::Predicate", size)]
pub struct PredicateWrap {
    pub inner: Predicate,
}

impl PredicateWrap {
    fn satisfied_by(&self, signers_value: Value) -> Result<bool, Error> {
        let arr = magnus::RArray::try_convert(signers_value)?;
        let mut owned: Vec<SignerAttributes> = Vec::with_capacity(arr.len());
        for v in arr.each() {
            let signer_wrap = Obj::<SignerWrap>::try_convert(v?)?;
            owned.push(signer_wrap.inner.borrow().clone());
        }
        let refs: Vec<&SignerAttributes> = owned.iter().collect();
        Ok(evaluate(&self.inner, &refs))
    }
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Attributes::Signer", size)]
pub struct SignerWrap {
    pub inner: std::cell::RefCell<SignerAttributes>,
}

impl SignerWrap {
    fn new() -> Self {
        Self {
            inner: std::cell::RefCell::new(SignerAttributes::new()),
        }
    }

    fn add(&self, key: String, value: String) {
        self.inner.borrow_mut().add(key, value);
    }

    fn has(&self, key: String) -> bool {
        self.inner.borrow().has(&key)
    }

    fn values(&self, key: String) -> Vec<String> {
        self.inner.borrow().values(&key)
    }
}

fn parse(expr: String) -> Result<Obj<PredicateWrap>, Error> {
    let predicate = dsl_parse(&expr)
        .map_err(|e| crate::util::parse_error(e.to_string(), "Attributes.parse", Some("dsl"), None))?;
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    Ok(ruby.obj_wrap(PredicateWrap { inner: predicate }))
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let attributes = parent.define_module("Attributes")?;
    attributes.define_module_function("parse", function!(parse, 1))?;

    let pred_class = attributes.define_class("Predicate", ruby.class_object())?;
    pred_class.define_method(
        "satisfied_by?",
        method!(PredicateWrap::satisfied_by, 1),
    )?;

    let signer_class = attributes.define_class("Signer", ruby.class_object())?;
    signer_class.define_singleton_method("new", function!(SignerWrap::new, 0))?;
    signer_class.define_method("add", method!(SignerWrap::add, 2))?;
    signer_class.define_method("has?", method!(SignerWrap::has, 1))?;
    signer_class.define_method("values", method!(SignerWrap::values, 1))?;

    Ok(())
}
