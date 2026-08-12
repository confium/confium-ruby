//! Confium::Identity + Confium::Config — Ruby surface for the deployment
//! crate's identity + manifest types.
//!
//! Phase 1C-2 scope:
//!   - `Confium::Identity::Actor` — wraps `confium_deployment::identity::ActorIdentity`.
//!   - `Confium::Identity::ACTOR_TYPES` — array of valid actor-type strings.
//!   - `Confium::Config::Manifest` — parse + validate deployment manifest TOML.

use confium_deployment::{
    identity::{ActorIdentity, ActorType},
    manifest::{parse_manifest, Manifest as RustManifest},
    validate::validate_manifest,
};
use crate::util::enforce_size;
use magnus::{exception, function, method, typed_data::Obj, DataTypeFunctions, Error, Module, Object, Ruby, TypedData};

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Identity::Actor", size)]
pub struct Actor {
    pub inner: std::cell::RefCell<ActorIdentity>,
}

impl Actor {
    fn from_json(json: String) -> Result<Obj<Self>, Error> {
        enforce_size(json.len())?;
        let actor: ActorIdentity = serde_json::from_str(&json)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(actor),
        }))
    }

    fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(&*self.inner.borrow())
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))
    }

    fn actor_id(&self) -> String {
        self.inner.borrow().actor_id.clone()
    }

    fn actor_type(&self) -> String {
        actor_type_str(self.inner.borrow().actor_type).to_string()
    }

    fn quorum_id(&self) -> Option<String> {
        self.inner.borrow().quorum_id.clone()
    }

    fn registered_at_iso8601(&self) -> String {
        self.inner.borrow().registered_at.to_rfc3339()
    }

    fn expires_at_iso8601(&self) -> Option<String> {
        self.inner.borrow().expires_at.map(|t| t.to_rfc3339())
    }

    fn certificate_count(&self) -> usize {
        self.inner.borrow().certificate_chain_der.len()
    }
}

fn actor_type_str(t: ActorType) -> &'static str {
    match t {
        ActorType::Manufacturer => "manufacturer",
        ActorType::TestingLab => "testing_lab",
        ActorType::IssuingAuthorityOfficer => "issuing_authority_officer",
        ActorType::BimlDirector => "biml_director",
        ActorType::QuorumCoordinator => "quorum_coordinator",
        ActorType::Verifier => "verifier",
    }
}

fn actor_types() -> Vec<&'static str> {
    vec![
        actor_type_str(ActorType::Manufacturer),
        actor_type_str(ActorType::TestingLab),
        actor_type_str(ActorType::IssuingAuthorityOfficer),
        actor_type_str(ActorType::BimlDirector),
        actor_type_str(ActorType::QuorumCoordinator),
        actor_type_str(ActorType::Verifier),
    ]
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Config::Manifest", size)]
pub struct Manifest {
    pub inner: std::cell::RefCell<RustManifest>,
}

impl Manifest {
    fn from_toml(toml_str: String) -> Result<Obj<Self>, Error> {
        enforce_size(toml_str.len())?;
        let manifest = parse_manifest(&toml_str)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(Self {
            inner: std::cell::RefCell::new(manifest),
        }))
    }

    fn deployment_name(&self) -> String {
        self.inner.borrow().deployment.name.clone()
    }

    fn operator(&self) -> String {
        self.inner.borrow().deployment.operator.clone()
    }

    fn manifest_version(&self) -> u32 {
        self.inner.borrow().deployment.manifest_version
    }

    fn tier_count(&self) -> usize {
        self.inner.borrow().tiers.len()
    }

    fn tier_name_at(&self, index: usize) -> Result<String, Error> {
        self.inner
            .borrow()
            .tiers
            .get(index)
            .map(|t| t.name.clone())
            .ok_or_else(|| {
                Error::new(
                    exception::index_error(),
                    format!("tier index {index} out of range"),
                )
            })
    }

    fn quorum_count(&self) -> usize {
        self.inner.borrow().quorums.len()
    }

    fn validate(&self) -> Result<Vec<String>, Error> {
        let m = self.inner.borrow();
        let report = validate_manifest(&m);
        Ok(report.errors)
    }

    fn is_valid(&self) -> Result<bool, Error> {
        let m = self.inner.borrow();
        let report = validate_manifest(&m);
        Ok(report.errors.is_empty())
    }
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let identity = parent.define_module("Identity")?;
    identity.define_module_function("actor_types", function!(actor_types, 0))?;
    let actor_class = identity.define_class("Actor", ruby.class_object())?;
    actor_class.define_singleton_method("from_json", function!(Actor::from_json, 1))?;
    actor_class.define_method("to_json", method!(Actor::to_json, 0))?;
    actor_class.define_method("actor_id", method!(Actor::actor_id, 0))?;
    actor_class.define_method("actor_type", method!(Actor::actor_type, 0))?;
    actor_class.define_method("quorum_id", method!(Actor::quorum_id, 0))?;
    actor_class.define_method("registered_at", method!(Actor::registered_at_iso8601, 0))?;
    actor_class.define_method("expires_at", method!(Actor::expires_at_iso8601, 0))?;
    actor_class.define_method("certificate_count", method!(Actor::certificate_count, 0))?;

    let config = parent.define_module("Config")?;
    let manifest_class = config.define_class("Manifest", ruby.class_object())?;
    manifest_class.define_singleton_method("from_toml", function!(Manifest::from_toml, 1))?;
    manifest_class.define_method("deployment_name", method!(Manifest::deployment_name, 0))?;
    manifest_class.define_method("operator", method!(Manifest::operator, 0))?;
    manifest_class.define_method("manifest_version", method!(Manifest::manifest_version, 0))?;
    manifest_class.define_method("tier_count", method!(Manifest::tier_count, 0))?;
    manifest_class.define_method("tier_name_at", method!(Manifest::tier_name_at, 1))?;
    manifest_class.define_method("quorum_count", method!(Manifest::quorum_count, 0))?;
    manifest_class.define_method("validate", method!(Manifest::validate, 0))?;
    manifest_class.define_method("valid?", method!(Manifest::is_valid, 0))?;

    Ok(())
}
