//! Confium::Transparency::OTS — OpenTimestamps calendar client.
//!
//! Binds confium-transparency's real wire-protocol client (0.9):
//! `stamp` POSTs the 32-byte digest to a calendar server and parses
//! the returned partial proof (op stream + pending attestation);
//! `upgrade` fetches a more complete proof; `verify` replays the op
//! tree from the digest and classifies the attestations. Network
//! errors surface as Ruby exceptions — there is no silent nil.

use std::cell::RefCell;

use confium_transparency::ots::OtsClient;
use confium_transparency::ots::wire;
use magnus::prelude::*;
use magnus::Error;
use magnus::RHash;
use magnus::RString;
use magnus::Ruby;
use magnus::TypedData;
use magnus::DataTypeFunctions;

/// An OTS proof: the raw .ots file bytes plus the digest it anchors.
#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Transparency::OTS::Proof", size)]
pub struct OtsProof {
    digest: Vec<u8>,
    bytes: Vec<u8>,
}

fn digest_arg_error() -> Error {
    Error::new(magnus::exception::arg_error(), "digest must be exactly 32 bytes")
}

impl OtsProof {
    fn initialize(_ruby: &Ruby, digest: RString, bytes: RString) -> Result<Self, Error> {
        let digest = digest.to_bytes().to_vec();
        if digest.len() != 32 {
            return Err(digest_arg_error());
        }
        Ok(Self {
            digest,
            bytes: bytes.to_bytes().to_vec(),
        })
    }

    fn digest(&self) -> RString {
        RString::from_slice(&self.digest)
    }

    fn to_bytes(&self) -> RString {
        RString::from_slice(&self.bytes)
    }

    /// Replay the proof tree and classify attestations. Returns a Hash:
    /// { pending: [uri, ...], bitcoin: [height, ...],
    ///   litecoin: [height, ...], anchored: bool }
    fn verify(&self) -> Result<RHash, Error> {
        let ruby = Ruby::get().map_err(|_| Error::new(magnus::exception::runtime_error(), "not on Ruby thread"))?;
        let file = wire::parse(&self.digest, &self.bytes)
            .map_err(|e| Error::new(parse_error_class(&ruby), format!("invalid OTS proof: {e}")))?;
        let summary = wire::verify(&file)
            .map_err(|e| Error::new(ruby.exception_runtime_error(), format!("replay failed: {e}")))?;

        let out = RHash::new();
        let pending: Vec<String> = summary
            .pending
            .iter()
            .map(|(_, uri)| uri.clone())
            .collect();
        out.aset(
            "pending",
            ruby.into_value(ruby.ary_from_vec(pending)),
        )?;
        let bitcoin: Vec<i64> = summary.bitcoin.iter().map(|(_, h)| i64::from(*h)).collect();
        out.aset(
            "bitcoin",
            ruby.into_value(ruby.ary_from_vec(bitcoin)),
        )?;
        let litecoin: Vec<i64> = summary.litecoin.iter().map(|(_, h)| i64::from(*h)).collect();
        out.aset(
            "litecoin",
            ruby.into_value(ruby.ary_from_vec(litecoin)),
        )?;
        // Bitcoin/Litecoin attestations are on-chain anchors; pending
        // means recorded at a calendar awaiting confirmation.
        let anchored = !summary.bitcoin.is_empty() || !summary.litecoin.is_empty();
        out.aset("anchored", ruby.into_value(anchored))?;
        Ok(out)
    }
}

/// A calendar client bound to a server pool.
#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Transparency::OTS::Client", size)]
pub struct Client {
    inner: RefCell<OtsClient>,
}

impl Client {
    fn initialize(_ruby: &Ruby, servers: Vec<String>) -> Result<Self, Error> {
        Ok(Self {
            inner: RefCell::new(OtsClient::with_servers(servers)),
        })
    }

    /// Submit a 32-byte digest to the calendar pool. Returns a Proof
    /// carrying the returned partial proof (pending attestation).
    fn stamp(&self, digest: RString) -> Result<OtsProof, Error> {
        let ruby = Ruby::get().map_err(|_| Error::new(magnus::exception::runtime_error(), "not on Ruby thread"))?;
        let digest = digest.to_bytes().to_vec();
        if digest.len() != 32 {
            return Err(digest_arg_error());
        }
        let arr: [u8; 32] = digest.as_slice().try_into().map_err(|_| digest_arg_error())?;
        let mut inner = self.inner.borrow_mut();
        // Release the GVL for the network round trip: calendars take
        // seconds-to-tens-of-seconds, and holding the VM would freeze
        // every Ruby thread (including any in-process peer).
        let stamped = unsafe {
            crate::gvl::without_gvl(|| inner.stamp_wire(arr))
        };
        let file = stamped
            .map_err(|e| Error::new(ruby.exception_io_error(), format!("calendar stamp failed: {e}")))?;
        let bytes = wire::serialize(&file).map_err(|e| {
            Error::new(
                ruby.exception_runtime_error(),
                format!("calendar returned an unserializable proof: {e}"),
            )
        })?;
        Ok(OtsProof { digest, bytes })
    }

    /// Fetch a more complete proof for a pending attestation. Returns
    /// the upgraded Proof (replaces the pending one).
    fn upgrade(&self, proof: &OtsProof) -> Result<OtsProof, Error> {
        let ruby = Ruby::get().map_err(|_| Error::new(magnus::exception::runtime_error(), "not on Ruby thread"))?;
        let file = wire::parse(&proof.digest, &proof.bytes)
            .map_err(|e| Error::new(parse_error_class(&ruby), format!("invalid OTS proof: {e}")))?;
        let mut inner = self.inner.borrow_mut();
        let upgraded_result = unsafe { crate::gvl::without_gvl(|| inner.upgrade(&file)) };
        let upgraded = upgraded_result
            .map_err(|e| Error::new(ruby.exception_io_error(), format!("calendar upgrade failed: {e}")))?;
        let bytes = wire::serialize(&upgraded).map_err(|e| {
            Error::new(
                ruby.exception_runtime_error(),
                format!("calendar returned an unserializable proof: {e}"),
            )
        })?;
        Ok(OtsProof {
            digest: proof.digest.clone(),
            bytes,
        })
    }
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let ots = parent.define_module("OTS")?;
    let parse_error = ots.define_error("ParseError", ruby.exception_standard_error())?;
    ots.const_set("PARSE_ERROR", parse_error)?;

    let proof = ots.define_class("Proof", ruby.class_object())?;
    proof.define_singleton_method("new", magnus::function!(OtsProof::initialize, 2))?;
    proof.define_method("digest", magnus::method!(OtsProof::digest, 0))?;
    proof.define_method("to_bytes", magnus::method!(OtsProof::to_bytes, 0))?;
    proof.define_method("verify", magnus::method!(OtsProof::verify, 0))?;

    let client = ots.define_class("Client", ruby.class_object())?;
    client.define_singleton_method("new", magnus::function!(Client::initialize, 1))?;
    client.define_method("stamp", magnus::method!(Client::stamp, 1))?;
    client.define_method("upgrade", magnus::method!(Client::upgrade, 1))?;

    Ok(())
}

fn parse_error_class(ruby: &Ruby) -> magnus::ExceptionClass {
    ruby
        .class_object()
        .const_get::<_, magnus::RModule>("Confium")
        .and_then(|m| m.const_get::<_, magnus::RModule>("Transparency"))
        .and_then(|m| m.const_get::<_, magnus::RModule>("OTS"))
        .and_then(|m| m.const_get::<_, magnus::ExceptionClass>("PARSE_ERROR"))
        .unwrap_or_else(|_| ruby.exception_runtime_error())
}
