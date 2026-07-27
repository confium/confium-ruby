//! Confium::Transparency — Ruby surface for `confium_transparency`.
//!
//! Exposes:
//!   - `Confium::Transparency::MerkleTree` — append-only Merkle tree with
//!     RFC 6962 inclusion proofs (wraps `confium_transparency::merkle::MerkleTree`).
//!   - `Confium::Transparency::InclusionProof` — proof object with `#verify(root)`.

use confium_transparency::{
    entry::{ArtifactType, MerkleEntry},
    merkle::{Hash, InclusionProof as RustInclusionProof, MerkleTree as RustMerkleTree, Side},
};
use magnus::{
    exception, function, method, prelude::*, typed_data::Obj, DataTypeFunctions, Error, IntoValue,
    Module, Object, RHash, RString, Ruby, TryConvert, TypedData, Value,
};

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Transparency::MerkleTree", size)]
pub struct MerkleTree {
    inner: std::cell::RefCell<RustMerkleTree>,
}

impl MerkleTree {
    fn new() -> Self {
        Self {
            inner: std::cell::RefCell::new(RustMerkleTree::new()),
        }
    }

    fn append(&self, artifact_hash: Value) -> Result<u64, Error> {
        let bytes = bytes_from_value(artifact_hash)?;
        if bytes.len() != 32 {
            return Err(Error::new(
                exception::arg_error(),
                format!("artifact_hash must be exactly 32 bytes, got {}", bytes.len()),
            ));
        }
        let mut artifact_hash = [0u8; 32];
        artifact_hash.copy_from_slice(&bytes);
        let entry = MerkleEntry::new(0, ArtifactType::CertificateIssuance, artifact_hash);
        let seq = self.inner.borrow_mut().append(entry);
        Ok(seq)
    }

    fn len(&self) -> usize {
        self.inner.borrow().len()
    }

    fn is_empty(&self) -> bool {
        self.inner.borrow().is_empty()
    }

    fn root(&self) -> Value {
        let ruby = Ruby::get().expect("Ruby must be available");
        let bytes = self.inner.borrow().root();
        bytes_to_rstring(&ruby, &bytes).as_value()
    }

    fn inclusion_proof(&self, seq: u64) -> Result<Obj<InclusionProofWrap>, Error> {
        let tree = self.inner.borrow();
        let proof = tree
            .inclusion_proof(seq)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let entry = tree
            .entry(seq)
            .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        // Re-derive the leaf hash with the same algorithm the tree uses
        // internally (H(0x01 | entry_hash)).
        let leaf_hash = hash_leaf(entry.entry_hash());
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(ruby.obj_wrap(InclusionProofWrap {
            inner: proof,
            leaf_hash,
        }))
    }
}

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::Transparency::InclusionProof", size)]
pub struct InclusionProofWrap {
    pub inner: RustInclusionProof,
    /// The leaf hash (entry_hash run through the leaf-domain hash) at the
    /// time the proof was generated. Stored alongside the proof so that
    /// `#verify(root)` doesn't need to recompute it (which would require
    /// the original entry, including its timestamp).
    pub leaf_hash: Hash,
}

impl InclusionProofWrap {
    fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    fn steps(&self) -> Result<Value, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        let result = ruby.hash_new();
        for (i, step) in self.inner.steps.iter().enumerate() {
            let step_hash = ruby.hash_new();
            step_hash.aset("sibling", bytes_to_rstring(&ruby, &step.sibling))?;
            step_hash.aset(
                "side",
                match step.side {
                    Side::Left => "left",
                    Side::Right => "right",
                },
            )?;
            result.aset(i, step_hash)?;
        }
        Ok(result.into_value_with(&ruby))
    }

    fn verify(&self, root_bytes: Value) -> Result<bool, Error> {
        let bytes = bytes_from_value(root_bytes)?;
        if bytes.len() != 32 {
            return Err(Error::new(
                exception::arg_error(),
                format!("root must be exactly 32 bytes, got {}", bytes.len()),
            ));
        }
        let mut root: Hash = [0u8; 32];
        root.copy_from_slice(&bytes);
        let mut current = self.leaf_hash;
        for step in &self.inner.steps {
            current = match step.side {
                Side::Left => hash_internal(step.sibling, current),
                Side::Right => hash_internal(current, step.sibling),
            };
        }
        Ok(current == root)
    }
}

fn bytes_from_value(v: Value) -> Result<Vec<u8>, Error> {
    // Accept either a binary String (preferred for byte data) or an Array
    // of small integers (also commonly used in Ruby crypto code).
    if let Ok(s) = RString::try_convert(v) {
        // SAFETY: we treat the string's raw bytes as opaque cryptographic
        // input — we never interpret them as a UTF-8 string. Encoding is
        // irrelevant for hash input.
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

fn hash_leaf(entry_hash: Hash) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(entry_hash);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn hash_internal(left: Hash, right: Hash) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(left);
    h.update(right);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let transparency = parent.define_module("Transparency")?;

    let tree_class = transparency.define_class("MerkleTree", ruby.class_object())?;
    tree_class.define_singleton_method("new", function!(MerkleTree::new, 0))?;
    tree_class.define_method("append", method!(MerkleTree::append, 1))?;
    tree_class.define_method("length", method!(MerkleTree::len, 0))?;
    tree_class.define_method("size", method!(MerkleTree::len, 0))?;
    tree_class.define_method("empty?", method!(MerkleTree::is_empty, 0))?;
    tree_class.define_method("root", method!(MerkleTree::root, 0))?;
    tree_class.define_method("inclusion_proof", method!(MerkleTree::inclusion_proof, 1))?;

    let proof_class = transparency.define_class("InclusionProof", ruby.class_object())?;
    proof_class.define_method("sequence", method!(InclusionProofWrap::sequence, 0))?;
    proof_class.define_method("steps", method!(InclusionProofWrap::steps, 0))?;
    proof_class.define_method("verify", method!(InclusionProofWrap::verify, 1))?;

    Ok(())
}
