//! Confium::TC::Cmp20::Mta — the proved MtA sub-protocol binding.
//!
//! Wraps `confium-tc-cmp20`'s `paillier_mta`: the GG18/GG20 §3 +
//! Appendix A multiplicative-to-additive conversion with zero-knowledge
//! range proofs on every ciphertext. `full` runs the whole exchange
//! in-process; `party_i_init` / `party_j_respond` / `party_i_finish`
//! expose the three passes with messages as plain Hashes of hex
//! integers so rounds can be JSON-encoded onto a transport.
//!
//! Trust model: coordinator. The finish step decrypts the response
//! under the RESPONDER's Paillier key — that is the shape the upstream
//! crate implements — so the process calling `party_i_finish` (or
//! `full`) must hold the keypair, exactly like the in-process signing
//! drivers. Splitting the passes across machines needs the upstream
//! per-party state machine; until it exists, these are message-level
//! building blocks under a trusted coordinator.

use confium_tc::paillier::{
    generate_keypair as generate_paillier_keypair, PaillierKeypair, PaillierPrivateKey,
    PaillierPublicKey,
};
use confium_tc_cmp20::mta_proofs::{
    generate_commitment_key, p256_order, CommitmentKey, RangeProof, RespondentProof,
};
use confium_tc_cmp20::paillier_mta::{
    full_mta_proved, party_i_finish_proved, party_i_init_proved, party_j_respond_proved,
    MtaProofError, ProvedMessage1, ProvedMessage2,
};
use magnus::prelude::*;
use magnus::{Error, RHash, RString, Ruby, TryConvert};
use num_bigint::BigUint;
use num_traits::Num;

const ALGORITHM: &str = "CMP20-ECDSA-P256";

fn parse_hex(value: &str, what: &str) -> Result<BigUint, Error> {
    BigUint::from_str_radix(value.trim(), 16)
        .map_err(|_| crate::util::arg_error(format!("{what} must be a hex integer")))
}

fn hex_string(ruby: &Ruby, value: &BigUint) -> RString {
    ruby.str_from_slice(value.to_str_radix(16).as_bytes())
}

fn string_field(hash: &RHash, key: &str) -> Result<String, Error> {
    let value: magnus::Value = hash
        .get(key)
        .ok_or_else(|| crate::util::arg_error(format!("missing field {key:?}")))?;
    String::try_convert(value)
        .map_err(|_| crate::util::arg_error(format!("field {key:?} must be a String")))
}

fn hash_field(hash: &RHash, key: &str) -> Result<RHash, Error> {
    let value: magnus::Value = hash
        .get(key)
        .ok_or_else(|| crate::util::arg_error(format!("missing field {key:?}")))?;
    RHash::try_convert(value)
        .map_err(|_| crate::util::arg_error(format!("field {key:?} must be a Hash")))
}

fn set_hex(ruby: &Ruby, hash: &RHash, key: &str, value: &BigUint) -> Result<(), Error> {
    hash.aset(key, hex_string(ruby, value))
}

fn check_prime_bits(prime_bits: i64) -> Result<u32, Error> {
    if !(64..=8192).contains(&prime_bits) {
        return Err(crate::util::arg_error(format!(
            "prime_bits must be between 64 and 8192, got {prime_bits}"
        )));
    }
    Ok(prime_bits as u32)
}

// ---- key codecs ---------------------------------------------------------

fn public_from_hash(hash: &RHash) -> Result<PaillierPublicKey, Error> {
    Ok(PaillierPublicKey {
        n: parse_hex(&string_field(hash, "n")?, "public key n")?,
        n_squared: parse_hex(&string_field(hash, "n_squared")?, "public key n_squared")?,
        g: parse_hex(&string_field(hash, "g")?, "public key g")?,
    })
}

fn private_from_hash(hash: &RHash) -> Result<PaillierPrivateKey, Error> {
    Ok(PaillierPrivateKey {
        lambda: parse_hex(&string_field(hash, "lambda")?, "private key lambda")?,
        mu: parse_hex(&string_field(hash, "mu")?, "private key mu")?,
    })
}

fn public_to_hash(ruby: &Ruby, public: &PaillierPublicKey) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    set_hex(ruby, &out, "n", &public.n)?;
    set_hex(ruby, &out, "n_squared", &public.n_squared)?;
    set_hex(ruby, &out, "g", &public.g)?;
    Ok(out)
}

fn keypair_to_hash(ruby: &Ruby, kp: &PaillierKeypair) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    out.aset("public", public_to_hash(ruby, &kp.public)?)?;
    let private = ruby.hash_new();
    set_hex(ruby, &private, "lambda", &kp.private.lambda)?;
    set_hex(ruby, &private, "mu", &kp.private.mu)?;
    out.aset("private", private)?;
    Ok(out)
}

fn commitment_key_from_hash(hash: &RHash) -> Result<CommitmentKey, Error> {
    Ok(CommitmentKey {
        n_tilde: parse_hex(&string_field(hash, "n_tilde")?, "commitment key n_tilde")?,
        h1: parse_hex(&string_field(hash, "h1")?, "commitment key h1")?,
        h2: parse_hex(&string_field(hash, "h2")?, "commitment key h2")?,
    })
}

fn commitment_key_to_hash(ruby: &Ruby, ck: &CommitmentKey) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    set_hex(ruby, &out, "n_tilde", &ck.n_tilde)?;
    set_hex(ruby, &out, "h1", &ck.h1)?;
    set_hex(ruby, &out, "h2", &ck.h2)?;
    Ok(out)
}

// ---- message codecs -----------------------------------------------------

fn range_proof_from_hash(hash: &RHash) -> Result<RangeProof, Error> {
    Ok(RangeProof {
        z: parse_hex(&string_field(hash, "z")?, "range proof z")?,
        u: parse_hex(&string_field(hash, "u")?, "range proof u")?,
        w: parse_hex(&string_field(hash, "w")?, "range proof w")?,
        s: parse_hex(&string_field(hash, "s")?, "range proof s")?,
        s1: parse_hex(&string_field(hash, "s1")?, "range proof s1")?,
        s2: parse_hex(&string_field(hash, "s2")?, "range proof s2")?,
    })
}

fn range_proof_to_hash(ruby: &Ruby, proof: &RangeProof) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    set_hex(ruby, &out, "z", &proof.z)?;
    set_hex(ruby, &out, "u", &proof.u)?;
    set_hex(ruby, &out, "w", &proof.w)?;
    set_hex(ruby, &out, "s", &proof.s)?;
    set_hex(ruby, &out, "s1", &proof.s1)?;
    set_hex(ruby, &out, "s2", &proof.s2)?;
    Ok(out)
}

fn respondent_proof_from_hash(hash: &RHash) -> Result<RespondentProof, Error> {
    Ok(RespondentProof {
        z: parse_hex(&string_field(hash, "z")?, "respondent proof z")?,
        z_prime: parse_hex(&string_field(hash, "z_prime")?, "respondent proof z_prime")?,
        t: parse_hex(&string_field(hash, "t")?, "respondent proof t")?,
        v: parse_hex(&string_field(hash, "v")?, "respondent proof v")?,
        w: parse_hex(&string_field(hash, "w")?, "respondent proof w")?,
        s: parse_hex(&string_field(hash, "s")?, "respondent proof s")?,
        s1: parse_hex(&string_field(hash, "s1")?, "respondent proof s1")?,
        s2: parse_hex(&string_field(hash, "s2")?, "respondent proof s2")?,
        t1: parse_hex(&string_field(hash, "t1")?, "respondent proof t1")?,
        t2: parse_hex(&string_field(hash, "t2")?, "respondent proof t2")?,
    })
}

fn respondent_proof_to_hash(ruby: &Ruby, proof: &RespondentProof) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    set_hex(ruby, &out, "z", &proof.z)?;
    set_hex(ruby, &out, "z_prime", &proof.z_prime)?;
    set_hex(ruby, &out, "t", &proof.t)?;
    set_hex(ruby, &out, "v", &proof.v)?;
    set_hex(ruby, &out, "w", &proof.w)?;
    set_hex(ruby, &out, "s", &proof.s)?;
    set_hex(ruby, &out, "s1", &proof.s1)?;
    set_hex(ruby, &out, "s2", &proof.s2)?;
    set_hex(ruby, &out, "t1", &proof.t1)?;
    set_hex(ruby, &out, "t2", &proof.t2)?;
    Ok(out)
}

fn msg1_from_hash(hash: &RHash) -> Result<ProvedMessage1, Error> {
    Ok(ProvedMessage1 {
        ciphertext: parse_hex(&string_field(hash, "ciphertext")?, "message 1 ciphertext")?,
        range_proof: range_proof_from_hash(&hash_field(hash, "range_proof")?)?,
    })
}

fn msg1_to_hash(ruby: &Ruby, msg: &ProvedMessage1) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    set_hex(ruby, &out, "ciphertext", &msg.ciphertext)?;
    out.aset("range_proof", range_proof_to_hash(ruby, &msg.range_proof)?)?;
    Ok(out)
}

fn msg2_from_hash(hash: &RHash) -> Result<ProvedMessage2, Error> {
    Ok(ProvedMessage2 {
        ciphertext: parse_hex(&string_field(hash, "ciphertext")?, "message 2 ciphertext")?,
        respondent_proof: respondent_proof_from_hash(&hash_field(hash, "respondent_proof")?)?,
        beta: parse_hex(&string_field(hash, "beta")?, "message 2 beta")?,
    })
}

fn msg2_to_hash(ruby: &Ruby, msg: &ProvedMessage2) -> Result<RHash, Error> {
    let out = ruby.hash_new();
    set_hex(ruby, &out, "ciphertext", &msg.ciphertext)?;
    out.aset(
        "respondent_proof",
        respondent_proof_to_hash(ruby, &msg.respondent_proof)?,
    )?;
    set_hex(ruby, &out, "beta", &msg.beta)?;
    Ok(out)
}

// ---- ops ----------------------------------------------------------------

fn mta_error(ruby: &Ruby, operation: &str, e: MtaProofError) -> Error {
    let message = e.to_string();
    crate::audit::fire_event(
        operation,
        "failure",
        Some(ALGORITHM),
        None,
        Some(&message),
    );
    Error::new(mta_error_class(ruby), message)
}

fn mta_generate_keypair(ruby: &Ruby, prime_bits: i64) -> Result<RHash, Error> {
    let bits = check_prime_bits(prime_bits)?;
    // Safe-prime search is CPU-bound and takes seconds at production
    // sizes — release the GVL so sibling Ruby threads keep running.
    let kp = unsafe { crate::gvl::without_gvl(|| generate_paillier_keypair(bits)) };
    crate::audit::fire_event("tc_cmp20_mta_keypair", "success", Some(ALGORITHM), None, None);
    keypair_to_hash(ruby, &kp)
}

fn mta_generate_commitment_key(ruby: &Ruby, prime_bits: i64) -> Result<RHash, Error> {
    let bits = check_prime_bits(prime_bits)?;
    let ck = unsafe { crate::gvl::without_gvl(|| generate_commitment_key(bits)) };
    crate::audit::fire_event("tc_cmp20_mta_commitment_key", "success", Some(ALGORITHM), None, None);
    commitment_key_to_hash(ruby, &ck)
}

fn mta_party_i_init(
    ruby: &Ruby,
    j_public: RHash,
    ck_j: RHash,
    q: String,
    k_i: String,
) -> Result<RHash, Error> {
    let public = public_from_hash(&j_public)?;
    let ck = commitment_key_from_hash(&ck_j)?;
    let q = parse_hex(&q, "q")?;
    let k_i = parse_hex(&k_i, "k_i")?;
    let msg = party_i_init_proved(&public, &ck, &q, &k_i).map_err(|e| mta_error(ruby, "tc_cmp20_mta_init", e))?;
    crate::audit::fire_event("tc_cmp20_mta_init", "success", Some(ALGORITHM), None, None);
    msg1_to_hash(ruby, &msg)
}

fn mta_party_j_respond(
    ruby: &Ruby,
    j_public: RHash,
    j_private: RHash,
    ck_i: RHash,
    ck_j: RHash,
    q: String,
    msg1: RHash,
    x_j: String,
) -> Result<magnus::RArray, Error> {
    let public = public_from_hash(&j_public)?;
    let private = private_from_hash(&j_private)?;
    let ck_i = commitment_key_from_hash(&ck_i)?;
    let ck_j = commitment_key_from_hash(&ck_j)?;
    let q = parse_hex(&q, "q")?;
    let msg1 = msg1_from_hash(&msg1)?;
    let x_j = parse_hex(&x_j, "x_j")?;
    let (msg2, beta) = party_j_respond_proved(
        &PaillierKeypair {
            public,
            private,
        },
        &ck_i,
        &ck_j,
        &q,
        &msg1,
        &x_j,
    )
    .map_err(|e| mta_error(ruby, "tc_cmp20_mta_respond", e))?;
    crate::audit::fire_event("tc_cmp20_mta_respond", "success", Some(ALGORITHM), None, None);
    let out = ruby.ary_new_capa(2);
    out.push(msg2_to_hash(ruby, &msg2)?)?;
    out.push(hex_string(ruby, &beta))?;
    Ok(out)
}

fn mta_party_i_finish(
    ruby: &Ruby,
    j_public: RHash,
    j_private: RHash,
    ck_i: RHash,
    q: String,
    msg1_ciphertext: String,
    msg2: RHash,
) -> Result<RString, Error> {
    let public = public_from_hash(&j_public)?;
    let private = private_from_hash(&j_private)?;
    let ck_i = commitment_key_from_hash(&ck_i)?;
    let q = parse_hex(&q, "q")?;
    let ciphertext = parse_hex(&msg1_ciphertext, "message 1 ciphertext")?;
    let msg2 = msg2_from_hash(&msg2)?;
    let alpha = party_i_finish_proved(&public, &ck_i, &q, &ciphertext, &private, &msg2)
        .map_err(|e| mta_error(ruby, "tc_cmp20_mta_finish", e))?;
    crate::audit::fire_event("tc_cmp20_mta_finish", "success", Some(ALGORITHM), None, None);
    Ok(hex_string(ruby, &alpha))
}

fn mta_full(
    ruby: &Ruby,
    j_public: RHash,
    j_private: RHash,
    ck_i: RHash,
    ck_j: RHash,
    q: String,
    k_i: String,
    x_j: String,
) -> Result<magnus::RArray, Error> {
    let public = public_from_hash(&j_public)?;
    let private = private_from_hash(&j_private)?;
    let ck_i = commitment_key_from_hash(&ck_i)?;
    let ck_j = commitment_key_from_hash(&ck_j)?;
    let q = parse_hex(&q, "q")?;
    let k_i = parse_hex(&k_i, "k_i")?;
    let x_j = parse_hex(&x_j, "x_j")?;
    let (alpha, beta) = full_mta_proved(
        &PaillierKeypair {
            public,
            private,
        },
        &ck_i,
        &ck_j,
        &q,
        &k_i,
        &x_j,
    )
    .map_err(|e| mta_error(ruby, "tc_cmp20_mta_full", e))?;
    crate::audit::fire_event("tc_cmp20_mta_full", "success", Some(ALGORITHM), None, None);
    let out = ruby.ary_new_capa(2);
    out.push(hex_string(ruby, &alpha))?;
    out.push(hex_string(ruby, &beta))?;
    Ok(out)
}

pub fn init(ruby: &Ruby, cmp20: &magnus::RModule) -> Result<(), Error> {
    let mta = cmp20.define_module("Mta")?;
    let error = cmp20.define_error("MtaError", ruby.exception_standard_error())?;
    cmp20.const_set("MTA_ERROR", error)?;
    let order = p256_order().to_str_radix(16);
    mta.const_set("P256_ORDER", ruby.str_from_slice(order.as_bytes()))?;

    mta.define_module_function("generate_keypair", magnus::function!(mta_generate_keypair, 1))?;
    mta.define_module_function(
        "generate_commitment_key",
        magnus::function!(mta_generate_commitment_key, 1),
    )?;
    mta.define_module_function("party_i_init", magnus::function!(mta_party_i_init, 4))?;
    mta.define_module_function("party_j_respond", magnus::function!(mta_party_j_respond, 7))?;
    mta.define_module_function("party_i_finish", magnus::function!(mta_party_i_finish, 6))?;
    mta.define_module_function("full", magnus::function!(mta_full, 7))?;
    Ok(())
}

fn mta_error_class(ruby: &Ruby) -> magnus::ExceptionClass {
    ruby
        .class_object()
        .const_get::<_, magnus::RModule>("Confium")
        .and_then(|m| m.const_get::<_, magnus::RModule>("TC"))
        .and_then(|m| m.const_get::<_, magnus::RModule>("Cmp20"))
        .and_then(|m| m.const_get::<_, magnus::ExceptionClass>("MTA_ERROR"))
        .unwrap_or_else(|_| ruby.exception_runtime_error())
}
