//! Confium::TC — threshold cryptography surface for Ruby.
//!
//! Phase 1D-1 scope: real P-256 Shamir secret sharing + keypair generation +
//! single-party sign + verify. Multi-party FROST sessions land in Phase 1D-2
//! (they need a session/coordinator abstraction that doesn't fit in one PR).

use confium_tc_frost_p256::{
    generate_keypair, public_key_for,
    scalar::{scalar_from_bytes, scalar_to_bytes},
    shamir::{recover_secret, split_secret, Share},
    sign_message,
    Keypair,
};
use magnus::{exception, function, method, prelude::*, DataTypeFunctions, Error, Module, Object, RHash, Ruby, TryConvert, TypedData, Value};
use p256::Scalar;

#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::TC::FrostP256::Share", size)]
pub struct ShareWrap {
    pub x: u32,
    pub y_bytes: Vec<u8>,
}

impl ShareWrap {
    fn x(&self) -> u32 {
        self.x
    }

    fn y_bytes(&self) -> Result<magnus::RString, Error> {
        let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
        Ok(bytes_to_rstring(&ruby, &self.y_bytes))
    }
}

fn split_secret_into_shares(
    secret_bytes: Value,
    threshold: u32,
    party_count: u32,
) -> Result<magnus::RArray, Error> {
    let bytes = bytes_from_value(secret_bytes)?;
    if bytes.len() != 32 {
        return Err(Error::new(
            exception::arg_error(),
            format!("secret must be exactly 32 bytes, got {}", bytes.len()),
        ));
    }
    let secret_arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let secret = scalar_from_bytes(&secret_arr).ok_or_else(|| {
        Error::new(
            exception::arg_error(),
            "secret is not a valid P-256 scalar (reduce mod n failed)",
        )
    })?;
    let shares: Vec<Share> = split_secret(&secret, threshold, party_count);
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let result = ruby.ary_new_capa(shares.len());
    for s in shares {
        result.push(ruby.obj_wrap(ShareWrap {
            x: s.x,
            y_bytes: scalar_to_bytes(&s.y).to_vec(),
        }))?;
    }
    Ok(result)
}

fn recover(shares_value: Value) -> Result<magnus::RString, Error> {
    let arr = magnus::RArray::try_convert(shares_value)?;
    let mut shares: Vec<Share> = Vec::with_capacity(arr.len());
    for v in arr.each() {
        let h: RHash = RHash::try_convert(v?)?;
        let x: u32 = h.fetch::<_, u32>("x")?;
        let y_value: Value = h.fetch::<_, Value>("y")?;
        let y_bytes = bytes_from_value(y_value)?;
        if y_bytes.len() != 32 {
            return Err(Error::new(
                exception::arg_error(),
                format!("share y must be 32 bytes, got {}", y_bytes.len()),
            ));
        }
        let y_arr: [u8; 32] = y_bytes.as_slice().try_into().unwrap();
        let y = scalar_from_bytes(&y_arr).ok_or_else(|| {
            Error::new(exception::arg_error(), "share y is not a valid P-256 scalar")
        })?;
        shares.push(Share { x, y });
    }
    let refs: Vec<&Share> = shares.iter().collect();
    let secret = recover_secret(&refs)
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    Ok(bytes_to_rstring(&ruby, &scalar_to_bytes(&secret).to_vec()))
}

fn keypair(ruby: &Ruby) -> Result<RHash, Error> {
    let kp = generate_keypair();
    let result = ruby.hash_new();
    let signing_bytes = kp.to_signing_key().to_bytes();
    let verifying_bytes = kp.to_verifying_key().to_sec1_bytes();
    result.aset("private_key", bytes_to_rstring(ruby, &signing_bytes.to_vec()))?;
    result.aset("public_key", bytes_to_rstring(ruby, &verifying_bytes))?;
    Ok(result)
}

fn sign(private_key_bytes: Value, message: Value) -> Result<RHash, Error> {
    let pk_bytes = bytes_from_value(private_key_bytes)?;
    let msg = bytes_from_value(message)?;
    if pk_bytes.len() != 32 {
        return Err(Error::new(
            exception::arg_error(),
            format!("private key must be 32 bytes, got {}", pk_bytes.len()),
        ));
    }
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();
    let secret = scalar_from_bytes(&pk_arr).ok_or_else(|| {
        Error::new(exception::arg_error(), "private key not a valid P-256 scalar")
    })?;
    let kp = Keypair {
        secret_scalar: secret,
        public_key: public_key_for(&secret),
    };
    let signed = sign_message(&kp, &msg)
        .map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let ruby = Ruby::get().map_err(|e| Error::new(exception::runtime_error(), e.to_string()))?;
    let result = ruby.hash_new();
    result.aset("der", bytes_to_rstring(&ruby, &signed.der_bytes))?;
    result.aset("fixed", bytes_to_rstring(&ruby, &signed.fixed_bytes))?;
    Ok(result)
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

fn bytes_to_rstring(_ruby: &Ruby, bytes: &[u8]) -> magnus::RString {
    let s = magnus::RString::buf_new(0);
    s.cat(bytes);
    s
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let tc = parent.define_module("TC")?;
    let frost = tc.define_module("FrostP256")?;
    frost.define_module_function("split_secret", function!(split_secret_into_shares, 3))?;
    frost.define_module_function("recover_secret", function!(recover, 1))?;
    frost.define_module_function("generate_keypair", function!(keypair, 0))?;
    frost.define_module_function("sign", function!(sign, 2))?;

    let share_class = frost.define_class("Share", ruby.class_object())?;
    share_class.define_method("x", method!(ShareWrap::x, 0))?;
    share_class.define_method("y_bytes", method!(ShareWrap::y_bytes, 0))?;

    // Touch Scalar to silence unused-import warnings if any.
    let _: Option<Scalar> = None;

    Ok(())
}
