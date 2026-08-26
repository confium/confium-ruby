//! Confium::TC::Session — per-party threshold protocol sessions.
//!
//! Binds `confium_tc_core::Session`: each signer process runs ONE
//! session for its own party, feeding it the messages received from
//! the peers and sending on what `round_step` produces. The scheme
//! never leaves the process — this is the per-party half of the
//! multi-host signing story (the NetworkCoordinator is the transport
//! half).
//!
//!   session = Confium::TC::Session.new("FROST-ed25519-dkg",
//!                                      parties: ["p0", "p1", "p2"],
//!                                      threshold: 2,
//!                                      this_party_idx: 0)
//!   loop do
//!     result = session.round_step(incoming)
//!     break if result["complete"]
//!     incoming = broadcast(result["outgoing"])
//!   end
//!   session.result
//!
//! Messages are Hashes with string keys: `"from"`, `"to"` (nil for
//! broadcast), `"round"`, `"payload"` (binary String).

use magnus::{prelude::*, DataTypeFunctions, Error, Module, RArray, RHash, Ruby, TryConvert, TypedData, Value};

// Force the frost-ed25519 crate (and its `inventory::submit!` calls for
// FrostEd25519 + FrostEd25519Dkg) to be linked into the cdylib even
// though the binding itself never names a symbol from it — otherwise
// the linker drops the registration statics and `Session::create`
// reports the scheme as unknown.
extern crate confium_tc_frost_ed25519 as _frost_ed25519_link;

use confium_tc_session::{
    session::{Session as RustSession, SessionParams}, share::Share, Error as TcError, Message,
    Party, PartyList,
};
// (confium-tc-session is the renamed confium-tc-core 0.4.7 dependency.)

fn typed_session_error(e: TcError, operation: &str) -> Error {
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(_) => return Error::new(magnus::exception::runtime_error(), e.to_string()),
    };
    let details = crate::util::new_details(&ruby);
    let _ = details.aset("operation", operation);
    crate::util::confium_error(e.to_string(), "Error", details)
}

/// Confium::TC::Session — see the module docs.
#[derive(TypedData, DataTypeFunctions)]
#[magnus(class = "Confium::TC::Session", size)]
pub struct Session {
    inner: std::cell::RefCell<RustSession>,
}

fn bytes_arg(v: Value, name: &str) -> Result<Vec<u8>, Error> {
    crate::util::bytes_from_value(v)
        .map_err(|e| crate::util::arg_error(format!("Session: {name}: {e}")))
}

impl Session {
    fn initialize(ruby: &Ruby, args: &[Value]) -> Result<Self, Error> {
        let scanned = magnus::scan_args::scan_args::<(String,), (Option<RHash>,), (), (), (), ()>(args)
            .map_err(|e| crate::util::arg_error(e.to_string()))?;
        let scheme = scanned.required.0;
        let raw_opts = scanned
            .optional
            .0
            .ok_or_else(|| crate::util::arg_error("Session.new: options Hash is required"))?;
        // Ruby callers pass keywords (`parties: [...]`), which arrive as
        // symbol keys; accept both symbol and string keys.
        let opts = ruby.hash_new();
        raw_opts.foreach(|k: Value, v: Value| {
            let key: String = if k.is_kind_of(ruby.class_symbol()) {
                k.funcall("to_s", ())?
            } else {
                <String as TryConvert>::try_convert(k)?
            };
            opts.aset(key, v)?;
            Ok(magnus::r_hash::ForEach::Continue)
        })?;

        let required = |key: &str| -> Result<Value, Error> {
            opts.fetch(key).map_err(|_| {
                crate::util::arg_error(format!("Session.new: :{key} is required"))
            })
        };
        let parties_val = required("parties")?;
        let ids: Vec<String> = <Vec<String> as TryConvert>::try_convert(parties_val).map_err(|_| {
            crate::util::arg_error("Session.new: :parties must be an Array of String ids")
        })?;
        if ids.len() < 2 {
            return Err(crate::util::arg_error(
                "Session.new: at least two parties are required",
            ));
        }
        let mut parties = PartyList::new();
        for id in &ids {
            parties.push(Party::new(id.clone(), None::<String>));
        }

        let threshold: u32 = <u32 as TryConvert>::try_convert(required("threshold")?)
            .map_err(|_| crate::util::arg_error("Session.new: :threshold must be an Integer"))?;
        let this_party_idx: usize = <usize as TryConvert>::try_convert(required("this_party_idx")?)
            .map_err(|_| {
                crate::util::arg_error("Session.new: :this_party_idx must be an Integer")
            })?;

        let local_share_v: Value = opts
            .get("local_share")
            .unwrap_or_else(|| ruby.qnil().as_value());
        let local_share: Option<Share> = if local_share_v.is_nil() {
            None
        } else {
            Some(Share::new(
                scheme.clone(),
                bytes_arg(local_share_v, "local_share")?,
            ))
        };
        let message_v: Value = opts
            .get("message")
            .unwrap_or_else(|| ruby.qnil().as_value());
        let message: Option<Vec<u8>> = if message_v.is_nil() {
            None
        } else {
            Some(bytes_arg(message_v, "message")?)
        };

        let params = SessionParams {
            scheme: scheme.clone(),
            parties,
            threshold,
            this_party_idx,
            local_share,
            message,
        };
        let inner = RustSession::create(&params)
            .map_err(|e| typed_session_error(e, "Session.new"))?;
        let _ = ruby;
        Ok(Self {
            inner: std::cell::RefCell::new(inner),
        })
    }

    fn scheme_name(&self) -> String {
        self.inner.borrow().scheme_name().to_string()
    }

    fn threshold(&self) -> u32 {
        self.inner.borrow().threshold()
    }

    fn party_count(&self) -> usize {
        self.inner.borrow().party_count()
    }

    fn this_party_idx(&self) -> usize {
        self.inner.borrow().this_party_idx()
    }

    fn round(&self) -> u8 {
        self.inner.borrow().round()
    }

    fn complete(&self) -> bool {
        self.inner.borrow().is_complete()
    }

    fn round_step(&self, args: &[Value]) -> Result<RHash, Error> {
        let ruby = Ruby::get().map_err(|e| crate::util::runtime(e.to_string()))?;
        let scanned =
            magnus::scan_args::scan_args::<(), (Option<Value>,), (), (), (), ()>(args)
                .map_err(|e| crate::util::arg_error(e.to_string()))?;
        let incoming = match scanned.optional.0 {
            Some(v) if !v.is_nil() => parse_messages(&ruby, v)?,
            _ => Vec::new(),
        };

        let result = self
            .inner
            .borrow_mut()
            .round_step(&incoming)
            .map_err(|e| typed_session_error(e, "Session#round_step"))?;

        let out = ruby.hash_new();
        let arr = ruby.ary_new();
        for m in &result.outgoing {
            let h = ruby.hash_new();
            let _ = h.aset("from", m.from_party_id.as_str());
            let to: Value = match &m.to_party_id {
                Some(t) => ruby.str_new(t).as_value(),
                None => ruby.qnil().as_value(),
            };
            let _ = h.aset("to", to);
            let _ = h.aset("round", m.round as i64);
            let _ = h.aset(
                "payload",
                crate::util::bytes_to_rstring(&ruby, &m.payload),
            );
            arr.push(h)?;
        }
        let _ = out.aset("outgoing", arr);
        let _ = out.aset("complete", result.complete);
        Ok(out)
    }

    fn result(&self) -> Result<magnus::RString, Error> {
        let ruby = Ruby::get().map_err(|e| crate::util::runtime(e.to_string()))?;
        let bytes = self
            .inner
            .borrow()
            .result()
            .map_err(|e| typed_session_error(e, "Session#result"))?;
        Ok(crate::util::bytes_to_rstring(&ruby, &bytes))
    }
}

fn parse_messages(ruby: &Ruby, value: Value) -> Result<Vec<Message>, Error> {
    let arr: RArray = <RArray as TryConvert>::try_convert(value)
        .map_err(|_| crate::util::arg_error("Session#round_step: incoming must be an Array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr.into_iter() {
        let h: RHash = <RHash as TryConvert>::try_convert(item).map_err(|_| {
            crate::util::arg_error("Session#round_step: each message must be a Hash")
        })?;
        let fetch = |key: &str| -> Result<Value, Error> {
            h.fetch(key)
                .map_err(|_| crate::util::arg_error(format!("message: '{key}' is required")))
        };
        let from: String = <String as TryConvert>::try_convert(fetch("from")?)
            .map_err(|_| crate::util::arg_error("message: 'from' must be a String"))?;
        let to_v: Value = fetch("to")?;
        let to: Option<String> = if to_v.is_nil() {
            None
        } else {
            Some(
                <String as TryConvert>::try_convert(to_v)
                    .map_err(|_| crate::util::arg_error("message: 'to' must be a String"))?,
            )
        };
        let round: u8 = <u8 as TryConvert>::try_convert(fetch("round")?)
            .map_err(|_| crate::util::arg_error("message: 'round' must be an Integer"))?;
        let payload: Value = fetch("payload")?;
        let payload = crate::util::bytes_from_value(payload)?;
        let msg = match to {
            Some(t) => Message::directed(from, t, round, payload),
            None => Message::broadcast(from, round, payload),
        };
        out.push(msg);
        let _ = ruby;
    }
    Ok(out)
}

pub fn init(ruby: &Ruby, parent: magnus::RModule) -> Result<(), Error> {
    let tc = parent.define_module("TC")?;
    let class = tc.define_class("Session", ruby.class_object())?;
    class.define_singleton_method("new", magnus::function!(Session::initialize, -1))?;
    class.define_method("scheme_name", magnus::method!(Session::scheme_name, 0))?;
    class.define_method("threshold", magnus::method!(Session::threshold, 0))?;
    class.define_method("party_count", magnus::method!(Session::party_count, 0))?;
    class.define_method("this_party_idx", magnus::method!(Session::this_party_idx, 0))?;
    class.define_method("round", magnus::method!(Session::round, 0))?;
    class.define_method("complete?", magnus::method!(Session::complete, 0))?;
    class.define_method("round_step", magnus::method!(Session::round_step, -1))?;
    class.define_method("result", magnus::method!(Session::result, 0))?;
    Ok(())
}
