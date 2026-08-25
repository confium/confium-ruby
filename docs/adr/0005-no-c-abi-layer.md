# ADR 0005 — The magnus extension is the only binding layer

## Status

Accepted (2026-08-25; user decision — "remove all legacy, we do not
need fallbacks").

## Context

The 0.1 gem wrapped the `libconfium` C ABI through the `ffi` gem
(`Confium::Lib` attach tables, `CFM`, `Digest`, a `TC::Session`
wrapper). Since 0.4.0 the extension is pure Rust via magnus + rb_sys
and wraps the `confium-*` crates directly. The FFI files were never
loaded by the entry point and had rotted past function: they called
`Confium.call_ffi`, a method that never existed, while the RBS
carried a phantom declaration of it purely to keep steep green.

Keeping them invited the wrong mental model — a reader asking "how
do sessions work?" found three answers, one of them a lie — and no
fallback was ever real.

## Decision

The C-ABI files are deleted (not attic'd). There is exactly one
binding layer: the magnus extension. If a future need for a C ABI
appears (embedding, non-Ruby hosts), it is a new proposal with its
own ADR, not a revival of these files.

## Consequences

- No `ffi`-gem-based path exists; do not re-add one as a "fallback".
- `Confium::TC::SessionStub` (an interface-shape placeholder) is
  gone too; the real per-party session protocol is tracked in
  TODO.full/01 and will land behind the SigningSession seam.
- The RBS declares only what actually runs.
