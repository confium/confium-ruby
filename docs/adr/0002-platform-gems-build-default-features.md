# ADR 0002 — Platform gems build default cargo features only

## Status

Accepted (0.4.0 removed the vendored C++ stack; 0.5.x added the
opt-in `pgp` feature on top).

## Context

The 0.1–0.3 extension vendored the full librnp + Botan + json-c
C/C++ stack to get ASCII armor — every install paid for a toolchain
it did not use, and Windows/musl could not ship at all.

## Decision

The extension is pure Rust by default. OpenPGP armor is pure Ruby.
Anything needing a C/C++ vendored build (currently OpenPGP
signature verification via rnp-rs) goes behind an opt-in cargo
feature (`pgp`) selected at build time via
`RB_SYS_CARGO_FEATURES=pgp bundle exec rake compile` (extconf.rb
seeds `r.features` from that variable — the env var alone is a
no-op in rb_sys).

Ruby-facing contract: `Confium::OpenPGP::PGP_AVAILABLE` reports
whether the feature was compiled in; the verify methods raise with
rebuild instructions when it was not. A dedicated CI job
(`pgp-verify`) compiles the feature so the path cannot rot.

## Consequences

- Source builders can opt in; platform gems stay C-toolchain-free.
- Feature-gated code needs a runtime availability constant and a
  stub that raises, or gem users hit silent NameErrors.
