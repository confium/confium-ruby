# confium-ruby domain glossary

The nouns this gem uses, so architecture reviews and new
contributors share one vocabulary. The parent framework's glossary
lives in the sibling Rust repo (`confium/CONTEXT.md`); this file is
the binding layer on top. Architecture terms (module, interface,
depth, seam, adapter, leverage, locality) come from the
`/codebase-design` skill.

## Threshold signing

- **Quorum** — the T-of-N signing group a coordinator serves,
  identified by `quorum_id`.
- **Signing session** — one threshold-signing operation: message,
  threshold, scheme, and the collected commitments/shares.
  `Confium::TC::SigningSession` owns the state machine
  (`pending → commitments_collected → completed`), signer identity,
  and the CMP20/GG18 combine.
- **Coordinator** — the in-process adapter over signing sessions:
  a quorum-scoped session registry (`Confium::TC::Coordinator`).
- **Network coordinator** — the TCP/NDJSON adapter over the same
  sessions for signers on separate hosts
  (`Confium::TC::NetworkCoordinator` + `SignerClient`).
- **Commitment / share** — a signer's round-one and round-two
  submission blobs. Keyed by signer id: one signer never counts
  twice toward the threshold.
- **Share file** — the JSON envelope for persisting keygen share
  blobs (`Confium::TC::ShareFile`), interop-identical to the Python
  binding's format.

## Native binding layer

- **Native extension** — the Rust cdylib (`confium_native`, magnus
  + rb_sys) that defines most `Confium::*` modules at load time.
- **Native companion** — a pure-Ruby file that reopens a
  native-defined module to add idiomatic surface (defaults,
  mixins, JSON transport). Loaded eagerly because autoloads on
  native-defined constants never fire.
- **ABI window** — a Ruby minor-version compatibility window the
  platform gems ship binaries under. Resolution rules:
  `Confium::NativeWindows.candidates` (exact minor everywhere;
  3.3-window loads 3.3/3.4; never a cross-major fallback).
- **Platform gem** — a prebuilt gem for one OS/arch, built with
  default cargo features only (no C toolchain).
- **pgp feature** — the opt-in cargo feature vendoring librnp for
  OpenPGP verification; `Confium::OpenPGP::PGP_AVAILABLE` reports
  whether the running extension was built with it.

## Audit

- **Audit record** — the String-keyed Hash emitted for every
  signing/verification/encryption operation.
- **Sink** — where audit records go (`Confium::Audit::Sink`
  subclass or any callable; `FileSink`, `MemorySink`, `StderrSink`,
  `OtlpSink` shipped).

## Errors

- **Typed error** — a `Confium::*Error` subclass carrying a details
  Hash with named fields (`have_count`/`need_count`, `param`,
  `kind`…), constructed identically from Ruby kwargs and from the
  native extension's positional Hash.
