# Changelog

## [Unreleased]

### Added

- **Ruby 4.0 support** — Windows ships an exact `4.0` ABI window;
  every platform install-checks on Ruby 4.0; the test matrix gains
  4.0 legs. (There is no Ruby 3.5 — 4.0 is the successor line.)
- **Multi-host threshold signing**: `Confium::TC::NetworkCoordinator`
  (TCP service, NDJSON + hex wire protocol) + `Confium::TC::SignerClient`
  — signers on separate machines submit commitments and shares;
  aggregation runs the real CMP20/GG18 combine and returns an
  OpenSSL-verifiable signature. Plain TCP for loopback/private
  networks; the upstream noise transport replaces it later.
- **OpenTelemetry export**: `Confium::Audit::OtlpSink` ships every
  audit record to an OTLP collector over OTLP/HTTP JSON (logs
  signal, stdlib-only, failures drop-and-report).
- `Confium::Composite::Signature#to_json` — instances remember their
  source (components or a canonical JSON document) and re-serialize
  losslessly, completing the JSON transport symmetry.

### Fixed

- `Confium::TC::Coordinator` now aggregates REAL threshold-ECDSA
  signatures: once the threshold is met, it runs the CMP20 or GG18
  combine (selected per session via `scheme:`) and returns a 64-byte
  signature verifiable under the quorum public key. Previously
  `aggregate` concatenated the share bytes — a placeholder that
  returned garbage. Unknown sessions below-threshold now raise
  `Confium::ThresholdError`.
- `Confium::TC::Coordinator` and `ShareFile` were unreachable after
  `require "confium"`: the TC namespace file that registers them
  never loaded because the native extension pre-defines
  `Confium::TC` (the same orphaned-module trap PKI had). The
  namespace file is now eager-required; `TC::Session` stays lazy —
  it wraps the engine via FFI and needs the external libconfium
  dylib.

## [0.4.1] — 2026-08-24

### Fixed

- **Windows platform gems load on every supported Ruby.** A PE
  import names the version-specific ruby DLL
  (`x64-ucrt-ruby330.dll`), so the shared 3.3 window could not load
  under 3.4 (Windows error 126). Windows gems now carry an exact
  window per Ruby (3.1-3.4); the loader prefers the exact minor and
  falls back to the shared 3.3 window on other platforms. The
  mingw runtime is embedded (`-static-libgcc`).
- 0.4.0 shipped as a source gem only — its platform publish was
  correctly blocked by the failing Windows install-check; the
  platform gems first appear here.

## [0.4.0] — 2026-08-23

### Changed

- **The native extension is pure Rust — the vendored RNP stack
  (librnp + Botan + json-c, a full C/C++ build) is gone.** It was
  compiled into every install but used only for ASCII armor, which
  is now implemented in pure Ruby (RFC 9580 §6, byte-for-byte
  compatible with the previous output; differential vectors in
  spec/fixtures/openpgp_armor_vectors.json). Source builds now need
  only a Rust toolchain — no C compiler, no cmake, and no network
  fetch of C sources — and compile in ~2 minutes instead of ~15.

### Added

- **Windows (`x64-mingw-ucrt`) and musl Linux
  (`x86_64-linux-musl`, `aarch64-linux-musl`) platform gems**,
  unblocked by the dependency removal: pure Rust builds natively
  under mingw and in Alpine containers (aarch64 under QEMU). All
  are install-checked on every supported Ruby before publishing,
  and Windows joins the test matrix.
- `Confium::OpenPGP.dearmor` now verifies the CRC-24 checksum and
  raises `Confium::ParseError` on malformed blocks (previously a
  bare rnp failure).

## [0.3.4] — 2026-08-23

### Fixed

- **Typed-error sweep completed.** Crypto operation failures
  (FrostP256 sign, ElGamal encapsulate/decrypt/aggregate, composite
  sign) raise `Confium::CryptoError` with the primitive in `details`;
  `PathValidator` DER extraction failures raise `Confium::ParseError`;
  `Manifest#tier_name_at` and `SignedData#certificate_at` out-of-range
  raise the typed `Confium::IndexError` (unifying with the
  transparency proofs — they previously raised Ruby's core
  `IndexError`).
- **Zero compiler warnings.** All 80 direct
  `magnus::exception::*` constructor sites are centralized into
  `util::runtime`/`util::arg_error` (the deprecated API survives in
  exactly one module whose job is wrapping it); the remaining magnus
  deprecations (`RString::buf_new`, `RArray::each`) and dead imports
  are fixed.
- **DoS guard now covers every byte input**: the duplicate local
  `bytes_from_value` copies in tc/transparency — one of which
  skipped the 1 MiB size cap — are consolidated onto the util
  version that enforces it.

## [0.3.3] — 2026-08-23

### Added

- **Typed native errors everywhere**: PEM/DER, JSON, TOML, DSL, and
  XML parse failures raise `Confium::ParseError`; out-of-range
  sequence indexes raise `Confium::IndexError`; consistency-proof
  failures raise `Confium::VerificationError` — each with a
  structured `details` Hash (format, operation, index, ...).
  Previously these surfaced as bare `RuntimeError`.

### Added

- `Confium::Composite::Signature.components_to_json` /
  `.from_json` — JSON transport for composite signatures with the
  binary fields hex-encoded on the wire (fixes the Sinatra example's
  happy path, which called a `from_json` that did not exist).
- Steep type checking in CI: the Steepfile never loaded before
  (it used a `configure_code_diagnostics` API that does not exist in
  steep 1.10). `sig/confium.rbs` now covers every pure-Ruby
  subsystem — including the TC session machinery — and
  `bundle exec steep check` is green and enforced. Only the FFI
  layer is excluded (the ffi gem has no RBS signatures).

### Fixed

- `Confium::PKI::CMS::SignedDataBuilder#build` raised KeyError on
  the ECDSA-P256 path (`FrostP256.sign` returns `der`/`fixed`, not
  `signature`); it now uses the DER form, which is what CMS carries.
- `Confium::PKI::CertificateBuilder`, `Confium::PKI::CNML`, and
  `Confium::Transparency::OTS` were unreachable after
  `require "confium"` (missing autoload wiring); the PKI namespace
  file is now eager-required and registers them.
- All five `hello_*` quickstart examples, the Sinatra example's
  happy path, and every page under `docs/` were rewritten against
  the real APIs (see the docs audit), and CI now runs every example
  on every push.

## [0.3.2] — 2026-08-22

Native platform gems (linux x86_64/aarch64, macOS x86_64/arm64) ship
alongside the source gem — `gem install` no longer needs a Rust
toolchain on those platforms.

The 0.3.0/0.3.1 native-gem builds never actually produced platform
gems: the cross-compile task targeted a nonexistent rake task inside
a container whose shell swallowed the failure, and the fallback
`gem build` stamped platform=ruby. RubyGems blocks re-pushing a
version that ever existed, so the native gems first appear here.

### Fixed

- Platform gems now build on native-arch runners (one per target
  platform). Cross-compilation via rake-compiler-dock is impossible
  for this gem: the dock images are Ubuntu 20.04 (gcc 9.4) while the
  vendored RNP stack needs Botan 3.12, which requires gcc 11+.
- Each platform gem carries one extension per C-ABI window — exact
  minors 3.1 and 3.2, plus 3.3 (loads on 3.3+) — because Ruby 3.2
  broke the 3.1 ABI (a 3.1-built extension segfaults on 3.2) and
  rb-sys references `ruby_current_vm_ptr` when built against
  Ruby <= 3.2, which libruby stopped exporting in 3.3.
  `lib/confium.rb` picks the window for the running Ruby; source
  builds keep the flat extension path.
- The release workflow no longer builds a source gem (that burned
  the 0.3.1 version slots against test-and-release.yml's publish),
  refuses to push any gem stamped platform=ruby, and installs each
  packaged gem on Ruby 3.1 through 3.4 before publishing.
- Windows remains unsupported: the vendored RNP (json-c + botan)
  build has no MSVC/mingw story.

## [0.3.1] — 2026-08-21

Shipped as a source gem only (the intended native platform gems
failed to materialize; see 0.3.2).

### Added

- ERS archival binding (`Confium::EvidenceRecord`, RFC 4998) and the
  `CONFIUM_LIB` explicit dylib path override.
- Audit log bindings with sign-triggered autofire and an Enumerable
  `MemorySink`.
- Typed error hierarchy across all subsystems with native-error
  coercion.
- CMP20/GG18 in-process threshold ECDSA (`Confium::TC::Cmp20`,
  `Confium::TC::Gg18`) and TC share files with the documented
  envelope shape.
- Twenty worked examples plus the examples and CNML-profile guides.

### Fixed

- The PKI CSR spec no longer shells out to the openssl CLI (it
  generated its fixture with a key file that was never created).
- CI: first `.rubocop.yml`, Ruby-3.1-compatible lockfile, and a test
  matrix matching the shipped platforms.

## [0.3.0] — 2026-08-04

Synced with Confium Rust workspace v0.3.0 (product restructuring).

### Changed

- **Rust edition bumped to 2024** (was 2021). Requires Rust 1.85+.
- **All confium dependencies now from crates.io** (removed path deps for
  `confium-tc-cmp20` and `confium-tc-gg18`). `gem install confium` now works
  without a local workspace checkout.
- **Version synced to 0.3.0** (was 0.1.0) to match the workspace version.

### Added

- Dependencies on newly published shared crypto crates:
  `confium-tc-core`, `confium-crypto-vss`, `confium-crypto-zk`,
  `confium-privacy`, `confium-observability`.

### Migration from 0.1.0

- Update `Gemfile`: `gem "confium", "~> 0.3"`
- Ensure Rust 1.85+ is installed (`rustup update stable`)
- Run `bundle exec rake compile` to rebuild the native extension

## [0.1.0] — 2026-07-27

First public release of the Ruby bindings. Replaces the previous FFI-based
prototype with a Rust native extension built via `rb_sys` + `magnus`
(parsanol-ruby pattern). The extension is compiled at `gem install` time
and exposes the high-value Confium subsystems directly to Ruby.

### Added

- **Native extension scaffold** (`ext/confium_native/`). cdylib built via
  `rb_sys` and `magnus`; required by `lib/confium.rb` at load time.
  `Confium::Native.version`, `Confium::Native.loaded?`, and
  `Confium.core_version` provide a smoke-test surface.

- **`Confium::Transparency::MerkleTree`** — append-only RFC 6962 Merkle
  tree. `#append(artifact_hash)`, `#root`, `#length`, `#empty?`,
  `#inclusion_proof(seq)`. `Confium::Transparency::InclusionProof` with
  `#sequence`, `#steps`, `#verify(root)`.

- **`Confium::Composite`** — PQ-migration composite signatures.
  `.generate_ed25519_keypair`, `.sign_ed25519(private_key, message)`.
  `Confium::Composite::Signature.new(components)` + `#verify(message)` +
  `#component_count` + `#algorithms`.
  `Confium::Composite::VerificationResult#all_verified?` + `#per_component`.

- **`Confium::Attributes`** — attribute-based threshold-signing policy DSL.
  `.parse(expr)` + `Confium::Attributes::Predicate#satisfied_by?(signers)`.
  `Confium::Attributes::Signer.new` + `#add(key, value)` + `#has?(key)` +
  `#values(key)`. DSL covers `min_count`, `min_distinct`, `any`, `all`,
  `none`, `and`, `or`, `not`.

- **`Confium::PKI::Certificate`** — X.509 v3 certificate parse + inspect.
  `.from_der(binary)` / `.from_pem(string)`. `#to_der`, `#to_pem`,
  `#fingerprint_sha256`, `#serial_hex`, `#not_before`, `#not_after`,
  `#valid_at?(iso8601)`, `#public_key_bytes`.

- **`Confium::PKI::CSR`** — PKCS#10 certificate signing request.
  `.from_der` / `.from_pem` / `#to_der` / `#to_pem`.

- **`Confium::PKI::CMS::SignedData`** — JSON-backed RFC 5652 model.
  `.from_json` / `#to_json` / `#signer_count` / `#content_type` /
  `#content` / `#certificate_count` / `#certificate_at(index)`.

- **`Confium::PKI::CMS::Content`** — value object for optional content.
  `#bytes`, `#length`.

- **`Confium::PKI::XMLDSig`** — Canonical XML (RFC 3076) and Exclusive
  C14N. `.canonicalize(xml)`, `.canonicalize_exclusive(xml)`.

- **`Confium::Identity::Actor`** — actor identity from JSON.
  `.from_json` / `#to_json` / `#actor_id` / `#actor_type` / `#quorum_id` /
  `#registered_at` / `#expires_at` / `#certificate_count`.
  `Confium::Identity.actor_types` returns the six canonical role strings
  (`manufacturer`, `testing_lab`, `issuing_authority_officer`,
  `biml_director`, `quorum_coordinator`, `verifier`).

- **`Confium::Config::Manifest`** — deployment manifest parse + validate.
  `.from_toml` / `#deployment_name` / `#operator` / `#manifest_version` /
  `#tier_count` / `#tier_name_at` / `#quorum_count` / `#validate` /
  `#valid?`.

- **`Confium::TC::FrostP256`** — real P-256 Shamir + ECDSA.
  `.generate_keypair`, `.split_secret(secret, t, n)`,
  `.recover_secret([{x:, y:}, ...])`, `.sign(private_key, message)`.
  `Confium::TC::FrostP256::Share#x` / `#y_bytes`.

- **`Confium::TC::ElGamalP256`** — threshold ElGamal-P256 KEM.
  `.encapsulate(public_key)` → `{ ciphertext: { c1:, c2: }, shared_secret: }`,
  `.partial_decrypt(party_index, share_bytes, ciphertext)`,
  `.aggregate_partials(partials, threshold, ciphertext)`.

### Changed

- `confium.gemspec` switched from `ffi` (pure-Ruby FFI to C ABI) to
  `rb_sys` (Rust native extension). Required Ruby version bumped to 3.1.
- `lib/confium.rb` now requires `confium_native/confium_native` instead
  of declaring autoloads for hand-written FFI wrappers.
- All binary inputs and outputs use `Encoding::ASCII_8BIT` Strings
  (binary), the idiomatic Ruby shape for cryptographic data.

### Removed

- The `ffi`-based modules (`Confium::FFI`, `Confium::CFM`, `Confium::Lib`,
  `Confium::Crypto`, `Confium::Digest`) — replaced by the magnus-based
  classes above. Old spec files deleted.

### Known limitations

- v0.1.0 ships as a **source gem** — `gem install` requires Rust + cargo
  on the host. Cross-platform binary gems for Linux/Windows via
  `rake-compiler-dock` will follow in v0.2.0.
- The threshold-cryptography surface covers Shamir + Lagrange + ECDSA +
  threshold ElGamal. Full multi-party FROST/CMP20/GG18 session
  orchestration (the async coordinator) is not yet exposed — lands in
  v0.2.0.
- The composite-signature surface verifies Ed25519 components only.
  ML-DSA-65 / SLH-DSA verifiers will land when the underlying Rust
  crates ship.
- RBS type signatures in `sig/` are not yet provided — planned for v0.2.0
  once the API stabilizes.
