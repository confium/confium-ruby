# Changelog

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
