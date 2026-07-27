# Changelog

## [Unreleased]

### Added

- Initial Rust native extension (`confium_native`) wired up via `rb_sys` and
  `magnus`. Compiles a `confium_native.bundle` that the gem loads at
  `require` time.
- `Confium::Native.version` and `Confium::Native.loaded?` smoke-test
  functions exposed to Ruby.
- `Confium.core_version` reports the `confium-core` crate version the
  extension was built against, so Ruby code can detect mismatched
  extension/library pairs at runtime.

### Changed

- `confium.gemspec` switched from `ffi` (pure-Ruby FFI to C ABI) to
  `rb_sys` (Rust native extension). Required Ruby version bumped to 3.1.
- `lib/confium.rb` now requires `confium_native/confium_native` instead
  of defining autoloads for hand-written FFI wrappers.

### Removed

- The `ffi`-based modules (`Confium::FFI`, `Confium::CFM`, `Confium::Lib`,
  `Confium::Crypto`, `Confium::Digest`) are no longer autoloaded. The
  files remain on disk for now and will be deleted in a follow-up once
  the new magnus-based classes reach feature parity.
