# ADR 0001 — Platform gems ship per-minor ABI windows

## Status

Accepted (proven by install-checks across the 0.4.x/0.5.0 releases).

## Context

One binary cannot serve all supported Rubies:

- a 3.1-built extension segfaults Ruby 3.2 (object shapes changed);
- rb_sys references a VM pointer libruby stopped exporting in 3.3;
- a 3.3-window binary fails Ruby 4.0 on every platform with a
  TypedData class-identity TypeError (not just PE naming);
- on Windows, PE imports name the version-specific ruby DLL, so
  Windows needs an exact-minor window per Ruby, always.

## Decision

Gems carry `lib/confium_native/{3.1,3.2,3.3,3.4,4.0}/`. Window
resolution is the pure function `Confium::NativeWindows.candidates`:
exact minor everywhere; 3.3 and 4.0 are distinct windows; the 3.3
fallback applies only within the 3.x line — never across a major.
Source builds install flat and fall back to the unversioned path.

## Consequences

- Adding a Ruby minor = adding a build-matrix leg and a window dir.
- The release pipeline's packaging globs must end in the ABI
  (`-[34].*`), or 4.0 artifacts silently vanish from gems.
- The decision is spec-pinned (`native_windows_spec.rb`) — it
  produced three release incidents before it had a test surface.
