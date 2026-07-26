# 00 — Ecosystem synchronization

## Overview

The Confium project spans multiple repositories. This document tracks
ecosystem-wide synchronization and is the master reference for which
repos need attention.

## Repositories

### Primary

| Repo | URL | Role | Status |
|---|---|---|---|
| `confium` | https://github.com/confium/confium | Rust workspace (main product) | ✅ Active (43 crates, 744+ tests, 69 TODO docs) |
| `confium-ruby` | https://github.com/confium/confium-ruby | Ruby FFI bindings gem | ✅ Active (this repo) |
| `confium.github.io` | https://github.com/confium/confium.github.io | Jekyll site for www.confium.org | ✅ Active (three-mode landing shipped) |
| `specs` | https://github.com/confium/specs | Multi-spec technical repository (deployed to www.confium.org/specs/) | ✅ Synced 2026-07-26 (renamed from `confium-report`) |
| ~~`infrastructure`~~ | ~~https://github.com/confium/infrastructure~~ | ~~Terraform for AWS~~ | ❌ Deprecated, ignored. |

### Consumed dependencies

| Repo | URL | Role | Status |
|---|---|---|---|
| `rnp-rs` | https://github.com/rnpgp/rnp-rs | Rust binding to RNP OpenPGP C library | ✅ All 3 Confium BUGREPORTs fixed (commit ed268d5) |
| `hash-botan` | https://github.com/confium/hash-botan | Botan hash plugin (extracted from main) | ✅ Standalone |

### Downstream consumers (not Confium repos)

| Repo | URL | Role |
|---|---|---|
| `oimlsmart/digital-certificates` | (private) | OIML CNML project — Mode 3 flagship consumer |
| `parsanol/parsanol-rs` | https://github.com/parsanol/parsanol-rs | Reference for publishing conventions |

## Synchronization matrix

When the framework changes, downstream repos may need updates:

| Framework change | Ruby | Site | Report (specs) | CNML |
|---|---|---|---|---|
| Public FFI surface | Update lib/confium/ffi.rb | Docs only | Spec doc update | Compile against new |
| New crate published | Add bindings if user-facing | Mention in features | Mention in spec | Use as needed |
| Architecture shift (e.g., three-mode) | README update | Landing page update | New spec document | Strategy alignment |
| Version bump | Bump gem version | Docs only | Optional | Update dependency |
| Crate consolidation (rename) | Update FFI paths | Update feature list | Update spec refs | Update imports |

## Recent synchronization work

### 2026-07-26: Three-mode architecture rollout

Triggered by framework reaching 43 crates + 744 tests + Mode 1/2/3 framing.

- ✅ `confium.github.io`: PR #11 merged — landing page now describes three modes
- ✅ `confium-ruby`: this branch — README rewritten with three-mode context, added `confium_spec.rb` for module-level coverage
- ⏳ `confium-report`: needs to be generalized into a multi-spec repository (per direction from Ribose)
- ⏭️ `infrastructure`: not affected (operator-managed)

### 2026-07-26: Crate consolidation (53 → 43)

Triggered by 5 logical merges.

- ✅ `confium`: 5 PRs merged (#42, #43), tests preserved (744), CLAUDE.md updated
- ✅ `confium-ruby`: not affected (no Ruby bindings to deleted crates)
- ✅ `confium.github.io`: not affected (no per-crate pages yet)
- ⏳ `confium-report`: should reference new consolidated crate names

## Per-repo TODO

### confium-ruby (this repo)

- [x] README rewrite (DONE this branch)
- [x] Add `spec/confium_spec.rb` for module-level coverage (DONE this branch)
- [ ] Bump gem version to 0.3.0 to match Rust workspace
- [ ] Add bindings for new interfaces: `confium-tc` (threshold signing), `confium-tc-kem` (threshold encryption), `confium-coordinator` (async session)
- [ ] Add integration test that builds Rust workspace and runs against gem
- [ ] Translate high-level framework docs into Ruby-idiomatic examples

### confium.github.io

- [x] Three-mode landing (DONE)
- [x] About page rewrite (DONE)
- [ ] Blog post: "Confium 0.3 released — three deployment modes"
- [ ] Documentation portal at docs.confium.org (links to RustDoc + examples)
- [ ] CNML case study page (summary of `TODO.roadmap/27-cnml-deployment.md`)
- [ ] NIST MPTS page (summary of `TODO.roadmap/25-nist-threshold-call.md`)

### specs (renamed from confium-report, deployed to Pages)

This repository is being **generalized into a multi-spec repository** covering all aspects of how Confium works and the various systems Confium provides. Specs include:

- Architecture overview (three-mode framework)
- Mode 1 (peer-to-peer threshold crypto) specification
- Mode 2 (TC PKI replacement) specification
- Mode 3 (TC Certificate PKI) specification
- Plugin contract specification
- Async session coordinator specification
- Share re-sharing protocol specification
- Threshold encryption interface specification
- Composite signatures specification
- Transparency log specification
- Identity / hardware interface specification
- Deployment manifest specification

Each spec includes:
- Conceptual overview
- Architectural diagram (SVG)
- Type definitions / API surface
- Wire formats (DER, JSON, TOML)
- Behavioral invariants
- Test vectors
- Cross-references to TODO.roadmap/

Existing 2022 `report.adoc` is preserved as historical context but no longer
the canonical technical reference.

### infrastructure (deprecated)

❌ **Deprecated** — per Ribose direction (2026-07-26), the `infrastructure/`
repository is no longer part of the Confium open-source workspace. Any
future infrastructure needs (DNS, coordinator hosting, transparency log
hosting, S3 buckets) will be handled via internal Ribose processes
outside the open-source project. This repository is ignored.

## Anti-goals

- **Not** forcing sync across all repos on every framework change — only when user-facing
- **Not** modifying `infrastructure` without operator approval (per CLAUDE.md)
- **Not** auto-generating bindings from Rust FFI surface (manual curation preferred for now)

## References

- `/Users/mulgogi/src/confium/CLAUDE.md` (workspace-level)
- `confium/TODO.roadmap/26-confium-framework.md` (framework vision)
- `confium/TODO.roadmap/65-project-governance.md` (project governance)
- `confium/TODO.roadmap/68-roadmap-timeline.md` (multi-year phases)
