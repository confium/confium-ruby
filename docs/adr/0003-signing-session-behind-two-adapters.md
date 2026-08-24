# ADR 0003 — SigningSession is the deep module; coordinators are adapters

## Status

Accepted (2026-08-25, PR #76).

## Context

The session existed only as a bare Hash inside `Coordinator`;
`NetworkCoordinator` copied the same bookkeeping one layer out, so
the wire path could drift from the in-process path. Duplicate
signer submissions counted twice toward the threshold — one signer
could meet any threshold alone.

## Decision

`Confium::TC::SigningSession` owns the semantics: the state
machine, signer identity (commitments and shares keyed by signer
id; duplicates raise `ValidationError`), and the CMP20/GG18
combine. `Coordinator` is the in-process adapter (quorum-scoped
session registry); `NetworkCoordinator` is the TCP/NDJSON adapter.
Two adapters over one seam is what makes the seam real.

Aggregate stays callable after completion: the combine randomizes
its nonce, so a retrying network client gets a fresh valid
signature over the same shares (documented, spec-pinned).

## Consequences

- State-machine bugs have one home; the wire protocol tests become
  pure framing tests.
- Unknown session ids raise `NotFoundError`; below-threshold
  aggregation raises `ThresholdError` with have/need counts.
