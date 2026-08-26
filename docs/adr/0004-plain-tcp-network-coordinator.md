# ADR 0004 — NetworkCoordinator is plain TCP, deliberately

## Status

Accepted (stopgap; revisit when the upstream noise transport lands).

## Context

Multi-host signing needed a transport before the upstream
per-party session protocol delivers the
noise-transport replacement.

## Decision

`NetworkCoordinator` speaks one-JSON-object-per-line over plain
TCP, binary fields hex-encoded, errors returned as
`{"error": Class, "message": ...}`. It is intended for loopback or
private networks only. The seam (SigningSession) is positioned so
the noise transport replaces the framing without touching session
semantics.

## Consequences

- Do not expose it on untrusted networks.
- When the noise transport lands, retire the NDJSON framing and
  this ADR with it.
