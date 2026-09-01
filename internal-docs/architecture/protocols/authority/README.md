# IOI Authority Protocol Research Corpus

Status: internal protocol research corpus index; non-canonical.
Authority: `docs/architecture/` owners and accepted ADRs are canonical and win
on drift; this corpus may identify gaps and test candidates but cannot amend a
profile or implementation claim.
Supports: the canonical Machine Authority and IOI Authority Protocol owners.
Last alignment pass: 2026-08-30.

## Scope

This corpus develops and pressure-tests the smallest public protocol surfaces
needed for action authorization, portable delegated authority, governed exact
effects, and the complete Machine Authority claim.

It concentrates on specification sufficiency, typed refusals, trust-input
closure, crash/concurrency behavior, profile downgrade resistance, independent
implementation, and release evidence. Product UX, marketplace economics, AIIP,
and L1 settlement remain with their owners.

## Candidate Profile Family

- `ioi_authority_core_v1`
- `ioi_delegated_authority_v1`
- `ioi_governed_effect_v1`
- `ioi_machine_authority_complete_v1`

The canonical protocol owner defines these target profile ids. This directory
contains no released profile or conformance entitlement.

## Canonical Inputs

- [`machine-authority.md`](../../../../docs/architecture/foundations/machine-authority.md)
- [`ioi-authority-protocol.md`](../../../../docs/architecture/foundations/ioi-authority-protocol.md)
- [`authority-and-access.md`](../../../../docs/architecture/foundations/objects/authority-and-access.md)
- [`invariants.md`](../../../../docs/architecture/foundations/invariants.md)
- [`security-privacy-policy-invariants.md`](../../../../docs/architecture/foundations/security-privacy-policy-invariants.md)
- [daemon `doctrine.md`](../../../../docs/architecture/components/daemon-runtime/doctrine.md)
- [`events-receipts-delivery-bundles.md`](../../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md)
- [wallet.network `doctrine.md`](../../../../docs/architecture/components/wallet-network/doctrine.md)
- [`api-authority-scopes.md`](../../../../docs/architecture/components/wallet-network/api-authority-scopes.md)
- [`protocol-governance-neutrality.md`](../../../../docs/architecture/foundations/protocol-governance-neutrality.md)
- [`canon-to-code-delta.md`](../../../../docs/architecture/_meta/canon-to-code-delta.md)
- [ADR 0032](../../../../docs/decisions/0032-independently-implemented-client-definition.md)
- [ADR 0033](../../../../docs/decisions/0033-licensing-split-surface-and-license-manifest.md)
- [ADR 0040](../../../../docs/decisions/0040-make-machine-authority-the-category-and-ioi-authority-the-portable-protocol.md)

## Corpus Layout

- [`threat-model.md`](./threat-model.md) — adversaries, assets, trust
  boundaries, failures, and questions requiring promotion.
- [`conformance-and-release-gates.md`](./conformance-and-release-gates.md) —
  candidate profile vectors, refusal parity, independence, and release evidence.
- [`twin/`](./twin/) — the planned clean-room retrospective evidence verifier
  for composed Delegated Authority and Governed Effect candidate manifests; no
  implementation or result is claimed yet.

## Evidence Ladder

```text
owner contract
  -> candidate surface manifest
  -> positive and independently derived adversarial vectors
  -> internal clean-room twin
  -> separate codegen/transport
  -> organizationally independent implementation
  -> outside-operated effect and exit demonstration
```

Each step retains an explicit `proves` and `does_not_prove` statement.

## Promotion Boundary

- Field, lifecycle, or claim changes go first to the canonical owner or an ADR.
- Code maturity changes go to the subject owner and canon-to-code delta.
- Exact released bytes go to the future public protocol artifact and its frozen
  manifest.
- This corpus is retired or rewritten when its questions are resolved; it is
  never cited as public conformance evidence.

## Current Research Questions

1. What exact minimal closure makes the Core profile useful without importing
   grant or effect claims?
2. What signed object supplies complete delegation depth, re-delegation, and
   descendant-allocation closure without mutating grant v3?
3. Which receipt/signature construction authenticates completed admission and
   outcome wrappers without circular hashing?
4. What is the smallest effect-neutral ABI that lets a non-Hypervisor PEP derive
   and admit its actual effect deterministically?
5. Which refusal codes must be profile-stable versus implementation-specific?
6. How are key/revocation/currentness inputs acquired and pinned without making
   a hosted discovery service mandatory?
7. Which crash points distinguish no invocation, claimed/unknown invocation,
   observed effect, and safe retry?
8. What independence evidence is required before the complete profile can be
   called stable?
