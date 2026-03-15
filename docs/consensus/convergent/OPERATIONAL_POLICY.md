# Convergent Operational Policy

This document is the operator-facing contract for `GuardianMajority`.

## Committee Admission

Production validator guardian committees must satisfy all of the following:

- strict-majority threshold
- even-sized committees
- minimum committee size `>= 4`
- at least 2 distinct providers
- at least 2 distinct regions
- at least 2 distinct host classes
- at least 2 distinct key-authority classes across `TPM2`, `PKCS#11`, `CloudKms`
- non-empty transparency log identifier

The guardian registry enforces these requirements at committee-registration time.

## Witness Admission

Witness committees must satisfy the same structural majority rule and must:

- be registered on-chain
- be part of the active witness set for the epoch
- use the epoch seed published on-chain for deterministic assignment
- carry a witness-log checkpoint when checkpoint cadence is non-zero

## Outage Thresholds

A validator is expected to self-quarantine when:

- its guardian committee cannot reach threshold
- its registry epoch is stale
- required checkpoint evidence is unavailable
- in NestedGuardian mode, assigned witnesses are unavailable beyond the configured reassignment depth

Block production should pause when a local validator cannot obtain:

- a valid guardian certificate for the proposal slot
- a current registry view
- a required checkpoint

## Slashing Inputs

The chain treats the following as slashable evidence:

- conflicting guardian certificates for the same slot
- conflicting witness certificates for the same slot
- stale-manifest participation
- checkpoint inconsistency
- deterministic witness omission after reassignment evidence exists

## SLO Targets

Before production hardening is declared complete, operators should measure:

- guardian certificate latency p95 / p99
- registry freshness lag
- checkpoint freshness lag
- witness certificate latency in witness-mode testnets
- validator self-quarantine rate
