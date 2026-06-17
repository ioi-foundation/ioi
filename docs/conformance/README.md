# Conformance Contracts

Status: canonical conformance index.
Canonical owner: this file for the conformance tree and contract ownership.
Supersedes: product or architecture prose that treats conformance as tied to one
agent runtime, IDE, or harness.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Purpose

Conformance contracts define the testable invariants for bounded autonomous
work. They are not product surfaces and they are not a separate runtime.

The current architecture is heterogeneous:

```text
Hypervisor Core coordinates.
Harness profiles, agent harnesses, modules, tools, workers, and AIIP peers
execute under daemon/domain gates.
wallet.network authorizes.
Agentgres records admitted truth.
Receipts and observations decide completion.
```

Conformance keeps that architecture from collapsing into hidden shortcuts.

## Active Contract Families

| Family | Owner | Purpose |
| --- | --- | --- |
| [`hypervisor-core/intent-resolution.md`](./hypervisor-core/intent-resolution.md) | Hypervisor Core | Deterministic intent collapse, primitive capability ontology, provider/harness shortcut bans. |
| [`hypervisor-core/effect-execution.md`](./hypervisor-core/effect-execution.md) | Hypervisor Core | Effect execution, receipt-driven verification, terminal-state gates, remediation boundaries. |
| [`hypervisor-core/harness-profile-adapter.md`](./hypervisor-core/harness-profile-adapter.md) | Hypervisor Core | Minimum adapter contract for third-party harnesses, model runtimes, modules, and worker profiles. |

## Compatibility Labels

`CIRC` and `CEC` remain stable labels for traces, receipts, evidence bundles,
legacy specs, and tests:

```text
CIRC = Intent Resolution Contract
CEC  = Effect Execution Contract
```

The active documents now live under `docs/conformance/hypervisor-core/` because
the invariants apply across Hypervisor Core and heterogeneous harnesses, not one
desktop-agent runtime.

## Boundary

Conformance contracts may define:

- required typed objects;
- receipt fields;
- replay material;
- profile-specific tests;
- forbidden shortcuts;
- failure classes;
- migration obligations.

They do not define:

- product IA;
- model prompts;
- a single blessed harness;
- Agentgres schema ownership;
- wallet.network policy ownership;
- IOI L1 settlement triggers.

## Anti-Patterns

- Treating conformance as optional because a third-party harness is used.
- Treating a model reply, UI toast, or debug string as completion truth.
- Embedding provider, model, or harness shortcuts in intent resolution.
- Retrying effects invisibly inside one admitted operation instead of opening a
  new proposal, gate, receipt, and observation path.
- Letting product clients bypass Hypervisor Core/domain APIs for consequential
  work.
