# IOI Consensus

This crate implements the consensus algorithms for the IOI Kernel. It defines how validators communicate, agree on block ordering, and achieve finality.

The current production-facing consensus family is documented as **Aft Fault
Tolerance**: durable history converges through canonical public-state collapse
objects, while guardian-backed quorums and shared registry/log state provide
transport, tentative progress, and admissibility evidence.

Primary protocol specs:

*   [`../../docs/consensus/aft/specs/guardian_majority.md`](../../docs/consensus/aft/specs/guardian_majority.md)
*   [`../../docs/consensus/aft/specs/asymptote.md`](../../docs/consensus/aft/specs/asymptote.md)
*   [`../../docs/consensus/aft/specs/nested_guardian.md`](../../docs/consensus/aft/specs/nested_guardian.md)
*   [`../../formal/aft/guardian_majority/README.md`](../../formal/aft/guardian_majority/README.md)
*   [`../../formal/aft/nested_guardian/README.md`](../../formal/aft/nested_guardian/README.md)

## Architecture

The consensus module is designed to be **pluggable**. It implements the `ConsensusEngine` trait defined in `ioi-api`, allowing the `Orchestrator` to drive the logic without knowing the underlying algorithm details.

### Core Traits

*   **`ConsensusEngine`**: The main state machine. It accepts network events (Proposal, Vote) and chain context (Parent View) and returns a `ConsensusDecision` (Produce, Wait, ViewChange).
*   **`PenaltyMechanism`**: Defines slashing and quarantine conditions from conflicting guardian certificates, stale registry participation, and other aft safety faults.

## Engines

### GuardianMajority

The primary engine for the IOI Mainnet.
*   **Source:** `src/aft/guardian_majority/mod.rs`
*   **Model:** Leader-based transport and tentative-progress engine for the Aft Fault Tolerance family, with committee-backed non-equivocation evidence.
*   **Safety:** Constrains admissible proposals and tentative `BaseFinal` progression under the configured `AftSafetyMode`; durable AFT state is still gated by canonical collapse.
*   **Liveness:** Uses **Mirror Channels** (redundant gossip topics) to detect censorship or network partitions.

### Asymptote

The scalable sealing overlay for Aft.
*   **Model:** Fast `BaseFinal` block progression with asynchronous stratum-backed `SealedFinal` upgrades.
*   **Safety:** Durable ordering and `SealedFinal` release require deterministic close-or-abort collapse over guardian, witness / observer, registry, and transparency-log state.
*   **Operational Use:** High-risk external effects should require `SealedFinal`; ordinary block ordering continues on the fast path.

### Witness/Audit Sampling

*   **Source:** `src/aft/experimental/`
*   **Role:** Support for NestedGuardian witness assignment, confidence tracking, and observability helpers.
*   **Scope:** These components inform witness assignment and degraded-mode diagnostics, but they do not replace the core guardian-majority consensus path.

## Structure

*   **`src/aft/mod.rs`**: The Aft Fault Tolerance wrapper used by production `Aft` nodes.
*   **`src/aft/guardian_majority/`**: The Aft deterministic engine and its subcomponents.
*   **`src/aft/experimental/`**: Sampling, sortition, and confidence helpers used by the NestedGuardian witness path.
*   **`src/common/`**: Shared logic for validator set management and penalties.
*   **`src/service.rs`**: The `PenaltiesService`, a system service exposed to the transaction layer allowing users to submit fraud proofs (`report_misbehavior`).
