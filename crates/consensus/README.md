# IOI Consensus

This crate implements the consensus algorithms for the IOI Kernel. It defines how validators communicate, agree on block ordering, and achieve finality.

The current production-facing consensus family is documented as **Convergent Fault Tolerance**: finalized history must converge through certified quorums, guardian committee evidence, and shared registry/log state.

Primary protocol specs:

*   [`../../docs/consensus/convergent/specs/guardian_majority.md`](../../docs/consensus/convergent/specs/guardian_majority.md)
*   [`../../docs/consensus/convergent/specs/nested_guardian.md`](../../docs/consensus/convergent/specs/nested_guardian.md)
*   [`../../formal/convergent/guardian_majority/README.md`](../../formal/convergent/guardian_majority/README.md)
*   [`../../formal/convergent/nested_guardian/README.md`](../../formal/convergent/nested_guardian/README.md)

## Architecture

The consensus module is designed to be **pluggable**. It implements the `ConsensusEngine` trait defined in `ioi-api`, allowing the `Orchestrator` to drive the logic without knowing the underlying algorithm details.

### Core Traits

*   **`ConsensusEngine`**: The main state machine. It accepts network events (Proposal, Vote) and chain context (Parent View) and returns a `ConsensusDecision` (Produce, Wait, ViewChange).
*   **`PenaltyMechanism`**: Defines slashing and quarantine conditions from conflicting guardian certificates, stale registry participation, and other convergent safety faults.

## Engines

### GuardianMajority

The primary engine for the IOI Mainnet.
*   **Source:** `src/convergent/guardian_majority/mod.rs`
*   **Model:** Leader-based BFT for the Convergent Fault Tolerance family, with committee-backed non-equivocation evidence.
*   **Safety:** Relies on guardian committees, receipts, and externalized evidence to constrain equivocation under the configured `ConvergentSafetyMode`.
*   **Liveness:** Uses **Mirror Channels** (redundant gossip topics) to detect censorship or network partitions.

### Witness/Audit Sampling

*   **Source:** `src/convergent/experimental/`
*   **Role:** Support for NestedGuardian witness assignment, confidence tracking, and observability helpers.
*   **Scope:** These components inform witness assignment and degraded-mode diagnostics, but they do not replace the core guardian-majority consensus path.

## Structure

*   **`src/convergent/mod.rs`**: The Convergent Fault Tolerance wrapper used by production `Convergent` nodes.
*   **`src/convergent/guardian_majority/`**: The Convergent deterministic engine and its subcomponents.
*   **`src/convergent/experimental/`**: Sampling, sortition, and confidence helpers used by the NestedGuardian witness path.
*   **`src/common/`**: Shared logic for validator set management and penalties.
*   **`src/service.rs`**: The `PenaltiesService`, a system service exposed to the transaction layer allowing users to submit fraud proofs (`report_misbehavior`).
