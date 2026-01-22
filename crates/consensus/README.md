# IOI Consensus

This crate implements the consensus algorithms for the IOI Kernel. It defines how validators communicate, agree on block ordering, and achieve finality.

## Architecture

The consensus module is designed to be **pluggable**. It implements the `ConsensusEngine` trait defined in `ioi-api`, allowing the `Orchestrator` to drive the logic without knowing the underlying algorithm details.

### Core Traits

*   **`ConsensusEngine`**: The main state machine. It accepts network events (Proposal, Vote) and chain context (Parent View) and returns a `ConsensusDecision` (Produce, Wait, ViewChange).
*   **`PenaltyMechanism`**: Defines the slashing conditions. Because IOI emphasizes hardware-root-of-trust, penalties are often based on cryptographic proofs of equivocation (broken monotonicity).

## Engines

### A-DMFT (Adaptive Deterministic Mirror Fault Tolerance)

The primary engine for the IOI Mainnet.
*   **Source:** `src/admft.rs`
*   **Model:** Leader-based BFT with a hardware anchor.
*   **Safety:** Relies on the **Guardian** container to enforce monotonic counter increments on signatures. This prevents a single key from signing two different blocks at the same height, reducing the safety threshold from the standard BFT $n > 3f$ to $n > 2f$.
*   **Liveness:** Uses **Mirror Channels** (redundant gossip topics) to detect censorship or network partitions.

## Structure

*   **`src/admft.rs`**: The implementation of the A-DMFT state machine.
*   **`src/common/`**: Shared logic for validator set management and penalties.
*   **`src/service.rs`**: The `PenaltiesService`, a system service exposed to the transaction layer allowing users to submit fraud proofs (`report_misbehavior`).