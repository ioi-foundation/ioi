# A-DMFT: Adaptive Deterministic Mirror Fault Tolerance

A-DMFT is the consensus algorithm powering the IOI Kernel. It is designed specifically for networks where validators are equipped with secure hardware (Guardians/TEEs).

It differs from traditional BFT algorithms (like PBFT or Tendermint) by replacing probabilistic timeout/voting mechanisms with **Deterministic Monotonicity**.

## The Core Concept: Guardian-Anchored Safety

In standard BFT, safety ($n > 3f$) relies on validators not double-voting. This is enforced by collecting quorum certificates. If a leader equivocates (proposes two blocks at the same height), the network must detect it via conflicting votes.

In A-DMFT, safety ($n > 2f$) is enforced *physically* by the Guardian:
1.  **Monotonicity:** The Guardian hardware maintains a strictly increasing counter.
2.  **Binding:** Every signature produced by the Guardian includes this counter and a hash of the previous signature (the Trace).
3.  **The Invariant:** It is physically impossible for a single Guardian to sign two different block headers at the same height without breaking the counter sequence or the hash chain.

Because equivocation is prevented at the hardware source, the consensus protocol simplifies significantly. We treat the Guardian signature as a "Proof of Unique Proposal."

## Algorithm Phases

### 1. View Definition (`decide`)
A-DMFT divides time into linear **Views**.
*   The Leader for a view `v` at height `h` is deterministically calculated: `Leader = ValidatorSet[(h + v) % N]`.
*   If you are the leader, you propose immediately.
*   If you are not the leader, you wait for a block signed by the expected leader with the correct View ID.

### 2. Mirror Channels (`handle_block_proposal`)
To ensure liveness even if a leader is slow, A-DMFT uses **Mirror Channels**.
*   Blocks are broadcast on two distinct gossip topics: `Mirror A` and `Mirror B`.
*   A validator accepts a block if it is valid on *either* mirror.
*   **Divergence Detection:** If a validator sees different valid blocks on Mirror A and Mirror B for the same height/view, it constitutes cryptographic proof of a broken Guardian (or a compromised private key). This triggers an immediate **View Change**.

### 3. View Change (`handle_view_change`)
If the leader fails to produce a block (or produces conflicting ones), validators broadcast a `ViewChangeVote`.
*   Unlike Tendermint, we don't need to wait for a timeout if we detect divergence. The proof of divergence itself justifies the view change.
*   Once a quorum ($2f+1$) of view change votes is received, the network advances to `v+1`, selecting a new deterministic leader.

## Benefits for Agents

1.  **Speed:** In the happy path (honest leader), block production is limited only by network latency, not artificial timeouts.
2.  **Finality:** A-DMFT offers **Single-Slot Finality**. Once a block is committed with a valid Guardian signature and no divergence is seen, it is final.
3.  **Accountability:** Any safety violation is attributable to a specific hardware signature trace, allowing for automated slashing.