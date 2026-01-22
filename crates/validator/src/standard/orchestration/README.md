# Orchestration Container (Control Plane)

The Orchestrator is the central coordinator of the IOI Node. It acts as the gateway for all external input (P2P network, RPC) and acts as the gatekeeper for all execution.

## Core Components

### 1. Main Event Loop (`mod.rs`)
The orchestrator runs a `tokio::select!` loop that processes disparate event streams:
*   **Network Events:** Incoming blocks, transactions, and peer messages from `libp2p`.
*   **Consensus Ticks:** Signals from the A-DMFT engine to produce blocks.
*   **Ingestion Results:** Validated transactions returning from the ingestion worker.

### 2. Ingestion Worker (`ingestion.rs`)
To prevent the main loop from stalling during heavy validation, transaction ingestion is offloaded to a dedicated worker thread.
*   **Pre-Flight Checks:** Stateless signature verification.
*   **Policy Enforcement:** The **Agency Firewall** evaluates the transaction intent against active policies (e.g., blocking `fs::write` if unauthorized).
*   **Workload Check:** Performs `check_tx` via IPC to ensure stateful validity (nonce, balance).

### 3. Mempool (`mempool.rs`)
A sharded, thread-safe memory pool.
*   **Sharding:** Uses `SHARD_COUNT = 64` mutexes to minimize contention between the ingestion worker (writer) and the block producer (reader).
*   **Nonce Ordering:** Maintains strict nonce ordering per account to ensure valid block templates.

### 4. Remote State View (`remote_state_view.rs`)
The Orchestrator does not have direct access to the database (RocksDB/Redb). Instead, it uses an `AnchoredStateView`.
*   This is a proxy that fetches data from the **Workload** via IPC.
*   **Verification:** It cryptographically verifies Merkle proofs returned by the Workload against the trusted state root, ensuring the Workload cannot lie about the state.

## Consensus Integration

The Orchestrator holds the `ConsensusEngine` (A-DMFT).
1.  **Decide:** It asks the engine "What should I do?" (Produce, Wait, Vote).
2.  **Sign:** If producing, it constructs a block header and sends it to the **Guardian** for signing.
3.  **Process:** It sends the block to the **Workload** for execution/commit.
4.  **Broadcast:** It gossips the valid block to the P2P network.