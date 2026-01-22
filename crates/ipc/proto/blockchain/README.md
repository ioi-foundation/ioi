# Blockchain Internal IPC Protocol

**Package:** `ioi.blockchain.v1`

This directory defines the **Consensus-to-Execution** interface. It is the primary communication channel between the **Orchestrator** (which handles networking and consensus) and the **Workload** (which holds the state, VM, and transaction logic).

These services allow the Orchestrator to drive the state machine without having direct access to the state itself.

## Architecture: Hybrid Data Plane

This protocol supports the IOI Kernel's **Hybrid Data Plane**.

*   **Control Messages:** Standard gRPC messages (metadata, headers, small queries).
*   **Bulk Data:** Large payloads (e.g., Blocks containing heavy transactions) can be passed via the `SharedMemoryHandle` primitive. This allows zero-copy transfer of data between containers using memory-mapped regions.

## Services

### `ChainControl`
Manages the lifecycle of the blockchain state machine.
*   **`ProcessBlock`**: The core execution loop. Sends a block (inline or via shmem) to the Workload for execution and state commitment.
*   **`GetBlocksRange`**: Used during sync to fetch historical blocks from storage.
*   **`UpdateBlockHeader`**: Allows the Consensus engine to retroactively update the header of a committed block (e.g., adding Oracle signatures).
*   **`GetStatus` / `GetGenesisStatus`**: Liveness and synchronization checks.

### `StateQuery`
Provides deep inspection of the cryptographic state tree.
*   **`CheckTransactions`**: Runs "Ante Handlers" (stateless validity + nonce checks) before admitting transactions to the mempool.
*   **`QueryStateAt`**: Returns a Merkle-proof (membership or non-membership) for a key at a specific root.
*   **`QueryRawState`**: Fast lookups for local operations (no proof generation).
*   **`PrefixScan`**: Iterates over keys in the state tree.

### `ContractControl`
Direct interface to the Virtual Machine (WASM).
*   **`DeployContract`**: Instantiates new code.
*   **`CallContract`**: Executes a state-changing transaction on a contract.
*   **`QueryContract`**: Executes a read-only method on a contract.

### `StakingControl`
Manages the validator set.
*   **`GetStakedValidators`**: Retrieves current weights.
*   **`GetNextStakedValidators`**: Retrieves the set scheduled for the next epoch.

### `SystemControl`
Debugging and maintenance operations.
*   **`DebugPinHeight` / `DebugUnpinHeight`**: Protects specific state versions from Garbage Collection (used by ZK provers or long-running queries).
*   **`DebugTriggerGc`**: Manually forces a database compaction pass.