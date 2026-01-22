# Public RPC API

**Package:** `ioi.public.v1`

This directory defines the user-facing API exposed by the **Orchestrator**. It serves as the gateway for CLI tools, Wallets, and the Autopilot UI. It proxies relevant read requests to the Workload and submits writes to the P2P network.

## Services

### `PublicApi`

#### Transaction Management
*   **`SubmitTransaction`**: Accepts a canonical SCALE-encoded transaction. Returns a hash immediately or an `ApprovalToken` request if the Agency Firewall intercepts the action.
*   **`GetTransactionStatus`**: Polls for the commit status of a transaction hash.

#### State & Data
*   **`QueryState`**: Returns a Merkle proof for a specific key/root.
*   **`GetBlockByHeight`**: Fetches block data.
*   **`GetContextBlob`**: Retrieves raw context data (e.g., screenshots, large logs) stored in the Sovereign Context Substrate (SCS) by hash.

#### Real-Time Telemetry
*   **`SubscribeEvents`**: A streaming RPC that pushes `ChainEvent` messages to the UI. This powers the "Visual Sovereignty" features. Events include:
    *   `AgentThought`: Internal monologue/reasoning steps.
    *   `ActionIntercepted`: Firewall gates (Allow/Block/Ask).
    *   `BlockCommitted`: Chain progress.
    *   `GhostInput`: User physical inputs (mouse/keyboard events).

#### Intent Resolution
*   **`DraftTransaction`**: The "God Mode" feature. Accepts a natural language string (e.g., "Send 50 tokens to Bob"), uses the local LLM to resolve it into a valid transaction payload, and returns the unsigned bytes for user review and signing.