# `ioi_swarm.types`

This module defines the core data structures used to interact with the IOI Kernel. These classes correspond directly to the Rust types defined in the kernel's `ioi-types` crate, ensuring protocol compatibility.

They use **Pydantic** to provide runtime type validation and easy serialization.

## Classes & Enums

### `enum ActionTarget`
Defines the semantic permission scope for a tool or action. This maps to the capabilities controlled by the Agency Firewall policy.

*   `NET_FETCH` (`"net::fetch"`): Outbound network requests.
*   `FS_WRITE` (`"fs::write"`): File system write operations.
*   `FS_READ` (`"fs::read"`): File system read operations.
*   `UI_CLICK` (`"ui::click"`): GUI interaction events.
*   `SYS_EXEC` (`"sys::exec"`): System shell command execution.
*   `WALLET_SIGN` (`"wallet::sign"`): Cryptographic signing operations.
*   `CUSTOM` (`"custom"`): Application-specific actions.

### `class ActionContext`
Metadata binding an action to a specific agent and session.

*   **`agent_id`** (`str`): The identifier of the agent performing the action.
*   **`session_id`** (`Optional[bytes]`): The unique session ID (32 bytes) if this action is part of a larger task or "burst".
*   **`window_id`** (`Optional[int]`): The ID of the OS window context (for GUI actions).

### `class ActionRequest`
The canonical payload submitted to the blockchain for verification.

*   **`target`** (`ActionTarget`): The type of action being requested.
*   **`params`** (`bytes`): The arguments for the action, serialized as **Canonical JSON (RFC 8785)**. This byte sequence determines the hash signed by the agent.
*   **`context`** (`ActionContext`): Execution context metadata.
*   **`nonce`** (`int`): A counter to prevent replay attacks.

### `class Receipt`
Represents the result of a submitted transaction.

*   **`tx_hash`** (`str`): The SHA-256 hash of the transaction.
*   **`block_height`** (`int`): The block number where the transaction was committed.
*   **`status`** (`str`): The execution status (e.g., "COMMITTED", "REJECTED").