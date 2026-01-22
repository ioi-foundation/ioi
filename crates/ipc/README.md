# IOI Inter-Process Communication (IPC)

The `ioi-ipc` crate defines the communication layer between the isolated containers of the IOI Kernel (Orchestrator, Workload, Guardian).

It implements a **Hybrid Architecture** designed to solve the specific performance challenges of AI-integrated blockchains: low-latency control signaling mixed with massive, high-bandwidth data payloads (e.g., RAG contexts, model weights).

## The Hybrid Model

Traditional blockchains use simple RPC or P2P messages. However, passing a 1GB vector database or a 4MB block via gRPC (Protobuf) incurs massive serialization/deserialization overhead and memory copying.

IOI solves this by splitting communication into two planes:

### 1. Control Plane (gRPC)
*   **Technology:** `tonic` (Rust implementation of gRPC).
*   **Purpose:** High-frequency, low-latency signals and state queries.
*   **Examples:**
    *   "Process this block header."
    *   "Get current block height."
    *   "Execute Job #123 (Data is at offset X)."
*   **Schema:** Defined in `proto/*.proto`.

### 2. Data Plane (Shared Memory)
*   **Technology:** Memory-mapped files (`/dev/shm`) and `rkyv` (Zero-Copy deserialization).
*   **Purpose:** Bulk data transfer without copying.
*   **Examples:**
    *   **Context Slices:** Passing 50MB of retrieved documents to the LLM.
    *   **Inference Outputs:** Receiving large tensor arrays.
    *   **Blocks:** Transferring full block bodies during synchronization.
*   **Mechanism:**
    1.  Sender (e.g., Orchestrator) writes data to the shared memory region using `rkyv`.
    2.  Sender passes a `SharedMemoryHandle { offset, length }` via gRPC to the Receiver.
    3.  Receiver (e.g., Workload) reads the struct *in-place* without deserializing or copying.

## Protocol Definitions (`proto/`)

The `.proto` files define the strict contract for the Control Plane.

*   **`blockchain.proto`**: Core chain operations.
    *   `ProcessBlock`: Accepts a `oneof` payload—either inline bytes (for small blocks) or a `SharedMemoryHandle` (for large blocks).
    *   `QueryState`: Merkle proof queries.
*   **`control.proto`**: AI and Workload management.
    *   `LoadModel`: Instructions to load a model hash into VRAM.
    *   `ExecuteJob`: Trigger an inference task using inputs stored in the Data Plane.
    *   `SecureEgress`: Request the Guardian to perform an external API call.
*   **`public.proto`**: The external-facing API for the `ioi-cli` and UI.

## Zero-Copy Serialization (`src/data.rs`)

This module defines the Rust structures used in the Data Plane. They are annotated with `#[derive(Archive, Deserialize, Serialize)]` from `rkyv`.

*   **`AgentContext`**: The full context window for an agent, including vector embeddings and text tokens.
*   **`Tensor`**: Raw float arrays for model I/O.
*   **`ContextSlice`**: An encrypted, provenance-tracked slice of user data.

By using `rkyv`, we ensure that complex structures like `Vec<f32>` or nested structs have a memory representation on disk that is identical to their representation in memory, allowing for instant access.