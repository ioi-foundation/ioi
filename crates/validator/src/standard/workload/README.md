# Workload Container (Execution Plane)

The Workload container is the sandbox where code execution happens. It is designed to be ephemeral and isolated; if a malicious smart contract or AI model crashes the Workload, the Orchestrator and Guardian remain unaffected.

## Hybrid IPC Architecture

Communication with the Orchestrator uses a dual-path system:

1.  **Control Plane (gRPC):**
    *   Defined in `ipc/grpc_blockchain.rs`.
    *   Handles low-latency, small-payload signals like `ProcessBlock`, `GetStatus`, and `DeployContract`.
    *   Uses `tonic`.

2.  **Data Plane (Shared Memory):**
    *   Handles high-bandwidth payloads (AI Contexts, Large Blocks).
    *   Uses a memory-mapped file (`/dev/shm`) and `rkyv` for Zero-Copy deserialization.
    *   See `ipc/grpc_control.rs`: The `ExecuteJob` RPC passes a *pointer* (offset/length) to the data in shared memory, avoiding expensive serialization/copying overhead.

## Inference Runtime

The Workload manages the execution of AI models (the "Alien Intelligence").

### JIT Hydration (`hydration.rs`)
Models are not baked into the binary. They are loaded Just-In-Time from disk or IPFS.
*   **Integrity:** Before loading, the hydrator calculates the SHA-256 hash of the `.gguf` file and compares it against the on-chain registry hash.
*   **Warm Start:** Tracks loaded models in VRAM to skip reloading if the same model is requested sequentially.

### Hardware Drivers (`drivers/`)
*   **`cpu.rs`:** Uses `candle` to run quantized models on the CPU (universal compatibility).
*   **`verified_http.rs`:** A special driver that routes inference requests to external APIs (OpenAI/Anthropic) via the **Guardian**. This ensures the Workload never sees the API keys (Bring Your Own Key).