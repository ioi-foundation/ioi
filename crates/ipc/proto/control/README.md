# Control Plane & Secure Egress Protocol

**Package:** `ioi.control.v1`

This directory defines the high-frequency signaling and security protocols used for **Agentic AI** workflows and **Secure Enclaves**. It connects the Workload container to the Orchestrator (for compute scheduling) and the Guardian (for network security).

## Services

### `WorkloadControl`
*Exposed by: Workload Container*
*Called by: Orchestrator*

This service drives the **AI Inference Runtime**. Unlike standard blockchain transactions, AI inference often requires massive context windows that exceed gRPC limits.

*   **`LoadModel`**: Pre-loads a specific AI model (by hash) into accelerator memory (GPU/NPU).
*   **`ExecuteJob`**: Triggers an inference task.
    *   **Zero-Copy Input/Output**: The request does not contain the data. Instead, it contains `input_offset` and `input_length` pointing to the **Shared Memory Data Plane**. The Workload reads tensors directly from memory and writes results back to `output_offset`.

### `GuardianControl`
*Exposed by: Guardian Container*
*Called by: Workload*

This service implements the **Secure Egress** pattern. The Workload container is air-gapped and holds no API keys. When an Agent needs to access the outside world (e.g., call OpenAI or Stripe), it delegates the call to the Guardian.

*   **`SecureEgress`**:
    1.  Workload requests an HTTP call (Method, URL, Body).
    2.  Workload specifies a `secret_id` (reference to a key stored in the Guardian's vault) and an optional `json_patch_path`.
    3.  Guardian decrypts the key in memory, injects it into the request (Header or JSON body), performs the TLS handshake, and executes the request.
    4.  Guardian returns the response body + a **Cryptographic Attestation** (signature) proving that the network traffic occurred.