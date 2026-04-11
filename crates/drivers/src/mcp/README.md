# Model Context Protocol (MCP) Driver

This module implements the [Model Context Protocol](https://github.com/modelcontextprotocol), a standardized interface for connecting AI models to external tools and data sources.

In the IOI Kernel, MCP is the **extension bus for software integrations**. Core/kernel-grade capabilities (`file__*`, `shell__*`, browser/UI primitives) stay typed and native; MCP is used for dynamic plugin tools.

## Architecture

### 1. The Manager (`mod.rs`)
The `McpManager` is the central registry.
*   **Startup:** Reads `workload.toml` for explicitly configured extension servers.
*   **Admission Policy:** Enforces mode/tier/source/integrity/containment before launch (e.g., denies installer-style commands outside dev mode, enforces hash pins for audited/verified servers, and gates tools against explicit `allowed_tools` where configured).
*   **Discovery:** Performs the initialization handshake (`initialize`, `notifications/initialized`) and queries `tools/list` to discover capabilities.
*   **Routing:** Maintains a map of `tool_name -> server_instance` with namespaced tool IDs (`server__tool`), and rejects collisions with reserved native tool names.
*   **Provenance:** Records per-server receipts (command path/hash, version, tier, mode, admitted tool set).

### 2. Transport (`transport.rs`)
Implements the JSON-RPC 2.0 transport over **Standard Input/Output (Stdio)**.
*   **Isolation:** The MCP server runs in its own process. It cannot access the Kernel's memory.
*   **Containment:** Launches with an explicit environment contract (no ambient env inheritance) plus strict-mode process hardening hooks.
*   **Secure Config:** Sensitive environment variables are injected only if explicitly configured.

## Usage Flow

1.  **Agent:** Requests a dynamic extension tool (for example `slack__post_message`).
2.  **Kernel:** Calls `RuntimeAgentService`.
3.  **Firewall:** Intercepts the call. Checks workload lease + policy targets.
4.  **Router:** If allowed, `McpManager` resolves the correct server and applies runtime containment checks.
5.  **Execution:** The JSON-RPC request is sent to the child process via Stdin.
6.  **Response:** The child writes the result to Stdout, which is parsed and returned to the agent.
