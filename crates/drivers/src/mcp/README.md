# Model Context Protocol (MCP) Driver

This module implements the [Model Context Protocol](https://github.com/modelcontextprotocol), a standardized interface for connecting AI models to external tools and data sources.

In the IOI Kernel, MCP acts as the **"Device Driver" layer for Software**. Instead of hardcoding integrations for filesystems, databases, or APIs, the Kernel spawns lightweight MCP servers as child processes and routes agent requests to them.

## Architecture

### 1. The Manager (`mod.rs`)
The `McpManager` is the central registry.
*   **Startup:** Reads `workload.toml` to find configured servers (e.g., `filesystem`, `postgres`).
*   **Spawning:** Uses `std::process::Command` to launch the server binary (e.g., `npx -y @modelcontextprotocol/server-filesystem`).
*   **Discovery:** Performs the initialization handshake (`initialize`, `notifications/initialized`) and queries `tools/list` to discover capabilities.
*   **Routing:** Maintains a map of `tool_name -> server_instance`. It namespaces tools to prevent collisions (e.g., `filesystem__write_file`).

### 2. Transport (`transport.rs`)
Implements the JSON-RPC 2.0 transport over **Standard Input/Output (Stdio)**.
*   **Isolation:** The MCP server runs in its own process. It cannot access the Kernel's memory.
*   **Secure Config:** Sensitive environment variables (API keys) are injected into the child process environment *only* at spawn time, resolved from the Guardian's secure vault.

## Usage Flow

1.  **Agent:** "I want to write to a file." -> LLM outputs JSON: `{"name": "filesystem__write_file", "args": {...}}`.
2.  **Kernel:** Calls `DesktopAgentService`.
3.  **Firewall:** Intercepts the call. Checks if `filesystem__write_file` is allowed by policy.
4.  **Router:** If allowed, `McpManager` looks up the handler for `filesystem`.
5.  **Execution:** The JSON-RPC request is sent to the child process via Stdin.
6.  **Response:** The child writes the result to Stdout, which is parsed and returned to the agent.