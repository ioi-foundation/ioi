# IOI Hardware Drivers (`ioi-drivers`)

**The "Body" of the IOI Agent.**

This crate provides the native hardware implementations that allow the IOI Kernel to perceive and manipulate the host operating system. It implements the abstract driver traits defined in `ioi-api`, replacing fragile external scripts (like Python-based UI-TARS) with secure, performant, and type-safe Rust code.

## 🧩 Modules

### 1. GUI Automation (`src/gui`)
The primary "Eyes and Hands" of the agent.
*   **Vision:** High-performance screen capture using `xcap`.
*   **Input:** Deterministic mouse and keyboard injection using `enigo`.
*   **Accessibility:** Parses OS accessibility trees for semantic understanding.
*   **Safety:** Implements "Atomic Vision-Action" checks to prevent Visual Drift (clicking the wrong thing because the screen changed).

### 2. Browser Control (`src/browser`)
Direct integration with web browsers via the Chrome DevTools Protocol (CDP).
*   **Engine:** Built on `chromiumoxide`.
*   **Capabilities:** Navigation, DOM extraction, and precise element interaction.

### 3. Model Context Protocol (`src/mcp`)
A native host for the standard **Model Context Protocol**.
*   Spawns and manages external MCP servers (e.g., `filesystem`, `postgres`).
*   Bridges external tools into the Agent's context window via stdio JSON-RPC.

### 4. Universal Commerce Protocol (`src/ucp`)
The "Digital Wallet" driver for agentic commerce.
*   **Discovery:** Parses `/.well-known/ucp` manifests.
*   **Checkout:** Generates secure payment injection payloads, keeping secrets isolated from the LLM logic layer.

### 5. Terminal & OS (`src/terminal`, `src/os`)
*   **Terminal:** Sandbox-aware command execution with strict timeouts.
*   **OS:** Provides window management context (e.g., "Which application currently has focus?").

## 🛡️ Security

Unlike standard automation libraries, `ioi-drivers` is designed for **Sovereignty**:
*   **Policy Enforcement:** Drivers do not execute commands blindly. They require a valid `ActionRequest` authorized by the **Agency Firewall**.
*   **SCS Integration:** Observations (Screenshots, DOM trees) are automatically hashed and committed to the **Sovereign Context Substrate (SCS)** for auditability.