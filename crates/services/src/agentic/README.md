# Agentic Services

This module implements the core logic for autonomous agents within the IOI Kernel. It transforms the blockchain from a passive ledger into an active orchestration layer for AI "Thoughts" and "Actions."

## Structure

*   **`desktop/`**: The `DesktopAgentService`. This is the high-level state machine that manages long-running agent sessions, history, and tool execution loops.
*   **`policy.rs` & `rules.rs`**: The **Agency Firewall**. The deterministic security kernel that sits between the AI model's output and the actual execution drivers.
*   **`scrubber.rs`**: The **Privacy Airlock**. A system for sanitizing data (PII/Secrets) before it leaves the user's secure environment.
*   **`intent.rs`**: The **Intent Resolver**. Maps natural language user requests (e.g., "Send money to Bob") into precise, signable transactions.
*   **`grounding.rs`**: Translates fuzzy AI outputs (e.g., "Click the login button") into absolute OS coordinates.