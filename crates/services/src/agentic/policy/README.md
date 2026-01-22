# The Agency Firewall

The Agency Firewall is the security boundary for autonomous agents. It solves the **Alignment Problem** at the runtime level by enforcing deterministic constraints on agent actions *before* they are executed.

## Core Concepts

### 1. Action Request (`types/app/action.rs`)
Before any driver is invoked, the agent's intent is normalized into a canonical `ActionRequest`.
*   **Target:** `net::fetch`, `fs::write`, `wallet::sign`, etc.
*   **Params:** The arguments (URL, file path, amount).

### 2. Rules (`rules.rs`)
A policy consists of a list of `Rule` objects.
*   **Pattern Matching:** A rule matches an action if the `target` matches (e.g., `fs::*`).
*   **Conditions:** Fine-grained checks (e.g., `allow_domains`, `max_spend`, `allow_paths`).

### 3. Verdict (`Verdict` enum)
The policy engine evaluates the request against the active rules and returns one of three verdicts:

*   **`Allow`**: The action proceeds immediately.
*   **`Block`**: The action is rejected. The agent receives an error ("Blocked by Policy") and must try a different approach.
*   **`RequireApproval` (The "Gate")**:
    *   The action is halted.
    *   The agent state is set to `Paused`.
    *   The Kernel emits a `FirewallInterception` event to the UI.
    *   The user sees a pop-up: *"Agent wants to send 100 USDC. Approve?"*
    *   If approved, the UI generates an **`ApprovalToken`**, which is submitted via `resume@v1` to unlock the action.

## Default Policy
The `ioi-local` node defaults to **Interactive Mode** (`DefaultPolicy::RequireApproval`). This means the agent can try anything, but the user remains in the loop for any action not explicitly whitelisted.