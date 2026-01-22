# Desktop Agent Service

The `DesktopAgentService` is the "Brain" of the local User Node. It manages the lifecycle of autonomous tasks, maintaining the state (memory, history, goals) across blocks.

## Session Lifecycle

An agent session follows a strict state machine:

1.  **`start@v1`**:
    *   Initializes a new session with a `goal` and `budget`.
    *   Creates the initial `AgentState` in the blockchain state.
    *   Logs the user's prompt into the history.

2.  **`step@v1`**:
    *   The "Heartbeat" of the agent. Called repeatedly by the `AgentDriver` background task.
    *   **Observe:** Captures the screen and accessibility tree (via `GuiDriver`).
    *   **Think:** Sends the context + history to the Inference Engine (e.g., GPT-4 or Local Llama).
    *   **Act:** Parses the tool call (e.g., `browser__navigate`) from the response.
    *   **Firewall:** Passes the action to the **Agency Firewall**. If blocked, the step fails or pauses.
    *   **Execute:** If allowed, executes the action via hardware drivers.
    *   **Record:** Saves the `StepTrace` (Input -> Thought -> Action -> Result) to the chain state.

3.  **`resume@v1`**:
    *   Used when an agent is `Paused` (e.g., waiting for user approval on a dangerous action).
    *   Takes a signed `ApprovalToken` from the user.
    *   Unblocks the agent, allowing it to retry the action that triggered the pause.

## State Management (`types.rs`)

The service persists the agent's cognition in the state tree:

*   **`AgentState`**:
    *   `history`: A list of `ChatMessage` (User/Assistant/System) objects.
    *   `short_term_memory`: Recent observations.
    *   `long_term_memory`: References to vector embeddings in the SCS.
    *   `status`: Running, Paused, Completed, Failed.