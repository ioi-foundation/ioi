# `ioi_swarm.ghost`

This module implements **Ghost Mode**, a powerful feature for safe agent development described in the IOI Whitepaper §14.

**Ghost Mode** allows you to record the behavior of an agent (or a human using tools) without enforcing strict blocking policies. These recordings are then used to **synthesize** a least-privilege security policy automatically.

## Workflow

1.  **Record:** Run the agent in Ghost Mode. It executes tools freely, but every action is logged locally.
2.  **Synthesize:** The `GhostRecorder` analyzes the logs to understand what the agent *actually needs*.
3.  **Generate Policy:** It produces a `policy.json` file that whitelists exactly those actions (and their specific parameters, like domains or file paths), setting the default to `DENY_ALL`.
4.  **Enforce:** Apply this policy to the IOI Kernel to lock down the agent for production.

## Usage

```python
from ioi_swarm.ghost import GhostRecorder

# 1. Initialize the recorder
recorder = GhostRecorder()

# 2. Simulate or execute actions
# In a real integration, this is hooked into the @tool decorator
recorder.record_action("net::fetch", {"args": ["https://api.weather.gov/gridpoints/TOP/31,80/forecast"]})
recorder.record_action("fs::write", {"args": ["logs/weather.txt", "..."]})

# 3. Generate the policy
policy_json = recorder.synthesize_policy()

print(policy_json)
# Output:
# {
#   "policy_id": "auto-generated-v1",
#   "defaults": "DENY_ALL",
#   "rules": [
#     {
#       "target": "net::fetch",
#       "action": "ALLOW",
#       "conditions": { "allow_domains": ["weather.gov"] }
#     },
#     {
#       "target": "fs::write",
#       "action": "ALLOW",
#       ...
#     }
#   ]
# }
```

## API Reference

### `class GhostRecorder`

#### `record_action(target: str, params: dict)`
Logs a specific action occurrence.
*   **`target`**: The action permission scope (e.g., `net::fetch`).
*   **`params`**: The dictionary of arguments passed to the tool.

#### `synthesize_policy() -> str`
Analyzes the recorded trace log and returns a JSON string representing an IOI Agency Firewall policy (`ActionRules`). It applies heuristics to narrow the scope of permissions (e.g., extracting the domain from a URL to create an `allow_domains` condition).