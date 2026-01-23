# `ioi_swarm.agent`

This module contains the core `Agent` class, which serves as the primary abstraction for defining autonomous entities within the IOI Swarm framework.

## Overview

An `Agent` in the IOI ecosystem is composed of three main pillars:
1.  **Identity:** A unique identifier (`name`).
2.  **Governance:** A `policy_id` that links the agent to a specific set of security rules enforced by the IOI Kernel's Agency Firewall.
3.  **Capabilities:** A registry of **Tools** that the agent can invoke to interact with the digital or physical world.

## Usage

```python
from ioi_swarm.agent import Agent
from ioi_swarm.tools import tool, ActionTarget

# 1. Define a tool (capability)
@tool(name="my_tool", target=ActionTarget.CUSTOM)
def my_custom_function(arg1):
    print(f"Executing with {arg1}")
    return "Done"

# 2. Initialize the Agent
# 'policy_id' corresponds to a policy defined in the IOI Kernel's state.
agent = Agent(
    name="WorkerBot", 
    policy_id="standard-safety-v1"
)

# 3. Register capabilities
agent.register_tool(my_custom_function)

# 4. Execute a task
# This triggers the reasoning loop (LLM) which will invoke registered tools.
agent.run("Perform the task using your custom function.")
```

## API Reference

### `class Agent`

#### `__init__(name: str, policy_id: str = "default")`
Initializes a new agent instance.

*   **`name`** (`str`): The human-readable name of the agent.
*   **`policy_id`** (`str`, optional): The identifier of the security policy to enforce. Defaults to `"default"`.

#### `register_tool(func: Callable) -> Callable`
Registers a Python function as a tool available to the agent's AI reasoning engine.

*   **`func`** (`Callable`): The function to register. It is recommended to decorate this function with `@tool` from `ioi_swarm.tools` to ensure proper metadata generation for the LLM.
*   **Returns**: The original function (allows for decorator-style usage).

#### `run(task: str)`
Starts the agent's main execution loop to accomplish the specified task.

*   **`task`** (`str`): A natural language description of the goal.