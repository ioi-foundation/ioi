# sdk/python/src/ioi/tools.py
import functools
import json
from typing import Callable, Any
from .client import IoiClient
from .types import ActionRequest, ActionTarget, ActionContext

# Global client instance (singleton for simplicity in v0.1)
_CLIENT = IoiClient()

def tool(name: str, target: ActionTarget = ActionTarget.CUSTOM):
    """
    Decorator that registers a Python function as an IOI Tool.
    When called, it emits an ActionRequest to the Orchestrator instead of just running.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # 1. Capture Inputs
            params = {
                "args": args,
                "kwargs": kwargs
            }
            params_bytes = json.dumps(params, sort_keys=True).encode('utf-8')
            
            # 2. Construct ActionRequest
            request = ActionRequest(
                target=target,
                params=params_bytes,
                context=ActionContext(agent_id="local-agent"), # TODO: Context injection
                nonce=0 # TODO: Nonce management
            )
            
            # 3. Emit to Kernel (The "Ghost Mode" interception)
            print(f"[IOI] Intercepting tool call: {name}")
            tx_hash = _CLIENT.submit_action(request)
            print(f"[IOI] Action logged. Receipt: {tx_hash}")
            
            # 4. Execute the actual logic (Pass-through)
            # In "Ghost Mode", we log AND execute. 
            # In "Enforce Mode", the Orchestrator might block this.
            return func(*args, **kwargs)
            
        return wrapper
    return decorator