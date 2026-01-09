# sdk/python/src/ioi/agent.py
from typing import List, Callable
from .tools import tool

class Agent:
    def __init__(self, name: str, policy_id: str = "default"):
        self.name = name
        self.policy_id = policy_id
        self.tools: List[Callable] = []

    def register_tool(self, func: Callable):
        self.tools.append(func)
        return func

    def run(self, task: str):
        """
        Executes the agent loop.
        In v0.1, this is a placeholder for the LLM loop.
        """
        print(f"[Agent {self.name}] Starting task: {task}")
        # Logic to call tools based on LLM reasoning would go here.