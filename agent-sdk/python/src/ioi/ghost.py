# sdk/python/src/ioi/ghost.py
import json
from .agent import Agent
from .types import ActionTarget
from .tools import tool

class GhostRecorder:
    def __init__(self):
        self.trace_log = []

    def record_action(self, target: str, params: dict):
        self.trace_log.append({
            "target": target,
            "params": params,
            "timestamp": time.time()
        })

    def synthesize_policy(self) -> str:
        """
        Generates an ActionRules JSON based on observed behavior.
        Whitepaper §14.2 Step 2.
        """
        rules = []
        for entry in self.trace_log:
            # Heuristic: Generate allow rules based on observed parameters
            rule = {
                "target": entry['target'],
                "action": "ALLOW",
                "conditions": {}
            }
            
            if entry['target'] == "net::fetch":
                # Extract domain from URL for least-privilege scoping
                url = entry['params'].get('args', [None])[0]
                if url:
                    domain = url.split('/')[2]
                    rule["conditions"]["allow_domains"] = [domain]
            
            rules.append(rule)
            
        policy = {
            "policy_id": "auto-generated-v1",
            "defaults": "DENY_ALL",
            "rules": rules
        }
        return json.dumps(policy, indent=2)

# Usage Example
if __name__ == "__main__":
    recorder = GhostRecorder()
    
    # Define a tool that simulates the decorator in tools.py
    def fetch_weather(url):
        print(f"Fetching {url}...")
        recorder.record_action("net::fetch", {"args": [url]})
    
    print("--- Ghost Mode: Recording ---")
    fetch_weather("https://api.weather.gov/gridpoints/TOP/31,80/forecast")
    
    print("\n--- Synthesized Policy (policy.json) ---")
    print(recorder.synthesize_policy())