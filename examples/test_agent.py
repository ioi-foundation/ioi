from ioi.agent import Agent
from ioi.tools import tool
from ioi.types import ActionTarget
import time

# Explicitly connect to localhost, which maps to the 0.0.0.0 bind of the node
agent = Agent(name="Scout")
# Note: We need to ensure the underlying client uses this address.
# Since the current Agent class doesn't pass args to Client, 
# let's manually override it for this test:
import ioi.tools
ioi.tools._CLIENT = ioi.client.IoiClient("127.0.0.1:9000")

@tool(name="fetch_news", target=ActionTarget.NET_FETCH)
def fetch_news(source: str):
    print(f"--- [Python] Executing real logic: Fetching from {source} ---")
    time.sleep(0.5)
    return {"status": "success", "data": "Market is up 5%"}

if __name__ == "__main__":
    print("--- Starting Ghost Mode Recording ---")
    fetch_news("https://api.governance.ioi/proposals")
    print("--- Recording Complete ---")