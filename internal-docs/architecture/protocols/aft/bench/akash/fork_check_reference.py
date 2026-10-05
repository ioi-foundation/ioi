"""Reference algorithm for fork_check per_node_root_agreement.v1 (mirrors the Rust harness function).

Input: one entry per node: {"rpc": str, "reachable": bool, "tip": int|None, "blocks": {height: (block_hash_hex, state_root_hex)}}
Output: {"schema": "ioi.aft.fork-check.v1", "verdict": "agree"|"forked"|"degraded", "common_tip": int,
         "nodes": [...], "first_divergence": {"height": h, "per_node": [[rpc, hash, root], ...]} | None}
Rules (fail-closed):
  - any node unreachable, or any node missing a block at a height <= the common tip -> "degraded";
  - all reachable nodes must report the SAME (hash, state_root) at EVERY height 1..=common_tip, where
    common_tip = min(tip over nodes) -> else "forked" with the first divergent height;
  - otherwise "agree". Tips may differ (a lagging node is not a fork); only heights <= the common tip are compared.
"""
SCHEMA = "ioi.aft.fork-check.v1"

def root_agreement(nodes, scenario="", lane=""):
    summary = [{"rpc": n["rpc"], "reachable": bool(n.get("reachable")), "tip": n.get("tip")} for n in nodes]
    base = {"schema": SCHEMA, "scenario": scenario, "lane": lane, "nodes": summary, "first_divergence": None}
    if not nodes:
        return {**base, "verdict": "degraded", "common_tip": 0}
    if any(not n.get("reachable") or n.get("tip") is None for n in nodes):
        return {**base, "verdict": "degraded", "common_tip": 0}
    common_tip = min(int(n["tip"]) for n in nodes)
    for h in range(1, common_tip + 1):
        per = []
        for n in nodes:
            pair = n["blocks"].get(h)
            if pair is None:
                return {**base, "verdict": "degraded", "common_tip": common_tip}
            per.append([n["rpc"], pair[0], pair[1]])
        if len({(p[1], p[2]) for p in per}) != 1:
            return {**base, "verdict": "forked", "common_tip": common_tip, "first_divergence": {"height": h, "per_node": per}}
    return {**base, "verdict": "agree", "common_tip": common_tip}
