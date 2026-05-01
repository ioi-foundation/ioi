# Decision Loop

Status: guarded service lane.

This lane owns per-turn routing, intent resolution, cognitive signals, runtime
strategy decisions, and recovery routing. The broader service ownership map
lives in `crates/services/src/agentic/runtime/service/README.md`.

New decision-loop behavior should stay within this lane or move into a narrower
child module. Cross-lane behavior must be expressed through runtime contracts,
receipts, task state, or queue/tool/lifecycle handoff types rather than direct
state ownership.
