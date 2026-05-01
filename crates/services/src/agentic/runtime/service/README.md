# Runtime Service Ownership Map

Status: guarded source-tree ownership boundary.

This directory owns the runtime service loop over the shared runtime substrate.
New code should land in the narrow lane that owns the behavior, rather than
creating a second service loop or reviving legacy catch-all paths.

| Lane | Owns |
| --- | --- |
| `decision_loop` | Per-turn routing, intent resolution, cognitive signals, strategy decisions, and recovery routing. |
| `planning` | Planner fallback, playbook delegation, task-family strategy, and plan binding. |
| `queue` | Work queue envelopes, ready-work processing, lifecycle handoff to execution, and terminal reply assembly. |
| `tool_execution` | Tool-call parsing, execution guards, probes, repair, grounding, and action finalization. |
| `recovery` | Incident records, anti-loop state, failure classification, and recovery policy. |
| `output` | Inline answer shaping, token output, and final response composition. |
| `web_pipeline` | Search/read candidate expansion, citations, source selection, and web synthesis. |
| `visual_loop` | Visual foreground, UI perception, browser snapshot cognition, and visual task completion. |
| `lifecycle` | Session lifecycle, delegation, compaction, sudo/authority transitions, and worker result merge. |
| `memory` | Runtime memory retrieval, transcript state, enrichment, and diagnostics. |

Legacy `step/` references describe historical ownership only. They must not be
used as a target path for new behavior.
