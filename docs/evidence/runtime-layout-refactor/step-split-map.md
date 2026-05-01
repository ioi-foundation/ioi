# Runtime Service Step Split Map

Status: Complete.

The legacy `service/step/` implementation tree has been removed. Runtime
service behavior is now physically housed by concern:

| New lane | Former contents | Responsibility |
| --- | --- | --- |
| `service/decision_loop/` | `step/mod.rs`, clarification, cognition, helpers, intent resolver, ontology, orchestration, pending resume, route projection, signals, worker | Per-turn routing, task cognition, intent resolution, strategy selection, and decision-loop orchestration. |
| `service/planning/` | `step/planner.rs`, `step/planner/`, `step/playbook.rs` | Planner state, fallback guards, playbook delegation, and plan binding. |
| `service/queue/` | `step/queue.rs`, `step/queue/` | Ready-work queue processing, envelopes, terminal reply assembly, and queue-owned web pipeline entrypoints. |
| `service/tool_execution/` | `step/action.rs`, `step/action/` | Tool-call parsing, command contracts, probes, execution guards, repairs, and action finalization. |
| `service/recovery/` | `step/anti_loop.rs`, `step/anti_loop/`, `step/incident.rs`, `step/incident/` | Failure classification, anti-loop routing, incident records, and recovery policy. |
| `service/output/` | `step/direct_inline.rs`, `step/text_tokens.rs`, `step/text_tokens/` | Inline response shaping and token-level output helpers. |
| `service/visual_loop/` | `step/perception.rs`, `step/perception/`, `step/visual.rs`, `step/browser_completion.rs`, `step/browser_completion/` | Visual perception, screenshot/SOM context, browser snapshot completion, and visual foreground loop helpers. |
| `service/web_pipeline.rs` | New lane marker | Public lane marker for web retrieval pipeline ownership; queue keeps the ready-work entrypoint while web-specific processing remains explicit under queue processing. |

Guardrail:

- `npm run check:runtime-layout` fails if `service/step/` exists or production
  code imports `service::step`.
