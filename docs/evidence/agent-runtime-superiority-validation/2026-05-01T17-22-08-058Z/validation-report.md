# Agent Runtime Smarter-Superiority Validation Report

Status: Partial

Reference: examples/claude-code-main/claude-code-main/README.md
Master guide: docs/plans/architectural-improvements-broad-master-guide.md

| Area | Count |
| --- | --- |
| Scenarios | 12 |
| CompletePlus scenarios | 12 |
| Covered surfaces | 6 |
| Covered smarter dimensions | 18 |
| Incomplete | 1 |

## Scenario Results

| Status | Scenario | Reference score | IOI score | Margin | Outcome claim |
| --- | --- | --- | --- | --- | --- |
| CompletePlus | Destructive action becomes governed stop plus dry-run alternative | 3 | 11 | 8 | IOI can refuse unsafe progress with a recorded stop reason and offer bounded previews without executing the destructive action. |
| CompletePlus | Uncertainty routes to cheap probe before costly or risky action | 3 | 11 | 8 | IOI records why a probe is cheaper than direct execution and persists the confidence update path. |
| CompletePlus | Plan-only tasks bind plan state without mutation | 3 | 11 | 8 | IOI can preserve the objective, constraints, and stop reason for a no-mutation planning run. |
| CompletePlus | Semantic impact selects verification instead of relying on text diff alone | 4 | 10 | 6 | IOI turns changed symbols, schemas, policies, docs, and unknown paths into required checks and verifier policy. |
| CompletePlus | Memory, playbooks, and negative learning are governed assets | 3 | 8 | 5 | IOI separates memory quality, operator preferences, negative learning, and promotion gates from ordinary transcript state. |
| CompletePlus | Capability sequences can be selected and retired from evidence | 3 | 8 | 5 | IOI scores capability order and retirement, rather than treating tool discovery as the end of tool intelligence. |
| CompletePlus | Handoff preserves objective, blockers, state, evidence, and next action | 3 | 9 | 6 | IOI can score whether a human or child agent can continue without reconstructing context. |
| CompletePlus | Drift, compaction, and resume preserve world state | 3 | 11 | 8 | IOI makes stale state and trace replay explicit instead of relying only on compressed transcript continuity. |
| CompletePlus | Model routing is a quality, budget, privacy, and fallback decision | 3 | 9 | 6 | IOI records model choice as an optimization decision across task family, risk, budget, privacy, latency, and fallback. |
| CompletePlus | Verifier independence can request probes and create repair tasks | 2 | 8 | 6 | IOI makes verifier independence a policy-bearing runtime contract tied to postconditions and probes. |
| CompletePlus | Clean chat UX renders answer-first while matching backend evidence | 2 | 9 | 7 | IOI keeps evidence deep but optional and proves visible answers match trace, receipts, sources, and task state. |
| CompletePlus | Harness, compositor, benchmark, CLI, and UI use the same substrate | 1 | 10 | 9 | IOI validates dogfooding through the same public substrate, not a separate benchmark or UI runtime. |

## Coverage

| Coverage | Values |
| --- | --- |
| Surfaces | api, benchmark, cli, harness, ui, workflow_compositor |
| Smarter dimensions | bounded_self_improvement, clean_chat_ux, cognitive_budget, drift, dry_run, handoff_quality, memory_learning, operator_collaboration, postcondition_synthesis, probe, semantic_impact, stop_condition, strategy_routing, task_state, tool_model_selection, uncertainty, unified_substrate, verifier_independence |

## Failures

- passing P3 evidence bundle is missing
