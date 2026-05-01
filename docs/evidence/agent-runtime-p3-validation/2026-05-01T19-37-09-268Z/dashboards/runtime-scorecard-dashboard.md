# Runtime Scorecard Dashboard

Generated: 2026-05-01T19:37:09.324Z

| Dimension | Required evidence |
| --- | --- |
| Start | Session state persisted before work begins. |
| Prompt | Prompt sections, source hashes, and truncation diagnostics exist. |
| Plan | Plan exists or explicit no-plan rationale exists. |
| Tool proposal | Tool input validates against contract. |
| Policy | Policy decision receipt exists. |
| Approval | Approval grant is exact-scope when needed. |
| Execution | Tool lifecycle events and receipt exist. |
| Postcondition | Required evidence is checked. |
| Memory | Relevant memory read/write is recorded with provenance. |
| Error | Failure has class, retryability, and recovery suggestion. |
| Resume | Crash boundary has a passing resume test. |
| Export | Trace bundle reconstructs final state. |
| Verification | `ioi agent verify` can accept or explain failure. |
| Quality | `AgentQualityLedger` records scorecard metrics and failure ontology labels. |
| Strategy | Runtime strategy choice is recorded with rationale and outcome. |
| Task state | Objective, facts, uncertainty, assumptions, constraints, changed objects, blockers, stale facts, confidence, and evidence refs are current. |
| Uncertainty | Ask/probe/retrieve/dry-run/execute/stop decision records value of information and cost of being wrong. |
| Probe | Hypothesis, cheapest validation action, expected observation, result, confidence update, and next action are persisted. |
| Postcondition synthesis | Required checks are derived before execution and mapped to receipts or explicit unknowns. |
| Semantic impact | Changed symbols, APIs, schemas, policies, call sites, docs, generated files, migrations, and affected tests are analyzed. |
| Capability sequence | Tool/capability order is selected from evidence and outcomes, not only availability. |
| Verifier independence | High-risk verification uses required independent role/model/context/evidence policy. |
| Budget | Reasoning, tool, retry, verification, wall-time, escalation, and stop budgets are respected. |
| Drift | Plan, file, branch, connector auth, requirement, policy, model availability, and projection drift are checked. |
| Dry-run | High-impact side effects are previewed when dry-run support exists. |
| Stop | Terminal state includes explicit stop reason and evidence sufficiency status. |
| Handoff | Receiving agent or operator can continue without reconstructing objective, state, blockers, or evidence. |
| Autopilot GUI | `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop` launches retained desktop validation. |
| Chat UX | Final answer is primary; Markdown, Mermaid, collapsible work, explored files, and source pills render cleanly. |
| GUI/runtime consistency | Visible chat output matches trace, selected sources, receipts, task state, and stop reason. |
| Learning | Promoted skills/playbooks/model-route changes have validation, rollback, and policy evidence. |
| Substrate | Surface path records which public substrate contract and adapter were used. |
| Dogfooding | Workflow/harness/benchmark validation proves same envelope, event, receipt, replay, and quality-ledger contract. |

## Workflow Classes

| Status | Workflow class | Guide | Evidence |
| --- | --- | --- | --- |
| Complete | CLI workflow suite | guide:1356 | All anchors present |
| Complete | Session lifecycle and crash-resume suite | guide:1357 | All anchors present |
| Complete | Event stream schema and ordering golden suite | guide:1358 | All anchors present |
| Complete | Tool contract suite | guide:1359 | All anchors present |
| Complete | Filesystem stale-write/device/symlink/read-before-edit safety suite | guide:1360 | All anchors present |
| Complete | Shell job-control suite | guide:1361 | All anchors present |
| Complete | Policy/firewall/approval suite | guide:1362 | All anchors present |
| Complete | MCP containment suite | guide:1363 | All anchors present |
| Complete | Delegation and merge-contract suite | guide:1364 | All anchors present |
| Complete | Plan/execution binding suite | guide:1365 | All anchors present |
| Complete | Prompt precedence suite | guide:1366 | All anchors present |
| Complete | Memory/compaction suite | guide:1367 | All anchors present |
| Complete | Model routing/fallback suite | guide:1368 | All anchors present |
| Complete | Observability/export/replay suite | guide:1369 | All anchors present |
| Complete | Production profile fail-closed suite | guide:1370 | All anchors present |
