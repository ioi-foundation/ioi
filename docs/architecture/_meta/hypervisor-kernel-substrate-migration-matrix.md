# Hypervisor Kernel Substrate Migration Matrix

Status: compact implementation migration matrix.
Canonical owner: this file tracks live/current/final ownership for the
Hypervisor kernel substrate unification migration; doctrine remains owned by
the subject docs and the master guide.
Supersedes: ad hoc split-brain status notes for this migration when they
conflict with the route-family owner map below.
Superseded by: none.
Last alignment pass: 2026-06-12.
Last matrix pruning pass: 2026-06-12, after the direct-invoker-only runner cuts,
coding-tool approval-satisfaction JS gate retirement, the Rust approval
satisfaction/projection positive API cut, the Rust-owned coding-tool patch
snapshot capture cut, and the Rust-planned/Agentgres-admitted coding-tool
budget-block governance cut, and the public thread runtime-control Rust planner
cut, the generic runtime thread-event Rust Agentgres admission cut, and the
runtime thread-event projection Rust Agentgres cut, and the public runtime
thread-event replay positive API cut, and the public runtime thread/turn
projection positive API cut, and the public agent status-control Rust
planning/Agentgres commit cut, and the public agent delete Rust tombstone
planning/Agentgres commit cut, and the public agent create Rust
planning/Agentgres commit cut, and the public run create Rust
planning/Agentgres commit cut, and the public top-level thread create Rust
planning/Agentgres commit/projection cut, and the public non-runtime
resume/turn-create Rust lifecycle/projection cut, and the public task/job
cancel Rust planning/Agentgres commit cut, and the public task/job read
projection positive API cut, and the public task create Rust
planning/projection/Agentgres commit cut, and the workspace-trust
warning/ack Rust planning plus runtime-event Agentgres admission cut, and the
public runtime account/node/tool catalog Rust projection positive API cut, and
the public skill/hook registry Rust projection positive API cut, the public
model_mount catalog-status Rust read-projection positive API cut, the public
memory route projection Rust positive API cut, and the public conversation
artifact read projection Rust positive API cut.

## Purpose

This matrix is the Phase 0 inventory for
[`hypervisor-kernel-substrate-unification-master-guide.md`](./hypervisor-kernel-substrate-unification-master-guide.md).
It keeps each route family honest about current live authority, target owner,
truth path, conformance tier, and cleanup condition.

This file is no longer a per-slice evidence archive. Per-slice archaeology made
the migration optimize for token-maxing iteration instead of whole authority
cuts. The matrix now records macro boundaries only: what has changed ownership,
what remains temporary, and what must not be recreated.

Terminal status is not claimed here. The migration is open until
`hypervisor-conformance` passes and the terminal conditions in the master guide
are all true.

## Current Sprint Lane

The current implementation lane is Rust substrate migration plus JS facade
retirement. Current tier conformance is green, but the terminal migration is not
claimed. Future work must prioritize macro authority cuts over additional
bridge/fallback polish:

- replace a fail-closed JS facade with a positive Rust daemon-core API;
- move one route-family truth path into Rust, including authority, admission,
  receipts, projection, replay, and stable protocol shape;
- delete the JS facade or reduce it to product/API/IDE/SDK adapter behavior in
  the same cut;
- update conformance and this matrix once per macro cut, not once per helper.

The current `ioi-step-module-bridge` command path is acceptable only as
migration transport. It is not the terminal architecture. It must collapse into
the Rust daemon core API or remain narrow transport with no independent
authority, accepted-truth mutation, fallback execution, or compatibility-shim
semantics.

## Route-Family Owner Map

| Route family | Current live status | Terminal owner | Next macro cut |
| --- | --- | --- | --- |
| `coding-tools` | Rust-live StepModule execution exists for migrated tools; Rust daemon-core now constructs coding-tool `StepModuleInvocation` envelopes from canonical request facts before workload dispatch/admission; approval-required execution projects approval request/decision/lease truth through Rust `project_coding_tool_approval_satisfaction` and then asks Rust `plan_coding_tool_approval_satisfaction` before the StepModule path; unsatisfied approval block result/event materialization is Rust-planned by `plan_coding_tool_approval_block`; budget-block governance is Rust-planned by `plan_coding_tool_budget_block` and the blocked result event is Rust Agentgres-admitted through `admit_coding_tool_result_event` before JS returns the policy error; accepted coding-tool result events and command-stream events are admitted by Rust before JS projection registration; `file.apply_patch` patch snapshot capture now consumes Rust `workspace_restore.rs` snapshot record/event output and no longer calls the JS snapshot-event appender; public workspace snapshot list/content-package and restore preview/apply APIs now call Rust `workspace_restore.rs` projection/restore command responses through the direct-invoker runner instead of JS runtime-event/artifact readback; Rust `coding_tool_workspace.rs` emits canonical snake_case workload observations for migrated workspace, patch, test, and diagnostics tools; `plan_post_edit_diagnostics_feedback` now owns post-edit diagnostics skip/path selection, repair policy normalization, rollback refs, auto diagnostics `tool_call_id`, and `diagnostics_repair_context` authoring before JS forwards the Rust-authored `lsp.diagnostics` request; the JS approval satisfaction projection callback, JS approval manifest matcher, JS approval block facade, JS budget-block result/event facade, JS result-event admission hook, JS command-stream append facade, JS-created coding-tool StepModule envelope, JS post-edit diagnostics planner, public workspace snapshot JS projection/readback facade, and successful-without-Rust-snapshot compatibility path are deleted or demoted to Rust-client scaffolding. | Rust daemon core `step_router` plus workload/WASM backend, Agentgres admission, receipt/state-root binding, projection, and replay. | Move diagnostics projection/replay and remaining coding-tool context/result-event envelope authorship into one Rust-owned execution spine, then collapse the temporary JS runner transport into stable Rust protocol/API calls. |
| `approvals-gates` | Approval manifest planning, coding-tool approval satisfaction projection, approval satisfaction planning, approval block shaping, approval state-update command response shaping, public approval request/decision/revoke control, and public approval queue/read projection now route through Rust `approval.rs` via direct-invoker runners; public approval decision/revoke first calls Rust `authorize_approval_decision`, requires wallet.network grant refs and authority receipts, binds the Rust authority hash into the state update, and the Rust decision/revoke state planners reject missing wallet authority. JS governance no longer scans approval events/leases, JS approval request/decision readback is retired, JS approval satisfaction projection is retired, and the public approval surface persists only Rust-authored run/agent projections through Agentgres-gated state commits while `GET /v1/threads/:thread_id/approvals` returns the Rust `project_approval_queue` projection. | Rust daemon core `authority` backed by wallet.network grants, Agentgres expected heads, receipts, replay, and stable approval read APIs. | Move remaining approval authority issuance/consumption and approval-state runner transport into direct Rust authority/projection APIs. |
| `runtime-events-replay-trace` | Generic runtime thread-event append now calls Rust `admit_runtime_thread_event` through the direct-invoker Agentgres runner, requires receipt refs, expected heads, state roots, storage admission, and projection watermarks before JS can register the Rust-returned event in the local replay cache; synthetic `thread.started` projection and legacy run-event-to-runtime-event projection now call Rust `project_runtime_thread_events`, which authors thread/run event envelopes, skips known idempotency keys, admits each event through the same Rust Agentgres admission core, and returns only Rust-admitted events for JS replay registration. Public stream/turn replay readback now calls Rust `project_runtime_thread_event_replay`; Rust owns stream/turn selection, canonical cursor evaluation, required Agentgres admission refs, and the returned event set while JS only supplies temporary cache candidates. The runner transport remains adapter scaffolding. | Rust projection/replay core over Agentgres-admitted truth and receipt-bound state roots. | Replace the temporary runner/cache transport with direct Rust projection/replay APIs consumed by IDE/SDK. |
| `model-mounting` | Major route-decision, invocation, provider-execution, lifecycle, required-boundary, read-projection, and receipt-binding planning is Rust-owned behind migration transport; public `catalogStatus()` now returns the Rust-authored `catalog_status` projection directly with empty JS request state, and the old JS/Rust catalog-status refusal shim is retired; JS model-mounting state still contains other fail-closed or adapter surfaces. | Rust daemon core `model_mount` owns provider lifecycle, route control, backend/server/runtime/tokenizer projection, invocation, receipt binding, Agentgres replay, and stable APIs. | Move the next model_mount positive surface, such as provider lifecycle or catalog/search projection over Agentgres truth, into Rust daemon-core end to end and delete the corresponding JS facade. |
| `agentgres-admission` | Runtime Agentgres runner is direct-invoker-only and Rust response shaping exists; public agent creation now calls Rust `plan_agent_create_state_update`, agent-scoped run creation calls Rust `plan_run_create_state_update`, public task creation calls Rust `plan_runtime_task_job_create_state_update`, public run cancellation calls Rust `plan_run_cancel_state_update`, public task/job cancellation calls Rust `plan_runtime_task_job_cancel_state_update`, public task/job list/get now calls Rust `project_runtime_task_job_projection` for projection/filter/public-id selection over run candidates, public agent archive/unarchive/resume/close/reload controls call Rust `plan_agent_status_state_update`, permanent delete calls Rust `plan_agent_delete_state_update`, and those lifecycle controls commit only Rust-authored projections/tombstones through Agentgres-backed `writeAgent`/`writeRun`; JS thread/store persistence facades still stage some other calls. | Rust daemon core `agentgres_admission` is the only admitted truth path for meaningful state transitions and artifact/payload refs. | Move remaining thread lifecycle commit and projection persistence through direct Rust Agentgres APIs; delete JS accepted-truth mutation paths. |
| `receipt-binding` | Receipt binder and many receipt aliases are Rust-owned or retired; JS facades still translate some receipt-required errors. | Rust daemon core `receipt_binder` binds every meaningful operation to expected heads, state roots, ArtifactRefs, PayloadRefs, and replay. | Collapse remaining JS receipt translators into Rust-owned response envelopes for one live route family. |
| `ctee-private-workspace` | cTEE Private Workspace runner is direct-invoker-only and fail-closed without Rust; CLI admission surface exists. | Rust daemon core `ctee` enforces no-plaintext-custody, declassification, leakage failure, and private workspace receipt semantics. | Replace the JS runner with a direct Rust cTEE custody protocol/API and remove the runner facade. |
| `workload-client-wasm` | StepModule ABI and Rust workload client contracts exist; migrated coding-tool invocation envelopes and workload dispatch requests are now constructed in Rust daemon-core from canonical JS client facts, while JS still initiates the temporary runner transport. | Rust/WASM workload backends execute admitted Step/Module work through the shared contract under daemon authority. | Replace temporary runner transport with stable Rust protocol/API calls and extend Rust-owned invocation construction across remaining route families. |
| `workflow-compositor` | IDE/compositor projections have many alias retirements and negative guards; public runtime thread/turn projection records now call Rust `project_runtime_thread_turn_projection`, so Rust owns the thread/turn record shape, seq-range and item-id derivation from admitted replay events, canonical projection hashes, and retired request alias rejection while JS only gathers canonical agent/run/event facts. Public runtime account/node/tool catalog, skill/hook registry, repository workflow, lifecycle, memory list/policy/path/status/validation, and conversation-artifact list/get/revision route projections now call Rust `project_runtime_tool_catalog`, `project_skill_hook_registry`, `project_repository_workflow`, `project_runtime_lifecycle`, `project_runtime_memory_projection`, and `project_runtime_conversation_artifact_projection`, so the old JS projection-required catalog/repository/lifecycle facades plus the fail-closed public memory and conversation-artifact read facades are retired; JS only forwards canonical request/environment/workspace/lifecycle/memory/artifact candidates and fails closed if the Rust projector is missing. Other IDE/runtime views still consume adapter-shaped runtime surfaces. | IDE consumes Rust projection/replay records and never creates accepted truth. | Wire the next compositor/runtime view directly to Rust projection output and remove the corresponding JS projection fallback. |
| `worker-service-packages` | Worker/service package runner is direct-invoker-only and Rust governed-receipt response shaping exists. | Rust daemon core package invocation path with authority, artifacts, receipts, Agentgres truth, and compositor projection. | Replace the JS package runner with direct Rust protocol/API and keep JS as SDK/API adapter only. |
| `meta-improvement` | Governed-improvement runner is direct-invoker-only and Rust governed-admission response shaping exists. | Rust daemon core governs proposal admission, verification receipts, authority gates, and accepted improvement truth. | Move proposal execution/projection/read APIs out of JS facade scaffolding. |
| `rust-daemon-core` | Command envelope identity, typed operation dispatch, public runtime account/node/tool catalog projection, public skill/hook registry projection, public repository workflow projection, public lifecycle projection, public memory route projection, public conversation-artifact read projection, and many response planners are Rust-owned; some temporary command transport remains. Shared JS command-spawn helper is deleted. | Rust daemon core owns hot-path execution semantics, authority gates, StepModuleRouter dispatch, Agentgres admission, receipt binding, replay, projection, and stable APIs. | Replace command-transport-shaped daemon runners with direct in-process or stable daemon protocol APIs. |
| `js-facade-retirement` | Many JS pass-through wrappers, compatibility aliases, and local writers are deleted; public agent create/run create/run cancel/task create/task-job cancel/status/delete controls, task/job list/get projections, workspace-trust warning/ack event controls, public runtime account/node/tool catalog projections, public skill/hook registry projections, public repository workflow projections, public lifecycle projections, public memory list/policy/path/status/validation route projections, and conversation-artifact list/get/revision projections moved from fail-closed JS facade to Rust-owned positive paths; remaining non-test `rust_core_required` markers are honest fail-closed boundaries. | JS facades are non-authoritative clients only, or retired. | Convert fail-closed facades into Rust-backed positive paths in whole route-family batches, then delete the facade. |

## Macro Authority Cut Ledger

This ledger replaces the old per-slice evidence list. It records the meaningful
authority-boundary cuts that should guide future work.

| Macro cut | Current proof | Still temporary |
| --- | --- | --- |
| Rust-live coding-tool StepModule path | Migrated coding tools execute through Rust workload/StepModule contracts, explicit `daemon_js`/shadow/gated/backend selection fails closed, and Rust daemon-core constructs the coding-tool `StepModuleInvocation` envelope before workload dispatch/admission. | JS invocation surface still builds protocol context and coordinates fail-closed governance/artifact/snapshot surfaces. |
| Rust command-envelope and bridge contraction | Rust owns canonical command-envelope parsing, typed operation identity, and many child command response families; deleted bridge delegates must not return. | `ioi-step-module-bridge` remains migration transport, not terminal API. |
| Direct-invoker-only daemon runners | Worker/service package, L1 settlement, cTEE private workspace, external capability authority, governed improvement, coding-tool approval, approval-state, runtime Agentgres admission, workspace restore, context-policy/state-update, model_mount admission, and StepModule runners reject command/env compatibility and require `daemonCoreInvoker`. | The runner layer is still JS protocol scaffolding until direct Rust daemon-core APIs replace it. |
| Model_mount Rust owner split | Rust owns route decision, invocation admission, provider execution, provider result, lifecycle planning, backend-process planning, accepted-receipt planning, read-projection planning, and receipt-binding response shaping behind migration transport. | JS model_mount state/materialization/read adapters remain broad and must be retired by positive Rust APIs. |
| Model_mount catalog-status projection positive API | `plan_model_mount_read_projection` kind `catalog_status` now returns the Rust-authored catalog status through `status::catalog_status`; public `catalogStatus()` forwards empty request state and the obsolete JS edge translator plus Rust refusal module are deleted. | The projection is still an empty/default current-tier envelope behind temporary command transport; Agentgres-backed catalog search/status truth, provider catalog custody, and direct protocol APIs remain non-terminal. |
| Public runtime memory read projection positive API | Public memory list, policy, path, status, and validation route projections now call Rust daemon-core `project_runtime_memory_projection` through the mounted thread-memory surface; JS only supplies temporary projection candidates and the route fails closed if the Rust projector is absent or mismatched. | Memory mutation/admission, durable record truth, wallet/policy authority, cTEE-coupled private memory custody, Agentgres-backed replay/projection storage, and direct protocol APIs remain non-terminal. |
| Conversation-artifact read projection positive API | Public and thread-scoped conversation-artifact list, get, and revision route projections now call Rust daemon-core `project_runtime_conversation_artifact_projection` through the mounted conversation-artifact surface; JS only supplies temporary artifact candidates and the route fails closed before JS artifact-store readback if the Rust projector is absent or mismatched. | Conversation-artifact create/action/export/promote, durable ArtifactRef/PayloadRef admission, Agentgres-backed artifact storage/replay/projection, receipt/state-root binding, and direct protocol APIs remain non-terminal. |
| Public approval control Rust-owned | Rust `approval.rs` owns approval manifest planning, coding-tool approval satisfaction projection, approval satisfaction planning, approval block result/event materialization, public approval queue projection, and approval request/decision/revoke command response shaping. Public decision/revoke control now calls Rust `authorize_approval_decision` before state planning; Rust requires wallet.network grant refs and authority receipts, emits an authority hash/record, and the decision/revoke state planners fail closed without that binding before any JS commit can persist. JS command/env fallback, request/decision/lease scanning, approval satisfaction projection, approval readback helpers, direct runtime-event append, and the JS approval block facade are retired. | Approval request/grant issuance semantics and the approval-state runner transport still need direct Rust authority/projection APIs beyond migration scaffolding. |
| Public approval queue/read projection Rust-owned | `project_approval_queue` is a Rust daemon-core operation; Rust now derives pending/resolved approval queue records from run/agent approval projections, filters resolved records unless requested, emits canonical snake_case request/decision/lease/receipt fields, and the public `GET /v1/threads/:thread_id/approvals` route calls `approvalSurface.listThreadApprovals()` through the direct-invoker approval-state runner instead of any JS event/readback helper. | Approval authority projection/replay storage and the approval-state runner transport still need direct Rust ownership beyond migration scaffolding. |
| Coding-tool approval satisfaction positive API | `project_coding_tool_approval_satisfaction` and `plan_coding_tool_approval_satisfaction` are Rust daemon-core operations; Rust now projects approval request/decision/lease state from Agentgres-backed run/agent projections, attaches the manifest for satisfaction evaluation, selects revocation as the latest decision when present, and invocation can proceed past an approval manifest only when Rust returns a satisfied record with approval receipts/policy refs. The JS store projection callback and exported JS manifest matcher are retired. | Remaining approval authority replay/projection APIs still need direct Rust ownership. |
| Coding-tool approval block positive API | `plan_coding_tool_approval_block` is a Rust daemon-core operation; unsatisfied approval now returns a Rust-shaped blocked coding-tool result/event envelope with approval refs instead of calling `blockCodingToolForApproval()`. | Approval-block persistence still needs direct Rust authority/admission ownership beyond the current result-event admission path. |
| Coding-tool budget block positive API | `plan_coding_tool_budget_block` is a Rust daemon-core operation in `policy/context_lifecycle.rs`; blocked budget execution now returns a Rust-shaped coding-tool result/event envelope with budget status, policy refs, receipt refs, and canonical snake_case fields, and the invocation hot path admits that blocked event through Rust `admit_coding_tool_result_event` before returning the policy error. The JS governance surface only forwards canonical request facts to Rust and remains fail-closed when the planner is absent. | The context-policy runner is still temporary command transport, and broader diagnostics/projection/replay work remains outside this cut. |
| Coding-tool result-event admission positive API | `admit_coding_tool_result_event` is a Rust daemon-core operation; successful, failed, and approval-blocked coding-tool result events require Rust Agentgres admission with receipt refs, expected heads, state roots, payload refs, storage admission, and projection watermarks before JS can register them for replay. | JS still constructs the candidate result-event envelope, diagnostics orchestration, and some readback/projection adapter context. |
| Coding-tool command-stream admission positive API | `admit_coding_tool_command_stream_events` is a Rust daemon-core operation; Rust owns stream request evaluation, stdout/stderr chunking, command-stream event materialization, Agentgres storage admission, receipt/state-root binding, payload refs, and projection watermarks before JS can register stream events for replay. | JS still constructs StepModule/workload request context and coordinates diagnostics follow-up plus projection/readback adapters. |
| Coding-tool StepModule invocation construction Rust-owned | `run_coding_tool_step_module` now accepts canonical coding-tool request facts; Rust daemon-core owns the migrated tool contract table, input hashing, invocation id generation, authority/custody/backend fields, workload dispatch request construction, router admission, receipt binding, Agentgres admission, and projection record creation. JS no longer imports the coding-tool StepModule ABI builder or passes a `StepModuleInvocation` into the command. | JS still initiates temporary runner transport and coordinates diagnostics follow-up plus projection/readback adapters. |
| Coding-tool patch workspace snapshot capture Rust-owned | Rust `workspace_restore.rs` now emits snapshot capture records and snapshot events with canonical ids, hashes, trigger context, receipt refs, artifact refs, and restore metadata; `file.apply_patch` consumes that Rust output through the direct-invoker workspace restore runner and no longer calls `appendWorkspaceSnapshotEvent()` or completes successfully when the Rust snapshot record is missing. | Diagnostics follow-up remains JS-coordinated, restore artifact/event admission remains fail-closed, and the runner is temporary migration transport. |
| Public workspace snapshot/restore API Rust-owned | `project_workspace_snapshot_list`, `project_workspace_snapshot_content_package`, `preview_workspace_snapshot_restore`, and `apply_workspace_snapshot_restore` are Rust daemon-core command responses in `workspace_restore.rs`; the public daemon surface now calls the direct-invoker workspace restore runner for list/content/preview/apply and no longer derives snapshot projection truth from JS runtime events or `codingArtifacts`. | Agentgres-backed persistence/projection storage and restore artifact/event admission still need direct Rust ownership beyond the temporary runner transport. |
| Coding-tool workload observation contract canonicalized | Rust `coding_tool_workspace.rs` now emits snake_case result observations for `workspace.status`, `git.diff`, `file.inspect`, `file.apply_patch`, `test.run`, and `lsp.diagnostics`; the JS Rust-live result wrapper recursively strips retired camelCase observation keys instead of translating them, and coding-tool result summaries/output contracts read only canonical Rust result fields. | JS still wraps the Rust observation into candidate result-event/context envelopes and coordinates post-edit diagnostics, projection, replay, and public readback adapters. |
| Post-edit diagnostics feedback plan Rust-owned | `plan_post_edit_diagnostics_feedback` is a Rust daemon-core operation; Rust owns post-edit diagnostics mode normalization, changed-path selection from canonical `changed_files`, repair-policy normalization, workspace snapshot and rollback refs, auto diagnostics `tool_call_id`, `diagnostics_repair_context`, and the `lsp.diagnostics` request envelope. The diagnostics feedback JS surface now fails closed without the Rust planner and only forwards the Rust-authored request to the mounted coding-tool invocation surface. | The actual `lsp.diagnostics` follow-up still runs through temporary JS runner transport, and diagnostics projection/replay/readback remain JS adapter scaffolding until Rust projection APIs replace them. |
| Context-policy/state-update Rust planning | Context budget, coding-tool budget, compaction, context-compaction, operator control, run-cancel, thread lifecycle, MCP/memory, bridge thread/subagent, and lifecycle state-update planning use Rust response families and direct invoker only. | Public JS context/state facades remain protocol scaffolding. |
| Public agent create positive API | Public agent creation now calls Rust `plan_agent_create_state_update`; JS gathers candidate provider/model-route/MCP/runtime-control facts only after the Rust planner boundary exists, requires a Rust-returned `agent.create` projection with complete identity/timestamps, commits only that projection through Agentgres-backed `writeAgent`, and keeps direct `agents` map mutation retired. | Wallet/cTEE policy, replay/projection, and direct Rust lifecycle APIs remain non-terminal beyond the temporary context-policy runner transport. |
| Public top-level thread create positive API | Top-level public thread creation now calls Rust `plan_thread_create_state_update`; JS gathers canonical agent/thread candidate facts only after the Rust planner boundary exists, requires Rust-returned `agent` and `thread` projections with matching identity, commits only the Rust-authored `thread.create` agent projection through Agentgres-backed `writeAgent`, projects the returned thread through the Rust thread/turn projection boundary, and remains fail-closed before route planning when the Rust planner is absent. | Wallet/cTEE policy, direct lifecycle protocol APIs, durable thread-create replay/projection storage, and the context-policy runner transport remain temporary. Runtime-service thread start remains a separate fail-closed bridge boundary. |
| Public run create positive API | Agent-scoped public run creation now calls Rust `plan_run_create_state_update`; JS gathers agent/provider/model-route/memory/run-candidate facts only after the Rust planner boundary exists, requires a Rust-returned `run.create` projection with complete identity/timestamps, commits only that projection through Agentgres-backed `writeRun`, keeps direct `runs` map mutation retired, ignores retired thread/approval and diagnostics request aliases, and remains fail-closed before lookup/route/memory when the Rust planner is absent. | Run replay/projection, wallet/cTEE policy, and direct Rust lifecycle APIs remain non-terminal beyond the temporary context-policy runner transport. |
| Public task create positive API | Public task creation now calls Rust `plan_runtime_task_job_create_state_update`; JS requires canonical `agent_id`, gathers the existing agent, model-route, memory, and run candidate only after the Rust planner boundary exists, and requires Rust-authored `task.create` task/job/checklist plus run projections before committing only the returned run through Agentgres-backed `writeRun`. Direct `createAgent`, `createRun`, JS task/job/checklist projection synthesis, retired request aliases, and projection mismatch compatibility paths remain retired. | Wallet/operator authority, durable task-create replay/projection storage, and direct Rust lifecycle APIs remain non-terminal beyond the temporary context-policy runner transport. |
| Public run cancel positive API | Public run cancellation now calls Rust `plan_run_cancel_state_update`; JS supplies only the current run and cancel timestamp, requires a Rust-returned `run.cancel` projection with canceled status, terminal job/run events, runtime task/job/checklist records, receipts, and artifacts, commits only that Rust-authored projection through Agentgres-backed `writeRun`, and keeps direct run-map mutation plus JS runtime task/job/checklist/event/receipt/artifact materialization retired. | Wallet/operator authority, cancellation replay/projection storage, and direct Rust lifecycle APIs remain non-terminal beyond the temporary context-policy runner transport. |
| Public task/job cancel positive API | Public task and job cancellation now call Rust `plan_runtime_task_job_cancel_state_update`; JS derives only the canonical run id from `task_`/`job_` public ids, supplies the current run and cancel timestamp, requires Rust-returned `task.cancel`/`job.cancel` projections with matching canceled task/job/checklist and run records, terminal events, receipts, and artifacts, then commits only the Rust-authored run through Agentgres-backed `writeRun`. Direct `cancelRun`, public-id fallback, JS task/job/checklist/event/receipt/artifact materialization, and projection mismatch compatibility paths are retired. | Wallet/operator authority, cancellation replay/projection storage, and direct Rust lifecycle APIs remain non-terminal beyond the temporary context-policy runner transport. |
| Public task/job read projection positive API | Public task/job list and get now call Rust `project_runtime_task_job_projection`; JS only gathers raw run candidates after the Rust projector boundary exists, forwards canonical `agent_id`, `status`, `task_id`, and `job_id`, and requires Rust-authored task/job records, filters, and public-id selection before returning public records. The task/job surface no longer receives JS `runtimeTaskRecordForRun`/`runtimeJobRecordForRun` builders, retired `agentId` aliases remain ignored, and missing/mismatched Rust projections fail closed instead of falling back to JS record synthesis. | Wallet/operator authority, durable read projection storage/replay, and direct Rust lifecycle APIs remain non-terminal beyond the temporary context-policy runner transport. |
| Public non-runtime thread resume/turn create positive API | Public non-runtime thread resume now enters the mounted Rust-planned agent status-control path and returns the Rust thread projection; public non-runtime turn creation now enters the mounted Rust-planned run-create path and returns the Rust turn projection. Direct `store.updateAgent()`, `store.createRun()`, JS turn projection composition, and runtime-event append remain retired from the thread-turn surface. | Diagnostics-blocked turn creation, runtime-service bridge thread control/turn submit, direct lifecycle protocol APIs, durable replay/projection storage, and command-transport retirement remain non-terminal. |
| Public agent status-control positive API | Public archive/unarchive/resume/close/reload now call Rust `plan_agent_status_state_update`; JS supplies the current agent and requested status facts, requires a Rust-returned agent projection plus matching operation kind, and commits only that Rust-authored projection through Agentgres-backed `writeAgent`. Missing planner output or mismatched operation kind fails closed before persistence. | Replay, projection, and broader lifecycle APIs remain temporary or fail-closed. |
| Public agent delete positive API | Public permanent delete now calls Rust `plan_agent_delete_state_update`; JS supplies the current agent fact, requires a Rust-returned `agent.delete` tombstone with `status: deleted` and `deletedAt`, commits only that tombstone through Agentgres-backed `writeAgent`, and keeps local removal/duplicate operation append retired. | Wallet/retention authority, deletion replay/projection, durable cache invalidation, and broader lifecycle APIs remain non-terminal. |
| Public thread runtime-control positive API | Rust `plan_thread_control_agent_state_update` now owns public mode/model/thinking and generic runtime-control state planning. The JS surface gathers canonical agent, control, event-sequence, and model-route facts, fails closed without the Rust planner before lookup, persists only the Rust-authored agent projection through Agentgres-backed `writeAgent`, and leaves direct control-event append retired under `thread-control-js-facade-retired`. | Model route selection still depends on the separate model_mount route authority surface; direct runtime-control event materialization, deeper workspace-trust wallet/cTEE authority enforcement, replay/projection storage, and the context-policy runner transport remain temporary. |
| Workspace-trust warning/ack positive API | Rust `plan_workspace_trust_control_state_update` now owns workspace-trust warning and acknowledgement event envelope planning. Thread mode updates require the Rust workspace-trust planner before lookup/write, persist only the Rust-authored thread-control agent projection, then admit Rust-authored workspace-trust warning events through `admit_runtime_thread_event`; acknowledgement routes replay admitted warning events through the Rust runtime-event replay path, require Rust-authored acknowledgement events with receipts, and admit only those Rust-authored events. The old JS warning/ack payload builders and repository-context warning record path remain retired. | Wallet/cTEE workspace authority is represented as Rust-owned receipt/authority refs but still needs deeper direct cTEE/wallet enforcement and stable protocol APIs beyond the temporary context-policy runner and replay cache transport. |
| Generic runtime thread-event admission positive API | `admit_runtime_thread_event` is a Rust daemon-core operation; generic runtime event append now requires Rust Agentgres admission with receipt refs, expected heads, state roots, storage admission, payload refs, and projection watermarks before JS can register the Rust-returned event for local replay. | JS still constructs the candidate event envelope and only keeps a temporary replay cache; synthetic thread-start projection, legacy run-event projection, public readback APIs, and runner transport still need direct Rust projection/replay ownership. |
| Runtime thread-event projection positive API | `project_runtime_thread_events` is a Rust daemon-core operation; Rust now authors synthetic `thread.started` and run-event projection envelopes from canonical agent/run facts, rejects retired projection request aliases, skips known idempotency keys, requires receipt refs, admits each projected event through Rust Agentgres admission, and returns only Rust-admitted event records for local replay registration. The thread-event surface no longer receives the JS `ttiEnvelopeForRunEvent` builder. | JS still gathers current agent/run facts and maintains a temporary replay cache; runner transport still needs direct Rust projection/replay ownership. |
| Runtime thread-event replay positive API | `project_runtime_thread_event_replay` is a Rust daemon-core operation; public stream/turn readback now sends temporary cache candidates to Rust, and Rust owns replay-kind selection, canonical `since_seq`/`last_event_id` cursor evaluation, required Agentgres admission refs, resulting state/head/watermark projection, and the returned event list. The JS stream/turn helpers no longer call `runtimeCursorSeq()` or filter by stream/turn locally, and they fail closed without the Rust replay API. | JS still maintains and supplies the temporary replay cache, and the runtime Agentgres runner is still migration transport until stable Rust projection/replay protocol APIs replace it. |
| Runtime thread/turn projection positive API | `project_runtime_thread_turn_projection` is a Rust daemon-core operation; public thread and turn records are Rust-authored projections over canonical agent/run facts and Rust replay events, including seq ranges, input/output item ids, usage envelope placement, runtime identity fields, projection hashes, and retired alias rejection. The JS `threadForAgent()` and `turnForRun()` helpers now fail closed without the Rust projection API instead of composing public records locally. | JS still supplies canonical agent/run/usage facts and invokes the temporary runtime Agentgres runner transport until stable Rust projection APIs replace it. |
| Public runtime account/node/tool catalog projection positive API | `project_runtime_tool_catalog` is a Rust daemon-core operation; public `/v1/account`, `/v1/runtime/nodes`, and `/v1/tools` now require the Rust projector through the mounted tool surface, return Rust-authored account/node/tool catalog records, keep canonical snake_case tool catalog entries, and reject projection mismatches. The old `RuntimeToolCatalogProjectionRequiredCore` command path is removed from the Rust policy owner, command protocol, command dispatch, JS runner, and mounted tool surface. | JS still supplies temporary request/environment facts and invokes the context-policy runner transport; direct Rust catalog storage/projection APIs and broader Agentgres-backed catalog persistence remain non-terminal. |
| Public skill/hook registry projection positive API | `project_skill_hook_registry` is a Rust daemon-core operation; public `/v1/skills`, `/v1/hooks`, and doctor skill/hook readiness now require the Rust projector through the mounted skill-hook surface, return Rust-authored public catalog records, and reject registry-kind mismatches. The old `SkillHookRegistryProjectionRequiredCore` command path is removed from the Rust policy owner, command protocol, command dispatch, JS runner, and mounted skill-hook surface. | JS still supplies temporary workspace/home request facts and invokes the context-policy runner transport; direct Rust catalog persistence/replay APIs and broader Agentgres-backed governance storage remain non-terminal. |
| Public repository workflow projection positive API | `project_repository_workflow` is a Rust daemon-core operation; public repository workflow routes now require the Rust projector through the mounted repository surface, return Rust-authored repository context, branch policy, GitHub context, issue context, PR attempt, review gate, and GitHub PR create-plan records, and reject projection-kind mismatches. The old `RepositoryWorkflowProjectionRequiredCore` command path is removed from the Rust policy owner, command protocol, command dispatch, JS runner, and mounted repository surface. | JS still supplies temporary workspace request facts and invokes the context-policy runner transport; durable Agentgres-backed repository workflow storage/replay, wallet authority for external exits, receipt/state-root binding, and direct Rust protocol APIs remain non-terminal. |
| Public lifecycle projection positive API | `project_runtime_lifecycle` is a Rust daemon-core operation; public agent, thread, run, agent-run, thread usage, thread turn/detail/event, run wait/conversation/usage/event/replay/trace/inspect/computer-use/scorecard/artifact list/detail routes now require the Rust projector through the mounted lifecycle surface, return Rust-selected lifecycle projections, and reject projection-kind mismatches. The old `RuntimeLifecycleProjectionRequiredCore` command path is removed from the Rust policy owner, command protocol, command dispatch, JS runner, and mounted lifecycle surface. | JS still supplies temporary Agentgres/cache request facts and invokes the context-policy runner transport; direct Rust run-read storage/replay APIs, wallet/cTEE authority on lifecycle exits, receipt/state-root binding, and stable IDE/CLI/SDK protocol APIs remain non-terminal. |
| Public memory projection positive API | `project_runtime_memory_projection` is a Rust daemon-core operation; public memory list, policy, path, status, and validation routes require the Rust projector through the mounted thread-memory surface, return Rust-selected memory projections, and reject projection-kind mismatches. The public read/status/policy/path/validation fail-closed JS facade is removed, while missing Rust projection still fails before JS `AgentMemoryStore` readback. | JS still supplies temporary memory projection candidates from the current store; direct Rust memory admission/storage/replay APIs, wallet/policy authority, receipt/state-root binding, and stable SDK/IDE memory APIs remain non-terminal. |
| Public conversation-artifact read projection positive API | `project_runtime_conversation_artifact_projection` is a Rust daemon-core operation; public and thread-scoped conversation-artifact list/get/revision routes require the Rust projector through the mounted artifact surface, return Rust-selected artifact projections, and reject projection-kind mismatches. The public read fail-closed JS facade is removed, while missing Rust projection still fails before JS `ConversationArtifactStore` readback. | JS still supplies temporary artifact candidates from the current store; direct Rust artifact admission/storage/replay APIs, ArtifactRef/PayloadRef truth, wallet/cTEE authority where needed, receipt/state-root binding, and stable SDK/IDE artifact APIs remain non-terminal. |
| JS facade and alias retirement | Daemon-store pass-through wrappers, many compatibility aliases, local event writers, fixture selectors, provider JS drivers, and stale readback helpers have been deleted or fail closed. | Remaining `rust_core_required` surfaces should be collapsed into macro positive Rust APIs instead of producing more helper-level retirements. |

## Remaining Terminal Blockers

- Rust daemon core does not yet own every hot-path positive API. Many JS surfaces
  fail closed correctly, but fail-closed is not terminal ownership.
- StepModuleRouter dispatch, workload invocation construction, Agentgres
  admission, receipt/state-root binding, projection, and replay are not yet one
  Rust-owned execution spine for every route family.
- Approval-required coding-tool execution has Rust satisfaction, block planning,
  result-event admission, public approval request/decision/revoke control,
  public approval queue/read projection, public decision/revoke wallet authority
  binding, budget-block planning/admission, and coding-tool satisfaction
  projection, but approval request/grant issuance semantics and approval
  authority projection/replay still need direct Rust authority/admission
  ownership beyond temporary runner transport.
- Coding-tool invocation still builds candidate context/result-event envelopes
  in JS. Patch snapshot capture, public workspace snapshot/restore APIs,
  workload observation field ownership, and post-edit diagnostics feedback
  planning are Rust-owned, but diagnostics projection, replay, restore
  artifact/event admission, and temporary runner transport still need one
  Rust-owned execution spine.
- Model_mount provider lifecycle, route control, backend/server/runtime/tokenizer
  projection, conversation state, local provider inventory, catalog search/status
  truth beyond the current empty/default catalog-status projection, and most
  public read APIs still need direct Rust daemon-core ownership beyond migration
  transport.
- Public agent create/thread create/run create/task create/run cancel/task-job cancel/archive/unarchive/resume/close/reload/delete and thread
  mode/model/thinking runtime controls are now Rust-planned and
  Agentgres-backed at the public surface, while generic runtime thread-event
  append plus synthetic thread-start/run-event projection now use Rust
  Agentgres admission/projection spines. Public stream/turn replay readback now
  uses Rust replay selection over Agentgres-admitted event records, and public
  thread/turn projection records are Rust-authored over those replay events.
  Deletion/cancellation replay/projection, direct runtime-control event
  materialization, deeper wallet/cTEE workspace-trust authority enforcement,
  diagnostics-blocked turn creation, runtime
  bridge thread start/turn submit/control, durable task/job replay/projection
  storage, and broader run lifecycle still need Rust daemon-core ownership.
  Subagent control, workflow-edit apply, diagnostics repair, memory
  mutation/control, and MCP surfaces still include fail-closed JS facades.
- cTEE private workspace, worker/service package, L1 settlement, external
  capability, and governed-improvement runners are direct-invoker-only, but the
  JS runner facades still need replacement by stable Rust daemon-core APIs.
- IDE/CLI/SDK surfaces still need stable protocol APIs over Rust projection and
  replay records instead of depending on route-family JS adapter behavior.
- The temporary command transport must not become the terminal substrate.

## Do Not Recreate

The following paths are retired and must not be restored as compatibility
scaffolding:

- shared JS command-spawn helper:
  `packages/runtime-daemon/src/runtime-daemon-core-command-runner.mjs`
- StepModule command wrapper:
  `packages/runtime-daemon/src/step-module-command-runner.mjs`
- JS coding-tool approval satisfaction gate:
  `codingToolApprovalSatisfaction()`
- JS coding-tool approval satisfaction projection/matcher:
  `codingToolApprovalSatisfactionProjection()`,
  `codingToolApprovalManifestsMatch()`
- JS approval request readback facade:
  `latestApprovalRequestEvent()`
- JS approval block facade:
  `blockCodingToolForApproval()`
- command/env fallback selectors for migrated hot paths:
  `IOI_RUNTIME_DAEMON_CORE_COMMAND`, `IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`,
  per-runner `*_COMMAND` envs, constructor `command`, and constructor `args`
- bridge-local command identity/dispatch wrappers deleted from
  `crates/node/src/bin/ioi_step_module_bridge`
- daemon-store pass-through wrappers that re-enter mounted surfaces as duplicate
  authority
- standalone JS fixture-policy compatibility wrapper:
  `packages/runtime-daemon/src/model-mounting/fixture-policy.mjs`;
  `fixture-policy.mjs` is absent, and disabled-internal-fixture cleanup remains
  private inside `default-discovery.mjs`
- retired internal fixture enable selector:
  `IOI_ENABLE_INTERNAL_FIXTURE_MODELS` no longer enables fixture seeding; the
  only explicit selector is `IOI_EXPOSE_INTERNAL_FIXTURE_MODELS`
- JS event scans, local file cache reads, fixture selectors, provider-map
  readbacks, or compatibility aliases that can author accepted truth

## Conformance Posture

Current conformance is proof that the current tier surface is internally
consistent, not proof that terminal migration is done.

Required checks after every macro cut:

| Check | Purpose |
| --- | --- |
| `node --check` on touched JS/conformance files | syntax and module integrity |
| focused `node --test` or Rust tests | local behavior and negative guards |
| `npm run hypervisor-conformance:docs` | docs/source-of-truth consistency |
| `npm run hypervisor-conformance:bridge` | bridge/direct-invoker/facade guards |
| relevant tier commands | receipts, cTEE, compositor, negative, or ABI as touched |
| `npm run hypervisor-conformance` | full current-tier proof |
| `git diff --check` | whitespace and patch hygiene |

Terminal acceptance still requires the master guide terminal conditions, not
just a green current-tier suite.

## Matrix Maintenance Rule

Do not append one section per implementation slice. Add or update a row only
when a macro authority boundary changes:

- a positive Rust daemon-core API replaces a fail-closed JS facade;
- a route-family truth path moves into Rust with admission, receipts,
  projection, replay, and conformance;
- a temporary command transport or JS facade is deleted for an entire family;
- a terminal blocker changes shape.

If future work needs detailed evidence, cite tests, conformance check IDs, and
git commits. Do not rebuild a slice-by-slice narrative inside this matrix.
