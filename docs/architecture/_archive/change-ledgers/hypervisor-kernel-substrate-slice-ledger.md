# Hypervisor Kernel Substrate Unification — Per-Slice Ledger

Status: archived change ledger (verbatim extraction).
Doctrine status: archived
Implementation status: n/a (historical record)
Archived from: `docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md` on 2026-07-05.
Canonical owner: none; this file is history, not authority. Subject doctrine remains with the owners in `docs/architecture/_meta/source-of-truth-map.md`.
Superseded by: the non-doctrinal migration/evidence guide and implementation ledger. Git history retains the original placement.

---

Current lane note: after the public runtime projection family direct API cut,
public runtime account, runtime-node, tool catalog, skill/hook registry,
repository workflow, agent, thread, run, agent-run lifecycle, run wait, run conversation,
thread usage, thread turns, thread turn detail, thread events, run usage, run
events, run replay, run trace/inspect, run computer-use trace/trajectory, run
scorecard, run artifact, top-level usage, authority-evidence, public memory
list/policy/path/status/validation, public/thread-scoped
conversation-artifact route-facing projections, and public subagent
list/get/result projections are no
longer JS-authored public truth. Runtime account/node/tool catalog projections
now call typed `daemonCoreRuntimeProjectionApi.projectRuntimeToolCatalog`,
skill/hook registry projections now call typed
`daemonCoreRuntimeProjectionApi.projectSkillHookRegistry`, repository workflow
projections now call typed
`daemonCoreRuntimeProjectionApi.projectRepositoryWorkflow`, and runtime
lifecycle projections now call typed
`daemonCoreRuntimeProjectionApi.projectRuntimeLifecycle`; all four are backed by
Rust `RuntimeKernelService` projection methods and their old command operations,
dispatch arms, response wrappers, and JS generic `operation` envelopes are
retired. The mounted thread-memory surface
now calls Rust `project_runtime_memory_projection` for public memory
list/policy/path/status/validation before JS `AgentMemoryStore` readback;
conversation-artifact list/get/revision routes call Rust
`project_runtime_conversation_artifact_projection` through the mounted artifact
surface with runtime `state_dir` and reject JS artifact candidate transport,
while artifact create/action/export/promote call Rust
`plan_runtime_conversation_artifact_control` and Rust Agentgres artifact-state
commit before route truth returns; subagent list/get/result routes call Rust
`project_runtime_subagent_projection` through the store-owned subagent API
before JS subagent/run map readback, while subagent wait control uses Rust
`plan_runtime_subagent_control`, Rust runtime-event Agentgres admission, Rust
subagent record state-update planning, and Agentgres-backed `writeSubagent`;
subagent input/resume use the same Rust control/state path plus Rust-owned
child-agent run creation, subagent assign/cancel use the same Rust control/state
path, cancel composes with Rust run-cancel state planning, and cancellation
propagation uses Rust read projection plus propagated-cancel/run-cancel/state
planning before Agentgres-backed subagent persistence; direct subagent
control-event append uses Rust control planning plus Rust runtime-event
Agentgres admission without JS mutation; public workflow-edit proposal/apply
controls call Rust `plan_runtime_workflow_edit_control` and admit only
Rust-authored `workflow.edit_proposed`/`workflow.edit.apply` events through
Rust runtime-event Agentgres admission without JS event, approval, workflow JSON,
or legacy replay authorship; diagnostics repair decision execution and direct
decision-event append call Rust `plan_runtime_diagnostics_repair_control` and
admit only Rust-authored diagnostics repair events through Rust runtime-event
Agentgres admission without JS event append, run-state mutation, or repair-truth
persistence, and diagnostics repair decision resolution calls Rust
`project_runtime_diagnostics_repair_projection` over runtime `state_dir`
Agentgres event replay before accepted repair truth can return without JS
projection readback or decision-candidate transport; diagnostics operator
override execution calls Rust `plan_diagnostics_operator_override_state_update`,
sends raw operator request, decision, repair-policy context, and canonical
wallet authority refs instead of JS approval verdicts, lets Rust derive the
override approval state, requires wallet.network grant and authority receipt
refs for approval-required overrides, rejects retired verdict/authority
transport, and commits only the Rust-planned operator-control run projection
through Rust Agentgres run-state admission without JS run-map mutation; direct
operator-override event append also calls Rust diagnostics repair control
planning, applies the same wallet authority gate, and admits only the
Rust-authored operator-override event through Rust runtime-event admission;
diagnostics repair retry-turn creation composes with the direct Rust-backed
run-create lifecycle API and admits only a Rust-authored retry event through Rust
diagnostics repair event planning/runtime-event admission, while direct
retry-event append uses that same Rust-owned admission path; public agent
create, top-level thread create, agent status/delete, and agent-scoped run
create routes call direct Rust-backed lifecycle APIs; public
runtime account/node/tool catalog routes call the mounted tool API directly;
public repository workflow routes call the mounted repository API directly;
public skill and hook catalog routes call the mounted skill-hook registry
surface directly; public model catalog and model-capability routes call the
mounted model-mount read-projection surface directly;
model-mount `server_status` read projection now sends empty request state plus
request-level `base_url` into Rust, and the deleted JS
`serverStatusProjectionInput()` helper can no longer materialize public server
truth from volatile server-control state;
model-mount tokenizer and route-control Rust-core-required planner records now
live in dedicated Rust `model_mount/required/{tokenizer,route_control}.rs`
owner modules behind the facade-only `model_mount/required.rs`, while
backend-lifecycle, server-control, and runtime-engine positive control planners
live in Rust `model_mount/{backend_lifecycle,server_control,runtime_engine}.rs`
behind the stable `ModelMountCore` facade, and the Rust tests now live beside
those child owners instead of accumulating in the broad model-mount kernel file;
model-mount schema constants, `ModelMountError`, receipt-ref validation,
non-empty/string helpers, evidence-ref de-duplication, and SHA-256 helper logic
now live in the dedicated Rust `model_mount/common.rs` module, giving the split
model-mount owner modules one shared Rust foundation rather than re-growing the
broad facade file;
model-mount route-decision and invocation-admission request/record types,
validation, cTEE custody/plaintext checks, receipt binding checks, and admission
hashing now live in the dedicated Rust `model_mount/admission.rs` module behind
`ModelMountCore`, making the model-route and invocation admission gate a
distinct Rust core boundary rather than broad model-mount helper code, and the
admission Rust tests now live beside those gates instead of accumulating in the
broad model-mount kernel file;
model-mount backend-process plan request/result types, validation, public/spawn
argument shaping, readiness status, evidence refs, and plan hashing now live in
the dedicated Rust `model_mount/backend_process.rs` module behind
`ModelMountCore::plan_backend_process`, and the backend-process Rust
tests/fixtures now live beside that planner instead of in the broad parent
facade, keeping backend-process ownership directional toward Rust core
process/lifecycle APIs rather than a long-term Node bridge shape;
model-mount accepted-receipt head/transition request/result types, validation,
state-root derivation, operation/head refs, transition hashing, and tamper
validation now live in the dedicated Rust `model_mount/accepted_receipt.rs`
module behind `ModelMountCore`, and the accepted-receipt Rust tests/fixtures
now live beside that implementation instead of in the broad parent facade,
making receipt/state-root binding a distinct Rust core boundary rather than
broad model-mount helper code;
model-mount provider lifecycle, provider inventory, and model-instance
lifecycle request/result types, validation, backend/driver classification,
evidence refs, and transition hashes now live behind the Rust
`model_mount/lifecycle.rs` facade, with provider lifecycle owned by
`model_mount/lifecycle/provider.rs`, provider inventory owned by
`model_mount/lifecycle/inventory.rs`, and model-instance lifecycle owned by
`model_mount/lifecycle/instance.rs`; `ModelMountCore` still forwards through
the facade, but each lifecycle family now carries its own module-local Rust
proof so the next direct daemon-core API cut can retire JS edge translation
without treating the broad lifecycle facade as the long-term owner;
model-mount provider execution admission now lives in the Rust
`model_mount/provider_execution/admission.rs` boundary behind the
`model_mount/provider_execution.rs` facade and `ModelMountCore`, while
fixture/native-local provider invocation execution lives in
`model_mount/provider_execution/invocation.rs` and native-local stream
invocation chunk planning lives in
`model_mount/provider_execution/stream.rs`; provider-result admission now lives
in the dedicated Rust
`model_mount/provider_result.rs` module behind `ModelMountCore`, making
provider execution and provider-result binding separate Rust core boundaries
for the next direct daemon-core API cuts, and the provider execution,
invocation, stream, and provider-result Rust tests now live beside their owning
modules instead of accumulating in the broad model-mount kernel file;
model-mount read-projection adapter-boundary and workflow-binding projection
authors now live in the dedicated Rust
`model_mount/read_projection/adapter_boundary.rs` module, with module-local
Rust proof that wallet.network, cTEE/vault, OAuth, Agentgres, and workflow node
projection metadata are authored by Rust instead of a JS compatibility helper
or broad dispatcher body;
model-mount server/catalog status and authority-snapshot projection authors now
live in dedicated Rust `model_mount/read_projection/status.rs` and
`model_mount/read_projection/authority.rs` modules, with module-local Rust
proof that server status ignores retired JS status inputs, catalog status
ignores retired catalog-status inputs, and wallet authority summary/readback
metadata is owned outside the broad read-projection dispatcher;
model-mount receipt summary/replay read projections now live in the dedicated
Rust `model_mount/read_projection/receipt.rs` module, route-decision readback
now lives in Rust `model_mount/read_projection/route_decision.rs`, and latest
provider/vault health plus runtime-survey status now live in Rust
`model_mount/read_projection/health.rs`, with module-local Rust proof that
each family is derived from admitted receipt truth instead of JS topology,
provider-health, or runtime-survey materialization;
model-mount aggregate snapshot and projection envelopes now live in the
dedicated Rust `model_mount/read_projection/aggregate.rs` module, with
module-local Rust proof that top-level model_mount readback is assembled from
admitted receipts, projection summary, wallet/vault refs, adapter-boundary
metadata, and Rust-owned status/catalog helpers outside the broad dispatcher;
model-mount runtime-engine read-projection replay now lives in the dedicated
Rust `model_mount/read_projection/runtime.rs` module, with module-local Rust
proof that admitted `runtime-engine-controls` records materialize
engine/profile/preference/default-load/detail truth while caller-supplied JS
runtime-engine maps, profiles, preferences, and default load options cannot
become projection truth;
model-mount topology/product-catalog default read projections now live in the
dedicated Rust `model_mount/read_projection/topology.rs` module, with
module-local Rust proof that caller-supplied JS artifacts, providers,
endpoints, instances, routes, capabilities, downloads, backends,
provider-health rows, runtime catalog rows, and OpenAI-compatible model-list
rows cannot become projection truth;
model-mount public catalog-status readback now returns the Rust-authored
`catalog_status` projection from `model_mount/read_projection/status.rs` with
empty request state plus runtime `state_dir`, replaying admitted
`model-provider-inventory/*.json` Agentgres records into provider status,
storage status, last-search summary, and result rows; model-mount public OAuth
session/state readback now returns Rust-authored redacted rows from
`model_mount/read_projection/oauth.rs` by replaying admitted
`model-catalog-provider-controls/*.json` records with wallet/cTEE custody facts
and filtering legacy JS OAuth truth;
model-mount read-projection shared helpers now live in the dedicated Rust
`model_mount/read_projection/common.rs` module, with module-local Rust proof
that schema/generation defaults, array/object extraction, and receipt-kind
filtering are owned outside the broad dispatcher;
public studio intent-frame routing now calls typed
`daemonCoreRuntimeProjectionApi.projectStudioIntentFrame`, backed by Rust
`studio_intent_frame.rs`, while `studio-intent-frame.mjs` is absent so the
route cannot classify consequential Studio intents through a JS resolver;
Workbench Studio now consumes that Rust-authored `/v1/studio/intent-frame`
projection through canonical snake_case protocol fields, validates the Rust
decision material before use, and blocks instead of falling back to a local JS
prompt classifier when the daemon projection is unavailable;
public doctor routing now calls typed
`daemonCoreRuntimeProjectionApi.projectRuntimeDoctorReport` and returns the Rust
doctor report, while `runtime-doctor-report.mjs` is absent so the doctor route
cannot recompose readiness through mounted JS tool or skill surfaces;
Rust-live coding-tool invocation can still shape workload results through a
test-injected admission boundary, but the production-default invocation surface
now fails closed before appending an accepted coding-tool result event from JS.
Direct Rust daemon-core result-event admission over Agentgres expected
heads/state roots remains required before the coding-tool lane can be considered
terminal; daemon JS computer-use invocation facades for browser discovery,
control, native browser, visual GUI, and sandboxed hosted execution now fail
closed at entry before JS agent/thread lookup, local execution/projection, or
runtime-event append can author accepted truth; direct Rust daemon-core
computer-use invocation admission over wallet.network authority and Agentgres
expected heads/state roots remains required before that lane can be considered
terminal; daemon JS runtime thread-event append and legacy thread/run event
projection now fail closed before JS event-stream mutation or JSONL persistence
can author accepted replay truth; direct Rust daemon-core thread-event
admission/projection over Agentgres expected heads/state roots remains required
before replay is terminal; runtime agent/subagent persistence now refreshes JS
cache maps only after the Rust Agentgres state commit succeeds, so a rejected
Rust commit cannot leave JS in-memory lifecycle truth behind; model-mount
default seeding no longer writes derived backend records into the JS backend
registry map, and the retired backend seeding facade fails closed before backend
map mutation; public backend list projection now routes through the Rust
model-mount read-projection API with empty JS request state plus runtime
`state_dir` instead of the JS backend registry/readback facade, and Rust replays
admitted `model-backend-lifecycle-controls/*.json` records while filtering
JS-authored lifecycle controls; public backend health/start/stop/log lifecycle controls
now call Rust `plan_model_mount_backend_lifecycle` through the daemon-core
command bridge, receive Rust-authored `model-backend-lifecycle-controls`
records with backend-lifecycle evidence, commit only those records through Rust
Agentgres model_mount record-state admission, and return Rust public responses
before any JS backend registry lookup, derived backend projection, local backend
kind inference, receipt creation, process control, or log read/write can run;
public model-mount server-control start/stop/restart/write, operation
recording, and log append now call typed
`daemonCoreModelMountApi.planModelMountServerControl`, backed by Rust
`RuntimeKernel::plan_model_mount_server_control`, receive Rust-authored
`model-server-controls` records with server-control evidence, commit only
those records through Rust Agentgres model_mount record-state admission, and
return Rust public responses before any JS state write, log write, command
envelope, bridge backend tag, or transport execution can run;
public runtime-engine selection/profile/remove mutations now call typed `daemonCoreModelMountApi.planModelMountRuntimeEngine`, backed by Rust `RuntimeKernelService::plan_model_mount_runtime_engine`,
receive Rust-authored `runtime-engine-controls` records with runtime-engine
evidence, commit only those records through Rust Agentgres model_mount
record-state admission, and return Rust public responses before any JS runtime
preference/profile/projection write or receipt creation can run;
public tokenizer/count/context-fit utility facades now call typed
`daemonCoreModelMountApi.planModelMountTokenizer`, backed by Rust
`RuntimeKernelService::plan_model_mount_tokenizer`, bind the
Rust route-selection record and accepted receipt from `model_mount.route.select`,
commit only Rust-authored tokenizer/context-fit records through Rust Agentgres
model_mount record-state admission, and return committed Rust tokenizer truth
before any JS tokenizer required-record shim, command-envelope bridge,
context-window fallback, tokenization/context-fit receipt synthesis,
route-state mutation, truncation, or response-envelope shaping can run; public `modelTokenizerRecords()` now calls
Rust read-projection kind `model_tokenizer_records` with runtime `state_dir`, and
Rust replays persisted `model-tokenizer-utilities/*.json` Agentgres records while
filtering truth to Rust-authored tokenizer/context-fit records with tokenizer and
Agentgres evidence before any JS tokenizer projection path can return;
public route write/test now request Rust route-control plans through typed
`daemonCoreModelMountApi.planModelMountRouteControl`, backed by Rust
`RuntimeKernelService::plan_model_mount_route_control`, commit only the
Rust-authored route or route-test record through Rust Agentgres model_mount
record-state admission, and return committed Rust route-control truth before
any JS route-record authoring, route-control receipt synthesis, command-envelope
fallback, or duplicate route-state mutation can run; mounted route-selection and
explicit-model endpoint resolution now also request the same typed Rust
route-control plans, commit only Rust-authored
route-selection or endpoint-resolution records through Rust Agentgres
model_mount record-state admission, and return Rust-authored selection truth
before JS route map mutation, endpoint mounting, JS policy evaluation,
candidate scoring, JS-created route-control receipts, or duplicate
route-selection truth can run; runtime explicit/run-override model-route
selection now consumes that same Rust-authored route selection and accepted
receipt truth as a protocol client, without JS fallback route receipt minting;
model-mount read projection planning has moved out of the Node command bridge
helper body into `ModelMountCore::plan_read_projection`, and the bridge now
acts only as command transport for projection kinds while the duplicated
bridge-local projection planner/helper tree is removed; that Rust-owned
projection implementation now lives in `model_mount/read_projection.rs` behind
the `ModelMountCore` facade so future Rust-core projection/API cuts do not
accumulate in the broad model-mount kernel file;
the route-facing skill/hook, model catalog/capability, repository workflow,
runtime account/node/tool, and doctor-report daemon-store delegates have been
deleted rather than preserved as inert compatibility wrappers;
the mounted thread-turn surface now fails closed for missing non-runtime resume
and turn-create Rust boundaries before JS agent status mutation, run creation,
or turn projection can become accepted truth, while diagnostics-blocked turn
creation enters the Rust-planned run-create path and returns the Rust turn
projection instead of the retired diagnostics-block refusal route;
public usage, public authority-evidence, and `/api/v1` authority-evidence /
workflow-capability preflight routes now call the mounted lifecycle projection
surface, where Rust replays Agentgres state instead of the JS run-read cache;
and reload no longer reads JS agent state before fail-closed admission;
agent/thread memory write, edit, delete, policy, status, and validation routes
also call the mounted thread-memory surface directly before daemon-store
pass-through wrappers, with write/edit/delete/policy requiring Rust
`plan_runtime_memory_control` plus Rust Agentgres memory-state commit before
returning route projections and status/validation/direct event append requiring
Rust `plan_runtime_memory_control` event planning plus Rust runtime-event
admission; workflow-edit proposal/apply controls require Rust
`plan_runtime_workflow_edit_control` and Rust runtime-event admission before
accepted control truth can return; diagnostics repair decision execution and
direct decision-event append require Rust `plan_runtime_diagnostics_repair_control`
and Rust runtime-event admission before accepted repair control truth can return,
and diagnostics repair decision resolution requires Rust
`project_runtime_diagnostics_repair_projection` over runtime `state_dir`
Agentgres event replay before accepted repair projection truth can return;
diagnostics operator override execution requires Rust
`plan_diagnostics_operator_override_state_update` to derive the override
approval state from canonical request/decision/policy context plus Rust
Agentgres run-state admission before accepted override control truth can return;
thread fork now calls Rust daemon-core `plan_runtime_thread_fork_control`,
commits only the Rust-authored forked agent through Agentgres-backed
`writeAgent`, validates the forked-thread projection, and admits only the
Rust-authored `thread.forked` runtime event; workspace-change inspection and run
cancel routes call store-owned auxiliary API methods instead of a mounted
route-visible auxiliary facade while direct Rust daemon-core projection and
admission APIs are extracted; managed-session inspection/control now calls the Rust daemon-core
managed-session projection/control planner and admits only the Rust-authored
control event;
thread resume, turn create, interrupt, and steer routes now call
the mounted thread-turn surface directly instead of daemon-store route
pass-through wrappers while store methods remain temporary internal delegates
until direct Rust daemon-core turn admission and stable protocol APIs own that
surface. This is a
larger-cut migration seam, not terminal architecture: the command transport
including transitional Node bridge operations, JS edge error translation,
remaining internal descriptor helpers, and remaining
internal agent/thread/run list/get, usage, turn, event/replay, trace, and
artifact helpers plus internal memory and conversation-artifact projection
helpers are scaffolding only until Rust daemon-core catalog, lifecycle, agent/run
admission, memory admission/projection, durable managed-session
storage/replay/projection, workspace-change control, durable thread-fork
storage/replay/projection, run-cancel replay/projection, runtime thread/turn control, and
conversation-artifact projection over Agentgres-admitted truth,
ArtifactRef/PayloadRef binding where needed, wallet/network and cTEE authority
where required, receipt/state-root binding, replay, and stable Workbench/CLI/SDK
protocol APIs own the surfaces end to end.
Thread-tool invocation routes now also call the mounted coding-tool invocation
surface directly instead of the daemon-store `invokeThreadTool()` pass-through,
and post-edit diagnostics feedback now invokes `lsp.diagnostics` through that
mounted surface too. The daemon-store `invokeThreadTool()` wrapper is retired,
but the mounted JS surface and command transport remain migration scaffolding
until direct Rust daemon-core StepModuleRouter/workload-client APIs own dispatch
end to end.

Slice 1035 originally moved the policy projection-required refusal owner family
for skill/hook registry, repository workflow, runtime tool catalog, and runtime
lifecycle projections out of the broad Rust `policy.rs` facade. That
intermediate refusal-owner lane is now superseded for those public projection
families by positive Rust daemon-core APIs in `skill_hook_registry.rs`,
`repository_workflow.rs`, `runtime_tool_catalog.rs`, and
`runtime_lifecycle.rs`. Resume by replacing the remaining temporary runner
transport with direct Rust daemon-core projection/admission APIs over
Agentgres-admitted truth, wallet.network/cTEE authority where applicable,
receipt/state-root binding, replay, and stable Workbench/CLI/SDK protocol APIs.
Schedule a matrix-compaction pass after the next larger Rust-core extraction or
facade-retirement seam is clear.

Slice 1036 moves the run-cancel policy owner family out of the broad Rust
`policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/run_cancel.rs`. The child
module owns run-cancel state-update and admission-required request/record/error
types, planner cores, validation, cancellation helper planning, and focused
proof tests; the parent facade only re-exports the surface. This preserves the
larger pure-Rust extraction direction while keeping the current JS
run-cancel facade, context-policy runner, and Node command bridge explicitly
non-terminal. Resume by replacing that transport path with direct Rust
daemon-core cancellation admission/persistence over Agentgres expected
heads/state roots, receipt/event materialization, replay, projection, and
stable Workbench/CLI/SDK protocol APIs.

Slice 1037 moves the coding-tool budget recovery policy owner family out of
the broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/coding_tool_budget_recovery.rs`.
The child module owns budget-recovery state-update and control
request/record/error types, planner cores, validation, helper operator-control
planning, and focused proof tests; the parent facade only re-exports the
surface. This is an extraction toward the pure Rust daemon-core substrate, not
the terminal budget recovery architecture. The current JS coding-tool budget
recovery facade, JS context-policy runner, and Node command bridge remain
temporary migration transport. Resume by replacing that transport path with
direct Rust daemon-core budget recovery persistence over wallet
authority, Agentgres expected heads/state roots, policy receipts,
retry-event materialization, replay, projection, and stable Workbench/CLI/SDK
protocol APIs.

Slice 1038 moves the operator-control policy owner family out of the broad
Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/operator_control.rs`. The
child module owns diagnostics operator override, operator interrupt, and
operator steer state-update request/record/error types, planner cores,
validation, helper operator-control planning, and focused proof tests; the
parent facade only re-exports the surfaces. This is a larger Rust ownership
cut across two public controls, not terminal operator-control migration. The
current JS diagnostics repair facade, JS operator turn facade, JS
context-policy runner, and Node command bridge remain temporary migration
transport. Resume by replacing those transport paths with direct Rust
daemon-core operator-control admission/persistence over wallet authority,
runtime control custody, Agentgres expected heads/state roots, receipts/events,
replay, projection, and stable Workbench/CLI/SDK protocol APIs.

Slice 1039 moves the thread/run lifecycle policy owner family out of the
broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/thread_lifecycle.rs`. The
child module owns thread-control, agent create, run create, agent status,
runtime-bridge thread start, runtime-bridge turn run, and subagent record
state-update request/record/error types, planner cores, validation, model-route
alias rejection, subagent parent-thread mismatch rejection, and focused proof
tests; the parent facade only re-exports the surfaces. This is a larger
Rust ownership cut across lifecycle, runtime-bridge, and subagent state
planning, not terminal lifecycle migration. The current JS thread-control
facade, agent/run lifecycle facade, runtime-bridge thread facade, subagent
facade, JS context-policy runner, and Node command bridge remain temporary
migration transport. Resume by replacing those transport paths with direct
Rust daemon-core lifecycle admission/persistence over wallet authority,
cTEE policy where private workspace custody is involved, Agentgres expected
heads/state roots, receipts/events, replay, projection, and stable Workbench/CLI/SDK
protocol APIs. Schedule a matrix-compaction pass for Slices 1035-1039 once the
next larger Rust-core extraction/facade-retirement seam is clear.

Slice 1040 moves the context lifecycle policy owner family out of the broad
Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/context_lifecycle.rs`. The
child module owns context-budget policy, coding-tool budget policy,
compaction-policy, context-compaction plan, and context-compaction state-update
request/record/error types, planner/evaluator cores, validation, helper
planning, canonical context-compaction payload shaping, and focused proof
tests; the parent facade only re-exports the surfaces. This is a larger
Rust ownership cut across context policy and compaction planning, not terminal
context-policy migration. The current JS context-policy facade, JS
context-policy runner, and Node command bridge remain temporary migration
transport. Resume by replacing those transport paths with direct Rust
daemon-core context admission/persistence over wallet authority where policy
exits require it, Agentgres expected heads/state roots, policy receipts,
context-compaction events, replay, projection, and stable Workbench/CLI/SDK protocol
APIs. Keep the scheduled matrix-compaction pass for Slices 1035-1040 pending
until the next larger Rust-core extraction/facade-retirement seam is clear.

Slice 1041 moves the MCP/memory policy owner family out of the broad Rust
`policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/mcp_memory.rs`. The child
module owns MCP control state-update, MCP server validation, MCP validation
input projection, MCP manager validation/status/catalog/catalog-summary
projection, memory manager validation/status projection, and thread-memory
state-update request/record/error types, planner/projector cores, validation,
MCP catalog and memory projection helper logic, and focused proof tests; the
parent facade only re-exports the surfaces. This is a larger Rust ownership cut
across MCP and memory projection/control policy, not terminal MCP or memory
migration. The current JS MCP control/catalog/serve facades, JS thread-memory
surface, JS context-policy runner, and Node command bridge remain temporary
migration transport. Resume by replacing those transport paths with direct
Rust daemon-core MCP and memory admission/projection APIs over wallet authority
for external exits, cTEE custody where private workspace memory is involved,
Agentgres expected heads/state roots, MCP/memory receipts/events, replay,
projection, and stable Workbench/CLI/SDK protocol APIs. Keep the scheduled
matrix-compaction pass for Slices 1035-1041 pending until the next larger
Rust-core extraction/facade-retirement seam is clear.

Slice 1042 moves the workflow-edit and diagnostics-repair admission-required
owner family out of the broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/admission_required.rs`. The
child module owns the workflow-edit and diagnostics-repair
admission-required request/record/error types, planner cores, validation,
canonical detail shaping, and focused proof tests; the parent facade only
re-exports the surfaces. This finishes the current policy facade split: broad
`policy.rs` now carries shared policy constants, `PolicyEvaluationRecord`,
module declarations, and re-exports rather than owning migrated hot-path
planner cores. This is still not terminal workflow-edit or diagnostics-repair
migration. The current JS workflow-edit/diagnostics-repair facades, JS
context-policy runner, and Node command bridge remain temporary migration
transport. Resume by replacing those transport paths with direct Rust
daemon-core workflow-edit and diagnostics-repair admission/persistence APIs
over wallet approval authority where applicable, Agentgres expected
heads/state roots, proposal/apply/repair receipts and events, replay,
projection, and stable Workbench/CLI/SDK protocol APIs. Run the scheduled
matrix-compaction pass for Slices 1035-1042 once the next larger Rust-core
extraction/facade-retirement seam is clear.

Slice 1043 moves the workflow-edit and diagnostics-repair admission-required
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/policy_command.rs`. The service
owner remains `policy/admission_required.rs`; the bridge child module is only
fixed migration transport that translates the Rust-authored refusal records at
the process boundary. The conformance guard now proves the policy owner stays
out of the broad `policy.rs` facade and the admission-required command wrappers
stay out of the broad bridge module. This satisfies the scheduled
matrix-compaction pass for Slices 1035-1042, while preserving their
non-terminal status. Resume by replacing this command transport with direct
Rust daemon-core workflow-edit and diagnostics-repair admission/persistence
APIs over wallet approval authority where applicable, Agentgres expected
heads/state roots, proposal/apply/repair receipts and events, replay,
projection, and stable Workbench/CLI/SDK protocol APIs.

Slice 1044 moves the coding-tool approval manifest and approval
request/decision/revoke state-update daemon-core command wrappers out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into `crates/node/src/bin/ioi_step_module_bridge/approval_command.rs`.
The approval authority owner remains
`crates/services/src/agentic/runtime/kernel/approval.rs`; the bridge child
module is only fixed migration transport that translates Rust-authored
approval authority records at the process boundary. The conformance guard now
proves the approval command wrappers stay out of the broad bridge module.
This is not terminal approval migration. Resume by replacing this command
transport with direct Rust daemon-core approval authority/admission/persistence
APIs over wallet.network grants, Agentgres expected heads/state roots,
approval receipts/events, replay, projection, and stable Workbench/CLI/SDK protocol
APIs.

Slice 1045 moves the context-budget policy, coding-tool budget policy,
compaction policy, context-compaction plan, and context-compaction state-update
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/context_policy_command.rs`. The
context lifecycle policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/context_lifecycle.rs`; the
bridge child module is only fixed migration transport that translates
Rust-authored context policy records at the process boundary. The conformance
guard now proves the context lifecycle command wrappers stay out of the broad
bridge module. This is not terminal context-policy migration. Resume by
replacing this command transport with direct Rust daemon-core context
admission/persistence/projection APIs over wallet authority where applicable,
Agentgres expected heads/state roots, policy receipts/events, replay, and
stable Workbench/CLI/SDK protocol APIs.

Slice 1046 moves the MCP control state-update, MCP server validation, MCP
validation input projection, MCP manager status/validation/catalog/catalog
summary projection, memory manager status/validation projection, and
thread-memory state-update daemon-core command wrappers out of the monolithic
Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport
into `crates/node/src/bin/ioi_step_module_bridge/mcp_memory_command.rs`. The
MCP/memory policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/mcp_memory.rs`; the bridge
child module is only fixed migration transport that translates Rust-authored
MCP and memory policy records at the process boundary. The conformance guard
now proves the MCP/memory command wrappers stay out of the broad bridge
module. This is not terminal MCP or memory migration. Resume by replacing this
command transport with direct Rust daemon-core MCP and memory
admission/projection/persistence APIs over wallet authority for external
exits, cTEE custody where private workspace memory is involved, Agentgres
expected heads/state roots, MCP/memory receipts/events, replay, projection,
and stable Workbench/CLI/SDK protocol APIs.

Slice 1047 moves the thread-control, runtime-bridge thread-start, runtime
bridge turn-run, subagent record, agent create, agent status, and run create
state-update daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/thread_lifecycle_command.rs`. The
thread/run lifecycle policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/thread_lifecycle.rs`; the
bridge child module is only fixed migration transport that translates
Rust-authored lifecycle policy records at the process boundary. The
conformance guard now proves the thread lifecycle command wrappers stay out of
the broad bridge module. This is not terminal lifecycle migration. Resume by
replacing this command transport with direct Rust daemon-core lifecycle
admission/persistence/projection APIs over wallet authority and cTEE policy
where applicable, Agentgres expected heads/state roots, lifecycle
receipts/events, replay, projection, StepModuleRouter dispatch where lifecycle
work enters admitted module execution, and stable Workbench/CLI/SDK protocol APIs.

Slice 1048 moves the coding-tool budget recovery state-update and
admission-required, diagnostics operator-override state-update, operator
interrupt/steer state-update, and run-cancel state-update/admission-required
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/runtime_control_command.rs`. The
policy owners remain
`crates/services/src/agentic/runtime/kernel/policy/coding_tool_budget_recovery.rs`,
`crates/services/src/agentic/runtime/kernel/policy/operator_control.rs`, and
`crates/services/src/agentic/runtime/kernel/policy/run_cancel.rs`; the bridge
child module is only fixed migration transport that translates Rust-authored
runtime-control policy records at the process boundary. The conformance guard
now proves the runtime-control command wrappers stay out of the broad bridge
module. This is not terminal runtime-control migration. Resume by replacing
this command transport with direct Rust daemon-core budget-recovery,
operator-control, diagnostics-repair, and run-cancel
admission/persistence/projection APIs over wallet authority where applicable,
Agentgres expected heads/state roots, runtime-control receipts/events, replay,
projection, StepModuleRouter dispatch where control work enters admitted
module execution, and stable Workbench/CLI/SDK protocol APIs.

Slice 1049 originally moved the skill/hook registry, repository workflow,
runtime tool catalog, and runtime lifecycle projection-required daemon-core
command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport. That
intermediate projection-required lane is now superseded for those public
projection families: `project_skill_hook_registry`,
`project_repository_workflow`, `project_runtime_tool_catalog`, and
`project_runtime_lifecycle` are positive Rust daemon-core APIs, and the
projection-required policy owner for those migrated public routes is retired.
Slice 1225 now supersedes the remaining runner transport for this public
projection family with typed direct Rust daemon-core APIs and retires the old
command operations, dispatch arms, and response wrappers. This is still not
terminal projection migration. Resume with direct Rust daemon-core projection
APIs for the remaining lifecycle/run-read storage/replay, doctor/readiness,
replay, and stable Workbench/CLI/SDK surfaces over Agentgres-admitted truth,
receipt/state-root binding, wallet authority where applicable, and cTEE custody
where private workspace projection is involved.

Slice 1050 moves the workspace-restore apply-policy, preview/apply operations,
and workspace-snapshot capture daemon-core command wrappers out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/workspace_restore_command.rs`.
The workspace restore owner remains
`crates/services/src/agentic/runtime/kernel/workspace_restore.rs`; the bridge
child module is only fixed migration transport that translates Rust-authored
restore policy, operation, and snapshot capture records at the process
boundary. The conformance guard now proves the workspace-restore command
wrappers stay out of the broad bridge module. This is not terminal workspace
restore or snapshot migration. Resume by replacing this command transport with
direct Rust daemon-core workspace restore/snapshot admission, artifact
materialization, Agentgres expected-head/state-root persistence, receipts,
events, replay, projection, and stable Workbench/CLI/SDK protocol APIs.

Slice 1051 moves the cTEE private workspace action, worker/service package
invocation admission, L1 settlement admission, and governed runtime-improvement
proposal admission daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/governed_admission_command.rs`.
The Rust owners remain `ctee`, `marketplace`, `settlement`, `evolution`,
`receipt_binder`, and Agentgres admission; the bridge child module is only
fixed migration transport that translates those Rust-owned records at the
process boundary. The conformance guard now proves these governed
admission/action command wrappers stay out of the broad bridge module. This is
not terminal for the broader governed authority/admission/receipt migration.
Subsequent cuts replace external capability authority, cTEE, worker/service
package invocation, L1 settlement, and governed proposal admission with typed
Rust daemon-core APIs; the remaining work is richer receipt/state-root binding,
Agentgres admission, replay, projection, stable Workbench/CLI/SDK protocol surfaces,
and the same transport retirement for other route families.

Slice 1052 moves the Agentgres storage-write admission and runtime state commit
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/agentgres_command.rs`. This also
moves the runtime-state local persistence helper functions used by those commit
wrappers out of the broad bridge module. The Agentgres owner remains
`crates/services/src/agentic/runtime/kernel/agentgres_admission.rs`; the bridge
child module is only fixed migration transport that translates Rust-owned
admission and commit records at the process boundary. The conformance guard now
proves Agentgres command wrappers and bridge-local runtime-state write helpers
stay out of the broad bridge module. This is not terminal Agentgres migration.
Resume by replacing this command transport with direct Rust daemon-core
Agentgres admission, storage, persistence, replay, projection, and stable
IDE/CLI/SDK protocol APIs over expected heads, state roots, ArtifactRefs,
PayloadRefs, and receipts.

Slice 1053 moves the model_mount daemon-core command wrappers out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/model_mount_command.rs`. This
includes route-decision admission, invocation admission, provider execution,
provider invocation and stream planning, lifecycle/inventory/backend-process
planning, required-record planners, accepted-receipt head/transition planning,
invocation receipt binding, and read-projection wrappers. The Rust
owner remains `crates/services/src/agentic/runtime/kernel/model_mount.rs` and
its child modules, with receipt binding, StepModuleRouter admission,
Agentgres admission, and projection still called from Rust. The bridge child
module is only fixed migration transport that translates Rust-owned records at
the process boundary; it is not the long-term API. The conformance guard now
proves model_mount command structs and handlers stay out of the broad bridge
module while the bridge root keeps dispatch and proof tests. Resume by
replacing this command transport with direct Rust daemon-core model_mount APIs,
Agentgres-backed persistence/replay/projection, provider lifecycle/control,
and stable Workbench/CLI/SDK protocol surfaces.

Slice 1054 moves the external capability exit authority daemon-core command
wrapper out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/authority_command.rs`. The Rust
owner remains `crates/services/src/agentic/runtime/kernel/authority.rs`; the
bridge child module is only fixed migration transport that translates the
Rust-owned wallet.network authority record at the process boundary. The
conformance guard now proves the authority command struct and handler stay out
of the broad bridge module while the bridge root keeps dispatch and proof
tests. This is not terminal authority migration. Resume by replacing this
command transport with direct Rust daemon-core wallet.network authority APIs,
authority receipts, Agentgres/state-root binding where capability exits become
meaningful transitions, replay, projection, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1055 moves the coding-tool StepModule command wrapper family out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/coding_tool_command.rs`. This
includes the StepModule bridge request, `run_coding_tool_step_module`, the
workspace status, git diff, file inspect/apply patch, test run, LSP
diagnostics, artifact read, tool-result retrieval, computer-use lease response
wrappers, and the Rust workload/StepModuleRouter/receipt-binder/Agentgres
admission/projection response binding. The lower-level workspace filesystem,
diagnostic subprocess, patch, and path helpers remain temporary bridge helper
plumbing in the root module until the next direct Rust daemon-core execution
API extraction. This is not terminal coding-tool migration. Resume by replacing
both the command transport and the remaining bridge helper plumbing with direct
Rust daemon-core coding-tool execution/admission APIs, Rust/WASM workload
module execution, Agentgres-backed persistence, receipt/state-root binding,
replay, projection, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1056 moved the lower-level coding-tool workspace filesystem, path,
diagnostic subprocess, test-run, and patch helper plumbing out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/coding_tool_helpers.rs`. The broad
bridge root then retained proof tests and child-module wiring, while the
coding-tool command transport imports helper plumbing from a dedicated Rust
sibling module and Slice 1057 moves temporary operation dispatch to
`bridge_dispatch.rs`.
Conformance then failed if the helper function bodies returned to the root
bridge. Slice 1141 later retires this helper module entirely. This was still
not terminal coding-tool migration and must not canonize the Node bridge shape.
Resume by replacing the broad bridge transport and JS command runner/caller
path with direct Rust daemon-core coding-tool execution/admission APIs and
Rust/WASM workload modules, then retiring JS invocation facades, readback
shims, duplicate truth paths, and any compatibility wrappers that survive the
verified Rust-core boundary.

Slice 1057 moves the StepModule/daemon-core command dispatch table and
schema-family classifier out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/bridge_dispatch.rs`. The root
bridge now re-exports only the stdin response entry point and keeps child-module
wiring plus proof tests, while conformance fails if the operation match or
`is_daemon_core_operation` classifier returns to the root. This is still a
command-transport boundary, not terminal Rust daemon-core API ownership.
Resume by replacing the dispatch table with direct daemon-core protocol/API
entry points, retiring JS command callers/facades/readbacks, and binding
accepted work through Rust/WASM modules, Agentgres admission, receipt/state-root
binding, replay, projection, wallet.network authority, and cTEE custody.

Slice 1058 starts collapsing duplicated JS daemon-core command-runner spawn
scaffolding into
`packages/runtime-daemon/src/runtime-daemon-core-command-runner.mjs`. The
external capability authority, L1 settlement, governed improvement, and cTEE
private workspace runners now delegate empty-argv command invocation, mock
handling, JSON parsing, process failure mapping, and Rust rejection mapping to
that shared helper instead of each importing `node:child_process` and owning
local command-process semantics. Conformance now requires those runners to use
the shared helper and forbids direct child-process imports in them. This is a
JS-scaffolding reduction, not terminal API migration. Resume by moving the
remaining daemon-core runners onto the shared helper only as an intermediate
step, then replacing the shared command-runner helper itself with direct Rust
daemon-core protocol/API calls and retiring JS command facades/readbacks.

Slice 1059 extends that temporary shared command-runner helper to the
worker/service package, coding-tool approval, and approval-state runners. Those
runners no longer import `node:child_process` or own local JSON/process/Rust
rejection handling; conformance requires them to delegate to
`runtime-daemon-core-command-runner.mjs` while the helper keeps the fixed
empty-argv transport rule. This is still an intermediate scaffolding collapse,
not a canonical Node bridge. Resume by moving the remaining large daemon-core
runners onto the helper only where it reduces duplicate migration plumbing, then
cutting the helper itself over to direct Rust daemon-core protocol/API ownership
and retiring JS command facades, readback adapters, and compatibility wrappers
once Rust admission, Agentgres truth, receipt/state-root binding, replay,
projection, wallet.network authority, and cTEE custody are verified.

Slice 1060 extended the same temporary helper to the then-live runtime
Agentgres admission runner and workspace restore. That historical cut reduced
duplicated JS command transport on the Agentgres truth path and restore
planning/execution path, but the Agentgres runner side is now superseded by the
later mounted-core cut; do not recreate that shared command helper or runner
path. Resume by collapsing the remaining large context-policy, model-mount
admission, and StepModule command surfaces where helpful, then
replace the shared helper and Node command bridge with direct Rust daemon-core
protocol/API ownership.

Slice 1061 extends the temporary helper to the remaining large daemon-core
command runners: context policy and model-mount admission.
`runtime-context-policy-core.mjs` and
`model-mounting/model-mount-core.mjs` now delegate fixed empty-argv
command spawn, mock handling, JSON parsing, process failure mapping, and Rust
rejection mapping to `runtime-daemon-core-command-runner.mjs` instead of
importing `node:child_process` directly. This leaves the StepModule workload
runner as the only direct command-runner holdout, because it uses the
StepModule workload command schema rather than the daemon-core command schema.
Resume by making the StepModuleRouter/Rust workload boundary a deliberate
Rust-core cut, then replacing the shared daemon-core command helper and Node
command bridge with direct Rust daemon-core protocol/API ownership.

Slice 1062 removes the final runner-local command spawn from the StepModule
workload runner without treating the Node bridge as canonical architecture.
`packages/runtime-daemon/src/step-module-runner.mjs` now delegates the
temporary StepModule command-bridge transport to
`packages/runtime-daemon/src/step-module-command-runner.mjs`; the runner keeps
the Rust workload live contract, invocation projection, and fail-closed backend
selection behavior, but no longer imports `node:child_process` or owns the
spawn/JSON/Rust-rejection mechanics. Conformance now fails if the StepModule
runner regains direct child-process ownership, while the helper is explicitly
the remaining temporary process boundary for the distinct StepModule workload
schema. This is still not terminal StepModuleRouter migration. Resume by
replacing the StepModule command helper, the shared daemon-core command helper,
and the Node bridge with direct Rust daemon-core/workload protocol APIs,
Rust/WASM module execution, Agentgres admission, receipt/state-root binding,
replay, projection, wallet.network authority, cTEE custody, and stable
IDE/CLI/SDK protocol surfaces. Slice 1142 later retires the dedicated
StepModule command helper and collapses the remaining StepModule command
transport onto the shared temporary daemon-core command invoker.

Slice 1063 moved bridge command-envelope schema ownership out of the temporary
stdin dispatch transport and into the temporary bridge-envelope adapter at
`crates/node/src/bin/ioi_step_module_bridge/command_envelope.rs`. At that slice,
the adapter carried the StepModule command schema version, daemon-core command
schema version, expected-schema lookup, and daemon-core operation-family
classifier so `bridge_dispatch.rs` could keep only transport and schema checks.
This was an intermediate split, not canonical Rust ownership. Resume by
replacing bridge-envelope adapter ownership, the StepModule command helper, and
the shared daemon-core command helper with direct Rust daemon-core/workload
protocol APIs, while preserving Rust-owned StepModuleRouter dispatch, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1064 moves temporary bridge operation routing out of stdin/envelope
transport and into
`crates/node/src/bin/ioi_step_module_bridge/command_dispatch.rs`.
`bridge_dispatch.rs` now only reads stdin, parses the canonical envelope,
checks the Rust-owned command schema from `command_envelope.rs`, and calls
`dispatch_bridge_operation()`. The large operation match still exists as
temporary bridge routing, but it no longer lives in the process-envelope
transport. Conformance now fails if `bridge_dispatch.rs` regains the operation
table. This is still not terminal bridge retirement. Resume by replacing
`command_dispatch.rs`, `command_envelope.rs`, the StepModule command helper,
and the shared daemon-core command helper with direct Rust daemon-core/workload
protocol APIs over Rust/WASM execution, Agentgres admission, receipt/state-root
binding, replay, projection, wallet.network authority, cTEE custody, and
stable Workbench/CLI/SDK protocol surfaces.

Slice 1065 moves command schema-family ownership out of the Node bridge adapter
and into Rust kernel protocol code at
`crates/services/src/agentic/runtime/kernel/command_protocol.rs`. The Rust
module now owns the StepModule command schema version, daemon-core command
schema version, expected-schema lookup, and daemon-core operation-family
classifier with Rust proof tests for StepModule and daemon-core operation
families. `ioi_step_module_bridge/command_envelope.rs` is now adapter-only and
re-exports the Rust kernel protocol for the remaining temporary Node bridge.
Conformance now fails if schema-family truth is redefined in the Node envelope,
dispatch transport, or broad bridge module. This is still not terminal bridge
retirement. Resume by replacing `command_dispatch.rs`, the adapter-only
`command_envelope.rs`, the StepModule command helper, and the shared
daemon-core command helper with direct Rust daemon-core/workload protocol APIs
over Rust/WASM execution, Agentgres admission, receipt/state-root binding,
replay, projection, wallet.network authority, cTEE custody, and stable
IDE/CLI/SDK protocol surfaces.

Slice 1066 makes Rust command protocol classification fail closed for unknown
bridge operations. `command_protocol.rs` now explicitly distinguishes known
StepModule operations, known daemon-core operations, and operations with no
schema family. `expected_command_schema_version()` returns no schema for an
unknown operation instead of implicitly treating it as a StepModule command, and
`bridge_dispatch.rs` rejects that operation before the temporary dispatch table
can run. Rust and bridge tests prove unknown operations have no schema family.
Conformance now fails if the bridge stops rejecting unknown operations before
dispatch or if Rust protocol ownership loses the StepModule/daemon-core/unknown
classification split. This is still not terminal bridge retirement. Resume by
replacing `command_dispatch.rs`, the adapter-only `command_envelope.rs`, the
StepModule command helper, and the shared daemon-core command helper with direct
Rust daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1067 makes the Rust kernel command protocol own the typed operation
family catalog instead of leaving that catalog implicit in the temporary bridge
dispatch table. `command_protocol.rs` now exposes `CommandFamily`,
`STEP_MODULE_OPERATIONS`, `DAEMON_CORE_OPERATIONS`, and `command_family()`;
the daemon-core catalog includes the full temporary bridge operation surface,
including workflow-edit admission and MCP/memory projection commands that were
previously dispatchable but not cataloged by Rust classification. The bridge
intake resolves the Rust-owned family before schema validation, and
`command_dispatch.rs` now dispatches on `(CommandFamily, operation)` so the
remaining Node command table consumes Rust protocol classification instead of
acting as an independent admissibility list. Rust tests prove every cataloged
operation has the expected schema family, and bridge tests prove unknown
operations have no Rust family. This is still not terminal bridge retirement:
the operation catalog belongs in Rust now, but the temporary Node dispatch
table, StepModule command helper, and shared daemon-core command helper still
must be replaced by direct Rust daemon-core/workload protocol APIs over
Rust/WASM execution, Agentgres admission, receipt/state-root binding, replay,
projection, wallet.network authority, cTEE custody, and stable Workbench/CLI/SDK
protocol surfaces.

Slice 1068 moves command-envelope validation into the Rust kernel protocol.
`command_protocol.rs` now exposes `ValidatedCommandEnvelope`,
`CommandProtocolError`, and `validate_command_envelope()`, so the Rust
protocol layer owns both unknown-operation rejection and schema-family mismatch
rejection. The temporary bridge stdin transport now parses JSON, calls the
Rust validator, adapts the Rust protocol error into the bridge response shape,
and passes the Rust-owned `CommandFamily` into dispatch; it no longer rebuilds
`expected_schema_version` or `schema_version_invalid` logic locally.
Conformance now fails if schema-version validation drifts back into
`bridge_dispatch.rs` or if Rust loses the typed envelope validator and mismatch
tests. This is still not terminal bridge retirement: the remaining Node command
dispatch table, adapter-only command envelope, StepModule command helper, and
shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1069 retires the adapter-only bridge command-envelope wrapper. After
Slices 1065-1068 moved schema versions, operation-family cataloging, and
envelope validation into `command_protocol.rs`,
`crates/node/src/bin/ioi_step_module_bridge/command_envelope.rs` only
re-exported Rust protocol symbols and had become compatibility scaffolding.
The wrapper file and `mod command_envelope` declaration are now removed, and
the remaining bridge transport imports `validate_command_envelope()` and
command protocol symbols directly from
`ioi_services::agentic::runtime::kernel::command_protocol`. Conformance now
fails if the adapter-only wrapper returns or if the bridge stops using the
Rust protocol module directly. This is still not terminal bridge retirement:
the remaining Node command dispatch table, StepModule command helper, and
shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1070 moves temporary bridge operation identity into the Rust command
protocol. `command_protocol.rs` now exposes a typed `CommandOperation`, maps
every StepModule and daemon-core operation string to that Rust enum, round-trips
catalog entries through `CommandOperation::as_str()`, and returns the typed
operation from `ValidatedCommandEnvelope`. The stdin bridge still parses the
wire envelope, but it now dispatches on `validated.command_operation`; the
bridge-local dispatch module no longer matches `(CommandFamily, operation)` raw
strings or carries an unsupported string fallback. Conformance now fails if the
bridge reintroduces raw operation-string routing or if Rust loses the typed
operation identity and tests. This is still not terminal bridge retirement: the
remaining `command_dispatch.rs` function table, StepModule command helper, and
shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1071 moves temporary bridge envelope parsing into the Rust command
protocol. `command_protocol.rs` now owns the deserializable `CommandEnvelope`
wire shape with canonical `schema_version` plus operation fields, exposes
`validate_command_envelope_payload()`, and tests that the retired
`schemaVersion` alias cannot satisfy command intake. The stdin bridge still
reads bytes and parses JSON transport, but it no longer declares a bridge-local
`BridgeEnvelope`; it deserializes the Rust protocol envelope and passes it back
to Rust validation before dispatching on the Rust-owned `CommandOperation`.
Conformance now fails if a bridge-local envelope struct returns or if the
bridge stops using the Rust envelope/payload validator. This is still not
terminal bridge retirement: the remaining `command_dispatch.rs` function table,
StepModule command helper, and shared daemon-core command helper must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
execution, Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1072 retires duplicate bridge-local envelope identity checks from the
authority, admission-required policy, and projection-required command wrappers.
Because `bridge_dispatch.rs` now deserializes the Rust `CommandEnvelope`, calls
the Rust payload validator, and dispatches by Rust `CommandOperation`, these
child wrappers no longer carry local `schema_version` or `operation` fields and
no longer own `schema_version_invalid` or `operation_unsupported` branches.
They deserialize only body-specific backend/request fields before entering the
Rust authority and policy cores. Conformance now fails if those local envelope
checks return to `authority_command.rs`, `policy_command.rs`, or
`projection_command.rs`, and the schema-family mismatch proof now lives at the
Rust command protocol validator boundary. This is still not terminal bridge
retirement: the remaining `command_dispatch.rs` function table, StepModule
command helper, and shared daemon-core command helper must still be replaced by
direct Rust daemon-core/workload protocol APIs over Rust/WASM execution,
Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1073 retires the same duplicate bridge-local envelope identity checks
from the governed-admission command wrappers for cTEE private workspace
execution, worker/service package invocation, L1 settlement admission, and
governed runtime-improvement proposal admission. Those wrappers no longer carry
local `schema_version` or `operation` fields and no longer own local
`schema_version_invalid` or `operation_unsupported` branches; they deserialize
only the body-specific backend/invocation/request/attempt/proposal fields
before entering the Rust cTEE, marketplace, settlement, receipt-binder,
Agentgres admission, and governed-evolution cores. The StepModule-schema
rejection proofs for those operations now live at the Rust command protocol
validator boundary. Conformance now fails if the governed-admission child
module regains local command-envelope identity. This is still not terminal
bridge retirement: the remaining `command_dispatch.rs` function table,
StepModule command helper, and shared daemon-core command helper must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
execution, Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1074 retires duplicate bridge-local envelope identity checks from the
approval and workspace-restore command wrappers. The approval child module no
longer carries local `schema_version` or `operation` fields for coding-tool
approval manifests or approval request/decision/revoke state-update planning,
and the workspace-restore child module no longer carries those fields for
apply-policy planning, preview/apply operations, or snapshot capture. The
wrappers now deserialize only body-specific backend/request fields before
entering the Rust approval and workspace-restore cores. The StepModule-schema
rejection proofs for those operations now live at the Rust command protocol
validator boundary. Conformance now fails if approval or workspace-restore
child modules regain local command-envelope identity. This is still not
terminal bridge retirement: the remaining `command_dispatch.rs` function table,
StepModule command helper, and shared daemon-core command helper must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
execution, Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1075 retires duplicate bridge-local envelope identity checks from the
context-policy, runtime-control, thread-lifecycle, and MCP/memory command
wrappers. Those child modules no longer carry local `schema_version` or
`operation` fields and no longer own local `schema_version_invalid` or
`operation_unsupported` branches for budget policy, compaction policy,
context-compaction state updates, operator/runtime-control updates, run cancel
gates, runtime bridge thread/run state updates, agent/run lifecycle updates,
MCP control, MCP validation/projection, memory projection, or thread-memory
state updates. They deserialize only body-specific backend/request fields
before entering the Rust policy cores. The representative StepModule-schema
rejection proofs for those families now live at the Rust command protocol
validator boundary. Conformance now fails if any of those child modules regain
local command-envelope identity. This is still not terminal bridge retirement:
the remaining `command_dispatch.rs` function table, StepModule command helper,
and shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1076 retires duplicate bridge-local envelope identity checks from the
Agentgres command wrapper. `agentgres_command.rs` no longer carries local
`schema_version` or `operation` fields and no longer owns local
`schema_version_invalid` or `operation_unsupported` branches for storage-backend
write admission or runtime run/agent/memory/subagent/artifact/model-mount
record and receipt state commits. The wrapper now deserializes only
body-specific backend/state-dir/request fields before entering the Rust
Agentgres admission core and persistence helpers. The representative
StepModule-schema rejection proofs for Agentgres admission and commit
operations now live at the Rust command protocol validator boundary.
Conformance now fails if the Agentgres child module regains local
command-envelope identity. This is still not terminal bridge retirement:
Agentgres admission and persistence semantics are Rust-owned, but the remaining
`command_dispatch.rs` function table, shared daemon-core command helper, and
JS command callers must still be replaced by direct Rust daemon-core protocol
APIs over Agentgres-admitted truth, receipt/state-root binding, replay,
projection, wallet.network authority, cTEE custody, and stable Workbench/CLI/SDK
protocol surfaces.

Slice 1077 retires duplicate bridge-local envelope identity checks from the
model-mount command wrapper. `model_mount_command.rs` no longer carries local
`schema_version` or `operation` fields and no longer owns local
`schema_version_invalid` or `operation_unsupported` branches for route
decision, invocation admission, provider execution, provider invocation and
stream invocation, provider lifecycle and inventory, instance lifecycle,
provider-result admission, backend-process planning, backend/server/runtime/
tokenizer/route-control required records, accepted-receipt head and transition
planning, invocation receipt binding, or read projection. The wrapper now
deserializes only body-specific backend/request/invocation/result/head fields
before entering the Rust model_mount core, StepModuleRouter, ReceiptBinder,
Agentgres admission, and Rust projection cores. The model-mount runtime schema
constant remains only for Rust-authored route-selection receipt payload output;
it is no longer command-envelope identity.

The representative StepModule-schema rejection proofs for model-mount route
decision, provider invocation, receipt binding, and read projection now live at
the Rust command protocol validator boundary. Conformance now fails if the
model-mount child module regains local command-envelope identity. This is
still not terminal bridge retirement: `command_dispatch.rs`, the shared
daemon-core command helper, JS command callers, and model-mount JS facades must
still be replaced by direct Rust daemon-core/model_mount protocol APIs over
Rust/WASM workload execution, Agentgres-admitted truth, receipt/state-root
binding, replay, projection, wallet.network authority, cTEE custody, and stable
IDE/CLI/SDK protocol surfaces.

Slice 1078 retires duplicate bridge-local envelope identity checks from the
coding-tool StepModule command wrapper. `coding_tool_command.rs` no longer
carries local `schema_version` or `operation` fields and no longer owns local
`schema_version_invalid` or `operation_unsupported` branches for
`run_coding_tool_step_module`. The wrapper now deserializes only
body-specific backend, invocation, workspace-root, and input fields before
entering StepModule invocation validation, StepModuleRouter admission,
Rust workload-client dispatch planning, receipt binding, Agentgres admission,
projection binding, and the Rust-live coding-tool handlers.

The StepModule schema-family rejection proof for coding-tool execution now
lives at the Rust command protocol validator boundary:
`validate_command_envelope()` rejects `run_coding_tool_step_module` when it is
sent with the daemon-core command schema. Conformance now fails if the
coding-tool StepModule wrapper regains local command-envelope identity. This is
still not terminal bridge retirement: `command_dispatch.rs`, the StepModule
command helper, JS command callers, and coding-tool JS facades must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
module execution, Agentgres-admitted truth, receipt/state-root binding, replay,
projection, wallet.network authority where applicable, cTEE custody where
applicable, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1079 retires duplicate camelCase model-route projection fields from the
runtime thread-control model envelope. `initialThreadRuntimeControls()` and
`normalizedAgentRuntimeControls()` now emit canonical `route_id`,
`selected_model`, `endpoint_id`, `provider_id`, `receipt_id`,
`reasoning_effort`, `max_cost_usd`, `workflow_graph_id`, `workflow_node_id`,
and `updated_at` fields without parallel `routeId`, `selectedModel`,
`endpointId`, `providerId`, `receiptId`, `reasoningEffort`, `maxCostUsd`,
`workflowGraphId`, `workflowNodeId`, or `updatedAt` aliases. The normalized
runtime-control model reader also stops treating those retired model-control
aliases as persisted truth.

This slice does not complete thread-control migration: the JS surface remains
fail-closed/migration scaffolding until direct Rust daemon-core thread-control
admission, Agentgres state-root binding, replay, and projection APIs own the
surface. It does, however, remove a duplicate projection shape that could have
survived as a compatibility contract beside the Rust-owned snake_case protocol.

Slice 1080 retires the Rust policy-boundary request alias that allowed
`modelRoute` to satisfy the canonical `model_route` field for thread-control
state-update planning. `ThreadControlAgentStateUpdateRequest` now accepts only
the canonical snake_case request field; a retired camelCase `modelRoute` input
deserializes as unknown request data and fails closed before the Rust planner
can produce a thread-control state-update plan.

Conformance now fails if the Rust thread-lifecycle policy regains
`#[serde(alias = "modelRoute")]` or if the focused Rust proof for the retired
request alias disappears. This is still not terminal thread-control migration:
the command transport and JS fail-closed facade remain temporary scaffolding.
The intended long-term shape is direct Rust daemon-core thread-control
admission, Agentgres expected-head/state-root binding, replay, projection, and
stable protocol APIs without compatibility request aliases.

Slice 1081 retired RuntimeAgentService bridge command/input alias tolerance at
both migration edges while the bridge still existed. Slice 1251 supersedes that
interim guard: the JS command adapter, Rust bridge binary, bridge env policy
override, and bridge-backed proof scripts are now deleted. Runtime-service
execution remains non-terminal until direct Rust daemon-core runtime
thread/turn/control APIs own admission, execution dispatch, persistence,
replay, projection, wallet/cTEE policy, and Agentgres expected-head/state-root
binding.

Slice 1082 retired the daemon-store thread-control compatibility delegates that
remained after public routes moved to mounted surfaces. Slice 1432 later
supersedes the thread-turn portion: public resume, turn create, interrupt, and
steer routes now enter through store-owned `resumeThread()`, `createTurn()`,
`interruptTurn()`, and `steerTurn()` methods backed by the internal
`threadTurnApi` delegate instead of route-addressing `threadTurnSurface`
directly. The thread-control pass-through methods
`updateThreadRuntimeControls()` and `appendThreadRuntimeControlEvent()` remain
retired.

Conformance now fails if thread-control store delegates return in `index.mjs`,
if public turn routes call `store.threadTurnSurface.*`, if daemon startup
restores `this.threadTurnSurface`, or if tests stop proving the store-owned turn
methods delegate only through `threadTurnApi`. This is still not terminal
thread/turn/control migration: the internal JS delegate remains migration
scaffolding until direct Rust daemon-core admission, execution dispatch,
persistence, replay, projection, wallet/cTEE policy, and Agentgres
expected-head/state-root binding own the surface.

Slice 1083 moved the public operator turn-control admission-required refusal
contract into the Rust policy core. That intermediate fail-closed public
facade is now retired for normal interrupt/steer execution: public operator
interrupt calls Rust `plan_operator_interrupt_state_update`, public operator
steer calls Rust `plan_operator_steer_state_update`, the JS surface validates
the Rust-planned operator-control envelope and run projection, resolves the
current run through the mounted run resolver, and persists only the Rust-planned
run through Agentgres-backed `writeRun` before returning route truth. The Rust
`OperatorTurnControlAdmissionRequiredCore` still owns the canonical
`runtime_operator_turn_control_rust_core_required` record for missing Rust
state-update planning, so absence of the Rust boundary fails closed before any
JS runtime bridge control, event append, or local run mutation can execute.

Conformance now fails if the operator turn-control required-boundary envelope
is authored only in JS, if the Rust state-update command operations are removed
from typed command dispatch, if public interrupt/steer stop invoking the Rust
state-update planners before Agentgres run persistence, if direct runtime
bridge control/event append returns, or if camelCase detail aliases return on
the missing-boundary refusal details. This remains non-terminal: command
transport, wallet/runtime-control authority, Agentgres expected-head/state-root
commit depth, replay/projection storage, and stable protocol APIs must still
become direct Rust daemon-core surfaces.

Slice 1084 moved the public non-runtime thread-turn admission-required refusal
contract into the Rust thread-lifecycle policy core. Slice 1280 supersedes the
temporary mounted lifecycle surface: missing direct Rust lifecycle APIs still
fail closed, while normal public non-runtime resume calls the direct
Rust-backed agent status-control API and returns the Rust thread projection, and
normal public non-runtime turn creation calls the direct Rust-backed run-create
API and returns the Rust turn projection.
Slice 1260 supersedes the earlier diagnostics-blocked exception: blocking
diagnostics feedback now travels through the same Rust-planned run-create path,
and `ThreadTurnAdmissionRequiredCore` rejects the retired diagnostics-block
operation instead of preserving a separate refusal lane. Direct JS
`updateAgent()`, `createRun()`, JS turn projection composition, runtime-event
append, and daemon-store pass-through wrappers stay retired from the
thread-turn surface.

Conformance now fails if the thread-turn required-boundary envelope is authored
only in JS, if the typed Rust daemon-core boundary drifts back into broad
command-wrapper plumbing, if the public non-runtime path re-enters direct JS
mutation wrappers, or if diagnostics-blocked turn creation re-enters the
retired admission-required refusal path instead of Rust run-create planning.
This remains non-terminal: direct Rust daemon-core thread-turn protocol APIs,
durable replay/projection storage, and command transport retirement still need
Rust ownership across the remaining lifecycle edges.

Slice 1085 moves the public agent/run lifecycle admission-required refusal
family into the Rust thread-lifecycle policy core. The Rust
`LifecycleAdmissionRequiredCore` now owns the canonical required-boundary
records for agent creation, top-level thread creation, run creation, agent
status control, and permanent agent deletion, and the daemon-core command
protocol exposes them through
`plan_lifecycle_admission_required`. The JS agent/run lifecycle and thread
store surfaces consume these Rust-authored records while still failing closed
before JS route/model/memory planning, agent lookup where forbidden, `writeRun`,
`writeAgent`, agent/run map mutation, or Agentgres commit.

Conformance now fails if these lifecycle required-boundary envelopes are
authored only in JS, if the typed Rust command operation is removed, if the
temporary Node command wrapper moves back into the broad bridge module, or if
the JS surfaces stop proving they called the Rust admission-required planner
before any retired state-update or persistence path. This remains
non-terminal: direct Rust daemon-core lifecycle admission, wallet/cTEE policy
where applicable, Agentgres expected-head/state-root commit, replay,
projection, and stable protocol APIs must still replace the temporary command
transport.

Public agent status-control state updates are now a positive Rust
daemon-core path. Public archive/unarchive/resume/close/reload call Rust
`plan_agent_status_state_update`; JS supplies the current agent and requested
status facts, requires a Rust-returned agent projection with the requested
operation kind, and persists only that Rust-authored projection through the
Agentgres-backed `writeAgent` commit path.

Public agent creation is now a positive Rust daemon-core path. `createAgent()`
requires Rust `plan_agent_create_state_update` before JS can persist any
candidate provider/model-route/MCP/runtime-control facts, rejects missing Rust
agent projection, mismatched operation kind, or incomplete identity/timestamp
output, and persists only the Rust-returned `agent.create` projection through
the Agentgres-backed `writeAgent` commit path. Direct `agents` map mutation
remains retired.

Public agent-scoped run creation is now a positive Rust daemon-core path.
`createRun()` requires Rust `plan_run_create_state_update` before JS can look
up the agent, resolve provider/model-route/memory facts, construct the canonical
run candidate, assemble usage envelopes, or persist anything. JS requires a
Rust-returned `run.create` projection with complete identity/timestamp output,
persists only that projection through the Agentgres-backed `writeRun` commit
path, keeps direct `runs` map mutation retired, and ignores retired
thread/approval plus diagnostics request aliases. Missing Rust planner support
still fails closed before lookup, route, memory, or persistence.

Public top-level thread creation is now a positive Rust daemon-core path.
`createThread()` requires Rust `plan_thread_create_state_update` before JS can
route model/provider/MCP/runtime-control candidate facts or persist anything.
JS requires Rust-returned `agent` and `thread` projections with matching
identity, persists only the Rust-authored `thread.create` agent projection
through the Agentgres-backed `writeAgent` commit path, emits the thread-start
projection through the Rust thread-event surface, and returns only the Rust
thread/turn projection record. Missing Rust planner support still fails closed
before route planning or persistence. Runtime-service thread start is now a
separate positive Rust bridge-start boundary: it requires
`plan_runtime_bridge_thread_start_agent_state_update`, commits only the
Rust-planned bridge agent through Agentgres `writeAgent`, and returns the Rust
thread projection. Runtime-service thread control is now a paired Rust
bridge-control boundary: it requires
`plan_runtime_bridge_thread_control_agent_state_update`, commits only the
Rust-planned `thread.runtime_bridge.control` agent through Agentgres
`writeAgent`, and returns the Rust thread projection without dispatching the
deleted JS bridge `controlThread` path. Runtime-service turn submit is now a
paired Rust bridge-turn boundary: it requires
`plan_runtime_bridge_turn_run_state_update`, commits only the Rust-planned
`turn.runtime_bridge.submit` run through Agentgres `writeRun`, and returns the
Rust turn projection without dispatching the deleted JS bridge `submitTurn`
path.

Public permanent agent deletion is now a positive Rust daemon-core path.
`deleteAgent()` calls Rust `plan_agent_delete_state_update`; JS supplies only
the current agent fact, requires a Rust-returned `agent.delete` tombstone with
`status: deleted` and `deletedAt`, and persists only that tombstone through the
Agentgres-backed `writeAgent` commit path. Wallet/retention authority,
lifecycle replay/projection, and stable lifecycle protocol APIs remain
non-terminal.

Slice 1086 retires the `RuntimeDaemonStore.createAgent()`,
`RuntimeDaemonStore.createRun()`, and `RuntimeDaemonStore.createThread()`
compatibility pass-throughs. Public agent creation, top-level thread creation,
and agent-scoped run creation now enter direct Rust-backed lifecycle APIs; the
daemon store no longer exposes a second lifecycle creation method family that
can be mistaken for the canonical authority boundary after context compaction.

Conformance now fails if the daemon store re-imports the retired
`createAgentState`/`createRunState` helpers, reintroduces store-level
`createAgent()`/`createRun()`/`createThread()` wrappers, or routes public
agent/thread/run creation through the store compatibility layer instead of the
direct lifecycle APIs. Slice 1280 also makes conformance fail if the mounted
`agentRunLifecycleSurface` facade or `createRuntimeAgentRunLifecycleSurface`
export returns. This remains non-terminal: durable lifecycle replay/projection,
Agentgres expected-head/state-root binding, wallet/cTEE authority, and stable
protocol APIs still need terminal Rust-owned coverage.

Slice 1087 converts the stale `runtime-thread-control.test.mjs` live
runtime-service proof into bounded Rust-ownership evidence. That test no longer
tries to seed model routes through retired JS model-mount mutation facades or
exercise subagent recovery through removed daemon-store compatibility wrappers.
It proves that route seeding fails through the Rust model-mount route-control
required record, runtime-service thread creation uses Rust bridge-start state
planning and Agentgres agent commit before any JS runtime bridge `startThread`
dispatch, and the retired daemon-store lifecycle and thread-control/subagent
wrappers remain absent.

Conformance now fails if this test drifts back into JS runtime-service bridge
dispatch or if it stops checking the Rust-required route-control and runtime
bridge-start boundaries. Runtime-service thread control and turn submit have
since moved to Rust bridge-control/bridge-turn planning plus Agentgres
`writeAgent`/`writeRun`; managed-session inspection/control has now moved to
Rust managed-session projection/control planning plus runtime-event admission,
but durable managed-session storage/replay/projection and wallet/cTEE session
authority still need direct Rust daemon-core ownership before managed-session
live proof can become terminal. Subagent recovery still needs direct Rust
daemon-core admission, dispatch, Agentgres binding, replay, and projection
before it can become an active live proof again.

Slice 1088 deletes the obsolete Stage 5 stop/cancel/recover and Stage 7
delegation live-GUI proof scripts that still encoded JS model-mount
`importModel`/`mountEndpoint` setup plus JS runtime-service bridge dispatch as
successful product proof. Those scripts were self-contained, unreferenced by
the conformance suite, and contradicted the current Rust-required boundary
where model-route mutation and subagent recovery must fail closed until direct
Rust daemon-core admission and Agentgres binding exist; managed-session control,
runtime-service thread start, control, and turn submit are now positive
Rust-planned Agentgres-backed boundaries but still require durable replay,
projection, authority, and stable protocol ownership before terminal proof.

Conformance now fails if either retired live-GUI proof script is restored. New
live GUI proof for these scenarios must be introduced only after the Rust
daemon core owns the runtime-service/subagent execution path end to end and the
proof drives stable protocol APIs over the unified substrate.

Slice 1089 retires the remaining JS runtime-service bridge result and live-event
normalizers after the start, turn-submit, and control facades were already made
fail-closed. `RuntimeDaemonService` no longer exposes
`normalizeRuntimeBridgeThreadStart()`, `normalizeRuntimeBridgeTurnSubmit()`, or
`normalizeRuntimeBridgeLiveEvent()` pass-through methods, and
`runtime-bridge-thread.mjs` no longer carries the old bridge-result projection
helpers or camelCase payload scrubber.

Conformance now proves the runtime-service bridge normalizers stay absent
instead of treating them as compatibility evidence. The next positive
runtime-service proof must be Rust daemon-core admission, Agentgres
expected-head/state-root binding, replay, and projection over stable protocol
APIs; it must not restore JS bridge result shaping.

Slice 1090 removes the stale runtime-service bridge success-path fixtures from
`runtime-bridge-thread.test.mjs`. The fail-closed test no longer defines fake
RuntimeAgentService bridge objects, fake Rust planner delegates, fake in-flight
turn registration, fake event append, or fake agent/run persistence helpers; it
uses only inert call logs and verifies the start, turn-submit, and control
facades fail before any such operation could exist.

Conformance now rejects reintroducing fake bridge/planner/persistence helpers
into that negative-boundary proof. Positive runtime-service evidence must come
from the future direct Rust daemon-core path, not from resurrected JS bridge
success fixtures inside tests.

Slice 1091 removes stale conformance-parser scaffolding for the deleted
runtime-service bridge normalizers. The conformance suite no longer extracts
`normalizeRuntimeBridgeThreadStart()`, `normalizeRuntimeBridgeTurnSubmit()`, or
`normalizeRuntimeBridgeLiveEvent()` bodies from `runtime-bridge-thread.mjs`;
instead, the existing checks prove those names remain absent from the runtime
bridge module, daemon index, and focused tests.

This keeps the verifier aligned with the target architecture: deleted JS bridge
projection bodies must not remain encoded as parse targets inside conformance.

Slice 1092 retired the JS RuntimeAgentService command adapter. Slice 1251
finishes the substrate cut: `RuntimeApiBridge` no longer exports an adapter
class/factory, bridge command envs are absent from the profile helper, the
`ioi-runtime-bridge` binary is deleted, and daemon startup rejects
`runtimeBridge`. New positive runtime-service execution must land as direct
Rust daemon-core admission, Agentgres expected-head/state-root binding, replay,
and projection over stable protocol APIs.
Slice 1272 then deletes the bridge-named profile helper artifact itself:
`runtime-api-bridge.mjs` and its focused test are absent, live daemon imports
use `runtime-profile.mjs`, and conformance guards that the old bridge module
filename cannot return as a compatibility shim.

Slice 1093 retires the stale JS runtime-service bridge projection authoring
that survived after the command adapter and runtime bridge facades were made
fail-closed. At that stage, `runtime-record-projections.mjs` stopped exporting
`runtimeBridgeRunRecord()`, `runtimeBridgeMessagesForProjection()`, or
`runtimeBridgeComputerUseTrace()`, and `runtime-event-envelopes.mjs` stopped
deriving action-proposal or commit-gate events from bridge readback. The daemon
index no longer wired these helpers into the runtime bridge turn path; Slice
1094 then deletes the remaining JS bridge-thread facade rather than preserving
it as a fail-closed wrapper, and Slice 1402 later deletes
`runtime-record-projections.mjs` outright.

Conformance now proves these projection builders and derived-event injector
stay absent instead of merely proving their output uses canonical field names.
Future positive runtime-service replay must be emitted by direct Rust
daemon-core projection over Agentgres-admitted truth, not by resurrected JS
bridge event shaping.

Slice 1251 hard-retires the remaining RuntimeAgentService bridge substrate.
`RuntimeApiBridge` no longer exports an adapter class/factory, the
`ioi-runtime-bridge` binary and Cargo bin entry are deleted, the daemon and
service reject `runtimeBridge` options, Rust service policy no longer reads
bridge allow-command envs, the renamed `apps/hypervisor` app path uses
an inference/model-route helper instead of a bridge helper, and bridge-backed
live proof scripts/tests are
removed. Conformance now fails if the JS adapter export, bridge helper,
command/env fallback, Cargo bridge binary, or runtimeBridge service option
returns.
Slice 1272 deletes the bridge-named JS helper file that still carried runtime
profile normalization: `runtime-api-bridge.mjs` and its test are absent, live
imports use `runtime-profile.mjs`, and conformance guards the old path as a
retired compatibility shim.

Slice 1094 retires the standalone runtime bridge thread/turn/control JS facade
module instead of preserving it as a fail-closed compatibility wrapper.
`packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs` and its focused
test are deleted, and the daemon store no longer imports or exposes
`createRuntimeBridgeThread()` or `createRuntimeBridgeTurn()` pass-through
methods. Runtime-service thread start, control, and turn submit now enter
positive Rust state-planning boundaries through direct lifecycle APIs; the
thread-turn surface delegates runtime resume to that Rust-owned lifecycle
boundary instead of preserving a JS bridge-control path.

Conformance now treats the deleted module as the invariant. Positive
runtime-service start, control, and turn submit arrived through Rust planning
plus Agentgres commit without recreating a Node bridge-thread facade. Remaining
runtime-service work must continue through direct Rust daemon-core admission,
execution dispatch, Agentgres expected-head/state-root binding, replay, and
projection paths.

Slice 1095 retires the dead computer-use JS invocation bodies that remained
behind the fail-closed facade guards. Browser discovery, control,
native-browser action, visual GUI action, sandboxed-hosted action, and visual
GUI observe now return the Rust-core-required boundary directly. The daemon
index no longer imports or calls local browser discovery, CDP execution,
controlled native-browser launch, visual GUI local capture/execution, or
computer-use request metadata helper plumbing from those invocation surfaces.
Visual GUI observe is also guard-only, so it cannot read local capture files or
look up JS truth before refusing the retired path.

Conformance now treats the absence of those JS invocation bodies as the
invariant. The bridge tier no longer expects canonical snake_case payload,
request, workflow-binding, selector, sandbox, controlled-relaunch, or visual
metadata construction inside daemon `index.mjs`; those shapes may only survive
in non-authoritative helper/replay contracts until direct Rust daemon-core
computer-use admission, wallet.network authority, cTEE custody policy where
applicable, Agentgres expected-head/state-root binding, event materialization,
replay, and projection own the positive path.

A later public computer-use request-lease cut supersedes that guard-only public
facade. Browser discovery, control, native-browser, visual GUI,
sandboxed-hosted, and visual GUI observe daemon methods now map their public
tool identity to canonical `computer_use.request_lease` input and invoke the
Rust-live coding-tool StepModule path. Rust `coding_tool_computer_use.rs` owns
lease request construction, provider registry selection, wallet.network
authority boundaries, provider-unavailable fail-closed semantics, receipt refs,
and canonical result fields. The JS edge remains only a narrow protocol
adapter; it still must not restore local browser discovery sync, CDP execution,
controlled native-browser launch, visual GUI capture/execution, local sandbox
execution, JS event projection construction, runtime-event append, or direct
computer-use event admission. Slice 1421 later deletes the last direct
computer-use event append store facade rather than preserving it as a
fail-closed shim. Concrete provider execution, direct Rust computer-use event
materialization, cTEE custody, durable Agentgres
expected-head/state-root binding, replay, projection, and stable Workbench/CLI/SDK
APIs remain non-terminal.

Slice 1096 retires the unused approval decision JS readback facade. The mounted
approval control surface no longer exports `latestApprovalDecisionEvent()`, and
the daemon store no longer exposes a pass-through method for approval decision
event lookup. Approval request, decision, and revoke routes already fail closed
at the mounted approval surface; this slice removes the stale duplicate
decision-readback shape so approval decision truth cannot be reintroduced as a
daemon-local event scan while Rust daemon-core authority admission, Agentgres
expected-head/state-root binding, wallet.network approval grants, receipt
materialization, replay, and projection remain the target owner.

Conformance now fails if the approval decision readback facade returns on the
approval surface or daemon store. At this point the remaining approval-request
event readback was explicitly limited to the current coding-tool
approval-satisfaction helper until that helper received a direct Rust
daemon-core replacement; Slice 1208 later retires that JS satisfaction gate
rather than preserving it as readback scaffolding.

Slice 1097 retires the coding-tool budget blocked-event JS projection facade.
`RuntimeCodingToolBudgetRecoveryApi` no longer exports
`latestCodingToolBudgetBlockedEventForRun()`, and the daemon store no longer
exposes the matching pass-through wrapper. The live run-level budget recovery
route still calls the mounted `codingToolBudgetRecoveryForRun()` control
surface, which fails closed through Rust-authored admission-required planning;
the deleted blocked-event projection was only stale readback scaffolding.

Conformance now fails if the blocked-event projection facade returns on the
budget-recovery surface or daemon store. Future budget-recovery blocked-event
projection must be authored by Rust daemon-core projection over Agentgres
admitted truth, not by reintroducing daemon-local event scans or JS projection
helpers.

Slice 1098 retires the remaining unused daemon-store thread auxiliary and MCP
helper pass-through delegates. Public/thread routes already call the mounted
thread auxiliary and MCP catalog/control surfaces directly; the daemon store no
longer exposes `inspectManagedSessionsForThread()`,
`inspectWorkspaceChangeReviewsForThread()`, `controlWorkspaceChangeForThread()`,
`controlManagedSessionForThread()`, `forkThread()`, `cancelRun()`,
`applyThreadMcpServerMutation()`, `mcpStatusWithLiveDiscovery()`,
`appendThreadMcpControlEvent()`, or `mcpServersForContext()` as compatibility
entrypoints.

Conformance now fails if those store-level delegates return. Thread auxiliary
and MCP route behavior must stay mounted-surface/protocol-edge only until Rust
daemon-core thread lifecycle, MCP authority/admission, Agentgres
expected-head/state-root binding, replay, and projection own the direct APIs;
future direct Rust APIs should replace the mounted JS surfaces rather than
reviving daemon-store wrapper methods.

The subsequent thread-fork cut moves the mounted fork path from fail-closed
scaffolding to Rust daemon-core `plan_runtime_thread_fork_control`: JS now only
forwards canonical source facts, commits the Rust-authored forked agent, admits
the Rust-authored `thread.forked` event, and validates the Rust projection.

Slice 1099 retires the daemon-store coding-tool artifact/governance,
workspace-snapshot/restore, and diagnostics-feedback helper pass-through
delegates. Slice 1431 later supersedes the workspace-snapshot portion: the
coding-tool invocation surface still calls mounted governance, artifact, and
diagnostics-feedback delegates, but patch snapshot capture now enters through
the store-owned `prepareWorkspaceSnapshotForPatch()` method over the internal
workspace snapshot API. The old route-visible `workspaceSnapshotSurface` call
does not remain as the public snapshot-capture path.

The daemon store no longer exposes the retired helper entrypoints, including
`appendCodingToolCommandStreamEvents()`, `codingToolApprovalSatisfaction()`,
`blockCodingToolForApproval()`, `blockCodingToolForBudget()`,
`prepareWorkspaceSnapshotForPatch()`, `materializeWorkspaceSnapshotArtifact()`,
`appendWorkspaceSnapshotEvent()`, `workspaceSnapshotContentPackage()`,
`materializeWorkspaceRestorePreviewArtifact()`,
`materializeWorkspaceRestoreApplyArtifact()`,
`appendWorkspaceRestorePreviewEvent()`, `appendWorkspaceRestoreApplyEvent()`,
`maybeRunPostEditDiagnostics()`, `pendingDiagnosticsFeedbackForNextTurn()`,
`materializeCodingToolArtifactDrafts()`,
`materializeVisualGuiObservationArtifacts()`, `readCodingToolArtifact()`, and
`retrieveCodingToolResult()`. Conformance now fails if those wrappers return.
The remaining mounted JS surfaces are protocol-edge migration scaffolding until
direct Rust daemon-core coding-tool governance, artifact admission, snapshot
admission, diagnostics feedback projection, Agentgres expected-head/state-root
binding, replay, and projection APIs replace them.

Slice 1100 retires the daemon-store diagnostics-repair and conversation-artifact
helper pass-through delegates. Public/thread routes already call the mounted
diagnostics-repair and conversation-artifact surfaces directly; the daemon store
no longer exposes `executeDiagnosticsOperatorOverride()`,
`turnForOperatorOverrideEvent()`, `appendDiagnosticsOperatorOverrideEvent()`,
`createDiagnosticsRepairRetryTurn()`, `turnForRepairRetryEvent()`,
`appendDiagnosticsRepairRetryTurnEvent()`,
`resolveDiagnosticsRepairDecision()`,
`appendDiagnosticsRepairDecisionExecutedEvent()`,
`createConversationArtifact()`, `listConversationArtifacts()`,
`getConversationArtifact()`, `listConversationArtifactRevisions()`,
`performConversationArtifactAction()`, `exportConversationArtifact()`, or
`promoteConversationArtifact()` as compatibility entrypoints.

Conformance now fails if those store-level delegates return. The mounted JS
surfaces remain migration scaffolding only: conversation-artifact read projection
now has a Rust replay API over runtime `state_dir`, create/action/export/promote
control now has a positive Rust daemon-core API, and future direct positive APIs
must still retire the remaining temporary protocol-edge scaffolding with richer
Rust daemon-core diagnostics repair admission/projection,
ArtifactRef/PayloadRef admission, Agentgres expected-head and state-root
binding, receipt_binder, replay, and stable projection APIs.

Slice 1101 retires the unused workflow-edit target/context JS helper facades
instead of preserving them as fail-closed compatibility surface area. No live
route or caller uses `workflowEditThreadContext()` or
`resolveWorkflowEditTarget()`; the daemon store and mounted workflow-edit
surface no longer expose those methods, and conformance fails if their
`workflow_edit_thread_context` or `workflow_edit_target_resolution` JS facade
patterns return.

Workflow-edit proposal/apply remain the only mounted JS protocol-edge
operations for this lane until direct Rust daemon-core workflow-edit context,
target resolution, proposal admission, apply admission, wallet approval
authority, Agentgres expected-head/state-root binding, receipt binding, replay,
and projection APIs replace the temporary surface.

Slice 1102 retired the daemon-store workspace-trust warning pass-through
delegate. At that point the mounted thread-control delegate kept
`appendWorkspaceTrustWarningEvent()` as a fail-closed migration API, but the
daemon store no longer provided a duplicate `store.appendWorkspaceTrustWarningEvent()`
compatibility entrypoint, and conformance failed if that wrapper returned.

Slice 1105 moved workspace-trust warning and acknowledgement event ownership
into Rust daemon-core planning. The subsequent workspace-trust transport cut
routes that planner through typed
`daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate`, so JS sends
canonical request bodies without generic command `operation`/`backend`
envelopes and Rust rejects `plan_workspace_trust_control_state_update` as a
command operation. `plan_workspace_trust_control_state_update` authors warning
and acknowledgement event envelopes, receipt refs, policy refs, and
replay-bound acknowledgement payloads; the internal thread-control API only
forwards canonical facts, requires the Rust planner before mode lookup/write,
and admits Rust-authored events through `admit_runtime_thread_event`. The old JS
repository-context warning record and acknowledgement payload construction stay
retired. Deeper wallet/cTEE workspace authority and stable direct projection
APIs remain terminal work beyond the temporary replay cache transport.

Slice 1103 splits the Rust StepModule bridge computer-use provider registry and
provider-selection helper out of `ioi_step_module_bridge/computer_use.rs` into
`ioi_step_module_bridge/computer_use_provider.rs`. The request-lease builder no
longer owns provider catalog records, provider hint matching, registry
projection, or fail-closed unavailable-provider selection.

This is bridge containment, not terminal architecture. The new provider module
is still temporary command-transport scaffolding for `computer_use.request_lease`
until direct Rust daemon-core computer-use admission, wallet.network authority,
cTEE/workspace custody, Agentgres expected-head/state-root binding,
receipt/event materialization, replay, and projection APIs replace the bridge.

Slice 1104 originally split the Rust model_mount accepted-receipt planning and invocation
receipt binding command boundary out of
`ioi_step_module_bridge/model_mount_command.rs` into
`ioi_step_module_bridge/model_mount_receipt_command.rs`. The general
model_mount command wrapper no longer owns `ReceiptBinder`,
`AgentgresAdmissionCore`, or `RustProjectionCore` imports, while the new receipt
boundary owns accepted-receipt head/transition planning, caller-supplied expected
head rejection, transition validation, StepModuleRouter admission, receipt
binding, accepted-receipt append, Agentgres admission, and projection binding.

That temporary command-transport receipt boundary is now superseded by the typed
Rust daemon-core model_mount receipt API: accepted-receipt head/transition
planning and invocation receipt binding call `daemonCoreModelMountApi` methods,
and Rust command-protocol source is deleted and conformance source-scans keep the old command operations absent before dispatch.

Slice 1105 splits the Rust coding-tool StepModule workload dispatch,
StepModuleRouter admission, receipt binding, Agentgres admission, and projection
binding path out of `ioi_step_module_bridge/coding_tool_command.rs` into
`ioi_step_module_bridge/coding_tool_receipt_command.rs`. The coding-tool command
wrapper now owns operation selection and workload observation shaping only; the
new receipt boundary owns `WorkloadClient::plan_step_module_dispatch`,
`StepModuleRouterCore`, `ReceiptBinder`, `AgentgresAdmissionCore`, and
`RustProjectionCore`.

This is still bridge containment, not terminal architecture. The receipt module
is temporary command-transport scaffolding until direct Rust daemon-core
coding-tool execution/admission APIs and Rust/WASM workload module execution
replace the Node bridge, JS StepModule command helper, JS command callers, and
remaining coding-tool JS protocol facades.

Slice 1106 splits receipt-bearing governed command execution out of
`ioi_step_module_bridge/governed_admission_command.rs` into
`ioi_step_module_bridge/governed_receipt_command.rs`. The governed-admission
wrapper now owns lighter L1 settlement and governed-improvement proposal
admission only; cTEE private workspace execution and worker/service package
invocation live in the governed receipt boundary, where accepted-receipt append
via `ReceiptBinder` remains explicit beside Rust cTEE/marketplace admission
records.

This is still bridge containment, not terminal architecture. The governed
receipt module is temporary command-transport scaffolding until direct Rust
daemon-core cTEE and worker/service package execution/admission APIs replace the
Node bridge, shared command runner, JS command callers, and remaining JS
protocol facades.

Slice 1107 moves durable Agentgres runtime-state persistence execution out of
`ioi_step_module_bridge/agentgres_command.rs` and into Rust
`AgentgresAdmissionCore`. The bridge no longer owns filesystem path
canonicalization, previous-transition lookup, projection-watermark derivation,
or admitted-record materialization writes for runtime state commits; it calls
Rust core `commit_runtime_run_state_to_dir` / persistence helpers and formats
the temporary command-transport response only.

This remains non-terminal because command transport and JS command callers still
exist, but the Agentgres durable-write side-effect boundary is now a Rust
daemon-core API instead of bridge-local persistence logic. Direct Rust
daemon-core Agentgres protocol APIs must still replace the Node bridge, shared
command runner, JS command callers, and remaining JS persistence facades.

Slice 1108 moves coding-tool subprocess and git command execution out of the
temporary StepModule bridge helper and into Rust
`coding_tool_execution.rs` under the kernel service crate. Bounded command
spawning, timeout enforcement, sanitized subprocess environment construction,
and read-only git execution are now Rust daemon-core service APIs; the bridge
helper delegates to them while keeping only workspace observation and
StepModule response shaping.

This is a larger Rust-core extraction cut, not terminal coding-tool migration.
The coding-tool bridge helper still owns path/observation helpers for now, and
the Node bridge, StepModule command runner, JS command callers, and remaining
coding-tool JS facades remain temporary scaffolding until direct Rust
daemon-core/workload APIs own coding-tool execution, admission, replay, and
stable protocol projection end to end.

Slice 1109 moves the coding-tool `file.apply_patch` workspace mutation path out
of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
patch edit validation, workspace path escape rejection, file read/write
execution, diff preview hashing, workspace snapshot draft construction, and
Agentgres-style operation/payload/head/state-root transition derivation for
patch mutations. The bridge helper delegates to Rust core and translates errors
only.

This remains non-terminal because the bridge still carries other coding-tool
workspace observation helpers and the JS invocation facade/StepModule command
transport still exist. The long-term target remains direct Rust
daemon-core/workload coding-tool execution and admission, with JS retained only
as stable protocol/API composition where needed.

Slice 1110 moves the coding-tool `file.inspect` workspace observation path out
of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
workspace path canonicalization, path escape rejection, metadata reads,
directory listing, file preview reads, preview line/byte bounding, and preview
hash derivation for `file.inspect`. The bridge helper delegates to Rust core
and translates errors only.

This remains non-terminal because the bridge still carries other coding-tool
workspace status, diff, test, and diagnostic observation helpers, and the JS
invocation facade/StepModule command transport still exist. The long-term
target remains direct Rust daemon-core/workload coding-tool execution and
admission, with bridge-local filesystem observation retired as each Rust-core
surface becomes verified.

Slice 1111 moves the coding-tool `workspace.status` and `git.diff` git-backed
workspace observation paths out of the temporary StepModule bridge helper and
into Rust `coding_tool_workspace.rs` under the kernel service crate. Rust core
now owns status command planning, diff command planning, workspace path
containment for diff targets, porcelain/diff output hashing, git-unavailable
response shaping, changed-file counting, diff preview truncation, and stat
projection for these observations. The bridge helper delegates to Rust core and
translates errors only.

This remains non-terminal because the bridge still carries `test.run` and
`lsp.diagnostics` helper plumbing, and the JS invocation facade/StepModule
command transport still exist. The long-term target remains direct Rust
daemon-core/workload coding-tool execution and admission, with bridge-local
workspace observation retired as each Rust-core surface becomes verified.

Slice 1112 moves the coding-tool `test.run` command execution observation path
out of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
test command allowlisting, command mapping for `node.test`, `npm.test`,
`cargo.test`, and `cargo.check`, cwd and path containment, sanitized test
environment filtering, timeout and output bounding, output hashing, pass/fail
status derivation, and response shaping. The bridge helper delegates to Rust
core and translates errors only.

This remains non-terminal because the bridge still carries `lsp.diagnostics`
helper plumbing, and the JS invocation facade/StepModule command transport
still exist. The long-term target remains direct Rust daemon-core/workload
coding-tool execution and admission, with bridge-local diagnostic/test
execution logic retired as each Rust-core surface becomes verified.

Slice 1113 moves the coding-tool `lsp.diagnostics` execution observation path
out of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
diagnostic command allowlisting, `auto` backend selection, node syntax-check
execution, TypeScript project/file check execution, local `tsc` discovery,
diagnostic project-context projection, TypeScript diagnostic parsing, node
diagnostic parsing, cwd/path containment, timeout and output bounding, output
hashing, diagnostic status derivation, and response shaping. The bridge helper
delegates to Rust core and translates errors only.

This remains non-terminal because the Node bridge, shared StepModule command
runner, JS command callers, and coding-tool JS protocol facades still exist.
The long-term target remains direct Rust daemon-core/workload coding-tool
execution and admission, with the now-thin bridge helper retired when direct
Rust daemon-core/workload APIs own execution, admission, replay, projection, and
stable protocol APIs end to end.

Slice 1114 moves the coding-tool artifact data-plane normalization path for
`artifact.read` and `tool.retrieve_result` out of the temporary StepModule
bridge and into Rust `coding_tool_artifact.rs` under the kernel service crate.
Rust core now owns canonical `rust_workload_data_plane` envelope validation,
data-plane schema/source/operation checks, artifact-store result object
validation, content-hash recomputation, shell-fallback suppression, canonical
artifact/receipt ref extraction, evidence-ref derivation, and retirement of
old camelCase result aliases before the bridge formats the StepModule response.

This remains non-terminal because the Node bridge, shared StepModule command
runner, JS command callers, and coding-tool JS protocol facades still exist.
The temporary bridge now delegates artifact/read retrieval normalization to
Rust core and rejects retired data-plane aliases; the long-term target remains
direct Rust daemon-core/workload coding-tool execution, admission, replay,
projection, artifact/event admission, and stable protocol APIs end to end.

Slice 1115 moves the coding-tool `computer_use.request_lease` planning path
out of the temporary StepModule bridge and into Rust
`coding_tool_computer_use.rs` under the kernel service crate. Rust core now
owns prompt/lane/session/action canonicalization, wallet.network authority
scope derivation, approval-required calculation, provider registry records,
provider hint matching, fail-closed unavailable-provider projection, request
seed hashing, receipt/evidence ref derivation, thread-tool input shaping, and
retired camelCase alias rejection/ignoring for request-lease inputs and output.

This remains non-terminal because the Node bridge, shared StepModule command
runner, JS command callers, and computer-use JS protocol facades still exist.
The deleted `ioi_step_module_bridge/computer_use_provider.rs` file is not a
long-term architecture target; the remaining bridge file delegates to Rust core
only, and the long-term target remains direct Rust daemon-core computer-use
admission, wallet.network/cTEE custody enforcement where applicable,
Agentgres-backed receipt/state-root binding, replay, projection, and stable
protocol APIs end to end.

Slice 1116 moves coding-tool StepModule result construction, workload dispatch
planning, StepModuleRouter admission, receipt binding, Agentgres admission,
projection binding, and response assembly out of the temporary Node receipt
bridge and into Rust `coding_tool_step_module.rs` under the kernel service
crate. Rust core now owns backend-to-projection status selection, successful
StepModule result shaping, workload-client dispatch request derivation,
dispatch evidence merging, result validation, router admission, receipt/state
binding, optional Agentgres operation admission, projection record creation,
and the canonical `rust_workload_command` response envelope for coding-tool
StepModule work.

This remains non-terminal because the Node bridge, command dispatch table,
shared StepModule command runner, JS command callers, and coding-tool JS
protocol facades still exist. The remaining
`ioi_step_module_bridge/coding_tool_receipt_command.rs` file is a temporary
delegate to Rust core, not a durable architectural boundary. The long-term
target remains direct Rust daemon-core/workload coding-tool execution,
admission, replay, projection, and stable protocol APIs end to end, with the
bridge deleted or reduced to external protocol transport once the direct Rust
daemon-core surface is verified.

Slice 1117 moved model_mount accepted-receipt response shaping and invocation
receipt binding/admission out of the temporary Node receipt bridge and into
Rust `model_mount_receipt.rs` under the kernel service crate. Rust core now
owns accepted-receipt head/transition direct API envelopes, model_mount
StepModule invocation/result gate checks, caller-supplied expected-head
rejection, Rust-planned accepted-receipt transition validation, transition
mismatch fail-closed checks, StepModuleRouter admission, receipt binding,
accepted-receipt append through `ReceiptBinder`, optional Agentgres operation
admission, projection record creation, and the canonical
`rust_daemon_core.model_mount.invocation_receipt_binding` response source.

The original receipt command-transport delegate is retired for this family:
`plan_model_mount_accepted_receipt_head`,
`plan_model_mount_accepted_receipt_transition`, and
`bind_model_mount_invocation_receipt` are no longer daemon-core command
operations. The remaining non-terminal work is the rest of model_mount transport
and stable protocol/API ownership, not accepted-receipt or invocation receipt
binding.

Slice 1118 moves governed receipt command response shaping for cTEE private
workspace execution and worker/service package invocation out of the temporary
Node receipt bridge and into Rust `governed_receipt.rs` under the kernel
service crate. Rust core now owns the governed receipt bridge request structs,
cTEE StepModule kind/backend guard, caller-supplied expected-head rejection,
private-workspace cTEE execution/admission wrapping, worker/service package
invocation admission wrapping, accepted-receipt append through `ReceiptBinder`,
and the canonical `rust_ctee_private_workspace_protocol` and
`rust_worker_service_package_invocation_protocol` response envelopes.

This was non-terminal because the Node bridge, command dispatch table, shared
daemon-core command runner, JS command callers, and receipt-bearing JS runners
still existed at that cut. Subsequent cTEE and worker/service package macro
cuts retired those JS runners. The remaining target is stable direct Rust
daemon-core cTEE and worker/service package protocol APIs over Agentgres-backed
receipt/state-root binding, replay, projection, wallet.network authority, cTEE
custody, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1119 moves Agentgres storage-write admission and runtime-state commit
command response shaping out of the temporary Node Agentgres command bridge and
into Rust `agentgres_command.rs` under the kernel service crate. Rust core now
owns the Agentgres command bridge request structs, storage-write admission
response envelope, runtime run-state persisted commit response envelope,
agent/memory/subagent/artifact/model-mount record/model-mount receipt state
commit response envelopes, and the per-record persistence helper that writes
through `AgentgresAdmissionCore` after storage admission.

This was non-terminal at that cut because the Node bridge, command dispatch
table, shared daemon-core command runner, JS command callers, runtime Agentgres
runner, and JS persistence callers still existed. The runtime Agentgres runner
and shared-command-helper path are now superseded by the mounted
`runtimeAgentgresAdmissionCore` cut; the remaining target is direct Rust
daemon-core Agentgres protocol APIs over admitted receipt/state-root truth,
replay, projection, wallet.network authority where applicable, cTEE custody
where applicable, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1120 moves L1 settlement and governed runtime-improvement command
response shaping out of the temporary Node governed-admission command bridge
and into Rust `governed_admission.rs` under the kernel service crate. Rust core
now owns the governed admission protocol request structs, L1 trigger-guard
wrapping, governed-evolution proposal admission wrapping, canonical
`rust_l1_settlement_guard_protocol` and
`rust_governed_meta_improvement_protocol` response envelopes, and the error
codes returned to the bridge boundary.

This was non-terminal because the Node bridge, command dispatch table, shared
daemon-core command runner, JS command callers, L1 settlement runner, and
governed-improvement runner still existed at that cut. The L1 runner has now
been retired behind mounted `l1SettlementCore`, and governed-improvement has
now been retired behind mounted `governedImprovementCore`. The long-term target
remains direct Rust daemon-core governed-admission protocol APIs over settlement
trigger guards, governed proposal admission, Agentgres-backed
receipt/state-root truth where
applicable, replay, projection, wallet.network authority where applicable, and
stable Workbench/CLI/SDK surfaces end to end.

Slice 1121 moved external capability exit authority response shaping out of the
temporary Node authority command bridge and into Rust `authority.rs` under the
kernel service crate. That path is now superseded by the direct authority API
cut: Rust core owns the protocol request struct, wallet.network authority
wrapping, canonical `rust_external_capability_exit_authority_protocol` response
envelope, authority grant/receipt/hash projection fields, and protocol-facing
error code for rejected external exits.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command caller, and external capability
authority runner still exist. The remaining
`ioi_step_module_bridge/authority_command.rs` file is a temporary delegate to
Rust core, not a durable wallet.network authority boundary. The long-term
target remains direct Rust daemon-core authority protocol APIs over
wallet.network grants, authority receipts, Agentgres-backed receipt/state-root
truth where applicable, replay, projection, and stable Workbench/CLI/SDK surfaces end
to end.

Slice 1122 moves coding-tool approval manifest and approval
request/decision/revoke state-update command request/response shaping out of
the temporary Node approval command bridge and into Rust `approval.rs` under
the kernel service crate. Rust core now owns the bridge request structs,
approval manifest wrapping, approval state-update response envelopes,
canonical `rust_coding_tool_approval_command`,
`rust_approval_request_state_update_command`,
`rust_approval_decision_state_update_command`, and
`rust_approval_revoke_state_update_command` source markers, and bridge-facing
error codes for rejected approval command bodies.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, approval runners, and
approval surfaces still exist. The remaining
`ioi_step_module_bridge/approval_command.rs` file is a temporary delegate to
Rust core, not a durable approval authority or state-update boundary. The
long-term target remains direct Rust daemon-core approval protocol APIs over
wallet.network grants, Agentgres-backed expected-head/state-root truth,
receipt/event materialization, replay, projection, cTEE custody policy where
relevant, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1123 moves workflow-edit and diagnostics-repair admission-required
command request/response shaping out of the temporary Node policy command
bridge files and into Rust `policy/admission_required.rs`. Its
projection-required portion for public skill/hook registry, repository
workflow, runtime tool catalog, and runtime lifecycle routes is superseded by
positive Rust projection APIs, so those public route families no longer retain a
projection-required command owner.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, policy/projection
runners, and public fail-closed surfaces still exist. The remaining
`ioi_step_module_bridge/policy_command.rs` and
`ioi_step_module_bridge/projection_command.rs` files are temporary delegates
to Rust core, not durable admission or projection boundaries. The long-term
target remains direct Rust daemon-core admission/projection protocol APIs over
wallet.network authority where applicable, Agentgres-backed expected-head and
state-root truth, receipt/event materialization, replay, projection, and stable
IDE/CLI/SDK surfaces end to end.

Slice 1124 moves context budget, coding-tool budget, compaction policy,
context-compaction plan, and context-compaction state-update command
request/response shaping out of the temporary Node context-policy bridge and
into Rust `policy/context_lifecycle.rs`. Rust core now owns the bridge request
structs, response envelopes, canonical command source markers, and
bridge-facing error codes for rejected context lifecycle command bodies.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, and context-policy
runners still exist. Public `compactThread()` now consumes the Rust
context-compaction plan and state-update plan through Rust Agentgres
runtime-event admission and Agentgres-backed run/agent persistence; public
thread/run context-budget and thread compaction-policy routes now require Rust
policy planning plus Rust Agentgres runtime-event admission before returning
route truth, with compaction-policy execution composed through the Rust-owned
`compactThread()` path when Rust approves compaction. The remaining
`ioi_step_module_bridge/context_policy_command.rs` file is a temporary delegate
to Rust core, not a durable context policy boundary. The long-term target
remains direct Rust daemon-core context admission/projection protocol APIs over
Agentgres expected-head and state-root truth, policy receipts, context
compaction event materialization, replay, projection, and stable Workbench/CLI/SDK
surfaces end to end.

Slice 1125 moves workspace-restore apply-policy, preview/apply operations, and
workspace-snapshot capture command request/response shaping out of the
temporary Node workspace-restore bridge and into Rust `workspace_restore.rs`.
Rust core now owns the bridge request structs, response envelopes, canonical
command source markers, and bridge-facing error codes for rejected
workspace-restore command bodies.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, workspace-restore
runner, and public fail-closed workspace snapshot/restore surfaces still
exist. The remaining `ioi_step_module_bridge/workspace_restore_command.rs`
file is a temporary delegate to Rust core, not a durable workspace
snapshot/restore boundary. The long-term target remains direct Rust
daemon-core workspace snapshot/restore admission, policy/approval,
filesystem-operation, artifact/payload admission, Agentgres expected-head and
state-root truth, receipts/events, replay, projection, and stable Workbench/CLI/SDK
surfaces end to end.

Slice 1126 moves thread lifecycle command request/response shaping out of the
temporary Node thread-lifecycle bridge and into Rust
`policy/thread_lifecycle.rs`. Rust core now owns the bridge request structs,
response envelopes, canonical command source markers, bridge-facing error
codes, and policy facade exports for runtime bridge thread-start state updates,
runtime bridge turn-run state updates, subagent record updates, thread-control
agent updates, thread-turn admission-required refusals, lifecycle
admission-required refusals, agent-create updates, agent-status updates, and
run-create updates.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime context-policy
runner, and public thread/agent/run/subagent lifecycle surfaces still exist.
At this slice, the remaining `ioi_step_module_bridge/thread_lifecycle_command.rs`
file was a temporary delegate to Rust core, not a durable lifecycle boundary;
Slice 1139 later deleted it. The long-term target remains direct Rust
daemon-core thread, turn, agent, run, subagent, and lifecycle
admission/persistence APIs over Agentgres expected-head and state-root truth,
wallet.network authority where applicable, receipt/event materialization,
replay, projection, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1127 moves MCP/memory command request/response shaping out of the
temporary Node MCP/memory bridge and into Rust `policy/mcp_memory.rs`. Rust
core now owns the bridge request structs, response envelopes, canonical command
source markers, bridge-facing error codes, and policy facade exports for MCP
control agent updates, MCP server validation, MCP validation-input projection,
MCP manager status/catalog/catalog-summary/validation projection, memory
manager status/validation projection, and thread-memory agent updates.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime context-policy
runner, MCP catalog/control surfaces, and thread-memory surfaces still exist.
At this slice, the remaining `ioi_step_module_bridge/mcp_memory_command.rs`
file was a temporary delegate to Rust core, not a durable MCP or memory
boundary; Slice 1139 later deleted it. The long-term target remains direct Rust
daemon-core MCP and memory admission/projection APIs over wallet.network
authority for external exits, Agentgres expected-head and state-root truth,
receipt/event materialization, transport containment, replay, projection, and
stable Workbench/CLI/SDK surfaces end to end.

Slice 1128 moves runtime-control command request/response shaping out of the
temporary Node runtime-control bridge and into the Rust policy owner modules:
`policy/coding_tool_budget_recovery.rs`, `policy/operator_control.rs`, and
`policy/run_cancel.rs`. Rust core now owns the bridge request structs, response
envelopes, canonical command source markers, and bridge-facing error codes for
coding-tool budget recovery state updates and admission-required refusals,
diagnostics operator override state updates, operator turn-control
admission-required refusals, operator interrupt/steer state updates, and
run-cancel state updates and admission-required refusals.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime context-policy
runner, diagnostics repair surface, operator turn-control surface,
coding-tool budget recovery surface, and run-cancel surface still exist. At
this slice, the remaining `ioi_step_module_bridge/runtime_control_command.rs`
file was a temporary delegate to Rust core, not a durable runtime-control
boundary; Slice 1139 later deleted it. The long-term target remains direct Rust
daemon-core runtime-control admission/persistence/projection APIs over
wallet.network authority where approval or operator authority applies,
Agentgres expected-head and state-root truth, receipt/event materialization,
replay, projection, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1129 originally moved model-mount read-projection request/response
shaping out of the temporary Node model-mount bridge and into Rust
`model_mount/read_projection.rs`. The current read-projection typed API cut
supersedes that command-envelope shape: Rust daemon-core now exposes
`RuntimeKernelService::plan_model_mount_read_projection`, and the JS
`ModelMountCore` calls it through
`daemonCoreModelMountApi.planModelMountReadProjection` without a command
operation, backend marker, or bridge response wrapper.

This remains non-terminal because the broader Node model-mount bridge, command
dispatch table, shared daemon-core command runner, JS command callers,
model-mount core, and JS state-materialization/read-projection
facades still exist. At this slice, the remaining
`ioi_step_module_bridge/model_mount_command.rs` file was temporary transport
scaffolding, not a durable model-mount projection boundary; Slice 1140 later
retires that child delegate. The long-term target remains direct Rust
daemon-core model-mount
projection APIs over Agentgres expected-head and state-root truth,
receipt-bound topology, wallet.network/cTEE authority where applicable,
replay, projection, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1130 moves model-mount backend-process and required-control command
request/response shaping out of the temporary Node model-mount bridge and into
Rust `model_mount/backend_process.rs` plus `model_mount/required.rs`. Rust core
now owns the bridge request structs, response envelopes, canonical command
source markers, backend defaults, and bridge-facing error propagation for
`plan_model_mount_backend_process`,
`plan_model_mount_backend_lifecycle_required`,
`plan_model_mount_tokenizer_required`, and
`plan_model_mount_route_control_required`; the remaining Node functions only
delegate to the Rust response functions. The server-control required command
was later retired when the positive `plan_model_mount_server_control` boundary
became the canonical server-control path, and the runtime-engine required
command was later retired when the positive
`plan_model_mount_runtime_engine` boundary became the canonical runtime-engine
control path. The backend-lifecycle required command was later retired when the
positive `plan_model_mount_backend_lifecycle` boundary became the canonical
public backend health/start/stop/log path. Slice 1220 later retires tokenizer
and route-control required command transport in favor of typed
`daemonCoreModelMountApi.planModelMountTokenizerRequired`,
`daemonCoreModelMountApi.planModelMountRouteControlRequired`, and
`daemonCoreModelMountApi.planModelMountTokenizer`.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers, local
model-mount materialization, provider/lifecycle wrapper delegates, and mounted
JS facades still exist. At this slice, the remaining
`ioi_step_module_bridge/model_mount_command.rs` file was temporary transport
scaffolding, not a durable backend-process or required-control boundary; Slice
1140 later retires that child delegate. The long-term target remains direct Rust daemon-core
model-mount control/projection APIs over Agentgres expected-head and state-root
truth, receipt-bound topology, wallet.network/cTEE authority where applicable,
replay, projection, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1131 moves model-mount provider lifecycle, provider inventory, and
instance lifecycle command request/response shaping out of the temporary Node
model-mount bridge and into Rust `model_mount/lifecycle.rs`. Rust core now owns
the bridge request structs, response envelopes, canonical command source
markers, backend defaults, and bridge-facing error propagation for
`plan_model_mount_provider_lifecycle`, `plan_model_mount_provider_inventory`,
and `plan_model_mount_instance_lifecycle`; the remaining Node functions only
delegate to the Rust response functions.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers, local
model-mount materialization, provider execution/provider-result wrapper
delegates, and mounted JS facades still exist. At this slice, the remaining
`ioi_step_module_bridge/model_mount_command.rs` file was temporary transport
scaffolding, not a durable provider lifecycle, provider inventory, or instance
lifecycle boundary; Slice 1140 later retires that child delegate. The long-term target remains direct Rust daemon-core
model-mount lifecycle/projection APIs over Agentgres expected-head and
state-root truth, receipt-bound topology, wallet.network/cTEE authority where
applicable, replay, projection, and stable Workbench/CLI/SDK surfaces end to end.

Slice 1132 moves model-mount route-decision and invocation-admission command
request/response shaping out of the temporary Node model-mount bridge and into
Rust `model_mount/admission.rs`. Rust core now owns the bridge request structs,
response envelopes, canonical command source markers, backend defaults, and
bridge-facing error propagation for `admit_model_mount_route_decision` and
`admit_model_mount_invocation`. The Rust admission owner also authors the
accepted `model_route_selection` receipt detail envelope, including canonical
snake_case route/model/provider/workflow fields and the
`rust_daemon_core_model_route_selection_receipt` evidence marker. The remaining
Node functions only delegate to the Rust response functions.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers,
model-mount core, provider execution/provider-result wrapper
delegates, local materialization, and mounted JS facades still exist. At this
slice, the remaining `ioi_step_module_bridge/model_mount_command.rs` file was
temporary transport scaffolding, not a durable model-mount admission boundary;
Slice 1140 later retires that child delegate. The long-term target remains
direct Rust daemon-core model-mount admission,
provider execution, receipt/state-root binding, Agentgres truth, wallet.network
and cTEE authority checks where applicable, replay, projection, and stable
IDE/CLI/SDK surfaces end to end.

Slice 1133 moves the remaining model-mount provider command response shaping
out of the temporary Node model-mount bridge and into Rust
`model_mount/provider_execution.rs` plus `model_mount/provider_result.rs`.
Rust core now owns the bridge request structs, response envelopes, canonical
command source markers, backend defaults, provider invocation alias fields,
stream invocation alias fields, and bridge-facing error propagation for
`admit_model_mount_provider_execution`,
`execute_model_mount_provider_invocation`,
`execute_model_mount_provider_stream_invocation`, and
`admit_model_mount_provider_result`. The remaining Node functions only
delegate to the Rust response functions.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers,
model-mount core, local materialization, mounted JS facades, and
direct daemon-core protocol/API extraction still exist. At this slice, the
remaining `ioi_step_module_bridge/model_mount_command.rs` file was temporary
transport scaffolding, not a durable model-mount provider boundary; Slice 1140
later retires that child delegate. The long-term target remains direct Rust
daemon-core model-mount admission, provider execution,
provider-result admission, receipt/state-root binding, Agentgres truth,
wallet.network and cTEE authority checks where applicable, replay, projection,
and stable Workbench/CLI/SDK surfaces end to end.

Slice 1134 moves coding-tool StepModule command request/response shaping out
of the temporary Node coding-tool bridge and into Rust
`coding_tool_step_module.rs`. Rust core now owns the bridge request struct,
command validation, per-tool dispatch, workload observation envelopes,
StepModule result construction, receipt binding, Agentgres admission,
projection records, artifact data-plane binding, and computer-use lease
receipt/evidence binding for the Rust-live coding-tool set. The remaining
`ioi_step_module_bridge/coding_tool_command.rs` file only delegates to Rust
response functions, while the dead `coding_tool_receipt_command.rs` and
`computer_use.rs` bridge shims are deleted.

This remains non-terminal because StepModule command transport, command
dispatch, JS command callers, runtime coding-tool invocation facades, and
direct daemon-core/workload protocol/API extraction still exist. The remaining
coding-tool Node bridge files are temporary transport/test scaffolding, not a
durable coding-tool execution boundary. The long-term target remains direct
Rust daemon-core and Rust/WASM coding-tool admission, execution,
receipt/state-root binding, Agentgres truth, wallet.network and cTEE authority
checks where applicable, replay, projection, and stable Workbench/CLI/SDK surfaces
end to end.

Slice 1135 retires the now-empty coding-tool StepModule command wrapper module
instead of preserving it as a compatibility shim. The temporary bridge no
longer declares `ioi_step_module_bridge/coding_tool_command.rs`; that file is
deleted, and the bridge module imports the Rust
`coding_tool_step_module.rs` response functions directly for the remaining
stdin/JSON dispatch and proof-test transport. Command identity and schema
validation moved through Rust command-protocol ownership and now resolve to
source-absence conformance, while coding-tool
request/response shaping, StepModuleRouter admission, workload dispatch,
receipt/state-root binding, Agentgres admission, projection, artifact
data-plane binding, and computer-use lease evidence binding remain Rust
`coding_tool_step_module.rs` ownership.

This remains non-terminal because the shared command dispatch table,
StepModule command runner, JS command callers, runtime coding-tool invocation
facades, and direct daemon-core/workload protocol/API extraction still exist.
The surviving `ioi_step_module_bridge` coding-tool imports are temporary
transport/test scaffolding, not a durable coding-tool execution boundary. The
next larger cut should replace the remaining command transport and JS caller
path with direct Rust daemon-core and Rust/WASM workload APIs once that seam is
clear enough to remove without preserving compatibility behavior.

Slice 1136 moves the remaining temporary command-operation dispatch table out
of the Node bridge and into Rust kernel code. The deleted
`ioi_step_module_bridge/command_dispatch.rs` file is replaced by
`crates/services/src/agentic/runtime/kernel/command_dispatch.rs`, where Rust
core now owns typed `CommandOperation` dispatch, request decoding, response
selection, and bridge-facing error mapping for the current StepModule and
daemon-core command surfaces. The Node `bridge_dispatch.rs` module now only
reads stdin JSON, validates the canonical Rust `CommandEnvelope`, and calls
Rust `dispatch_command_operation_response()`.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, and several
proof-test delegate modules still exist as migration scaffolding. The deleted
Node dispatch table must not be recreated or treated as canonical; the next
larger cuts should retire the shared JS command runner/caller path and replace
the remaining bridge transport with direct Rust daemon-core and Rust/WASM
workload protocol APIs once the seam is clear enough to remove without
preserving compatibility behavior.

Slice 1137 retires five now-redundant bridge child wrapper modules instead of
preserving them as compatibility shims. The deleted files are
`ioi_step_module_bridge/approval_command.rs`,
`ioi_step_module_bridge/authority_command.rs`,
`ioi_step_module_bridge/governed_admission_command.rs`,
`ioi_step_module_bridge/governed_receipt_command.rs`, and
`ioi_step_module_bridge/workspace_restore_command.rs`. Their proof-test
surfaces now import Rust response functions and request types directly from
`approval.rs`, `authority.rs`, `governed_admission.rs`,
`governed_receipt.rs`, and `workspace_restore.rs`, while runtime command
dispatch remains Rust `command_dispatch.rs` ownership.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, and remaining
bridge child delegates still exist as migration scaffolding. The deleted child
wrappers must not be recreated or treated as canonical. The next larger cuts
should continue collapsing remaining bridge delegates and then replace the JS
command-runner/caller path with direct Rust daemon-core and Rust/WASM workload
protocol APIs once the seam is clear enough to remove without preserving
compatibility behavior.

Slice 1138 retires four more bridge child wrapper modules that had become
pure Rust delegate shells. The deleted files are
`ioi_step_module_bridge/agentgres_command.rs`,
`ioi_step_module_bridge/context_policy_command.rs`,
`ioi_step_module_bridge/policy_command.rs`, and
`ioi_step_module_bridge/projection_command.rs`. The remaining bridge proof
surface imports Rust response functions and request types directly from
`agentgres_command.rs`, `policy/context_lifecycle.rs`,
`policy/admission_required.rs`, and the positive projection owner modules such
as `runtime_lifecycle.rs`; runtime operation dispatch remains Rust
`command_dispatch.rs` ownership.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, and remaining
bridge child delegates for runtime-control, thread lifecycle, MCP/memory, and
model-mount families still exist as migration scaffolding. The deleted child
wrappers must not be recreated or treated as canonical. The next larger cuts
should either retire the remaining child delegates the same way where they are
pure shells, or replace the JS command-runner/caller path with direct Rust
daemon-core and Rust/WASM workload protocol APIs once that seam is clear enough
to remove without preserving compatibility behavior.

Slice 1139 retires the runtime-control, thread-lifecycle, and MCP/memory
bridge child modules after runtime command dispatch had already moved into
Rust `command_dispatch.rs` and those files had become proof-only delegate
shells. The deleted files are
`ioi_step_module_bridge/runtime_control_command.rs`,
`ioi_step_module_bridge/thread_lifecycle_command.rs`, and
`ioi_step_module_bridge/mcp_memory_command.rs`. The bridge proof surface now
imports Rust response functions and request types directly from
`policy/coding_tool_budget_recovery.rs`, `policy/operator_control.rs`,
`policy/run_cancel.rs`, `policy/thread_lifecycle.rs`, and
`policy/mcp_memory.rs`.

This was non-terminal because the Node bridge binary, JS daemon-core command
runner, StepModule command runner, JS command callers, model-mount bridge
delegates, and broader JS facade/readback surfaces still existed as migration
scaffolding. Slice 1140 later retires the model-mount child delegates. The
deleted policy/lifecycle/MCP wrapper files must not be recreated or treated as
canonical, and the next larger cuts should replace the JS command-runner/caller
path and broad bridge transport with direct Rust daemon-core and Rust/WASM
workload protocol APIs once that seam is clear enough to remove without
preserving compatibility behavior.

Slice 1140 retires the final model-mount bridge child delegate modules after
runtime command dispatch had already moved into Rust `command_dispatch.rs` and
model-mount request/response ownership had moved into Rust
`model_mount.rs` and `model_mount_receipt.rs`. The deleted files are
`ioi_step_module_bridge/model_mount_command.rs` and
`ioi_step_module_bridge/model_mount_receipt_command.rs`. The bridge proof
surface now imports Rust model-mount admission, provider execution, lifecycle,
backend planning, accepted-receipt, and invocation-receipt binding response
functions and request types directly from the Rust kernel modules; current
read-projection ownership has since moved to the typed daemon-core model_mount
API.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, model-mount
admission runner, local materialization, JS readback/protocol edge surfaces,
and broader facade/readback surfaces still exist as migration scaffolding. The
deleted model-mount child wrappers must not be recreated or treated as
canonical. The next larger cuts should replace the broad bridge transport and
JS command-runner/caller path with direct Rust daemon-core and Rust/WASM
workload protocol APIs once that seam is clear enough to remove without
preserving compatibility behavior.

Slice 1141 retires the remaining `coding_tool_helpers.rs` bridge helper after
coding-tool workspace execution semantics had already moved into Rust
`coding_tool_workspace.rs`, Rust execution semantics had moved into
`coding_tool_execution.rs`, and StepModule command dispatch had moved into
Rust `command_dispatch.rs`. The broad bridge proof surface now imports the
Rust workspace inspect/test/git/LSP helpers directly for proof tests instead
of routing through a sibling helper module.

This was non-terminal because the Node bridge binary, JS StepModule command
runner, JS daemon-core command runner, JS command callers, runtime coding-tool
facades, and broad bridge stdin/JSON transport still existed as migration
scaffolding. Slice 1142 later retires the dedicated StepModule command runner
wrapper. The deleted coding-tool helper must not be recreated or treated as
canonical.

Slice 1142 retired `packages/runtime-daemon/src/step-module-command-runner.mjs`
as a second JS command-wrapper shape. At that historical cut, the temporary
StepModule runner remained `rust_workload_live` by construction and called the
shared `runtime-daemon-core-command-runner.mjs` invoker with StepModule-specific
schema/error metadata instead of owning a distinct child-process wrapper. Later
slices delete that shared command runner, the bridge binary, and finally the
temporary StepModule runner facade itself; the live coding-tool path now calls
the typed Rust workload API directly from the invocation surface.

This remains non-terminal because the Node bridge binary, shared JS daemon-core
command runner, JS command callers, runtime coding-tool facades, and broad
bridge stdin/JSON transport still exist as migration scaffolding. The deleted
StepModule command runner wrapper must not be recreated or treated as
canonical. The next larger cuts should replace the remaining shared command
runner/caller path and broad bridge transport with direct Rust daemon-core and
Rust/WASM workload protocol APIs once that seam is clear enough to remove
without preserving compatibility behavior.

Slice 1143 moves L1 settlement product-route admission envelope authorship out
of the JS surface and into Rust `governed_admission.rs`. The Rust
`L1SettlementAdmissionProtocolRequest` now accepts thread/agent route context and
`admit_l1_settlement_attempt_protocol_response()` emits the canonical
`ioi.runtime.l1_settlement_admission.v1` route envelope, including
`settlement_admitted`, `thread_id`, `agent_id`, settlement refs, trigger refs,
receipt refs, Rust-derived state-root refs, and admission hash. The internal L1
settlement product-route API now only extracts the canonical `attempt` request body,
rejects retired request aliases and caller-supplied state-root truth, looks up
the thread agent, and forwards context to the mounted core; it no longer mints
the public settlement-admission response locally. The mounted core now requires
typed `daemonCoreGovernedAdmissionApi.admitL1SettlementAttempt`, rejects generic
`daemonCoreInvoker`, and the old Rust `admit_l1_settlement_attempt` command
operation is retired.

This remains non-terminal because richer settlement replay/projection records,
receipt/state-root binding, and stable Workbench/CLI/SDK settlement read APIs
still need direct Rust ownership. The deleted JS-side L1 response-envelope
authorship and route-visible surface shape must not be recreated or treated as
canonical.

Slice 1144 moves worker/service package product-route admission envelope
authorship out of the JS surface and into Rust `governed_receipt.rs`. The Rust
`WorkerServicePackageInvocationProtocolRequest` now accepts thread/agent route
context and `admit_worker_service_package_invocation_protocol_response()` emits
the canonical `ioi.runtime.worker_service_package_admission.v1` route envelope,
including `invocation_admitted`, `thread_id`, `agent_id`, package refs,
StepModuleRouter admission, receipt binding, accepted-receipt append,
Agentgres admission, projection record, receipt refs, artifact refs, payload
refs, and authority grant refs. The internal worker/service package
product-route API now only extracts the canonical `invocation` body, rejects
retired request/truth fields,
looks up the thread agent, and forwards context to the mounted core; it no
longer mints the public package-admission response locally. The mounted core now
requires typed `daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation`,
rejects generic `daemonCoreInvoker`, and the old Rust
`admit_worker_service_package_invocation` command operation is retired.

This remains non-terminal because richer package projection/replay records,
Agentgres receipt/state-root binding, and stable Workbench/CLI/SDK package admission
read APIs still need direct Rust ownership. The deleted JS-side worker/service
package response-envelope authorship and command-envelope operation must not be
recreated or treated as canonical. The next larger cuts should continue moving
package projection/replay records and stable read APIs into direct Rust
daemon-core protocol APIs.

Slice 1145 moves cTEE Private Workspace product-route admission envelope
authorship out of the JS surface and into Rust `governed_receipt.rs`. The Rust
`CteePrivateWorkspaceProtocolRequest` accepts thread/agent route context and
`execute_private_workspace_ctee_action_protocol_response()` emits the canonical
`ioi.runtime.ctee_private_workspace_admission.v1` route envelope, including
`action_executed`, `thread_id`, `agent_id`, invocation/receipt refs, receipt,
result, receipt binding, accepted-receipt append, Agentgres admission,
projection record, receipt refs, and evidence refs. The JS cTEE surface now
only extracts the canonical `action` body, rejects retired request/truth
fields, looks up the thread agent, and forwards context to the Rust-backed
runner; it no longer mints the public cTEE admission response locally.

This remains non-terminal because the route still reaches Rust through the
shared JS daemon-core command runner and Node bridge stdin/JSON transport. The
deleted JS-side cTEE response-envelope authorship must not be recreated or
treated as canonical. The next larger cuts should replace the shared command
runner/caller path and broad bridge transport with direct Rust daemon-core
protocol APIs once that seam is clear enough, then continue facade retirement
for the remaining JS product/readback surfaces.

Slice 1146 moves governed runtime-improvement product-route admission envelope
authorship out of the JS surface and into Rust `governed_admission.rs`. The
Rust `GovernedRuntimeImprovementProtocolRequest` now accepts thread/agent route
context and `admit_governed_runtime_improvement_proposal_protocol_response()` emits the
canonical `ioi.runtime.governed_improvement_admission.v1` route envelope,
including `proposal_admitted`, `mutation_executed`, `thread_id`, `agent_id`,
proposal refs, admission hash, Agentgres operation/state roots, resulting
head, approval ref, and rollback ref. The JS governed-improvement surface now
only extracts the canonical `proposal` body, rejects retired request/truth
fields, looks up the thread agent, and forwards context to the Rust-backed
core; it no longer mints the public governed-improvement admission response
locally. The mounted core now requires typed
`daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal`,
rejects generic `daemonCoreInvoker`, and the old Rust
`admit_governed_runtime_improvement_proposal` command operation is retired.

This remains non-terminal because the route still reaches Rust through the
shared JS daemon-core command runner and Node bridge stdin/JSON transport. The
deleted JS-side governed-improvement response-envelope authorship must not be
recreated or treated as canonical. The next larger cuts should replace the
shared command runner/caller path and broad bridge transport with direct Rust
daemon-core protocol APIs once that seam is clear enough, then continue facade
retirement for the remaining JS product/readback surfaces.

Slice 1147 moves external capability exit authority product-route response
envelope authorship out of the JS surface and into Rust `authority.rs`. The
Rust `ExternalCapabilityExitAuthorityProtocolRequest` now accepts thread/agent
route context and `authorize_external_capability_exit_protocol_response()` emits
the canonical `ioi.runtime.external_capability_authority.v1` route envelope,
including `status`, `exit_authorized`, `direct_truth_write_allowed`,
`thread_id`, `agent_id`, authority refs, grant refs, receipt refs, and the
authority hash. The internal external-capability authority product-route API now only extracts
the canonical `request` body, rejects retired aliases, looks up the thread
agent, and forwards context to the mounted Rust core; it no longer mints the
public authority response locally.

This remains non-terminal because richer authority replay/projection records,
Agentgres receipt/state-root binding, and stable Workbench/CLI/SDK authority
read APIs still need direct Rust ownership. The deleted JS-side external
capability authority response-envelope authorship and route-visible surface
shape must not be recreated or treated as canonical. The next larger cuts
should continue moving authority projection/replay records and stable read APIs
into direct Rust daemon-core protocol APIs.

Slice 1148 removed the remaining JS-side defaulting for the external
capability authority product-route envelope from the daemon runner normalizer.
That direct-invoker-only migration edge is now superseded by the Slice 1205
core cut: `runtime-external-capability-authority-runner.mjs` is deleted,
`externalCapabilityAuthorityCore` is mounted on the daemon store, and external
capability authorization no longer has a runner normalizer, command/env
fallback, or JS response-envelope compatibility path.

This remains non-terminal because the shared JS daemon-core command runner and
Node bridge transport still carry the request to Rust. The long-term target is
still direct Rust daemon-core authority protocol/API wiring, not preservation
of the current Node command path.

Slice 1149 retires JS-side public projection fallbacks from the MCP/memory
manager context-policy runner normalizers. Rust `policy/mcp_memory.rs` already
authors MCP manager status, MCP validation, MCP catalog, MCP catalog summary,
memory manager status, and memory validation projection response fields through
the daemon-core command path. The JS
`runtime-context-policy-core.mjs` now passes missing Rust-owned
`object`, `status`, count, readiness, route, and projection policy fields
through as `null` instead of reconstructing public projection truth from
arrays, booleans, or hard-coded defaults.

This remains non-terminal because the shared JS daemon-core command runner and
Node bridge transport still carry those projection requests to Rust, and the
broader MCP/memory surfaces still need direct Rust daemon-core protocol APIs,
Agentgres-backed truth, replay, and stable Workbench/CLI/SDK projection wiring. The
retired JS fallback projection behavior must not be recreated as a
compatibility shim.

Slice 1150 retires JS-side public context lifecycle fallbacks from the
context-policy runner normalizers. Rust `policy/context_lifecycle.rs` already
authors context-budget policy, compaction-policy, context-compaction plan, and
context-compaction state-update public record fields through the daemon-core
command path. The JS `runtime-context-policy-core.mjs` now passes missing
Rust-owned `object`, `status`, mode/action, event identity, payload schema,
compaction policy, boolean decision, and target fields through as `null`
instead of reconstructing plausible context lifecycle records from hard-coded
defaults or bridge transport metadata.

This remains non-terminal because the shared JS daemon-core command runner and
Node bridge transport still carry those context lifecycle requests to Rust, and
context policy still needs direct Rust daemon-core protocol APIs, durable
Agentgres expected-head/state-root persistence, richer policy receipts/events,
replay, projection, and stable Workbench/CLI/SDK wiring. Public `compactThread()` is
now Rust-planned, admits the Rust-authored `context.compacted` event through
Rust Agentgres runtime-event admission, binds the state update to the admitted
event id/seq, and commits only the Rust-planned run/agent projection through
Agentgres-backed persistence. Public thread/run context-budget and thread
compaction-policy routes now validate Rust-authored policy-event identity and
admit the Rust-planned policy events before returning route truth; approved
compaction-policy execution composes through `compactThread()`. The retired JS
fallback context lifecycle behavior must not be recreated as a compatibility
shim.

Slice 1151 retires the remaining JS-side state-update envelope fallbacks from
the shared context-policy runner. Rust policy cores already author typed
state-update records for coding-tool budget recovery, diagnostics operator
override, operator interrupt/steer, run cancel, thread control, MCP control,
thread memory, runtime bridge thread start/control/turn submit, subagent record,
agent create/status, and run create paths. The JS
`runtime-context-policy-core.mjs` now passes missing Rust-owned `object` and
`status` fields through as `null` for those state-update normalizers instead
of synthesizing `status: "planned"` as compatibility truth.

This remains non-terminal because the JS context-policy runner and Node bridge
transport still carry the state-update requests to Rust. The target is direct
Rust daemon-core state-update/admission/projection APIs backed by Agentgres
expected-head/state-root persistence, receipts/events, replay, and stable
IDE/CLI/SDK protocol surfaces, not preservation of a JS normalizer as a
canonical state-update envelope author.

Slice 1152 retires JS-side fallback synthesis from the model_mount core
runner for Rust-authored receipt, evidence, process, inventory, accepted-head,
accepted-transition, receipt-binding, and read-projection result fields. Rust
`model_mount` already owns these response records behind the temporary
daemon-core command path, so `model-mount-core.mjs` now preserves
missing Rust-owned arrays, booleans, counts, and process args as `null` instead
of inventing empty refs, `false` supervision/spawn decisions, or inventory
counts from JS-local fallbacks.

This remains non-terminal because the JS model_mount core request builder, shared
daemon-core command runner, and Node bridge transport still carry requests to
Rust. The target is direct Rust daemon-core model_mount protocol/API ownership
over admission, receipt/state-root binding, Agentgres truth, projection,
replay, and stable Workbench/CLI/SDK protocol surfaces, not preservation of JS
normalizers as compatibility shims.

Slice 1153 first retired JS-side receipt/evidence ref fallback synthesis from
the cTEE Private Workspace migration edge. That runner has since been removed:
the daemon now mounts `cteePrivateWorkspaceCore`, requires typed
`daemonCoreCteeApi.executePrivateWorkspaceCteeAction`, rejects the retired
generic `daemonCoreInvoker` command-transport option, and returns the Rust
`governed_receipt.rs` cTEE custody protocol envelope as-is instead of inventing
receipt/evidence refs, source, or backend compatibility truth. The deleted command-protocol source plus conformance source scans keep the old
`execute_private_workspace_ctee_action` operation absent, so this migrated custody path cannot return through the temporary
command dispatcher.

This remains non-terminal because richer cTEE projection/replay records,
Agentgres receipt/state-root binding, and stable Workbench/CLI/SDK cTEE read APIs
still need direct Rust ownership, and other route families still carry
temporary command transport.

Slice 1154 retired JS-side ref fallback synthesis from the temporary
worker/service package runner. Rust `governed_receipt.rs` already owned the
receipt-bearing worker/service package invocation admission response behind the
temporary daemon-core command path, so omitted Rust-authored `receipt_refs`,
`artifact_refs`, `payload_refs`, and `authority_grant_refs` stopped becoming
invented empty arrays as compatibility truth.

That fallback-retirement slice is now superseded by the worker/service package
core API cut: the JS runner and normalizer are deleted, and the product route
reaches Rust-owned package admission through mounted `workerServicePackageCore`.
The target remains direct Rust daemon-core worker/service package protocol/API
ownership over StepModuleRouter admission, wallet authority, receipt/state-root
binding, Agentgres truth, projection, replay, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1155 retired JS-side trigger/receipt ref fallback synthesis from the
temporary L1 settlement runner. Rust `governed_admission.rs` already owned L1
settlement trigger admission and response shaping behind the temporary
daemon-core command path, so omitted Rust-authored `trigger_refs` and
`receipt_refs` stopped becoming invented empty arrays at the JS edge.

That fallback-retirement slice is now superseded by the L1 settlement core API
cut: the JS runner and normalizer are deleted, and the product route reaches
Rust-owned settlement admission through mounted `l1SettlementCore`. The current
transport cut then moves that core to typed
`daemonCoreGovernedAdmissionApi.admitL1SettlementAttempt` and retires the old
Rust command operation. The remaining target is richer Rust daemon-core
settlement projection/replay over wallet authority where applicable,
receipt/state-root binding, Agentgres truth, and stable Workbench/CLI/SDK protocol
surfaces.

Slice 1156 retired JS-side Agentgres head and receipt-ref fallback synthesis
from the then-temporary governed-improvement runner. That fallback-retirement
slice is now superseded by the governed-improvement core API cut: the JS runner
and normalizer are deleted, the daemon store mounts `governedImprovementCore`,
and the product route reaches Rust-owned proposal admission through that mounted
core. The current transport cut then moves that core to typed
`daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal` and
retires the old Rust command operation. The remaining target is richer Rust
daemon-core governed-improvement execution/projection/replay over Agentgres
admission, receipt/state-root binding, wallet approval, rollback metadata, and
stable Workbench/CLI/SDK protocol surfaces.

Slice 1157 retired JS-side runtime Agentgres ref/evidence fallback synthesis
from the then-live Agentgres admission runner. Rust `agentgres_admission.rs`
and `agentgres_command.rs` already owned storage-write admission and runtime
state-commit response shaping behind the temporary daemon-core command path, so
the JS edge stopped inventing empty `artifact_refs`, `payload_refs`,
`receipt_refs`, or `evidence_refs`.

That runner-normalizer cleanup is now superseded by the mounted
`runtimeAgentgresAdmissionCore` cut: the JS runner and normalizers are deleted,
and the core returns Rust daemon-core Agentgres envelopes as-is. The remaining
target is direct Rust daemon-core Agentgres protocol/API ownership over
expected-head checks, state-root binding, storage admission, durable write
materialization, projection, replay, and stable Workbench/CLI/SDK protocol surfaces.

Slice 1158 retired JS-side workspace snapshot capture ref fallback synthesis
from the then-live workspace restore runner. Rust `workspace_restore.rs` already
owned workspace restore apply-policy, preview/apply operation, and snapshot
capture response shaping, so `runtime-workspace-restore-runner.mjs` preserved
omitted Rust-authored per-file `receipt_refs` and `artifact_refs` as `null`
instead of inventing empty arrays at the JS edge.

That runner-normalizer cleanup is now superseded by the typed workspace restore
API cut: the JS runner, generic command invoker, Rust workspace restore command
operations, shared daemon-core command runner, and Node bridge transport no
longer carry workspace restore/snapshot requests to Rust. The remaining target
is richer Rust daemon-core workspace snapshot/restore projection and replay
ownership over durable storage, receipt/state-root binding, Agentgres
ArtifactRef/PayloadRef admission, and stable Workbench/CLI/SDK protocol surfaces, not
preservation of JS normalizers as compatibility shims.

Slice 1159 retired JS-side run-state materialization fallback synthesis from
the then-live runtime Agentgres admission runner. Rust `agentgres_command.rs`
already owned the single `commit_runtime_run_state` response that derives the
transition, storage write-set, persisted records, and written record proof
behind the temporary daemon-core command path, so the JS edge stopped inventing
empty `records` and `written_records`. `thread-persistence.mjs` carried that
absence into its fail-closed proof check instead of normalizing omitted
`written_records` before rejecting the commit.

That interim cleanup is now superseded by the mounted
`runtimeAgentgresAdmissionCore` cut: the JS runner, normalizer, command/env
fallback, and shared command helper path are gone for runtime Agentgres, while
the remaining direct Rust Agentgres protocol/API work is to remove the
command-envelope request builder, local replay cache, and thread persistence
scaffolding.

Slice 1160 retires JS-side required-boundary evidence fallback synthesis from
the model_mount core. Rust model_mount required-boundary planners
already own backend-lifecycle, server-control, runtime-engine, tokenizer, and
route-control required records behind the temporary daemon-core command path,
so `model-mount-core.mjs` now preserves omitted Rust-authored
required-boundary `evidence_refs` as `null` instead of inventing empty arrays
from JS. If Rust includes evidence in the returned record or record details,
the temporary JS edge may pass that Rust-authored array through, but it may not
create compatibility proof material when Rust omits it.

At that cut, the JS model_mount core request builder, shared daemon-core command
runner, and Node bridge transport still carried model_mount required-boundary
requests to Rust. Later model_mount typed API cuts retired those command paths;
Slice 1229 also retires the generic model_mount invoker shim. The remaining
target is Rust daemon-core model_mount materialization/protocol ownership over
lifecycle/control/tokenizer/route admission, receipt/state-root binding,
Agentgres projection, replay, and stable Workbench/CLI/SDK protocol surfaces, not
preservation of JS normalizers as compatibility shims.

Slice 1161 retires JS-side StepModuleResult receipt and result fallback
authorship for coding-tool StepModule execution. `step-module-abi.mjs` no
longer invents `receipt://projection/...` refs for successful coding-tool
StepModule results; accepted coding-tool results now require explicit
Rust-owned receipt refs just like the Rust `StepModuleResult` validator. The
Rust-workload StepModule runner now builds only the StepModule invocation before
calling Rust and preserves an omitted Rust result as `null` instead of falling
back to a JS-authored projection result.

This remains non-terminal because the JS StepModule ABI helper, shared
daemon-core command runner, and `ioi-step-module-bridge` transport still carry
the invocation to Rust. The target is direct Rust daemon-core StepModuleRouter,
workload-client, receipt-binder, Agentgres-admission, and projection ownership
over invocation/result construction, execution, receipt/state-root binding,
replay, and stable Workbench/CLI/SDK protocol surfaces, not preservation of JS result
projection as a compatibility fallback.

Slice 1162 retires JS-side receipt and policy-decision synthesis from
runtime context-pressure alert projection. `runtime-usage-events.mjs` may still
produce advisory `context.pressure_alert` projection rows for the protocol/UI
edge, but those alerts now carry empty `receipt_refs` and
`policy_decision_refs` unless a future Rust-owned policy/receipt admission path
provides admitted refs. The JS producer no longer mints
`receipt_context_pressure...` or `policy_context_pressure...` identifiers for
alert projection.

This remains non-terminal because runtime usage/context-pressure projection is
still assembled by JS while direct Rust daemon-core projection and policy APIs
are pending. The target is Rust daemon-core ownership of usage telemetry,
context-budget policy, receipt/policy admission, Agentgres-backed projection,
replay, and stable Workbench/CLI/SDK protocol surfaces, not preservation of JS
advisory alerts as a source of accepted receipt or policy truth.

Slice 1163 retires JS-side receipt and policy-decision synthesis from
diagnostics feedback projection. `diagnostics-feedback.mjs` may still compact
post-edit diagnostics into advisory injected context, repair-retry context, and
blocking-gate projection rows for the protocol/UI edge, but it no longer mints
`receipt_lsp_diagnostics...`, `receipt_lsp_diagnostics_gate...`, or
`policy_lsp_diagnostics_gate...` fields for those advisory records. Existing
receipt refs from Rust/admitted diagnostic events may pass through; diagnostics
repair policy projection now contributes Rust policy projection receipt refs,
while deeper repair, retry, override, and gate admission receipts still must come
from Rust-owned diagnostics-repair admission paths.

This remains non-terminal because diagnostics feedback still collects temporary
diagnostic event facts in JS while direct Rust daemon-core diagnostics repair
admission, receipt/policy binding, Agentgres-backed durable projection/replay,
and stable Workbench/CLI/SDK APIs are pending. The target is not preservation of JS
diagnostics feedback helpers as accepted truth authors; they are temporary
protocol/context scaffolding only.

The diagnostics repair policy-projection cut supersedes the earlier
snake_case-only JS policy scaffolding. `project_runtime_diagnostics_repair_policy`
is now a Rust daemon-core operation that receives runtime `state_dir` plus
diagnostic event ids, replays admitted Agentgres runtime events to derive
diagnostic status/count, rollback refs, snapshot refs, source tool-call refs,
repair contexts, and deterministic injection id, then returns the rollback
repair policy/config, decision refs, projection receipt refs, evidence refs, and
projection hash. Pending diagnostics feedback calls that Rust projector before
returning a blocking feedback envelope, and blocking-gate creation fails closed
when the Rust policy projection is absent or malformed.

The JS `diagnosticsRollbackRepairPolicy`, default-decision helper, and
context-policy aggregation facade are retired. The follow-on replay cut also
retires JS policy-input candidate transport for `diagnostic_status`,
`diagnostic_count`, `workspace_snapshot_refs`, `rollback_refs`,
`source_tool_call_ids`, `diagnostics_repair_contexts`, and `receipt_refs`.
`diagnostics-feedback.mjs` still selects diagnostic event ids and compacts prompt
text from the event stream, but it no longer supplies rollback repair policy
inputs or authors rollback repair policy truth. The diagnostics feedback
surface mounts the context-policy runner as the diagnostics repair policy
projector and refuses pending feedback policy projection without that Rust
boundary.

This remains non-terminal because broader diagnostics orchestration,
expected-head/state-root binding, receipt/policy binding, durable
projection/replay, and stable Workbench/CLI/SDK protocol
APIs are still pending beyond the Rust policy replay projection API. The
operator-override issuance edge is now wallet-gated by Rust for
approval-required overrides, while the target remains no JS repair policy object
or policy-input authoring as accepted truth.

Slice 1166 retires JS-side artifact-read receipt synthesis from the temporary
coding-tool artifact read/retrieve adapter. `runtime-coding-tool-results.mjs`
now passes through existing admitted `artifactRecord.receipt_refs` and leaves
`receipt_refs` empty when Rust/Agentgres did not provide them; it no longer
constructs `receipt_artifact_read...` identifiers from the artifact id and byte
range. The helper also no longer depends on `safeId` for retired receipt-id
construction.

This has since advanced: artifact read/retrieve projection now calls Rust
daemon-core `project_runtime_coding_tool_artifact_read` with runtime
`state_dir`, and Rust replays committed `artifacts/*.json` Agentgres records,
filters canonical Rust-authored coding-tool artifacts, enforces thread
ownership and canonical target/range aliases, shapes byte ranges/result
metadata/receipt refs, rejects retired `artifact_records` candidate transport,
and fails closed when the projector or `state_dir` is absent. This is still
non-terminal because richer ArtifactRef/PayloadRef admission, receipt binding,
expected-head/state-root checks, runner transport retirement, and stable
protocol APIs remain pending.

Slice 1167 retires the remaining coding-tool response facade inside the
temporary Rust Node bridge module. `ioi_step_module_bridge/mod.rs` now imports
`file_apply_patch_response`, `artifact_read_response`,
`tool_retrieve_result_response`, and `computer_use_request_lease_response`
directly from `crates/services/src/agentic/runtime/kernel/coding_tool_step_module.rs`
for bridge proof tests instead of defining bridge-local wrapper functions and
bridge-local `CodingToolStepModuleCommandError` remapping glue.

This remains non-terminal because the Node bridge itself is still fixed
migration transport. The target is direct Rust daemon-core StepModule/coding
tool protocol APIs, where the bridge no longer exists as a long-term endpoint
and coding-tool response authorship, admission, receipt/state-root binding,
Agentgres persistence, replay, and projection stay in the Rust daemon core.

Slice 1168 moves the temporary bridge transport error type out of the broad
`ioi_step_module_bridge/mod.rs` module and into
`ioi_step_module_bridge/bridge_dispatch.rs`. `BridgeError` and the raw
`run_bridge()` stdin/JSON transport helper are now private to the dispatch
module; the broad bridge module only re-exports
`run_bridge_response_from_stdin()` for the temporary binary entry point.

This remains non-terminal because stdin/JSON command transport still exists as
migration scaffolding. The target is direct Rust daemon-core protocol APIs that
remove the Node bridge path entirely after StepModule/coding-tool dispatch,
receipt/state-root binding, Agentgres admission, replay, and projection are
owned end to end by the Rust daemon core.

Slice 1169 scopes the remaining bridge proof schema constants into the Rust
test module. `CODING_TOOL_RESULT_SCHEMA_VERSION` and
`MODEL_MOUNT_RUNTIME_SCHEMA_VERSION` no longer live at broad bridge runtime
module scope; after Slice 1171 they live in
`ioi_step_module_bridge/proof_tests.rs`, where the bridge proof assertions use
them.

This remains non-terminal because the broad bridge module still hosts the
temporary proof suite. The target is direct Rust daemon-core protocol APIs and
focused owner tests where the Node bridge no longer exists as a long-term
endpoint or proof surface.

Slice 1170 moves Rust service-owner and workload-client imports out of
production `ioi_step_module_bridge/mod.rs` scope and into the Rust test module.
The production bridge module now exposes only the temporary dispatch re-export;
the broad proof suite may still import Rust owners, but only behind
`#[cfg(test)]`.

This remains non-terminal because the bridge proof suite still lives beside the
temporary Node bridge endpoint. The target is direct Rust daemon-core protocol
APIs and focused owner tests where no production bridge module imports Rust
owner families as if they were bridge-owned runtime surface.

Slice 1171 extracts the temporary Rust bridge proof suite out of production
`ioi_step_module_bridge/mod.rs` and into
`ioi_step_module_bridge/proof_tests.rs`. The production bridge module is now
only `bridge_dispatch`, the temporary `run_bridge_response_from_stdin()`
re-export, and `#[cfg(test)] mod proof_tests;`.

This remains non-terminal because `proof_tests.rs` still proves the temporary
Node bridge endpoint. The target is direct Rust daemon-core protocol APIs with
focused owner tests in the Rust kernel/service modules, after which the bridge
endpoint and its proof surface can be retired rather than maintained as
canonical architecture.

Slice 1172 moves command schema-alias, unknown-operation, daemon-core
schema-family mismatch, and StepModule schema-family mismatch proofs out of
`ioi_step_module_bridge/proof_tests.rs` and into the Rust command protocol
owner at `crates/services/src/agentic/runtime/kernel/command_protocol.rs`.
Bridge conformance now requires the owner tests and proves the old
bridge-named command-protocol proof tests are absent from the temporary bridge
proof surface.

This remains non-terminal because `proof_tests.rs` still contains many
temporary bridge endpoint proofs. The target is to keep migrating generic
protocol, authority, admission, receipt, projection, and replay proof coverage
into Rust owner modules until the bridge proof surface can disappear.

Slice 1173 moves the remaining generic daemon-core rejects-StepModule-schema
proofs out of `ioi_step_module_bridge/proof_tests.rs` and into a catalog-wide
Rust owner test in
`crates/services/src/agentic/runtime/kernel/command_protocol.rs`. The bridge
proof suite no longer carries per-surface
`*_rejects_step_module_command_schema` duplicates for authority, approval,
workspace restore, cTEE, worker/service package, L1 settlement,
governed-improvement, context policy, runtime control, lifecycle, MCP/memory,
runtime Agentgres, or model_mount command families. Bridge conformance now
requires the Rust `daemon_core_catalog_rejects_step_module_command_schema`
owner proof and proves those local bridge checks stay absent.

This remains non-terminal because `proof_tests.rs` still proves temporary
bridge endpoint behavior and the Node bridge is still migration transport. The
target is direct Rust daemon-core protocol APIs where schema-family validation,
operation identity, dispatch, authority, admission, receipt/state-root binding,
projection, replay, and conformance are owned by Rust modules rather than by
bridge-local proof scaffolding.

Slice 1174 moves the Agentgres command-response proof family out of the
temporary bridge proof surface and into the Rust owner at
`crates/services/src/agentic/runtime/kernel/agentgres_command.rs`. Storage
backend write admission, runtime run-state commit, agent-state commit,
memory-state commit, subagent-state commit, artifact-state commit, model_mount
record-state commit, and model_mount receipt-state commit response/persistence
proofs now run as Agentgres command owner tests. Receipts conformance now
requires those `agentgres_command_*_through_rust_core` tests and proves the old
bridge proof names, request-type imports, and response-function aliases stay
absent from `ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because Agentgres command request/response shaping is
still exposed through temporary command transport. The target is direct Rust
daemon-core Agentgres protocol/API ownership where admitted truth, expected
heads/state roots, durable writes, replay, and conformance no longer depend on
Node bridge endpoint proof scaffolding.

Slice 1175 moves the approval command-response proof family out of the
temporary bridge proof surface and relies on the Rust approval owner at
`crates/services/src/agentic/runtime/kernel/approval.rs`. Coding-tool approval
manifest shaping plus approval request, decision, and revoke state-update
response shaping now run as `approval.rs` owner tests. Bridge conformance now
requires those Rust owner tests and proves the old bridge-named approval tests,
request-type imports, and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This was non-terminal at that cut because approval command shaping was still
reachable through temporary command transport. Subsequent approval API cuts move
coding-tool approval and public approval-state control/read to typed
`daemonCoreApprovalApi` methods and retire the old Rust approval command
operations. The target remains richer Rust daemon-core authority/approval
projection and replay ownership where approval admission, event materialization,
state updates, and conformance no longer depend on Node bridge endpoint proof
scaffolding.

Slice 1176 moves the governed authority/admission/receipt command-response
proof cluster out of the temporary bridge proof surface and relies on the Rust
owners at `crates/services/src/agentic/runtime/kernel/authority.rs`,
`crates/services/src/agentic/runtime/kernel/governed_admission.rs`, and
`crates/services/src/agentic/runtime/kernel/governed_receipt.rs`. External
capability authority, wallet.network negative authority, cTEE private workspace
receipt admission, worker/service package invocation receipt admission, L1
settlement admission, and governed meta-improvement proposal admission now run
as Rust owner tests. Bridge conformance now requires those owner tests and
proves the old bridge-named tests, request-type imports, and response-function
aliases stay absent from `ioi_step_module_bridge/proof_tests.rs`.

This was non-terminal at that cut because these operations still crossed
temporary command transport. Subsequent macro cuts retire that command transport
for external capability authority, cTEE, worker/service package invocation, L1
settlement, and governed-improvement proposal admission. The target remains
direct Rust daemon-core governed authority/admission protocol/API ownership
where wallet authority, cTEE custody, settlement
triggering, receipt binding, Agentgres admission, projection, replay, and
conformance no longer depend on Node bridge endpoint proof scaffolding.

Slice 1177 moves the admission-required policy command-response proof cluster
out of the temporary bridge proof surface and relies on the Rust policy owner at
`crates/services/src/agentic/runtime/kernel/policy/admission_required.rs`.
The projection-required half for public skill/hook registry, repository
workflow, runtime tool catalog, and runtime lifecycle is superseded by positive
Rust projection owner tests. Bridge and compositor conformance now require
those owner tests and prove the old bridge-named tests, request-type imports,
and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because these policy decisions still cross temporary
command transport. The target is direct Rust daemon-core policy/projection API
ownership where admission-required refusal, projection-required refusal,
Agentgres truth, replay, and conformance no longer depend on Node bridge
endpoint proof scaffolding.

Slice 1178 moves the context lifecycle command-response proof cluster out of
the temporary bridge proof surface and relies on the Rust policy owner at
`crates/services/src/agentic/runtime/kernel/policy/context_lifecycle.rs`.
Context-budget policy, coding-tool budget policy, compaction policy,
context-compaction plan, and context-compaction state-update response shaping
now run as Rust owner tests. Bridge conformance now requires those owner tests
and proves the old bridge-named context lifecycle tests, request-type imports,
and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because durable context lifecycle replay/projection,
richer policy receipts/state roots, wallet/cTEE authority, and stable
IDE/CLI/SDK APIs still need direct Rust ownership. Public context compaction is no longer a
fail-closed JS facade: `compactThread()` now uses Rust event planning, Rust
runtime-event admission, Rust state-update planning bound to the admitted event
id/seq, and Agentgres-backed run/agent persistence. Thread/run context-budget and
thread compaction-policy are now Rust policy-event admission paths instead of
fail-closed JS facades, and approved compaction-policy execution routes through
the Rust-owned compaction API. Schedule the next
matrix-compaction pass only after the next direct Rust-core API extraction or
facade-retirement seam makes it clear which temporary transport rows can be
collapsed without canonizing the bridge.

The context lifecycle transport cut after Slice 1178 replaces the temporary
context lifecycle command path with typed `daemonCoreContextLifecycleApi`
methods for context-budget policy, coding-tool budget policy, coding-tool
budget-block planning, compaction-policy, context-compaction planning, and
context-compaction state-update planning. The JS runtime context-policy core now
sends canonical request bodies to that typed API without generic command
`operation`/`backend` envelopes, and Rust `command_protocol.rs`/
`command_dispatch.rs` reject the old context lifecycle command operations. This
does not claim terminal context-policy migration: durable replay/projection,
richer policy receipts/state roots, wallet/cTEE authority, stable Workbench/CLI/SDK
APIs, and the remaining non-context lifecycle state-update families still need
direct Rust ownership.

Slice 1179 moves the runtime-control command-response proof cluster out of the
temporary bridge proof surface and relies on the Rust policy owners at
`crates/services/src/agentic/runtime/kernel/policy/coding_tool_budget_recovery.rs`,
`crates/services/src/agentic/runtime/kernel/policy/operator_control.rs`, and
`crates/services/src/agentic/runtime/kernel/policy/run_cancel.rs`. Coding-tool
budget recovery state-update and admission-required responses, diagnostics
operator override state-update responses, operator turn-control
admission-required responses, operator interrupt/steer state-update responses,
and the then-current run-cancel state-update/admission-required responses moved
to Rust owner tests. Bridge conformance now requires those owner tests and proves the old
bridge-named runtime-control tests, request-type imports, and response-function
aliases stay absent from `ioi_step_module_bridge/proof_tests.rs`.
Slice 1230 retires the remaining run-cancel command-shaped owner wrappers from
that intermediate proof cluster.

The runtime-control transport cut after Slice 1179 replaces that temporary
command path with typed `daemonCoreRuntimeControlApi` methods for coding-tool
budget recovery state/control planning, diagnostics operator override
state-update planning, operator turn-control admission-required planning,
operator interrupt/steer state-update planning, and run-cancel
state/admission planning. The JS runtime context-policy core now sends
canonical request bodies to that typed API without generic command
`operation`/`backend` envelopes, the Rust kernel exposes the corresponding
positive daemon-core methods, and `command_protocol.rs`/`command_dispatch.rs`
reject the old runtime-control command operations. This does not claim
terminal runtime-control migration: durable replay/projection, richer
runtime-control receipts/state roots, wallet/runtime-control authority, stable
IDE/CLI/SDK APIs, and the remaining MCP/memory families still need direct Rust
ownership.

The thread-lifecycle state-update transport cut after Slice 1180 replaces the
temporary command path with typed `daemonCoreThreadLifecycleApi` methods for
thread-control agent state updates, runtime-bridge thread start/control state
updates, runtime-bridge turn run state updates, subagent record state updates,
agent/thread/run creation state updates, and agent status/delete state updates.
The JS runtime context-policy core now sends canonical request bodies to that
typed API without generic command `operation`/`backend` envelopes, the Rust
kernel exposes the corresponding positive daemon-core methods, and
`command_protocol.rs`/`command_dispatch.rs` reject the old thread-lifecycle
state-update command operations. This retires the command transport for the
runtime-bridge thread-control/start/turn-submit, agent-run-create, thread
control, and subagent-wait state-update hot paths guarded by bridge and
compositor conformance. This does not claim terminal lifecycle migration:
durable replay/projection, wallet/cTEE lifecycle authority, stable
IDE/CLI/SDK APIs, and MCP/memory policy/control transport remain non-terminal;
Slice 1223 later retires the thread-turn and lifecycle admission-required
command transport through typed lifecycle APIs.

Slice 1180 moves the thread-lifecycle and MCP/memory command-response proof
clusters out of the temporary bridge proof surface and relies on the Rust
policy owners at
`crates/services/src/agentic/runtime/kernel/policy/thread_lifecycle.rs` and
`crates/services/src/agentic/runtime/kernel/policy/mcp_memory.rs`. Thread
control, thread-turn admission-required, lifecycle admission-required,
runtime-bridge thread/turn state updates, subagent state updates,
agent/run lifecycle state updates, MCP control, MCP server validation/input,
MCP manager status/catalog/catalog-summary/validation, memory manager
status/validation, and thread-memory state-update command-response shaping now
run as Rust owner tests. Bridge conformance now requires those owner tests and
proves the old bridge-named thread/MCP/memory tests, request-type imports, and
response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because MCP/memory policy decisions still cross
temporary command transport. Thread-turn and lifecycle admission-required
refusals were later moved to typed Rust daemon-core lifecycle APIs, so they are
no longer a current command-transport blocker. The target is direct Rust
daemon-core MCP and memory API ownership where admission, projection,
Agentgres truth, replay, and conformance no longer depend on Node bridge
endpoint proof scaffolding.

The workspace-trust state-update transport cut replaces the temporary command
path with typed `daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate`.
The JS runtime context-policy core now sends canonical workspace-trust
warning/ack request bodies to that typed API without generic command
`operation`/`backend` envelopes, the Rust kernel exposes the corresponding
positive daemon-core method, and `command_protocol.rs`/`command_dispatch.rs`
reject the old workspace-trust state-update command operation. This retires the
command transport for the workspace-trust warning/ack hot path guarded by
compositor conformance; deeper wallet/cTEE workspace authority, durable
projection storage, and stable SDK/IDE/CLI APIs remain non-terminal.

Slice 1181 moved the workspace-restore command-response proof cluster out of
the temporary bridge proof surface and into the Rust workspace owner at
`crates/services/src/agentic/runtime/kernel/workspace_restore.rs`. That
proof move is now superseded by the typed workspace restore API cut: workspace
restore apply-policy planning, restore operation preview/apply, workspace
snapshot capture, snapshot projection, content-package projection, and restore
preview/apply all enter Rust through `daemonCoreWorkspaceRestoreApi`, and the
old workspace restore command catalog/dispatch operations are retired. The
remaining target is richer durable Rust daemon-core workspace snapshot/restore
projection and replay ownership where Agentgres truth, receipt/state-root
binding, and stable Workbench/CLI/SDK surfaces no longer depend on thin JS protocol
client scaffolding.

Slice 1182 moves the first model-mount admission/execution command-response
proof cluster out of the temporary bridge proof surface and relies on the Rust
model-mount owners at
`crates/services/src/agentic/runtime/kernel/model_mount/admission.rs` and
`crates/services/src/agentic/runtime/kernel/model_mount/provider_execution.rs`.
Route-decision admission, invocation admission, provider-execution admission,
fixture provider invocation, native-local provider invocation, and
native-local provider stream command-response shaping now run as Rust owner
tests. Bridge conformance now requires those owner tests, proves typed Rust
`command_dispatch.rs` still dispatches those operations, and proves the old
bridge-named tests, request-type imports, and response-function aliases stay
absent from `ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because model-mount admission and provider execution
still cross temporary command transport. The target is direct Rust daemon-core
model-mount protocol/API ownership where route selection, invocation
admission, provider execution, provider invocation, Agentgres truth, replay,
and stable Workbench/CLI/SDK surfaces no longer depend on Node bridge endpoint proof
scaffolding.

Slice 1183 moved the next model-mount provider-result and receipt-binding
command-response proof cluster out of the temporary bridge proof surface and
into the Rust owners at
`crates/services/src/agentic/runtime/kernel/model_mount/provider_result.rs`
and `crates/services/src/agentic/runtime/kernel/model_mount_receipt.rs`.
Provider-result command-envelope shaping and the then-command-shaped receipt
binding proofs moved to Rust owner tests first; later cuts moved provider-result
admission and invocation receipt binding to typed `daemonCoreModelMountApi`
methods and removed their command operations from Rust protocol/dispatch. The
target remains direct Rust daemon-core model-mount protocol/API ownership for
the remaining transport families.

Slice 1184 moves the model-mount provider lifecycle, provider inventory, and
instance lifecycle command-response proof cluster out of the temporary bridge
proof surface and into the Rust owner at
`crates/services/src/agentic/runtime/kernel/model_mount/lifecycle.rs`.
Provider lifecycle, provider inventory, and instance lifecycle command-envelope
response shaping now run as Rust owner tests. Bridge conformance now requires
those owner tests, proves typed Rust `command_dispatch.rs` still dispatches
`plan_model_mount_provider_lifecycle`,
`plan_model_mount_provider_inventory`, and
`plan_model_mount_instance_lifecycle`, and proves the old bridge-named tests,
request-type imports, and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`. The bridge proof suite now runs 41
tests.

This remains non-terminal because provider lifecycle, provider inventory, and
instance lifecycle planning still cross temporary command transport. The target
is direct Rust daemon-core model-mount protocol/API ownership where provider
lifecycle execution, provider inventory materialization, instance lifecycle
transition admission, Agentgres truth, replay, and stable Workbench/CLI/SDK surfaces
no longer depend on Node bridge endpoint proof scaffolding.

Slice 1185 moves the model-mount backend-process and required-control
command-response proof cluster out of the temporary bridge proof surface and
into Rust model-mount owners at
`crates/services/src/agentic/runtime/kernel/model_mount/backend_process.rs`
and `crates/services/src/agentic/runtime/kernel/model_mount/required.rs`.
Backend process planning plus tokenizer and route-control required
response shaping now run as Rust owner tests, while backend
lifecycle now has positive command-envelope and record-planning owner tests in
Rust `model_mount/backend_lifecycle.rs`. Bridge
conformance now requires those owner tests, proves Slice 1222 retired the
`plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle` command operations, and proves Slice 1220
retired `plan_model_mount_tokenizer_required`,
`plan_model_mount_route_control_required`, and
`plan_model_mount_tokenizer`, while public route write/test,
mounted route selection, explicit-model endpoint resolution, and runtime
explicit/run-override model-route selection now call typed
`daemonCoreModelMountApi.planModelMountRouteControl`, backed by Rust
`RuntimeKernelService::plan_model_mount_route_control`, and runtime-engine
selection/profile/remove mutations now call typed `daemonCoreModelMountApi.planModelMountRuntimeEngine`, backed by Rust `RuntimeKernelService::plan_model_mount_runtime_engine`, with Rust Agentgres model_mount record-state commits. The owner tests prove the required route-control record family for unmigrated helper edges, the positive runtime-engine direct API, and the retired runtime-engine command transport, while `command_protocol.rs` now rejects the retired
`plan_model_mount_route_control` operation and the old bridge-named tests,
request-type imports, and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`. Server-control later moved to the
positive `plan_model_mount_server_control` boundary and its required-record
command stayed retired; runtime-engine likewise moved to typed `daemonCoreModelMountApi.planModelMountRuntimeEngine` and retired its command transport plus required-record command;
backend lifecycle likewise moved to positive
`plan_model_mount_backend_lifecycle`, retired its required-record command, and
then Slice 1222 moved backend-process/backend-lifecycle planning to typed
daemon-core APIs. The
bridge proof suite now runs 35 tests.

This remains non-terminal because actual backend process supervision/transport
execution and live external backend process-state supervision still need Rust
ownership. Backend-process/backend-lifecycle planning, public route-control, and
model_mount conversation/stream planning no longer cross temporary command
transport. The target is direct Rust daemon-core model-mount protocol/API
ownership where backend supervision, tokenizer/context-fit control, Agentgres truth, replay, and stable
IDE/CLI/SDK surfaces no longer depend on Node bridge endpoint proof scaffolding.

Slice 1186 moved the remaining model-mount accepted-receipt proof cluster and
the then-temporary read-projection proof cluster out of the temporary bridge
proof surface and into Rust owners at
`crates/services/src/agentic/runtime/kernel/model_mount_receipt.rs` and
`crates/services/src/agentic/runtime/kernel/model_mount/read_projection.rs`.
Accepted-receipt head/transition planning and read-projection have since moved
to positive typed APIs owned by `RuntimeKernelService`; Rust command protocol
now rejects `plan_model_mount_accepted_receipt_head`,
`plan_model_mount_accepted_receipt_transition`, and
`bind_model_mount_invocation_receipt`. This remains non-terminal only because
other model_mount helpers still cross temporary transport.

Slice 1187 deletes the remaining temporary bridge proof module and moves its
coding-tool StepModule proof obligations into Rust owner tests. The Node bridge
module now exports only the temporary stdin/JSON transport entry point through
`bridge_dispatch.rs`; `ioi_step_module_bridge/proof_tests.rs` is absent and
`cargo test -p ioi-node --bin ioi-step-module-bridge` runs zero semantic bridge
tests. Coding-tool StepModule response/admission/receipt/projection coverage
now lives in
`crates/services/src/agentic/runtime/kernel/coding_tool_step_module.rs`, while
workspace execution/inspection coverage remains in
`crates/services/src/agentic/runtime/kernel/coding_tool_workspace.rs`.
Bridge conformance now requires the Rust owner test names for file patch,
artifact read, result retrieval, and computer-use request-lease alias/authority
proofs, and proves the bridge proof module and its service-owner imports stay
absent.

This remains non-terminal because the Node bridge is still temporary command
transport. The target is direct Rust daemon-core StepModule/coding-tool
protocol/API ownership where command-envelope validation, dispatch, workload
execution, receipt binding, Agentgres admission, replay, projection, and stable
IDE/CLI/SDK surfaces no longer require a Node bridge binary at all.

Slice 1188 was an intermediate contraction of the StepModule-specific command
path at the JS runner edge. It was superseded by the typed workload API cut and
the later command-env deletion: `createStepModuleRunnerFromEnv()` no longer
reads `IOI_STEP_MODULE_COMMAND` or `IOI_RUNTIME_DAEMON_CORE_COMMAND`, and no
command env is a live StepModule source.

Slice 1189 was the intermediate daemon-core command-schema contraction for
coding-tool StepModule dispatch. It was superseded by Slice 1228 and then
Slice 1262: the live coding-tool invocation surface no longer emits any command
schema or command envelope for `run_coding_tool_step_module`; it calls typed
`daemonCoreWorkloadApi.runCodingToolStepModule` directly, while the deleted command-protocol source plus conformance source scans keep
`run_coding_tool_step_module` absent as a command operation. The old StepModule and daemon-core command schemas remain
only as rejected legacy evidence.

Slice 1190 removes the dead StepModule command-family/catalog API left behind
after Slice 1189. `command_protocol.rs` no longer exposes
`STEP_MODULE_OPERATIONS`, `CommandFamily`, `command_family()`,
`is_step_module_operation()`, or `is_daemon_core_operation()`; all live
temporary command operations resolve their schema directly through
`CommandOperation::schema_version()` and the daemon-core operation catalog. The
retired `ioi.step_module.command_bridge.v1` schema constant remains only for
negative tests that prove legacy StepModule command envelopes fail closed.
Bridge conformance now rejects reintroducing the dead family API while still
requiring Rust-owned typed command operation validation before dispatch.

This remains non-terminal because the unified daemon-core command protocol
still crosses temporary Node-launched transport. The target is direct Rust
daemon-core StepModuleRouter/coding-tool protocol/API ownership where command
validation, dispatch, workload execution, receipt binding, Agentgres admission,
replay, projection, and stable Workbench/CLI/SDK surfaces do not depend on
command-bridge transport.

Slice 1191 moves the temporary stdin/JSON daemon-core command transport owner
out of `crates/node/src/bin/ioi_step_module_bridge/bridge_dispatch.rs` and into
Rust service-kernel ownership in `command_dispatch.rs`. The deleted bridge
module no longer owns `BridgeError`, raw `run_bridge()` parsing, canonical
`CommandEnvelope` validation, schema-alias rejection, operation dispatch, or
the `{ ok, result/error }` response envelope. `ioi-step-module-bridge` remains
only a temporary binary entry point that calls
`run_daemon_core_command_response_from_stdin()` from `ioi-services`.

This is still non-terminal because JS runners can still spawn the temporary
binary through `IOI_RUNTIME_DAEMON_CORE_COMMAND`. It is nevertheless a larger
pure-Rust cut: command transport semantics, error mapping, envelope validation,
and dispatch framing are now owned by the Rust daemon-core service boundary,
and conformance fails if the deleted bridge-local transport module is
recreated. Resume by replacing the remaining JS command invoker and binary
spawn path with direct Rust daemon-core protocol/API calls.

Slice 1192 removed the last live transport re-export from
`crates/node/src/bin/ioi_step_module_bridge/mod.rs`. Later Slice 1233 deleted
the temporary `ioi-step-module-bridge` binary and the empty
`ioi_step_module_bridge/mod.rs` tombstone, and Slice 1234 deleted the
`command_dispatch.rs` stdin/JSON transport; conformance now proves retired bridge
wrappers, proof modules, helper imports, command facades, binary fallback, and
service command dispatch are not recreated.

This is not terminal because the JS daemon still invokes the temporary binary.
It does remove another compatibility shim from the live path: there is no
bridge module between the temporary process entry point and the Rust
service-kernel command transport owner. Resume by replacing
`runtime-daemon-core-command-runner.mjs` and its `IOI_RUNTIME_DAEMON_CORE_COMMAND`
spawn path with direct Rust daemon-core protocol/API calls.

Slice 1193 adds an explicit direct Rust daemon-core API seam to the shared JS
daemon-core command invoker. `runtime-daemon-core-command-runner.mjs` now
accepts `daemonCoreInvoker`, runs it before the temporary binary spawn path,
and preserves missing-command fail-closed behavior when neither a direct
invoker nor the migration command is configured. The current StepModule,
approval, context-policy, governed-improvement, worker/service package,
workspace-restore, L1 settlement, external capability, model_mount core,
runtime Agentgres, and cTEE private workspace runners thread
`options.daemonCoreInvoker` through their environment factories and
constructors.

This is not terminal direct Rust ownership. It is the reviewed migration seam
for the next larger cut: wire the seam to real Rust daemon-core protocol/API
entry points, then delete the `IOI_RUNTIME_DAEMON_CORE_COMMAND` binary-spawn
fallback and the JS command invoker scaffolding once conformance proves every
hot-path surface is owned by Rust daemon-core APIs.

Slice 1194 removes the shared JS-authored `mockResult` command fallback from
`runtime-daemon-core-command-runner.mjs` and from all current daemon-core
command runners that used that shared helper. Tests that need an in-process
Rust-core substitute now use `daemonCoreInvoker` explicitly, while passing the
retired `mockResult` option without a direct invoker or migration command fails
closed instead of producing a JS-authored result.

This is still not terminal because the temporary binary-spawn fallback remains
for surfaces that have not yet been wired to direct Rust daemon-core APIs. It
does remove one duplicate JS truth/result path from the migration scaffolding:
there is now a single reviewed direct-invoker seam for in-process Rust API
wiring and one explicit binary-spawn fallback to delete after that wiring is
verified.

Slice 1195 lifted the direct daemon-core invoker seam from per-runner test
plumbing into the daemon composition boundary. At that historical cut,
`AgentgresRuntimeStateStore` accepted `daemonCoreInvoker`, stored it once, and
passed it through the default runtime Agentgres, context-policy,
governed-improvement, external capability, worker/service package, cTEE private
workspace, L1 settlement, workspace restore, model_mount core, and StepModule
runner construction paths. Later typed-core cuts retire that generic invoker,
and Slice 1262 deletes the temporary StepModule runner facade; the live
coding-tool invocation surface receives `daemonCoreWorkloadApi` directly.

This is still migration scaffolding, not terminal direct Rust ownership. It
does make the next pure-Rust cut larger and cleaner: a real Rust daemon-core
API can now be injected at the daemon boundary and exercised across default
hot-path runners before the `IOI_RUNTIME_DAEMON_CORE_COMMAND` spawn fallback and
JS command invoker are deleted.

Slice 1203 retires the daemon L1 settlement runner outright. The daemon store
now mounts `l1SettlementCore`; the JS runner facade, store runner option,
command/env fallback, and response normalizer are deleted.

The governed-admission transport cut supersedes that direct-invoker-only edge:
the L1 settlement core now requires typed
`daemonCoreGovernedAdmissionApi.admitL1SettlementAttempt`, rejects generic
`daemonCoreInvoker`, calls Rust with the canonical attempt plus thread/agent
route context, and returns the Rust `governed_admission.rs` admission protocol
envelope as-is. The deleted command-protocol source plus conformance source scans keep
`admit_l1_settlement_attempt` absent as a daemon-core command operation, so the old
command-envelope path cannot be selected for this migrated family.

This removes JS envelope truth for the settlement path: trigger admission,
settlement refs, trigger refs, receipt refs, state-root refs, admission hashes,
source, and backend truth must arrive from Rust daemon-core output or remain
absent at the JS edge. A later state-root authority cut also removes
`state_root_ref` from daemon, SDK, IDE, and CLI request clients; Rust
`settlement.rs` derives admitted `state_root_ref` from canonical
settlement/domain/trigger/receipt facts and direct L1 attempts reject unknown
state-root input at the Rust schema boundary. It is still not terminal because
richer L1 settlement projection/replay records, deeper Agentgres
receipt/state-root binding, stable Workbench/CLI/SDK settlement read APIs, and other
route-family command transports remain non-terminal.

Slice 1204 retires the daemon governed-improvement runner outright. The daemon
store now mounts `governedImprovementCore`; the JS runner facade, store runner
option, command/env fallback, and response normalizer are deleted.

The governed-admission transport cut supersedes that direct-invoker-only edge:
the governed-improvement core now requires typed
`daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal`,
rejects generic `daemonCoreInvoker`, calls Rust with the canonical proposal plus
thread/agent route context, and returns the Rust `governed_admission.rs`
admission protocol envelope as-is. The deleted command-protocol source plus conformance source scans keep
`admit_governed_runtime_improvement_proposal` absent as a daemon-core command
operation, so the old command-envelope path cannot be selected for this
migrated family.

This removes JS envelope truth for the governed-improvement path: expected
heads, eval/verifier receipt refs, proposal refs, admission hashes, Agentgres
operation refs, state roots, approval refs, rollback refs, source, and backend
truth must arrive from Rust daemon-core output or remain absent at the JS edge.
It is still not terminal because richer governed-improvement execution,
projection, and replay records, deeper Agentgres receipt/state-root binding,
stable Workbench/CLI/SDK governed-improvement read APIs, and other route-family
command transports remain non-terminal.

Slice 1205 retires the daemon external capability authority runner outright.
The daemon store now mounts `externalCapabilityAuthorityCore`; the JS runner
facade, store runner option, command/env fallback, and response normalizer are
deleted.

The current external capability authority transport cut retires the remaining
generic command-envelope request builder for this family. The core now requires
typed `daemonCoreAuthorityApi.authorizeExternalCapabilityExit`, rejects the
retired `daemonCoreInvoker` command-transport option plus request aliases/truth
fields before Rust invocation, and returns the Rust `authority.rs`
wallet.network authority protocol envelope as-is. Rust `command_protocol.rs`
also rejects `authorize_external_capability_exit` as an absent command operation,
so this migrated authority path cannot return through the temporary command
dispatcher.

This removes JS envelope truth for the external capability path:
authorization booleans, wallet.network grant refs, authority receipt refs,
authority hashes, route context, source, and backend truth must arrive from
Rust daemon-core output or remain absent at the JS edge. It is still not
terminal because richer authority projection/replay records, Agentgres
receipt/state-root binding, and stable Workbench/CLI/SDK authority read APIs still
need direct Rust ownership, and other route families still carry temporary
command transport.

The current cTEE Private Workspace transport cut retires the remaining generic
command-envelope request builder for this family. The core now requires typed
`daemonCoreCteeApi.executePrivateWorkspaceCteeAction`, rejects the retired
`daemonCoreInvoker` command-transport option plus request aliases before Rust
invocation, and returns the Rust `governed_receipt.rs` cTEE custody protocol
envelope as-is. Rust `command_protocol.rs` also rejects
`execute_private_workspace_ctee_action` as an absent command operation, so this
migrated custody path cannot return through the temporary command dispatcher.

This removes JS envelope truth for the cTEE path: action execution booleans,
custody proof refs, receipt refs, accepted-receipt append, Agentgres admission,
projection records, route context, source, and backend truth must arrive from
Rust daemon-core output or remain absent at the JS edge. It is still not
terminal because richer cTEE projection/replay records, Agentgres
receipt/state-root binding, and stable Workbench/CLI/SDK cTEE read APIs still need
direct Rust ownership, and other route families still carry temporary command
transport.

Slice 1197 retired the temporary binary-spawn fallback for the daemon external
capability authority runner. That direct-invoker-only migration edge is now
superseded by the Slice 1205 core cut: the runner file is deleted,
`externalCapabilityAuthorityCore` is mounted on the daemon store, and external
capability authorization no longer has a command/env fallback or JS response
normalizer.

This makes the wallet.network authority path a mounted core API instead of a
runner facade: external capability authorization, grant refs, receipt refs,
authority hashes, and public envelope facts must arrive from Rust daemon-core
authority output or stay absent at the JS edge. It is still not terminal
daemon-wide Rust API ownership because other command runners remain on
temporary command transport. Resume by cutting the remaining authority,
admission, and projection runners the same way.

Slice 1198 retired the temporary binary-spawn fallback for the daemon governed
improvement runner. That direct-invoker-only migration edge is now superseded by
the Slice 1204 core cut: `runtime-governed-improvement-runner.mjs` is deleted,
`governedImprovementCore` is mounted on the daemon store, and proposal
admission no longer has a command/env fallback or JS response normalizer.

This makes the admitted-truth path a mounted core API instead of a runner
facade: proposal admission, expected-head/state-root binding fields,
evaluation receipts, verifier receipts, approval refs, and rollback refs must
arrive from Rust daemon-core admission output or stay absent at the JS edge. It
is still not terminal daemon-wide Rust API ownership because other command
runners remain on temporary command transport. Resume by cutting the remaining
admission and receipt-bearing runners the same way.

Slice 1199 retired the temporary binary-spawn fallback for the daemon cTEE
Private Workspace migration edge. The follow-on cTEE macro cut removes the
runner facade entirely: Private Workspace cTEE execution now reaches Rust
through mounted `cteePrivateWorkspaceCore`, command/env selection is not read,
and receipt-bearing cTEE execution, custody proof refs, receipt binding,
accepted receipt append, Agentgres admission, projection records, receipt refs,
and evidence refs must arrive from Rust daemon-core output.

The follow-on transport cut supersedes the direct-invoker-only edge: the cTEE
core now requires typed `daemonCoreCteeApi.executePrivateWorkspaceCteeAction`,
rejects generic `daemonCoreInvoker`, and the old Rust
`execute_private_workspace_ctee_action` command operation is retired. This is
still not terminal because the internal product-route API remains a request
extractor and richer cTEE projection/replay records, Agentgres
receipt/state-root binding, and stable Workbench/CLI/SDK cTEE read APIs still need
direct Rust ownership.

Slice 1202 retires the daemon worker/service package runner outright. The
daemon store now mounts `workerServicePackageCore`; the JS runner facade, store
runner option, command/env fallback, and response normalizer are deleted.

The follow-on transport cut supersedes that direct-invoker-only edge: the
worker/service package core now requires typed
`daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation`, rejects
generic `daemonCoreInvoker`, calls Rust with the canonical invocation plus
thread/agent route context, and returns the Rust `governed_receipt.rs`
admission protocol envelope as-is. The deleted command-protocol source plus conformance source scans keep
`admit_worker_service_package_invocation` absent as a daemon-core command operation, so
the old command-envelope path cannot be selected for this migrated family.

This removes JS envelope truth for the receipt-bearing worker/service package
path: package admission, router admission, receipt binding, accepted receipt
append, Agentgres admission, projection records, receipt refs, artifact refs,
payload refs, authority grant refs, source, and backend truth must arrive from
Rust daemon-core output or remain absent at the JS edge. It is still not
terminal because richer package projection/replay records, deeper Agentgres
receipt/state-root binding, stable Workbench/CLI/SDK package admission read APIs, and
other route-family command transports remain non-terminal.

Slice 1201 retires the temporary binary-spawn fallback for the daemon workspace
restore runner. `runtime-workspace-restore-runner.mjs` no longer imports the
shared JS daemon-core command invoker, no longer exposes or reads a live
`WORKSPACE_RESTORE_COMMAND_ENV`, and no longer accepts constructor command
selection or spawn hooks. Workspace restore apply-policy planning,
preview/apply operation planning, and snapshot capture now require the
daemon-level `daemonCoreInvoker` direct Rust-core seam and fail closed when it
is absent. `IOI_RUNTIME_DAEMON_CORE_COMMAND` and retired
`IOI_WORKSPACE_RESTORE_COMMAND` values are treated only as forbidden command
selection input for this surface, not as fallback transport.

This makes workspace snapshot/restore planning direct-invoker-only at the
daemon runner: policy decisions, restore operations, snapshot capture file
records, receipt refs, and artifact refs must arrive from Rust daemon-core
output or remain absent at the JS edge. It is still not terminal because the
JS product facade remains fail-closed scaffolding until direct Rust daemon-core
workspace snapshot/restore APIs own admission, artifact/payload refs,
Agentgres expected-head/state-root binding, projection, and replay end to end.
Resume by cutting the remaining command-transport runners, then delete the
shared JS command invoker once every live surface has a direct Rust daemon-core
API.

Slice 1202 retired the temporary binary-spawn fallback for daemon runtime
Agentgres admission. The follow-on Agentgres API cut retires the generic
`daemonCoreInvoker` seam for this family as well: `runtimeAgentgresAdmissionCore`
now requires typed `daemonCoreAgentgresApi` methods, rejects command/env/spawn
selection plus generic invoker options, and the migrated Agentgres operation
names are absent from Rust `CommandOperation`, `DAEMON_CORE_OPERATIONS`, and
`command_dispatch.rs`. Storage admission, expected-head/state-root derivation,
transition hashes, materialization/write-set/persistence/commit hashes, written
records, ArtifactRefs, PayloadRefs, receipt refs, and evidence refs must arrive
from Rust daemon-core Agentgres protocol output or remain absent at the JS edge.
Thread persistence remains a JS caller/cache facade around those Rust APIs, and
model_mount/context/StepModule still carry temporary command or invoker
transport.

Recent direct-invoker macro cut:
model_mount, context-policy/state-update, and StepModule surfaces still use
direct-invoker-only or mounted core scaffolding at the daemon layer. Runtime
Agentgres admission has since moved off the generic direct invoker to typed
`daemonCoreAgentgresApi` methods, approval-state and coding-tool approval moved
to typed `daemonCoreApprovalApi` methods, and workspace restore moved to typed
`daemonCoreWorkspaceRestoreApi` methods. The migrated surfaces no longer import
the shared JS daemon-core command invoker, accept constructor command selection,
accept constructor args, or treat `IOI_RUNTIME_DAEMON_CORE_COMMAND`,
`IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`, or surface-specific command envs as
fallback transport. The shared
`runtime-daemon-core-command-runner.mjs` helper and its test are deleted and
must not be recreated.

This macro cut also retires the coding-tool approval-satisfaction JS gate. The
mounted coding-tool governance surface no longer exports
`codingToolApprovalSatisfaction()`, no longer reads approval request events,
approval decision event streams, or lease-state helpers, and the daemon
composition no longer injects the approval lease, approval reason, or manifest
match helpers into that surface. Approval-required coding-tool execution now
asks the Rust daemon-core `planCodingToolApprovalSatisfaction` approval API
method before entering the StepModule path. Only a Rust satisfied record can carry the
approval id, decision event, receipt refs, and policy-decision refs into the
execution context; otherwise the path calls the Rust daemon-core
`planCodingToolApprovalBlock` approval API method and returns the Rust-shaped blocked
coding-tool result/event envelope. The stale JS `latestApprovalRequestEvent()`
readback facade and `blockCodingToolForApproval()` approval-block facade are
retired and must not be recreated.

This is a positive Rust approval-satisfaction and approval-block API cut, but
not terminal approval migration. Coding-tool result-event admission is now a
positive Rust daemon-core API: `admit_coding_tool_result_event` admits successful,
failed, and approval-blocked coding-tool result events with Agentgres storage
admission, receipt refs, expected heads, state roots, payload refs, and projection
watermarks before the JS daemon registers the Rust-returned event for replay.
The JS result-event admission hook is deleted, and approval-block persistence now
routes through the same Rust admission boundary.

Normal coding-tool result envelope/context planning is now a positive Rust
daemon-core API. The invocation surface calls `plan_coding_tool_result_envelope`
before workload dispatch for the StepModule context and again after workload
observation for the result `payload_summary` and runtime-event candidate before
Agentgres admission. The JS surface forwards canonical request/result facts,
validates the Rust plan, and fails closed before runner execution if the Rust
planner is absent; JS-authored StepModule context, source-event kind selection,
payload-summary construction, and candidate result-event truth are retired for
the migrated normal path.

Command-stream persistence is now a positive Rust daemon-core API too:
`admit_coding_tool_command_stream_events` owns canonical stream request
evaluation, stdout/stderr chunking, command-stream event materialization,
Agentgres storage admission, receipt refs, expected heads, state-root chaining,
payload refs, and projection watermarks before the JS daemon registers the
Rust-returned stream events for replay. The old JS command-stream append facade
is deleted and must not be recreated.

Coding-tool StepModule invocation construction is Rust-owned for migrated live
tools. `run_coding_tool_step_module` now accepts canonical coding-tool request
facts; Rust daemon-core owns the migrated tool contract table, input hashing,
invocation id generation, authority/custody/backend fields, workload dispatch
request construction, StepModuleRouter admission, receipt binding, Agentgres
admission, and projection record creation. The JS runner no longer imports the
coding-tool StepModule ABI builder or passes a JS-created `StepModuleInvocation`
into the command. A supplied coding-tool invocation envelope fails closed with
`js_step_module_invocation_retired`.

Patch workspace snapshot capture is now a Rust-owned hot-path follow-up for
`file.apply_patch`. Rust `workspace_restore.rs` emits canonical
`snapshot_record`, `snapshot_artifact`, and `snapshot_event` output with
snapshot ids, hashes, trigger context, receipt refs, artifact refs, restore
metadata, payload summary, and runtime-event admission identity. The daemon
workspace-snapshot surface consumes that output through the mounted
`workspaceRestoreCore`, commits only the Rust-authored snapshot artifact
through Rust Agentgres artifact-state admission, admits only the Rust-authored
snapshot event through Rust Agentgres runtime-event admission, and the
coding-tool invocation surface no longer calls JS snapshot-event authorship or
completes a successful `file.apply_patch` result when the Rust snapshot
record/artifact/event is missing.

Coding-tool workload observation field ownership is now canonical at the Rust
source for the migrated hot path. `coding_tool_workspace.rs` emits snake_case
observations for workspace status, git diff, file inspect, file patch, test run,
and LSP diagnostics, including nested patch changed-file/snapshot drafts and
diagnostics project context. The runtime-daemon Rust-live result wrapper strips
retired camelCase observation keys recursively instead of translating them, and
the coding-tool result summaries/output contracts read only canonical Rust
result fields. Post-edit diagnostics consumes `file.apply_patch.changed_files`
only; retired `changedFiles`/`beforeHash`/`diagnosticsRecommended` patch result
aliases no longer trigger diagnostics repair context construction.

Post-edit diagnostics feedback planning is now a positive Rust daemon-core API.
`plan_post_edit_diagnostics_feedback` owns diagnostics mode normalization,
changed-path selection, repair-policy normalization, workspace snapshot and
rollback refs, auto diagnostics `tool_call_id`, diagnostics rollback repair
context authoring, and the `lsp.diagnostics` request envelope. The JS
diagnostics-feedback surface fails closed without that Rust planner and only
forwards the Rust-authored request to the mounted coding-tool invocation
surface.

Public workspace snapshot and restore read/control APIs are now Rust-owned at
the typed daemon-core workspace restore API boundary.
`projectWorkspaceSnapshotList`, `projectWorkspaceSnapshotContentPackage`,
`previewWorkspaceSnapshotRestore`, and `applyWorkspaceSnapshotRestore` are
typed `daemonCoreWorkspaceRestoreApi` methods backed by Rust
`workspace_restore.rs`; the daemon workspace-snapshot surface calls the mounted
`workspaceRestoreCore` for list/content-package and restore preview/apply
instead of deriving projection truth from JS runtime events or
`codingArtifacts`. Restore preview/apply responses now also carry
Rust-authored restore artifact records and restore runtime-event records; the
JS facade commits only those Rust artifact records through Rust Agentgres
artifact-state admission and admits only those Rust events through Rust
Agentgres runtime-event admission before public restore truth returns.

Public approval request, decision, and revoke controls are now positive Rust
authority calls instead of fail-closed JS facades. The daemon approval surface
uses mounted `approvalStateCore` for all three public control operations and
commits only the Rust-authored run/agent projection through the Agentgres-gated
state persistence hooks. State-update planning now sends runtime `state_dir`;
Rust replays the target run/agent from admitted Agentgres projections, can
resolve the latest run without JS supplying a run id, and rejects retired
`run`/`agent` candidate transport before public control truth can return. The
approval-state JS runner facade, command/env fallback, response normalizer, JS
approval request/decision readback, JS target lookup, runtime-event append, and
camelCase request aliases stay retired.

Public approval request authority is now Rust-issued before request state
planning. Rust `approval.rs` exposes `authorize_approval_request`; the public
request surface calls the typed approval API first, requires a Rust
request-authority record with authority receipt refs and authority hash, and
the Rust request state planner fails closed without that binding before any
Agentgres-gated JS commit can persist. The old one-call request state-update
shape is no longer terminally valid, and `authorize_approval_request` remains
retired from command transport.

Public approval decision/revoke authority is now wallet.network-bound at the
typed Rust daemon-core approval API boundary. Rust `approval.rs` exposes
`authorize_approval_decision`; the public decision/revoke surface calls the typed
approval API before state planning, and every decision outcome now requires a
typed `wallet_approval_grant` artifact. Rust verifies the grant structure,
derives the canonical approval grant artifact hash/ref, emits those bindings in
the authority record/hash, and ignores caller-supplied approval grant-ref strings
for approve, reject, and revoke. The Rust decision/revoke state planners fail
closed without that authority binding before any Agentgres-gated JS commit can
persist. The JS surface no longer treats caller-provided `receipt_refs` or
`authority_grant_refs` as approval authority truth; it forwards only the Rust
authority receipts/hash/grant bindings into the state update. Broader
wallet.network grant issuance and
consumption semantics, approval authority projection/replay, and stable direct
Rust approval protocol/API bindings remain non-terminal beyond the thin JS
protocol-client scaffolding.

Public approval queue/read projection is now Rust-owned at the daemon-core
approval API boundary. Rust `approval.rs` exposes `project_approval_queue`, derives
pending/resolved approval queue records by replaying admitted `agents/*.json`
and `runs/*.json` Agentgres projections from runtime `state_dir`, filters
resolved records unless explicitly requested, rejects JS-supplied
`agent`/`run`/`runs` queue candidate transport, and emits canonical snake_case
request, decision, lease, receipt, and policy refs. The daemon approval surface
exposes `listThreadApprovals()` only as a thin protocol client that forwards
`thread_id`, `include_resolved`, optional heads, and `state_dir`, and
`GET /v1/threads/:thread_id/approvals` now returns the Rust projection instead
of resurrecting JS approval event/readback helpers or candidate collectors.

Slice 1206 retires the approval-state runner facade. The daemon store now
mounts `approvalStateCore` directly; `runtime-approval-state-runner.mjs` and its
tests are deleted, `index.mjs` no longer reads command/env fallback for
approval-state, and the public approval surface consumes the mounted core for
request, decision, revoke, and queue projection. The core builds only canonical
Rust daemon-core approval API requests, requires typed `daemonCoreApprovalApi`,
rejects generic `daemonCoreInvoker` plus retired aliases/options, validates only
the Rust `operation_kind`, and returns the Rust `approval.rs` envelope
without JS synthesis of source, backend, queue counts, authority refs, or state
defaults. Conformance now requires the core mount and the old runner paths to
stay absent, and also requires queue reads to replay via `state_dir` instead of
JS `agent`/`run`/`runs` candidates.

Slice 1207 retires the runtime Agentgres admission runner facade. The daemon
store now mounts `runtimeAgentgresAdmissionCore` directly over typed
`daemonCoreAgentgresApi` methods;
`runtime-agentgres-admission-runner.mjs` and its tests are deleted, command/env
fallback and spawn hooks are gone, and runtime event admission, projection,
replay, thread/turn projection, storage-write admission, and runtime
run/agent/memory/subagent/artifact/model_mount state commits all call the
mounted core. The core sends typed Rust daemon-core Agentgres API requests,
rejects retired compatibility options including generic `daemonCoreInvoker`,
and returns Rust `agentgres_admission.rs`, `agentgres_protocol.rs`,
`runtime_thread_event.rs`, and `coding_tool_event.rs` envelopes without JS
normalization or fallback truth synthesis. Conformance now requires the core
mount, typed API wiring, Rust-envelope passthrough, retired command operations,
and old runner paths to stay absent.

Slice 1208 retires the workspace restore runner facade. The daemon store now
mounts `workspaceRestoreCore` directly; `runtime-workspace-restore-runner.mjs`
and its tests are deleted, command/env fallback and spawn hooks are gone, and
workspace restore apply-policy planning, preview/apply operation planning,
snapshot capture, snapshot list/content-package projection, and restore
preview/apply all call the mounted core. The core builds canonical Rust
daemon-core workspace restore protocol requests, requires typed
`daemonCoreWorkspaceRestoreApi`, rejects generic `daemonCoreInvoker` plus
retired compatibility options and request aliases, and returns Rust
`workspace_restore.rs` envelopes without JS normalization or fallback truth
synthesis. The old Rust workspace restore command operations are retired. The
workspace-snapshot surface now requires Rust `projection`, `restore_preview`,
and `restore_apply` envelopes before committing/admitting artifact or
runtime-event truth. Conformance now requires the core mount, Rust-envelope
passthrough, and old runner paths to stay absent.

Slice 1209 retires the coding-tool approval runner facade. The daemon store now
mounts `codingToolApprovalCore` directly; `runtime-coding-tool-approval-runner.mjs`
and its tests are deleted, command/env fallback and spawn hooks are gone, and
approval manifest planning, approval satisfaction projection, approval
satisfaction planning, and approval block planning all call the mounted core.
The core builds canonical Rust daemon-core approval API requests, requires typed
`daemonCoreApprovalApi`, rejects generic `daemonCoreInvoker` plus retired
compatibility options and request aliases, and returns Rust `approval.rs`
envelopes without JS normalization or fallback truth synthesis. The old Rust
approval command operations are retired. The coding-tool approval policy remains
a Rust-client adapter over that core, while the JS event/lease satisfaction gate,
manifest matcher, and approval-block facade stay retired. Conformance now
requires the core mount, Rust-envelope passthrough, and old runner paths to stay
absent.

Slice 1210 retires the model_mount admission runner facade. `ModelMountingState`
now mounts `modelMountCore` directly; `model-mount-admission-runner.mjs` and its
tests are deleted, the daemon store/service pass only `modelMountCore`, and the
old command/env factory path is gone. Route decision, invocation admission,
provider execution, provider invocation/stream execution, lifecycle/inventory,
instance lifecycle, provider-result admission, artifact-endpoint planning,
storage control, route-control planning, conversation/stream planning, MCP workflow planning, server-control planning, runtime-engine planning, runtime-survey planning, catalog-provider control planning, provider control planning, capability-token control planning, vault control planning, receipt-gate planning, accepted-receipt head/transition planning, and invocation receipt-binding now call typed
`daemonCoreModelMountApi` methods instead of command envelopes. Rust rejects the
retired command operations, dispatch arms, and bridge request/response wrappers
for that family. Backend process/lifecycle and projection
helpers still enter Rust through remaining migration transport. Read-projection now calls
`daemonCoreModelMountApi.planModelMountReadProjection`, backed by
`RuntimeKernelService::plan_model_mount_read_projection`; the old
read-projection command operation, dispatch arm, bridge wrapper, backend/source
marker, and JS command-envelope builder are retired. Catalog-provider control,
provider control,
capability-token control, vault control, and receipt-gate planning now call typed
`daemonCoreModelMountApi` methods backed by Rust `RuntimeKernelService`; the
old command operations, dispatch arms, bridge wrappers, backend markers, and JS
command-envelope builders are retired. The core requires typed
`daemonCoreModelMountApi` for migrated model_mount APIs, rejects retired
`command`, `args`, `env`, and `daemonCoreInvoker` compatibility options, stores
no generic direct-invoker shim, and keeps Rust-owned receipt refs, evidence refs,
process fields, inventory fields, expected heads, binding records, and
projection evidence absent instead of synthesizing JS fallback truth. The old JS
in-flight model invocation coalescing map is also deleted;
migrated invocation calls stay on the Rust provider path instead of minting a JS
`model_invocation_coalesced` receipt. Conformance now requires the old runner
paths and symbols to stay absent, typed API calls to omit `operation`/`backend`,
and the retired command transport to stay rejected.

Slice 1211 moves MCP external-exit wallet, cTEE custody, and containment
authority into Rust daemon-core
planning for the two live migration edges that still sit before actual MCP
transport execution. `plan_mcp_control_agent_state_update` now rejects
`mcp_invoke` and `mcp_live_discovery` without canonical wallet grant refs and
authority receipt refs, cTEE custody refs, and transport containment refs, binds
`wallet.network.mcp_external_exit`, the refs, and an authority hash into the
Rust control record, and marks custody/containment requirements instead of
letting JS mint or default them. The
model_mount `plan_model_mount_mcp_workflow` path applies the same wallet gate to
MCP tool invocation and workflow-node execution before Rust-authored workflow
records can be committed. Conformance now requires the no-authority negative
paths, no-custody/no-containment negative paths, and snake_case protocol
forwarding to remain in place. Live external MCP transport execution and
discovery, broader runtime containment sandboxing, and stable protocol APIs
remain non-terminal.

Slice 1212 retires the remaining JS-authored MCP manager catalog record
builders. `mcp-manager.mjs` no longer exports `normalizeMcpServerRecord()`,
`mcpToolsForServers()`, `mcpResourcesForServers()`, `mcpPromptsForServers()`,
or the JS tool/resource/prompt materializers. The JS manager only reads raw
inline/workspace/global config sources, forwards canonical
`mcp_json.mcp_servers` plus source path/scope/compatibility metadata to Rust
`project_mcp_server_validation_input`, and returns server/tool/resource/prompt
rows from Rust `plan_mcp_manager_catalog_projection`. Agent creation,
agent-scoped MCP status, and catalog projection pass the mounted Rust policy
core into that registry path, so the deleted JS builders cannot be recovered as
a no-invoker fallback. Rust `McpServerValidationInputCore` now owns source
metadata projection for MCP config files and rejects retired camelCase
source/config aliases before public server records can return. This is still
non-terminal because actual Rust MCP transport execution, runtime containment
sandboxing for live backends, command transport, and stable APIs remain open.

Slice 1213 retires the MCP workflow execution `rust_required` placeholder for
the migrated model-mount MCP tool and workflow-node hot paths. Rust
`plan_model_mount_mcp_workflow` now returns admitted execution contracts:
`model_mount.mcp_tool.invoke` emits `transport_execution_status:
"rust_admitted"` with content receipt refs and StepModuleRouter owner while
omitting the retired no-JS/no-command/no-binary-bridge/no-compatibility fallback
proof fields entirely, and
`model_mount.workflow_node.execute` emits the matching `execution_status:
"rust_admitted"` StepModule dispatch contract. The Rust authority hash binds
the transport containment ref alongside wallet grant refs, authority receipt
refs, and cTEE custody refs. The JS model-mount core rejects stale
`rust_required` and fallback-proof MCP workflow execution responses instead of
normalizing them into public truth. Slice 1382 supersedes the tool-invocation
side of this blocker by requiring Rust MCP live backend execution before
model_mount MCP tool truth can commit; live external MCP discovery, runtime
containment for external backends, direct protocol APIs, and command-transport
retirement remain open elsewhere.

Slice 1214 binds the migrated model-mount MCP execution hot paths to
Rust-authored execution/content receipts instead of leaving result truth implied
by the admitted control record. Rust `plan_model_mount_mcp_workflow` now returns
an `ioi.model_mount.mcp_workflow_receipt.v1` receipt for MCP tool invocation and
workflow-node execution, with `rust_daemon_core_receipt_author:
"model_mount.mcp_workflow"`, the workflow/authority hashes, cTEE custody and
transport containment refs, Agentgres operation refs, state roots, and
StepModuleRouter result binding. The JS model-mount state path now requires
`persistRustAuthoredReceiptWithCommit()` for those execution receipts and fails
closed when the Rust receipt or receipt-state commit is absent; store guards
reject direct JS MCP execution receipt appends without the Rust content receipt
and Agentgres/state-root binding. Slice 1238 extends this receipt path with
Rust-materialized protocol result payload hashes and makes the old pending
materialization state fail closed.

Slice 1215 binds runtime MCP live invoke/discovery exits to Rust-authored
runtime receipt-state commits. Rust `plan_mcp_control_agent_state_update` now
returns an `ioi.runtime.mcp-live-exit-receipt.v1` receipt for `mcp_invoke` and
`mcp_live_discovery`, with `rust_daemon_core_receipt_author:
"runtime.mcp_control"`, wallet authority refs, cTEE custody refs, transport
containment refs, before/after agent-state roots, Agentgres operation refs, and
resulting-head binding. The Rust planner adds the receipt id to the returned
agent projection's canonical `receipt_refs`, and the JS MCP control surface now
requires `commitRuntimeReceiptState()` before `writeAgent()` can persist the
live-exit projection. Missing Rust receipt, invalid receipt binding, missing
receipt-state committer, or receipt-state commit without `commit_hash` fails
closed before public live-exit truth can return. The new generic
`commit_runtime_receipt_state` daemon-core operation persists runtime receipts
under `receipts/*.json` through Rust Agentgres storage admission, so JS cannot
substitute direct JSON writes or a model-mount receipt path. This remains
non-terminal until the Rust MCP transport backend materializes real contained
tool/discovery result payloads and Rust replay/projection exposes those payloads
through stable protocol APIs without temporary command transport.

Slice 1216 binds runtime MCP live invoke/discovery exits to Rust-authored
live-result state commits. Rust `plan_mcp_control_agent_state_update` now
returns an `ioi.runtime.mcp-live-result.v1` result record for `mcp_invoke` and
`mcp_live_discovery`, with `rust_daemon_core_result_author:
"runtime.mcp_control"`, the live-exit receipt id, Agentgres operation refs,
before/after agent-state roots, resulting-head binding, and no retired
JS/command/binary-bridge/compatibility fallback proof fields. The Rust
planner adds the result id to the returned agent projection's canonical
`result_refs`, and the JS MCP control surface now requires
`commitRuntimeMcpLiveResultState()` after `commitRuntimeReceiptState()` and
before `writeAgent()` can persist the live-exit projection. Missing Rust result
record, invalid result/receipt/state-root binding, missing result-state
committer, or result-state commit without `commit_hash` fails closed before
public live-exit truth can return. The new
`commit_runtime_mcp_live_result_state` daemon-core operation persists runtime
MCP live-result records under `mcp-live-results/*.json` through Rust Agentgres
storage admission, so JS cannot substitute a live transport result projection.
This intermediate blocker is superseded by the later Rust live backend executor
cuts; remaining runtime MCP work is containment hardening for live backends and
stable protocol APIs that replay/project those Rust records without temporary
command transport.

Slice 1217 binds runtime MCP live-result public return to Rust-owned
Agentgres replay/projection. Rust `McpLiveResultReplayCore` and
`project_mcp_live_result_replay` now read committed runtime MCP live-result
records from `mcp-live-results/*.json` under runtime `state_dir`, filter only
canonical `ioi.runtime.mcp-live-result.v1` records with
`rust_daemon_core_result_author: "runtime.mcp_control"`, required
Agentgres/live-result evidence refs, and no retired JS/command/binary-bridge/
compatibility fallback proof fields, then return
`ioi.runtime.mcp-live-result-replay.v1` with `latest_result`
and a replay hash. The JS MCP control surface now calls
`projectMcpLiveResultReplay()` after `commitRuntimeReceiptState()` and
`commitRuntimeMcpLiveResultState()` and before `writeAgent()`, validates the
replayed result against the Rust receipt/control/state-root binding, and returns
that replayed result instead of the planner's direct `record.result`. Missing
state dir, missing replay API, invalid replay projection, JS-authored result
candidate, or uncommitted result id fails closed before public live-exit truth or
agent truth can return. This remains non-terminal until actual external Rust MCP
backend invocation and discovery execute inside the contained runtime, command
transport is retired for this hot path, and stable Workbench/CLI/SDK protocol APIs
consume the Rust replay records directly.

Slice 1218 moves public MCP tool search/fetch projection into Rust daemon-core.
Rust `McpToolSearchProjectionCore` / `McpToolFetchProjectionCore` and
`project_mcp_tool_search_projection` / `project_mcp_tool_fetch_projection` now
derive query/tool/server filtering, stable ordering, catalog summaries,
pagination, fetch `not_found`/`completed` status, routes, and evidence from
Rust `McpManagerCatalogProjectionCore` and
`McpManagerCatalogSummaryProjectionCore`. The runtime MCP catalog surface now
sends canonical `query`, `tool_id`, `server_id`, `thread_id`, `agent_id`,
`state_dir`, and `live_discovery` to Rust, and no longer imports or calls JS
`mcpToolMatchesQuery`, `mcpToolIdentityMatches`, `mcpToolKey`,
`resolveMcpServerRecord`, or `mcpLiveExecutionModeForServer` for public
search/fetch truth. JS maps Rust `not_found` to the route error only. This
remains non-terminal because actual MCP transport execution, payload
materialization, command transport retirement, and stable Workbench/CLI/SDK protocol
APIs over Rust projection/replay records still need deeper Rust ownership.

Slice 1219 retires the model_mount accepted-receipt and invocation
receipt-binding command transport. `ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountAcceptedReceiptHead`,
`planModelMountAcceptedReceiptTransition`, and
`bindModelMountInvocationReceipt` without `operation` or `backend` fields;
Rust `RuntimeKernelService` exposes the matching direct methods over
`model_mount_receipt.rs`; and command-protocol source absence keeps the retired
`plan_model_mount_accepted_receipt_head`,
`plan_model_mount_accepted_receipt_transition`, and
`bind_model_mount_invocation_receipt` operations. The JS normalizers preserve
Rust daemon-core sources instead of synthesizing command/backend truth, and
conformance now guards the old bridge request/response wrappers, dispatch arms,
source/backend markers, command-envelope builders, and direct-invoker fallback
from returning.

Slice 1220 retires the model_mount tokenizer and required-control command
transport. `ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountTokenizerRequired`,
`planModelMountRouteControlRequired`, and `planModelMountTokenizer` without
command-envelope `operation` or `backend` fields; Rust
`RuntimeKernelService` exposes
`plan_model_mount_tokenizer_required`,
`plan_model_mount_route_control_required`, and
`plan_model_mount_tokenizer`; and command-protocol source absence keeps the retired
`plan_model_mount_tokenizer_required`,
`plan_model_mount_route_control_required`, and
`plan_model_mount_tokenizer` operations. The JS normalizers preserve Rust
daemon-core sources instead of synthesizing tokenizer or required-control
command/backend truth, and conformance now guards the old bridge request/response
wrappers, dispatch arms, source/backend markers, command-envelope builders, and
direct-invoker fallback from returning.

Slice 1221 retires the model_mount conversation/stream command transport.
`ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountConversationState`,
`planModelMountStreamCompletion`, and `planModelMountStreamCancel` without
command-envelope `operation` or `backend` fields; Rust
`RuntimeKernelService` exposes
`plan_model_mount_conversation_state`,
`plan_model_mount_stream_completion`, and `plan_model_mount_stream_cancel`;
and command-protocol source absence keeps the retired
`plan_model_mount_conversation_state`,
`plan_model_mount_stream_completion`, and
`plan_model_mount_stream_cancel` operations. The JS normalizers preserve Rust
daemon-core sources instead of synthesizing conversation/stream command/backend
truth, and conformance guards the old bridge request/response wrappers,
dispatch arms, source/backend markers, command-envelope builders, and
direct-invoker fallback from returning.

Slice 1222 retires the model_mount backend-process/backend-lifecycle planning
command transport. `ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountBackendProcess` and
`planModelMountBackendLifecycle` without command-envelope `operation` or
`backend` fields; Rust `RuntimeKernelService` exposes
`plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle`; and command-protocol source absence keeps
the retired `plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle` operations. The Rust direct API responses
preserve daemon-core sources instead of command/backend markers, JS normalizers
no longer synthesize backend truth, and conformance guards the old bridge
request/response wrappers, dispatch arms, source/backend markers,
command-envelope builders, and direct-invoker fallback from returning. This is
not terminal backend execution ownership: actual process supervision/transport
execution, live external backend process-state supervision, and stable
SDK/IDE/CLI backend APIs remain open.

Coding-tool approval satisfaction projection is now Rust-owned. The daemon
approval core exposes `project_coding_tool_approval_satisfaction`; Rust
`approval.rs` derives the approval request, latest decision or revoke, lease
state, expected head, and state root by replaying admitted `agents/*.json` and
`runs/*.json` projections from runtime `state_dir` before
`plan_coding_tool_approval_satisfaction` evaluates the manifest. The optional
JS store projection callback, projection-context helper, `run`/`agent`
candidate transport, and exported JS manifest matcher are retired, so
approval-required coding-tool execution can no longer recover a parallel JS
truth path for request/decision/lease matching.

Coding-tool budget-block governance is now a positive Rust daemon-core path
instead of a fail-closed JS facade. Rust `policy/context_lifecycle.rs` exposes
`plan_coding_tool_budget_block`, emits the blocked coding-tool result/event
envelope with canonical budget status, policy refs, receipt refs, and
snake_case fields, and the invocation hot path admits that blocked event
through Rust `admit_coding_tool_result_event` before returning the public
policy error. The JS governance surface only forwards canonical request facts
to the Rust planner, strips retired budget-policy aliases, and remains
fail-closed when the planner is absent; it no longer owns budget-block event or
response-truth construction.

Public thread runtime-control state updates are now a positive Rust
daemon-core path. The public mode/model/thinking and generic runtime-control
facades call Rust `plan_thread_control_agent_state_update`, pass canonical
agent/control/event-sequence/model-route facts, require Rust-owned receipt refs,
and persist only the Rust-authored agent projection through the
Agentgres-backed `writeAgent` commit path. The direct JS runtime-control event
append facade remains retired, and model route selection remains a separate
model_mount authority dependency before the Rust thread-control plan is
accepted.

Public run cancellation is now a positive Rust daemon-core path. The run-cancel
surface calls Rust `plan_run_cancel_state_update`, requires the returned
`run.cancel` projection to be canceled and complete with terminal job/run
events, runtime task/job/checklist records, receipts, and artifacts, then
persists only that Rust-authored run through the Agentgres-backed `writeRun`
commit path. Missing planners still fail closed through the Rust
admission-required envelope, and JS run-map mutation plus JS runtime
task/job/checklist, event, receipt, and artifact materialization remain retired.

Public task/job cancellation is now a positive Rust daemon-core path. The
task/job control surface calls Rust `plan_runtime_task_job_cancel_state_update`,
derives only the canonical run id from `task_`/`job_` public ids in JS, requires
the returned `task.cancel` or `job.cancel` projection to match the requested
public id and include canceled task/job/checklist plus run records, terminal
events, receipts, and artifacts, then persists only that Rust-authored run
through the Agentgres-backed `writeRun` commit path. The old `cancelRun`
shortcut, public-id fallback, and JS task/job/checklist/event/receipt/artifact
materialization paths remain retired.

Public task creation now composes through the store-owned Rust run-create
lifecycle and Rust task replay projection instead of a duplicate task-create
planner. The task/job API requires canonical `agent_id`, requires the Rust
task/job projector before calling `createRun`, calls the store-owned
`createRun()` path so `RunCreateStateUpdateCore` authors the run plus
runtimeTask/runtimeJob/runtimeChecklist materialization, then returns only the
Rust `project_runtime_task_job_projection` `task.get` replay record. The
dedicated `plan_runtime_task_job_create_state_update` direct API, JS
`planRuntimeTaskJobCreateStateUpdate()` wrapper, task-create schema constants,
and task-create normalizer are retired as duplicate create truth.

Public task/job read projection is now a positive Rust daemon-core path. The
task/job control surface calls Rust `project_runtime_task_job_projection` for
task/job list and get, JS only supplies runtime `state_dir` plus canonical
`agent_id`, `status`, `task_id`, or `job_id` request facts, and Rust replays
admitted `runs/*.json` Agentgres state before record construction, filtering,
and public-id selection. The task/job API no longer receives the JS runtime
task/job record builders or `runs` candidate transport, retired `agentId`
aliases stay ignored, and missing or mismatched Rust projections fail closed
instead of falling back to JS readback.

Generic runtime thread-event append is now a positive Rust daemon-core
Agentgres admission path. Runtime events call Rust `admit_runtime_thread_event`,
must carry receipt refs, expected heads, state roots, storage admission, payload
refs, and projection watermarks, and JS may only register the Rust-returned
event in its temporary local replay cache. Synthetic `thread.started` and
run-event projection now call Rust `project_runtime_thread_events`; Rust authors
the projection envelopes from canonical agent/run facts, rejects retired
projection aliases, skips known idempotency keys, admits each projected event
through the same Agentgres admission core, and returns only Rust-admitted events
for local replay registration. Public stream/turn replay readback now calls Rust
`project_runtime_thread_event_replay` with replay kind, cursor, latest seq, and
runtime `state_dir`; Rust reads admitted Agentgres `events/*.jsonl` records,
owns replay selection, canonical cursor evaluation, required Agentgres
admission refs, state/head/watermark projection, and the returned event set,
and rejects caller-supplied replay `events` transport. Public run replay enters
through `eventsForRun`, while the duplicate `replayFromCanonicalState` facade
and JS replay-candidate collector are retired. Public thread/turn projection
records now call Rust
`project_runtime_thread_turn_projection`; Rust owns public thread/turn record
shape, runtime identity fields, projection hashes, and event-derived seq/input/
output fields through typed
`daemonCoreAgentgresApi.projectRuntimeThreadTurnProjection`; JS now sends only
projection kind, thread/run/turn identity, event stream, schema, and runtime
`state_dir`, while Rust replays Agentgres `agents`, `runs`, event, memory, and
subagent records and rejects caller fact transport. Stable
Rust lifecycle projection protocol APIs remain non-terminal beyond that thin JS
protocol-client scaffolding.

This is still not terminal coding-tool migration. Coding-tool artifact draft
materialization now calls Rust `plan_runtime_coding_tool_artifact_drafts`,
receives Rust-authored artifact records, and commits them through Rust
Agentgres artifact-state admission before the daemon updates its temporary read
cache; the old JS artifact draft record materializer remains retired. Artifact
read/retrieve projection now calls Rust
`project_runtime_coding_tool_artifact_read` with runtime `state_dir`, so Rust
owns durable `artifacts/*.json` Agentgres replay, canonical coding-tool artifact
filtering, thread ownership checks, byte-range shaping, result metadata,
receipt refs, available-artifact projection, and retired `artifact_records`
candidate-transport rejection. JS still coordinates snapshot materialization,
diagnostics orchestration, runner transport, and projection adapters around
Rust-owned plans. Diagnostics projection/replay, temporary runner transport,
wallet.network grant issuance semantics, and authority projection/replay still
need direct Rust daemon-core ownership; approval lease authority is now
Rust-owned and no longer comes from a JS helper.

This is still not terminal migration. These runner, gate, coding-tool,
thread-control, run-cancel, task/job create/control/projection,
agent-lifecycle, and subagent propagated-cancel cuts remove command fallback
and duplicate JS truth paths, but many public JS facades still remain
fail-closed protocol scaffolding. Resume with a macro authority cut that
replaces one fail-closed facade family with a positive Rust daemon-core API and
then deletes or demotes the JS facade in the same reviewable move. Public
memory write/edit/delete/policy controls have moved to Rust-owned planning plus
Agentgres memory-state commits. Mutation controls now send runtime `state_dir`;
Rust replays admitted `memory-records/*.json` for edit/delete current-record
truth and `memory-policies/*.json` for policy current truth, and rejects
JS-supplied `current_record`/`current_policy` transport. Status/validation/direct
control-event append now uses Rust memory-control event planning plus Rust runtime-event
admission. Explicit public thread/agent memory list/policy/path/status/validation routes now send
only route-owned thread/agent context, filters, and runtime `state_dir` to Rust
`project_runtime_memory_projection`; Rust replays admitted
`memory-records/*.json` and `memory-policies/*.json`, filters active canonical
records, synthesizes effective policy/path/status/validation truth, and rejects
retired JS projection candidate transport before public read truth can return.
The top-level `/v1/memory*` context-query/body route family, daemon-store
`memoryProjectionForContext`/`memoryStatus`/`validateMemory` helpers, SDK global
`getMemoryStatus()`/`validateMemory()` clients, and their context-query input
types are retired; memory status/validation clients now enter through explicit
thread/agent daemon protocol routes over the Rust-owned projection/control
records.
The remaining memory blockers are wallet/policy authority, cTEE private-memory
custody, direct memory admission/storage APIs, richer durable replay/projection,
and stable Workbench memory APIs.
Public approval queue/read projection now sends runtime `state_dir`; Rust
replays admitted `agents/*.json` and `runs/*.json` Agentgres projections and
rejects JS `agent`/`run`/`runs` queue candidate transport before queue truth can
return. Public approval request/decision/revoke state updates now use the same
runtime `state_dir` replay source and reject JS `agent`/`run` candidate
transport before target truth can return; the public JS surface no longer reads
`agentForThread`, `getRun`, `listRuns`, or `runs.get` for approval control.
Coding-tool approval satisfaction projection also uses runtime `state_dir`
replay and rejects JS `agent`/`run` candidate transport before
request/decision/lease truth can return. The remaining approval blockers are
richer approval authority projection/replay storage, grant issuance
semantics, and stable protocol APIs.
Runtime MCP registry/control state has moved from the fail-closed JS mutation
facade into Rust-owned `plan_mcp_control_agent_state_update` planning plus
Agentgres-backed `writeAgent` commits. Import/add/remove/enable/disable,
status-record, validation, and direct control-event state paths now require a
Rust-authored control envelope, registry count/hash, and agent projection before
persistence; live MCP invoke/discovery exits now also require Rust-authored
`mcp_invoke` or `mcp_live_discovery` transport-admission controls with
canonical wallet grant refs, authority receipt refs,
`wallet.network.mcp_external_exit`, an authority hash, cTEE custody refs, and
transport containment refs plus Rust-authored
`ioi.runtime.mcp-live-exit-receipt.v1` receipts and
`ioi.runtime.mcp-live-result.v1` live-result records before Agentgres-backed
receipt, result, and agent commits. The JS surface only forwards canonical
request/server/tool/transport/authority facts plus `agent_id` and runtime
`state_dir`, then acts as the
`commitRuntimeReceiptState()`/`commitRuntimeMcpLiveResultState()`/
`projectMcpLiveResultReplay()`/`writeAgent()` adapter for Rust-authored
live-exit truth;
Rust replays the admitted `agents/*.json` projection before planning registry
or transport-admission state and rejects JS-supplied `agent` candidate
transport. MCP manager config-source projection is also Rust-authored:
`mcp-manager.mjs` only forwards raw canonical config inputs plus source
metadata to Rust validation-input and catalog-projection cores, while deleted
JS server/tool/resource/prompt builders cannot return as fallback truth. Public
MCP tool search/fetch now calls Rust
`projectMcpToolSearchProjection()`/`projectMcpToolFetchProjection()` for
query/tool/server filtering, stable ordering, catalog summaries, pagination,
and fetch `not_found`/`completed` status; JS only maps Rust `not_found` to the
route error. Direct registry mutation, JS agent lookup, event append,
`agents.set`, JS MCP transport execution, JS MCP catalog row/search/fetch
building, and old compatibility aliases stay retired. MCP serve `tools/call`
now requires Rust daemon-core
`plan_runtime_mcp_serve_tool_call` for request-envelope authorship before
routing allowed served coding-tool requests through the Rust-owned coding-tool
invocation surface, then requires Rust daemon-core
`project_runtime_mcp_serve_tool_result` to author the MCP result envelope,
`content`, `structuredContent`, canonical `event_id`, receipt/policy/artifact
refs, and `isError` state before JSON-RPC wrapping. JS no longer derives served
tool-call ids, idempotency keys, workflow ids, `mcp_serve_request`, result text,
event refs, or result error state; the old `mcpServeToolCallResult` helper is
retired and the path fails closed instead of preserving a JS envelope/result
facade. Slice 1236 moves MCP serve result public truth behind Rust-authored
Agentgres live-result replay: the Rust projector emits a materialized
`ioi.runtime.mcp-live-result.v1` record whose payload contains the protocol
result, whose details declare `runtime.mcp_serve` authorship, receipt binding,
StepModuleRouter/Rust coding-tool invocation ownership, and no retired
JS/command/binary-bridge/compatibility fallback proof fields. The MCP serve
adapter now refuses to invoke the tool unless `commitRuntimeMcpLiveResultState`,
runtime `stateDir`, and `projectMcpLiveResultReplay` are available, commits the
Rust live-result record under Agentgres, and returns only the replayed protocol
payload. Rust `McpLiveResultReplayCore` accepts `runtime.mcp_serve` as a Rust
author while still filtering JS-authored live-result candidates. The runtime MCP
control/catalog direct API cut then removes temporary
command transport for MCP control state-update, live-result replay, server
validation, validation-input projection, manager validation/status/catalog/
catalog-summary projection, and tool search/fetch projection:
`RuntimeContextPolicyCore` now requires typed `daemonCoreMcpApi` methods,
`mcp-manager.mjs` no longer passes a generic command invoker or
`daemonCoreApi.mcp` compatibility mount, `policy/mcp_memory.rs` no longer
exports MCP command-response wrappers or bridge request structs, and
command-protocol source absence keeps the retired MCP command operations out of
daemon-core transport. Slice 1224
then retires the MCP serve command transport: `RuntimeContextPolicyCore` calls
typed `daemonCoreMcpApi.planRuntimeMcpServeToolCall` and
`daemonCoreMcpApi.projectRuntimeMcpServeToolResult`, Rust
`RuntimeKernelService` exposes the matching positive methods, the old
`plan_runtime_mcp_serve_tool_call` and
`project_runtime_mcp_serve_tool_result` command operations, dispatch arms,
response wrappers, `RuntimeMcpServeCommandError`, command source markers, and JS
command-envelope fields are absent, and conformance requires command-protocol
rejection for both retired operations. Runtime containment sandboxing for live
backend discovery/serve flows, broader serve admission, and stable protocol APIs
over Rust replay records remain non-terminal.
Model-mount MCP workflow control has a matching typed Rust positive boundary:
`daemonCoreModelMountApi.planModelMountMcpWorkflow` now calls Rust
`RuntimeKernel::plan_model_mount_mcp_workflow` for import, ephemeral
registration, MCP tool invocation, and workflow-node execution record planning;
the old `plan_model_mount_mcp_workflow` command operation, dispatch arm, bridge
wrapper, command-envelope builder, and backend tag are retired. Tool invocation
and workflow-node execution external exits now require Rust-enforced wallet
grant refs, authority receipt refs, cTEE custody refs, and transport containment
refs before planning/commit, bind those refs to the workflow authority hash and
committed control details, and fail closed without JS no-authority, no-custody,
or no-containment compatibility. Tool invocation and workflow-node execution
also return admitted Rust execution/StepModule dispatch contracts instead of the
retired `rust_required` placeholder response, and the JS model-mount core fails
closed on stale placeholder or pending-materialization responses before public
truth can return. Those execution ops now also require Rust-authored MCP
execution/content receipts, materialized protocol result payload hashes, and Rust
Agentgres receipt-state commit before route truth returns, so JS cannot invent
the content receipt, StepModule result binding, or result envelope locally. Rust
`mcp_servers` read projection replays admitted `mcp-servers` records for public
server list readback. Slice 1382 adds the terminal MCP tool-invocation cut:
`invokeMcpTool()` now requires `contextPolicyCore.executeRuntimeMcpLiveBackend`
over the Rust `ioi.runtime.mcp-backend-execution.v1` contract, canonical
`thread_id` / `agent_id`, and `workload_spec` before model_mount record or
receipt truth can commit. Missing executor, missing backend contract, or missing
live result fails closed with no Agentgres model_mount record commit, and the
committed response carries `runtime_mcp_live_backend_rust_driver_executed`
evidence plus the Rust driver-result hash. The JS surface remains only a
canonical request client plus record/receipt-state commit adapter; JS MCP receipt
synthesis, server-map projection, route tests, receipt-gate dispatch, model
invocation, and plan-only tool-result success stay retired for this family while
live external MCP discovery, broader runtime containment sandboxing, and stable
protocol APIs remain the terminal blockers.
Workflow-edit proposal/apply controls have also moved to Rust-owned event
planning plus Rust runtime-event admission; the remaining workflow-edit blockers
are wallet approval authority, workflow mutation custody, durable
projection/replay, ArtifactRef/PayloadRef binding where needed, command-transport
retirement, and stable protocol APIs.
Diagnostics repair policy projection, decision execution, direct decision-event
append, and decision resolution have moved to Rust-owned projection/event
planning plus Rust runtime-event admission, and diagnostics operator override
execution now uses Rust state-update planning plus Rust Agentgres run-state
admission with Rust-derived operator override approval state instead of JS
verdict transport. Approval-required diagnostics operator overrides now also
require wallet.network grant and authority receipt refs in Rust, bind a
Rust-authored override authority hash into the operator control projection, and
reject retired JS authority transport; direct operator-override event append
uses the same Rust wallet authority gate before runtime-event admission.
Diagnostics repair retry-turn creation now uses Rust
`plan_runtime_diagnostics_repair_retry_run` for retry run-create request
authorship before Rust-owned run-create state update and Rust diagnostics repair
event planning/admission; direct retry-event append still uses Rust diagnostics
repair event planning/admission.
Diagnostics repair policy projection now replays admitted Agentgres runtime
events from runtime `state_dir` instead of accepting JS policy-input candidates.
The remaining diagnostics repair blockers are broader orchestration, durable
projection/replay, receipt/state-root binding,
and stable protocol APIs.
Run-level coding-tool budget recovery retry completion has moved from the
fail-closed JS control facade to Rust `plan_coding_tool_budget_recovery_state_update`
plus Agentgres-backed run-state commit, and budget recovery `request_approval`
and `approve_override` now move through Rust `plan_coding_tool_budget_recovery_control`.
The public route now accepts these controls only when Rust returns a complete
operator control and run projection; override issuance additionally requires
wallet.network grant and authority receipt refs and carries a Rust-authored
authority hash. The standalone JS budget-recovery policy/result helper and the
old admission-required command remain retired. This remains non-terminal because
retry-event materialization, durable replay/projection, command-transport
retirement, and stable SDK/IDE/CLI APIs still need direct Rust ownership.
Managed-session inspection/control has moved from a fail-closed public facade to
Rust daemon-core projection/control planning plus Rust-authored runtime-event
admission. Inspection now sends runtime `state_dir`, and Rust replays admitted
`events/*.jsonl` records instead of accepting JS projection candidates; control
now also sends runtime `state_dir`, Rust replays the selected current session,
and JS control candidates are rejected. The remaining managed-session blockers
are durable session record storage beyond runtime-event replay, wallet/cTEE
session authority, and stable protocol APIs.
Workspace-change inspection/control has moved from a fail-closed public facade
to Rust daemon-core projection/control planning plus Rust-authored runtime-event
admission. Inspection now sends runtime `state_dir`, and Rust replays admitted
`events/*.jsonl` records instead of accepting JS projection candidates; control
now also sends runtime `state_dir`, Rust replays the selected current change,
and JS control candidates are rejected. The remaining workspace-change blockers
are durable workspace-change record storage beyond runtime-event replay,
wallet/workspace rollback authority, and stable
protocol APIs.
Model-mount provider lifecycle has moved from fail-closed JS public
health/start/stop facades to Rust `plan_model_mount_provider_lifecycle` plus
Rust Agentgres model_mount record-state commit. Migrated local/fixture,
native-local, and hosted/custom metadata health/start/stop now receive
Rust-authored `model-provider-lifecycle-controls` records with lifecycle
hash/evidence, operation kind, and `model_mount.provider_lifecycle` boundary,
then require Rust Agentgres commit before returning public lifecycle truth. They
still avoid JS driver execution, lifecycle receipt creation, provider-map
mutation, projection writes, JS endpoint-map subject selection, and JS-hosted
transport execution; provider lifecycle health/start/stop now derive implicit
endpoint/model subjects from the Rust `endpoints` read-projection list instead
of `state.endpoints`, so map-only endpoint rows cannot become lifecycle request
truth before Rust planning; hosted/custom
records carry Rust-contained metadata transport contracts with
`rust_hosted_provider_metadata_transport_materialized`,
`ctee_hosted_provider_secret_not_exposed`, and
`wallet_network_provider_transport_authority_bound` evidence while omitting
retired JS/command/binary-bridge/compatibility fallback proof fields. Public
provider-health list/latest projections now replay admitted
`model-provider-lifecycle-controls/*.json` records in Rust and ignore stale
`provider_health` receipts or JS telemetry inputs. This remains non-terminal
because live external hosted API/model payload execution, deeper
receipt/state-root binding, and stable protocol APIs remain open.
Public model artifact import and endpoint mount/unmount have moved from the
fail-closed artifact/endpoint JS facade to typed
`daemonCoreModelMountApi.planModelMountArtifactEndpoint`, backed by Rust
`RuntimeKernelService::plan_model_mount_artifact_endpoint`, plus Rust
Agentgres model_mount record-state commit. `importModel()`, `mountEndpoint()`,
and `unmountEndpoint()` now receive Rust-authored `model-artifacts` or
`model-endpoints` records with artifact/endpoint hashes, authority hashes,
wallet/cTEE boundary facts, and Agentgres artifact/endpoint truth evidence, then
require Rust commit before returning public truth. The old
`plan_model_mount_artifact_endpoint` command operation, command-dispatch arm,
bridge request/response wrapper, backend marker, and JS command-envelope builder
are retired. They no longer preserve JS artifact/endpoint map mutation, JS
lifecycle receipt synthesis, `writeMap("model-artifacts")`,
`writeMap("model-endpoints")`, local materialization, or no-commit planner
success as compatibility paths. This has since advanced on the read side: public
`listArtifacts()` and `listEndpoints()` now call Rust read-projection kinds over
runtime `state_dir`; Rust replays admitted `model-artifacts/*.json` and
`model-endpoints/*.json` artifact-endpoint records, merges them with
provider-inventory and route endpoint-resolution materializations, applies Rust
unmount records as endpoint removal, and filters JS-authored artifact/endpoint
truth. Hosted/provider endpoint materialization is now Rust-projected from
provider inventory; deeper receipt/state-root binding and stable protocol APIs
still need direct Rust ownership before the family is terminal.
Public model storage and catalog/download mutations have moved from fail-closed
JS facades to typed `daemonCoreModelMountApi.planModelMountStorageControl`,
backed by Rust `RuntimeKernel::plan_model_mount_storage_control`, plus Rust
Agentgres model_mount record-state commit. `catalogImportUrl()`,
`downloadModel()`, `cancelDownload()`, `deleteModelArtifact()`, and
`cleanupModelStorage()` now receive Rust-authored `model-catalog-imports`,
`model-downloads`, or `model-storage-controls` records with storage/download
evidence, authority hashes, wallet/cTEE boundary facts, and Agentgres truth
evidence, then require Rust commit before returning public truth. They no longer
preserve the storage-control command-envelope builder/operation, bridge response
wrapper, `daemonCoreApi` compatibility mount, JS catalog/download/storage
lifecycle receipts, JS download/artifact map mutation, `writeMap()` storage
truth, fixture/live network materialization, filesystem mutation, or no-commit
planner success as compatibility paths. `storageSummary()`, `listDownloads()`,
and `downloadStatus()` now call Rust model_mount read projection over runtime
`state_dir`, replay admitted storage-control records from `model-catalog-imports`,
`model-downloads`, and `model-storage-controls`, and filter out JS-authored
storage/download truth. Delete/cleanup filesystem custody now travels through
the same Rust storage-control boundary with contained path verification, hashed
root/target evidence, Rust mutation status, and no plaintext path custody by
the JS facade. Richer catalog/download materialization and stable protocol APIs
remain non-terminal.
Public provider inventory for migrated fixture/local-folder, native-local, and
hosted metadata providers has moved from fail-closed JS list facades to the Rust
`plan_model_mount_provider_inventory` planner. `listProviderModels()` and
`listProviderLoaded()` now require Rust inventory hash/evidence/action/status
envelopes, receive Rust-authored `model-provider-inventory` records, and commit
only those records through Rust Agentgres model_mount record-state admission
before inventory truth can return. Hosted/nonlocal provider inventory uses the
Rust `rust_model_mount_hosted_provider_inventory` backend, records canonical
provider metadata/item refs from the Rust-owned hosted catalog executor, carries
a live hosted catalog transport contract with request/response hashes, endpoint
hashes, cTEE no-plaintext custody evidence, wallet.network transport authority
evidence, and no retired JS/command/binary-bridge/compatibility fallback proof
fields, and still avoids JS driver/network execution. `providerInventoryRecords()` now
calls Rust read-projection kind `provider_inventory_records` with runtime
`state_dir`; Rust replays persisted `model-provider-inventory/*.json` Agentgres
records and filters public truth to Rust-authored provider inventory records.
Migrated provider inventory no longer uses JS driver execution, JS inventory
receipts, local artifact/instance fallback reads, artifact or instance map
mutation, or no-commit planner success.
Public model-mount server-control start/stop/restart/write, operation
recording, and log append have moved from the fail-closed required-record facade
to typed `daemonCoreModelMountApi.planModelMountServerControl`, backed by Rust
`RuntimeKernel::plan_model_mount_server_control`, plus Rust Agentgres
model_mount record-state admission. The old
`plan_model_mount_server_control` command operation, command-dispatch arm,
bridge request/response wrapper, backend marker, and JS command-envelope builder
are retired and guarded by conformance. Migrated server-control mutation methods
receive Rust-authored `model-server-controls` records, commit only those
records, and return Rust public responses with JS state writes, JS log writes,
and JS transport execution marked false. Dedicated `serverStatus()` now calls
Rust read-projection kind `server_status` with empty JS request state plus
runtime `state_dir`; Rust replays admitted `model-server-controls/*.json`,
filters JS-authored server controls, and materializes server status, last
operation, last receipt, topology counts, and backend-state counts from
Rust-owned records. `serverLogs()`, `serverEvents()`, and `serverLogRecords()`
now call Rust read-projection kinds `server_logs`, `server_events`, and
`server_log_records` with canonical `server_log_query` plus runtime `state_dir`;
Rust replays admitted `model-server-controls/*.json`, filters JS-authored
controls and retired read-as-mutation `logs_read`/`events_read`/`log_projection`
records, and returns redacted log/event projections without committing
server-control truth for reads. This remains non-terminal because actual
process supervision, transport execution, and stable server-control protocol
APIs still need direct Rust ownership.
Provider-inventory topology, catalog, and endpoint materialization now replays
that same admitted Agentgres truth in Rust. `listArtifacts()`,
`listProductArtifacts()`, `listProviders()`, `listEndpoints()`,
`runtimeModelCatalogList()`, and `openAiModelList()` call Rust read-projection
kinds with runtime `state_dir`; Rust filters out JS-authored inventory,
materializes Rust fixture/native-local provider/artifact/runtime-catalog/OpenAI
records, materializes hosted/provider endpoint projections from Rust-admitted
`model-provider-inventory` records, and carries hosted catalog transport hashes,
endpoint-url binding evidence, and cTEE no-plaintext facts into endpoint
projection. The dedicated JS request state stays empty so JS topology maps cannot
return as provider, catalog, artifact, or endpoint truth.
Public catalog search now consumes that Rust-owned inventory truth through Rust
read-projection kind `catalog_search`. `catalogSearch()` sends only canonical
query facts plus runtime `state_dir`; Rust replays admitted
`model-provider-inventory/*.json` `list_models` records, filters out JS-authored
inventory and loaded-instance inventory, and returns Rust-authored catalog
search entries bound to provider-inventory record ids and inventory hashes before
JS provider-port iteration, JS result aggregation, entry enrichment, or
`lastCatalogSearch` writes can return.
Public `catalogStatus()` now consumes the same Rust-owned inventory truth
through Rust read-projection kind `catalog_status`. `catalogStatus()` sends an
empty request state plus runtime `state_dir`; Rust replays admitted
`model-provider-inventory/*.json` records, filters out JS-authored inventory,
and returns catalog provider status, storage status, last-search summary, and
result rows with catalog-status evidence. JS `catalog_status_input`, provider
port iteration, storage summarization, `lastCatalogSearch` readback, and status
aggregation stay retired.
Live external hosted catalog API execution for provider inventory is now
Rust-owned: hosted `list_models` requires a canonical endpoint, executes the
catalog request in Rust, and binds request/response hashes before Agentgres
record-state commit. Remaining hosted materialization work is cTEE
secret-injection depth and richer
replay/protocol coverage; the public hosted inventory facade no longer fails
closed, returns the retired hosted-transport-not-executed marker, or returns
through JS driver execution. Public
provider upsert now moves through Rust daemon-core
`plan_model_mount_provider_control`: the mounted daemon facade sends canonical
provider facts, never resolves vault material, receives a Rust-authored
`model-providers` record with provider-control and authority hashes,
wallet.network/cTEE no-plaintext custody facts, and Agentgres provider-control
truth evidence, then commits only that record through Rust Agentgres
model_mount record-state admission before returning public provider truth. The
old fail-closed provider-upsert JS facade, provider-map mutation,
`writeMap("model-providers")`, JS vault resolution, plaintext material
readback, and no-commit success remain retired. Provider-control replay for
provider lookup now lives in the Rust `providers` read-projection kind: Rust
replays admitted `model-providers/*.json` records, filters JS-authored provider
truth, and the mounted provider accessor consumes that projection instead of
`state.providers` map truth. Hosted/provider transports and stable
direct Rust/Agentgres APIs remain non-terminal.
Public `listInstances()` now calls Rust read-projection kind
`instances` with runtime `state_dir`; Rust replays persisted
`model-instances/*.json` Agentgres records, filters to Rust-authored
instance-lifecycle records with lifecycle hashes and Agentgres registry
evidence, and keeps JS instance maps out of public-list request truth. Public
`listRoutes()` now calls Rust read-projection kind `routes` with runtime
`state_dir`; Rust replays persisted `model-routes/*.json` Agentgres records,
filters to Rust-authored route-control records with route-control evidence and
receipt refs, and keeps JS route maps out of public-list request truth. This is
still non-terminal until hosted provider transports, richer hosted catalog
materialization, deeper Agentgres receipt/state-root binding beyond record-state
commit, and stable protocol APIs are Rust-owned.
Public model route write/test has moved from the fail-closed route-control JS
facade to typed `daemonCoreModelMountApi.planModelMountRouteControl`, backed by
Rust `RuntimeKernelService::plan_model_mount_route_control`, plus Rust Agentgres
model_mount record-state commits. Mounted route-selection and explicit-model
endpoint resolution now use the same positive Rust route-control planner,
commit only Rust-authored route-selection or endpoint-resolution records, and route
selection reuses Rust model_mount route-decision admission plus the
Rust-authored accepted route-selection receipt before JS sees a selected
endpoint. Public route write/test no longer repopulates `state.routes` or sends
JS route-map `current_route` candidates into Rust; mounted route-selection now
feeds Rust candidate routes, endpoints, and providers from the Rust
read-projection list APIs instead of `this.routes`, `state.endpoints`, or
`state.providers` maps. Runtime explicit/run-override model-route selection now forwards
canonical runtime model-route requests through that Rust-owned route-control
client and returns only the Rust-authored route decision, receipt, and
route-control refs. Public `listRoutes()` now replays persisted
`model-routes/*.json` Agentgres records through Rust read-projection kind
`routes` and emits only Rust-authored route-control records; JS route maps stay
out of the dedicated request state. Public `modelRouteDecisions()` now replays
persisted `model-route-selections/*.json` Agentgres records through Rust
read-projection kind `model_route_decisions`, filters to Rust-authored
route-selection records with route-control evidence and accepted-receipt
binding, and keeps JS receipt arrays out of route-decision request truth.
Public `modelRouteEndpointResolutions()` now replays
`model-route-endpoint-resolutions/*.json` records through Rust
`model_route_endpoint_resolutions` and filters endpoint-resolution truth to
Rust-authored route-control records. Invocation route selection, deeper
wallet/cTEE route authority policy, and direct stable protocol APIs remain
non-terminal.
The old `plan_model_mount_route_control` command operation, Rust dispatch arm,
bridge response wrapper, backend marker, and JS command-envelope builder are
retired for these route-control hot paths; conformance now guards the typed API
and the retired command transport.
Public `listEndpoints()` now replays the same admitted
`model-route-endpoint-resolutions/*.json` Agentgres records through Rust
read-projection kind `endpoints`, materializes canonical endpoint records with
snake_case endpoint fields, filters out JS-authored endpoint-resolution records,
and keeps JS endpoint maps out of public-list request truth.
Public `listInstances()` now calls Rust read-projection kind `instances` with runtime
`state_dir`, replays persisted `model-instances/*.json` Agentgres records,
and emits only Rust-authored instance lifecycle records with lifecycle hashes
and Agentgres registry evidence. The dedicated instance-list request state
remains empty, so JS instance maps cannot return as public topology truth.
deeper receipt/state-root binding, hosted/provider transports, richer hosted
catalog materialization, stable route/instance APIs, and stable protocol APIs
remain required.
The mounted model_mount topology accessors now consume those Rust read
projections on the daemon hot path: `endpoint()`, `route()`, `instance()`,
`getModel()`, provider-direct mount lookup, model-id endpoint resolution, and
loaded-instance reuse call the Rust-owned `endpoints`, `routes`, `instances`,
and `artifacts` projection lists instead of reading JS topology maps as
accepted truth. Map-only endpoint, route, instance, or artifact cache rows now
fail not-found at the accessor boundary, while provider-direct artifact
creation still fails closed before JS mutation and load fallback enters the
Rust-planned mount/load surfaces.
Loaded-instance maintenance selection now follows the same boundary: idle
eviction, duplicate coalescing, and explicit supersede enumerate Rust
`instances` projection rows, enrich missing endpoint/provider facts from Rust
`endpoints` and `providers` projections, and leave map-only JS instance,
endpoint, or provider cache rows unable to trigger or shape lifecycle planning.
Public catalog-provider configuration, private runtime material, and OAuth
control now move through Rust daemon-core `plan_model_mount_catalog_provider_control`.
`listCatalogProviderConfigs()`, `getCatalogProviderConfig()`,
`configureCatalogProvider()`, `catalogProviderConfig()`,
`catalogProviderRuntimeMaterial()`, and OAuth start/callback/exchange/refresh/
revoke each receive a Rust-authored catalog-provider-control record, commit it
through Agentgres model_mount record-state admission, and return the committed
Rust response envelope. JS no longer executes OAuth credential helpers, resolves
catalog-provider vault refs, reads config/runtime-material maps as accepted
truth, writes OAuth/session/provider maps, or returns plaintext catalog-provider
material for those public control edges. Auth-header materialization, richer
hosted catalog transport, and stable protocol APIs remain required; the
catalog-provider-control command transport is retired.
Public model conversation-state writes and native stream-completion
finalization now move through Rust daemon-core model_mount planners.
`recordConversationState()` calls typed
`daemonCoreModelMountApi.planModelMountConversationState`, backed by
`RuntimeKernelService::plan_model_mount_conversation_state`, and commits only
the Rust-authored `model-conversations` record through Rust Agentgres
record-state admission before updating the local continuation cache.
`recordModelStreamCompleted()` calls typed
`daemonCoreModelMountApi.planModelMountStreamCompletion`, backed by
`RuntimeKernelService::plan_model_mount_stream_completion`, commits only the
Rust-authored conversation record, and persists only the Rust-authored
`model_invocation_stream_completed` receipt carrying
receipt_binder, accepted-receipt append, StepModule result, Agentgres
operation/state-root/resulting-head bindings, and conversation/stream hashes.
JS conversation record synthesis, JS stream-completion receipt synthesis, JS
receipt-binding construction, direct
`state.receipt("model_invocation_stream_completed")`, and
`writeMap("model-conversations")` remain retired. Public
`listConversations()` now calls Rust read-projection kind
`model_conversation_states` with the runtime `state_dir`; Rust replays
persisted `model-conversations/*.json` Agentgres records and emits only
Rust-authored model conversation records carrying conversation hashes, Rust
conversation/stream evidence, and Agentgres conversation-truth evidence. The
old fail-closed JS list facade and public-list `conversation_states` request
input are deleted. Slice 1221 later retired conversation/stream command
transport by moving conversation-state, stream-completion, and stream-cancel
planning to typed `daemonCoreModelMountApi` methods backed by
`RuntimeKernelService`. This remains non-terminal because live hosted stream
completion/finalization materialization, deeper wallet/cTEE conversation
authority, and stable Workbench/CLI/SDK APIs still need direct Rust ownership.

Model-mount route-decision admission now uses the typed Rust daemon-core
`daemonCoreModelMountApi.admitModelMountRouteDecision` surface instead of the
generic command-envelope transport. The deleted command-protocol source plus
conformance source scans keep the old `admit_model_mount_route_decision`
command operation absent, `command_dispatch.rs` has
no route-decision arm, and the route-decision bridge request/response helper is
deleted from `model_mount/admission.rs`. The mounted JS model-mount core fails
closed without the typed API and no longer sends `operation` or `backend` fields
for route-decision admission. This retires the route-decision command transport
cut only; later model_mount typed API cuts also retired command transport for
invocation admission, provider-execution admission, provider invocation/stream
execution, provider lifecycle/inventory, instance lifecycle, provider-result
admission, backend-process planning, backend-lifecycle planning,
artifact-endpoint planning, storage control, route-control planning, MCP
workflow planning, server-control planning, read-projection planning, and
conversation/stream planning. Remaining model_mount projection migration,
hosted/provider transport, hosted provider auth materialization, invocation
authority, and remaining non-OAuth cache scaffolding still need direct Rust
daemon-core protocol/API ownership; the read-projection, accepted-receipt,
invocation receipt-binding, tokenizer/required-control, conversation/stream,
backend-process, backend-lifecycle,
catalog-provider/provider/capability-token/vault/receipt-gate command
transports are retired.

Backend-process/backend-lifecycle planning also now uses typed
`daemonCoreModelMountApi.planModelMountBackendProcess` and
`planModelMountBackendLifecycle`, backed by Rust
`RuntimeKernelService::plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle`, and the old command operations, dispatch
arms, bridge request wrappers, command source/backend markers, and JS command
envelopes are retired.

Model-mount backend registry lookup now consumes Rust read-projection kind
`backends` through `ModelMountingState.backendRegistry()` and the internal
`backend()` accessor. The old JS backend-registry overlay export that merged
derived backend defaults, `state.backends`, and process snapshots is deleted, so
public APIs and internal process-planning preflight no longer have a duplicate
JS backend truth path. Slice 1266 additionally deletes the mounted
`deriveBackendRegistry()` and `seedBackends()` methods, removes the
`backendRegistryRecords()` JS default-record factory, and stops loading the
retired `model-backends` local map. This remains non-terminal because actual
backend process supervision/transport execution, richer backend process-state
materialization, stable SDK/IDE/CLI APIs still need direct Rust ownership.

Slice 1223 retires the admission-required command transport for workflow-edit,
diagnostics-repair, thread-turn, and lifecycle required-boundary refusals.
`RuntimeContextPolicyCore` now calls typed `daemonCoreRuntimeControlApi`
methods for workflow-edit and diagnostics-repair admission-required records and
typed `daemonCoreThreadLifecycleApi` methods for thread-turn and lifecycle
admission-required records. Rust `RuntimeKernelService` exposes positive direct
methods for the lifecycle admission-required planners, the old bridge request
structs and command-response wrappers are deleted, `command_dispatch.rs` has no
arms for the retired operations, and command-protocol source absence keeps
`plan_workflow_edit_admission_required`,
`plan_diagnostics_repair_admission_required`,
`plan_thread_turn_admission_required`, and
`plan_lifecycle_admission_required` absent as command operations. Conformance
now guards the typed API calls, direct Rust records, and retired command
operations so this family cannot return through JS authority, a command-env
fallback, or the binary bridge command path. This remains non-terminal only
because other route families, especially remaining MCP transport/materialization,
memory custody/replay, and model_mount materialization/protocol work, still need
direct Rust daemon-core ownership.

Slice 1224 retires the MCP serve `tools/call` command transport. MCP serve
planning and result projection now call typed `daemonCoreMcpApi` methods instead
of `evaluateRawPolicy`, backed by Rust
`RuntimeKernelService::plan_runtime_mcp_serve_tool_call` and
`RuntimeKernelService::project_runtime_mcp_serve_tool_result`.
Command-protocol source absence keeps `plan_runtime_mcp_serve_tool_call` and
`project_runtime_mcp_serve_tool_result` absent as command operations,
`command_dispatch.rs` is deleted, the Rust response wrappers and
`RuntimeMcpServeCommandError` are deleted, and JS no longer sends command
`operation`/`backend` envelopes or command-source markers for the MCP serve hot
path. Slice 1236 follows by committing and replaying the Rust-authored MCP serve
live-result record before JSON-RPC return. Conformance now guards the typed API,
direct Rust records, retired command transport, live-result commit/replay
boundary, and source-scan blockers. This remains non-terminal because actual
external Rust MCP transport execution, runtime containment for live backends,
and stable Workbench/CLI/SDK protocol APIs still need deeper Rust daemon-core
ownership.

Slice 1225 retires the public runtime projection family command transport for
skill/hook registry, repository workflow, runtime tool catalog, and runtime
lifecycle projections. `RuntimeContextPolicyCore` now calls typed
`daemonCoreRuntimeProjectionApi.projectSkillHookRegistry`,
`projectRepositoryWorkflow`, `projectRuntimeToolCatalog`, and
`projectRuntimeLifecycle` instead of the generic command-envelope
`evaluateRawPolicy` path. Rust `RuntimeKernelService` exposes the corresponding
direct projection methods, command-protocol source absence keeps the old
`project_skill_hook_registry`, `project_repository_workflow`,
`project_runtime_tool_catalog`, and `project_runtime_lifecycle` operations absent,
`command_dispatch.rs` is deleted, and the Rust command-response
wrappers/source markers are deleted. Conformance now guards the typed API,
direct Rust records, retired command operations, missing dispatch wrappers, and
source-scan blockers. The skill/hook projection contract no longer carries the
remaining command-shaped `operation` field: JS sends only `operation_kind`, Rust
serializes no `operation`, and the JS normalizer drops stale `operation` fields
instead of preserving a compatibility path. This remains non-terminal because
durable Rust storage/replay for catalog, repository workflow, lifecycle/run-read, and
doctor/readiness projections plus stable Workbench/CLI/SDK protocol APIs still need
deeper Rust daemon-core ownership.

Slice 1226 retires the runtime compositor/task-job command transport family.
Task/job create/cancel state planning, task/job read projection, workflow-edit
control, managed-session projection/control, workspace-change
projection/control, thread-fork control, conversation-artifact
projection/control, and subagent projection/control now enter Rust through typed
`daemonCoreRuntimeControlApi` or `daemonCoreRuntimeProjectionApi` methods backed
by `RuntimeKernelService` positive APIs. The old command operations,
`CommandOperation` variants, dispatch arms, command-response wrappers, command
source markers, and JS `operation`/`backend` command envelopes are retired for
these hot paths; `command_protocol.rs` proves the retired operation names are
unknown. Conformance now guards the typed APIs, direct Rust service methods,
retired command protocol entries, missing dispatch wrappers, source-scan
blockers, and absence of command-fallback source markers. This remained
non-terminal at that cut because coding-tool StepModule transport, deeper
durable replay/storage, MCP materialization, model_mount
backend/materialization work, and stable Workbench/CLI/SDK protocol APIs still needed
terminal Rust daemon-core ownership. Slice 1228 retires the StepModule transport
blocker.

Slice 1227 retires the coding-tool result/artifact and diagnostics-repair
command transport family. Coding-tool result envelope planning, coding-tool
artifact draft planning, coding-tool artifact read projection, post-edit
diagnostics feedback planning, diagnostics-repair control, diagnostics-repair
retry-run planning, diagnostics-repair decision projection, and diagnostics
rollback repair policy projection now enter Rust through typed
`daemonCoreRuntimeControlApi` or `daemonCoreRuntimeProjectionApi` methods backed
by direct `RuntimeKernelService` APIs. `RuntimeContextPolicyCore` rejects the
old generic `daemonCoreInvoker` option, no longer builds command envelopes for
these hot paths, and sends no command `operation`/`backend` transport fields.
Rust command-protocol source-absence conformance now keeps the retired
coding/artifact/diagnostics operation names absent; at that historical cut Rust
still retained the temporary
`run_coding_tool_step_module` operation at that cut, and `command_dispatch.rs`
had no dispatch arms or response-wrapper error conversions for the retired
coding/artifact/diagnostics operations. The Rust bridge request/response
wrappers and command-source markers for this family were deleted, while
conformance guarded the typed APIs, direct Rust service methods, retired
operation catalog, missing dispatch wrappers, missing command response helpers,
and source-scan blockers. Slice 1228 retires the remaining StepModule command
transport.

Slice 1228 retires the coding-tool StepModule command transport. At that cut
the runtime daemon passed `daemonCoreWorkloadApi` through the temporary
Rust-workload runner facade, and the facade called `runCodingToolStepModule`
with canonical `ioi.runtime.coding-tool-step-module-request.v1` facts instead
of a daemon-core command envelope. Constructor backend/command/argv selectors
and generic `daemonCoreInvoker` failed closed, while retired backend/command env
selectors were absent from the facade. Slice 1262 supersedes that scaffolding by
deleting the facade and having the coding-tool invocation surface call the typed
workload API directly. Rust `coding_tool_step_module.rs` exposes the direct
`CodingToolStepModuleRunRequest` with deny-unknown deserialization, while
`RuntimeKernelService::run_coding_tool_step_module` owns the positive API.
`command_protocol.rs` now has an empty `DAEMON_CORE_OPERATIONS` catalog. At that
cut, `command_dispatch.rs` had no StepModule dispatch arm and the old
`ioi-step-module-bridge` binary was only a fail-closed artifact; Slices 1233 and
1234 delete those artifacts instead of preserving them as terminal scaffolding.
The coding-tool invocation surface consumes `workload_result` rather than a
bridge result, and conformance guards the typed API path plus absence of the old
command operation, command response wrapper, binary fallback, and JS
command-envelope request builder. This remains non-terminal because durable
replay/storage, MCP runtime materialization, model_mount backend/materialization
work, richer protocol APIs, and IDE/CLI/SDK clients still need terminal
Rust-owned projection/replay records; the StepModule command transport itself is
retired.

Slice 1229 retires the model_mount generic daemon-core invoker shim. The
mounted `ModelMountCore` now rejects constructor `daemonCoreInvoker` as a
retired compatibility option, stores only `daemonCoreModelMountApi`, deletes
`invokeDaemonCore()`, and no longer exports the daemon-core command schema
marker from `model-mount-core.mjs`. `ModelMountingState` no longer forwards the
daemon-wide invoker into model_mount, and route-decision default source now
reports `rust_model_mount_api` instead of a command-transport marker.
Conformance guards the retired option, absence of generic invoker storage,
absence of the direct-invoker fallback error, absence of the command schema
marker, and the no-bridge/no-command-env source scan. This remains non-terminal
because live external backend binary spawning/supervision, hosted/provider transport,
hosted provider auth materialization, invocation authority, remaining
non-OAuth cache scaffolding, durable replay/storage, richer MCP runtime
materialization, and stable Workbench/CLI/SDK protocol APIs still need terminal
Rust-owned materialization and projection/replay records.

Slice 1230 retires the run-cancel command-shaped Rust owner wrappers. The
run-cancel policy child keeps only `RunCancelStateUpdateCore` and the internal
`RunCancelAdmissionRequiredCore` owner, while the direct public
`RuntimeKernelService` hot path uses the positive state-update planner;
`RunCancelCommandError`, `RunCancel*BridgeRequest`,
`plan_run_cancel_*_response`, and `rust_run_cancel_*_command` source markers
are deleted. `RuntimeContextPolicyCore` normalizes run-cancel state updates as
`rust_run_cancel_state_update_api`, and conformance fails if the old command
wrappers, bridge request types, command source markers, or JS
`planRunCancelAdmissionRequired` direct API return. This remains non-terminal
because wallet/operator authority, cancellation
replay/projection storage, direct lifecycle protocol APIs, durable
replay/storage, and stable Workbench/CLI/SDK protocol APIs still need terminal
Rust-owned records.

Slice 1231 retires the remaining runtime-control command-shaped Rust owner
wrapper cluster for coding-tool budget recovery and operator control. The
budget-recovery child now exposes only `CodingToolBudgetRecoveryStateUpdateCore`
and `CodingToolBudgetRecoveryControlCore`, while the operator-control child keeps
only `DiagnosticsOperatorOverrideStateUpdateCore`,
`OperatorTurnControlAdmissionRequiredCore`, `OperatorInterruptStateUpdateCore`,
and `OperatorSteerStateUpdateCore` plus the direct `RuntimeKernelService`
methods. `CodingToolBudgetRecoveryCommandError`,
`CodingToolBudgetRecovery*BridgeRequest`, `OperatorControlCommandError`,
`*Operator*BridgeRequest`, `plan_coding_tool_budget_recovery_*_response`,
`plan_diagnostics_operator_override_state_update_response`,
`plan_operator_*_response`, and the `rust_*_command` source markers are
deleted. `RuntimeContextPolicyCore` now normalizes these migrated
runtime-control responses as `_api` sources, and conformance fails if the old
command wrappers, bridge request types, command-source markers, or bridge-shaped
Rust owner tests return. This remains non-terminal because durable
runtime-control replay/projection, richer wallet/runtime-control authority,
deeper receipt/state-root binding, and stable Workbench/CLI/SDK protocol APIs still
need terminal Rust-owned records.

Slice 1232 removes the remaining StepModule command-env selector surface from
the temporary JS Rust-workload runner. `createStepModuleRunnerFromEnv()` no
longer read `IOI_STEP_MODULE_BACKEND`, `IOI_STEP_MODULE_COMMAND`,
`IOI_STEP_MODULE_COMMAND_ARGS`, `IOI_RUNTIME_DAEMON_CORE_COMMAND`, or
`IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`; it read only workload transport handles
(`IOI_WORKLOAD_GRPC_ADDR` and `IOI_SHMEM_ID`) before constructing
`RustWorkloadStepModuleRunner`. Slice 1262 then deletes that runner facade and
moves the workload transport handles to the daemon composition boundary. Command
env compatibility is deleted rather than preserved as a runtime selector, and
conformance now requires the retired runner files to stay absent. This remains
non-terminal because durable replay/storage, MCP/model_mount materialization,
and stable Workbench/CLI/SDK protocol APIs still need terminal Rust-owned
projection/replay records.

Slice 1233 deletes the retired `ioi-step-module-bridge` binary and tombstone
module. `crates/node/src/bin/ioi-step-module-bridge.rs` and
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` are absent; the old bridge
can no longer return a fail-closed command-transport response, be selected as a
binary fallback, or preserve a root module where command wrappers could be
reintroduced. Conformance now requires the old `ioi-step-module-bridge` binary
and `ioi_step_module_bridge/mod.rs` tombstone are absent while still proving the
retired command operation, command response wrapper, binary fallback, and JS
command-envelope request builder cannot return. This remains non-terminal
because durable replay/storage, MCP/model_mount materialization, richer
Agentgres projection/replay records, and stable Workbench/CLI/SDK protocol APIs still
need terminal Rust-owned records, but the StepModule bridge artifact itself is
gone.

Slice 1234 deletes the remaining Rust service-kernel command-dispatch transport
module. `crates/services/src/agentic/runtime/kernel/command_dispatch.rs` is
absent, `crates/services/src/agentic/runtime/kernel/mod.rs` no longer exports
`command_dispatch`, and the retired stdin/JSON helpers
`run_daemon_core_command_response_from_stdin`,
`run_daemon_core_command_from_stdin`,
`run_daemon_core_command_from_json_str`,
`run_daemon_core_command_from_value`, `CommandTransportError`, and
`dispatch_command_operation_response` cannot return. The empty
`command_protocol.rs` catalog remains only as a retired-operation guard for
source and conformance, not as an executable transport. This remains
non-terminal because durable replay/storage, MCP/model_mount materialization,
richer Agentgres projection/replay records, and stable Workbench/CLI/SDK protocol APIs
still need terminal Rust-owned records, but the command-dispatch process
transport is gone.

Slice 1235 retires the daemon-wide generic `daemonCoreInvoker` pass-through.
`packages/runtime-daemon/src/service/runtime-daemon-service.mjs` now rejects a
top-level `daemonCoreInvoker` option before constructing the store,
`AgentgresRuntimeStateStore` also fails closed if the stale option is supplied
directly, and `createCodingToolApprovalPolicy()` constructs its default core
from typed `daemonCoreApprovalApi` instead of forwarding
`deps.daemonCoreInvoker`. Conformance now forbids the live daemon surfaces from
storing or forwarding `daemonCoreInvoker: options.daemonCoreInvoker`,
`this.daemonCoreInvoker = options.daemonCoreInvoker`, or
`daemonCoreInvoker: deps.daemonCoreInvoker` while preserving direct core-level
negative tests that retired compatibility options fail closed. This remains
non-terminal because remaining `rust_core_required` route edges still need
positive Rust materialization/projection APIs, but the daemon-wide generic
invoker handle can no longer be used as split-brain fallback scaffolding.

Slice 1236 binds MCP serve `tools/call` public result truth to Rust-authored
Agentgres live-result replay. Rust `runtime_mcp_serve.rs` now requires coding
tool receipt refs, emits materialized `ioi.runtime.mcp-live-result.v1` records
with protocol payload hashes, `runtime.mcp_serve` authorship, StepModuleRouter
ownership, and no retired JS/command/binary-bridge/compatibility fallback proof fields, and
`policy/mcp_memory.rs` replays `runtime.mcp_serve` live results while still
filtering JS-authored candidates. `runtime-mcp-serve-api.mjs` now fails
closed without `commitRuntimeMcpLiveResultState`, runtime `stateDir`, or
`projectMcpLiveResultReplay`, commits the Rust live-result record, and returns
only the replayed protocol payload. This remains non-terminal because external
MCP transport execution, runtime containment sandboxing for live backends, and
stable SDK/IDE protocol APIs still need terminal Rust-owned records.

Slice 1237 hard-cuts hosted provider lifecycle/inventory metadata transport out
of the old refusal-marker compatibility lane. Rust provider lifecycle and
inventory planners now emit contained hosted metadata transport contracts with
`rust_materialized` execution status, cTEE no-plaintext custody checks,
wallet.network transport-authority evidence, and no retired JS/command/
binary-bridge/compatibility fallback proof fields. Public JS protocol adapters
must preserve and validate those Rust-authored contracts, and they now reject the
retired `hosted_provider_transport_not_executed` evidence marker before hosted
provider lifecycle or inventory truth can return. This remains non-terminal
because live external hosted API/model payload execution, richer hosted catalog
materialization, deeper receipt/state-root binding, and stable SDK/IDE provider
protocol APIs still need terminal Rust-owned records.

Slice 1238 hard-cuts model_mount MCP workflow execution out of the admitted-but-
pending result lane. Rust `plan_model_mount_mcp_workflow` now materializes
deterministic protocol result payloads for MCP tool invocation and workflow-node
execution, binds their `result_payload_hash` into the control details,
`ioi.model_mount.mcp_workflow_receipt.v1` receipt, and StepModuleRouter result,
and marks `model_mount_mcp_result_materialized: true` with
`rust_materialized` status. The JS model-mount core and mounted state path now
reject stale pending-materialization plans before public truth can return, and
receipt-write guards reject direct MCP execution receipt appends without the
Rust materialized result binding. Slice 1382 supersedes the MCP tool-invocation
transport blocker by requiring the Rust live backend executor before model_mount
tool truth can commit; live MCP discovery, broader runtime containment
sandboxing, and stable Workbench/CLI/SDK protocol APIs still need terminal Rust-owned
records.

Slice 1382 hard-cuts model_mount MCP tool invocation through the Rust MCP live
backend executor. Rust `plan_model_mount_mcp_workflow` now requires canonical
`thread_id`, `agent_id`, and `workload_spec` for `model_mount.mcp_tool.invoke`,
emits an `ioi.runtime.mcp-backend-execution.v1` contract bound to
`ioi_drivers::mcp::McpManager` / `McpTransport`, and provides a planned
`ioi.runtime.mcp-live-result.v1` result object for the backend executor. The
mounted daemon model_mount path receives `contextPolicyCore` from daemon startup
and calls `executeRuntimeMcpLiveBackend()` before model_mount record-state commit
or MCP execution receipt-state commit. If the executor, backend contract,
workload spec, Rust-authored content receipt, live result payload, or Rust driver
hash is missing, no model_mount MCP tool truth commits. Successful tool
invocation binds `runtime_mcp_live_backend_rust_driver_executed`,
`runtime_mcp_live_backend_actual_mcp_manager_io`, and
`runtime_mcp_live_backend_no_js_transport` evidence into the public response,
record details, and receipt, stamps `transport_execution_status:
"rust_driver_executed"`, and carries the Rust driver-result hash into
`result_payload_hash`, the StepModule result binding, and receipt details. The
old plan-only deterministic MCP tool payload remains admissible planning data
only; it cannot be terminal public truth or a compatibility fallback.

Slice 1267 hard-deletes the model_mount MCP workflow fallback-proof protocol
shape. Rust `plan_model_mount_mcp_workflow` no longer serializes
`js_registry_mutation`, `js_receipt_gate_dispatch`,
`js_transport_invocation`, `js_route_test`, `js_model_invocation`,
`js_mcp_tool_invocation`, `js_result_synthesis`,
`command_transport_fallback`, `binary_bridge_fallback`,
`compatibility_fallback`, or `legacy_js_result_fallback` as false-valued proof
fields on MCP server, MCP tool, workflow-node, or materialized result payload
contracts.
The JS model-mount core treats those keys as retired compatibility fields and
fails closed if they reappear in the public response, record details, or
receipt/result payloads. Conformance now requires the MCP workflow Rust source
to stay free of those false-valued fallback fields and requires the JS negative
guard that rejects stale fallback-proof responses.

Slice 1268 hard-deletes the hosted provider lifecycle/inventory fallback-proof
protocol shape for migrated model_mount provider metadata transport contracts.
Rust `plan_model_mount_provider_lifecycle` and
`plan_model_mount_provider_inventory` no longer serialize
`js_transport_invocation`, `command_transport_fallback`,
`binary_bridge_fallback`, or `compatibility_fallback` as false-valued proof
fields on provider lifecycle, provider inventory, or nested transport-contract
records. The mounted JS provider boundary treats those keys as retired
compatibility fields and fails closed if they reappear in the normalized result,
Rust record, public response, or transport contract. Conformance now scans the
model_mount Rust/JS production source for the retired false-valued provider
transport fields and requires focused provider lifecycle/inventory negative
tests.

Slice 1269 hard-deletes the runtime MCP live/serve fallback-proof protocol shape
for migrated MCP live-result, backend-execution, receipt, and served-tool result
records. Rust `mcp_control_backend_execution_contract`,
`mcp_control_live_exit_receipt`, `mcp_control_live_exit_result`,
`project_runtime_mcp_serve_tool_result`, Agentgres MCP live-result fixtures, and
`RuntimeAgentService::execute_runtime_mcp_live_backend()` no longer serialize
`js_backend_execution`, `js_transport_invocation`,
`command_transport_fallback`, `binary_bridge_fallback`, or
`compatibility_fallback` as false-valued proof fields. Rust replay/backend
validation and the JS MCP control/serve protocol clients treat those keys as
retired compatibility fields and fail closed if they reappear in receipt
details, result details, backend-execution payloads, or served live-result
details. Conformance now scans the runtime MCP Rust/JS production source for
retired false-valued MCP fallback fields and requires focused MCP control/serve
negative tests.

Slice 1239 hard-cuts runtime MCP control live invoke/discovery exits out of the
admitted-but-pending transport-result lane. Rust
`plan_mcp_control_agent_state_update` now materializes deterministic
`ioi.runtime.mcp-live-result-payload.v1` protocol payloads for `mcp_invoke` and
`mcp_live_discovery`, hashes the payload, binds that hash through the live-exit
receipt, control record, `ioi.runtime.mcp-live-result.v1` Agentgres result
record, and replay projection, and stamps the result as `rust_materialized`.
Rust replay now rejects MCP control live-result records that still carry the
retired pending backend evidence, and the JS MCP control surface rejects
`admitted_pending_rust_transport` / `runtime_mcp_transport_backend_pending`
records before result-state commit or public truth can return. This remains
non-terminal because runtime containment sandboxing for live backends and stable
IDE/CLI/SDK protocol APIs still need terminal Rust-owned records.

Slice 1240 hard-cuts runtime MCP catalog live-discovery out of the deferred
projection lane. Rust `McpToolSearchProjectionCore` now marks live catalog
search summaries as `rust_mcp_live_discovery_materialized`, emits
`runtime_mcp_live_discovery_rust_materialized` evidence, keeps the retired
`rust_mcp_live_discovery_deferred` field false, and returns completed,
non-deferred catalog summaries for declared Rust-projected server rows. The JS
catalog surface and context-policy adapter preserve the Rust materialized field
as protocol output, while conformance rejects the old deferred-live-discovery
surface name and marker from the success path. This remains non-terminal because
runtime containment sandboxing for live backends and stable Workbench/CLI/SDK protocol
APIs still need terminal Rust-owned records.

Slice 1241 hard-cuts runtime MCP control live results out of the generic
Rust-shaped backend-materialization lane. Rust `mcp_control_live_exit_result`
now requires every MCP-control live invoke/discovery result payload to carry an
`ioi.runtime.mcp-backend-execution.v1` `backend_execution` contract bound to
`ioi_drivers::mcp::McpManager` and
`ioi_drivers::mcp::transport::McpTransport`, with `tools/call` for invoke,
`tools/list` for discovery, custody/containment refs, Agentgres refs, and no
retired JS/command/binary-bridge/compatibility fallback proof fields. The
live-exit receipt and result details now carry
`runtime_mcp_backend_execution_rust_driver_bound` evidence and
`rust_driver_contract_bound` backend status, Rust replay filters MCP-control
live results that lack the driver-bound contract, and the JS MCP control surface
rejects missing backend contracts before receipt/result commit or public replay
can return. This remains non-terminal because the async daemon API still needs
to wire actual live MCP server process I/O through the Rust `McpManager`
backend under the recorded containment contract, then expose stable SDK/IDE/CLI
protocol APIs over those replay records.

Slice 1242 hard-cuts runtime MCP control live results out of the planner-direct
terminal-result lane. `RuntimeContextPolicyCore` now exposes the positive
`daemonCoreMcpApi.executeRuntimeMcpLiveBackend` request surface with
`ioi.runtime.mcp-live-backend-execution-request.v1`, and the MCP control
surface must call it before live-exit receipt/result state commits. The
committed live result must carry
`runtime_mcp_live_backend_rust_driver_executed` evidence plus
`rust_driver_executed` backend-execution observation details; if the backend
executor is absent or returns an unbound result, no receipt-state commit,
result-state commit, replay, or `writeAgent()` can run. Conformance now guards
the typed API, the backend execution -> receipt commit -> result commit ->
replay -> agent commit order, and the missing-executor failure. This remains
non-terminal because the new API
boundary still needs to be wired to actual live MCP server process I/O through
Rust `McpManager` under runtime containment, then exposed through stable
SDK/IDE/CLI protocol APIs over Rust replay records.

Slice 1243 wires that required MCP live-backend API to real Rust MCP process
I/O. `RuntimeAgentService::execute_runtime_mcp_live_backend()` now validates
`ioi.runtime.mcp-live-backend-execution-request.v1`, requires wallet authority,
cTEE custody, containment refs, and the Rust driver contract, and then calls the
mounted `ioi_drivers::mcp::McpManager` for `tools/call` or live
`tools/list`. `McpManager::list_admitted_tools_for_server()` performs a live
`McpTransport::list_tools()` query and filters the response to the server's
admitted receipt tools, while tool invocation continues through
`execute_tool_with_result()` and `WorkloadSpec` lease validation. The
underlying `McpTransport` now retains the spawned child process instead of
dropping a `kill_on_drop` child immediately after pipe extraction, so live stdio
JSON-RPC survives initialization. Rust tests execute both `tools/call` and
`tools/list` through the repo MCP stdio fixture, and conformance guards the
service API, admitted live discovery path, and child-retention fix. This remains
non-terminal because stable SDK/IDE/CLI protocol APIs over the Rust replay
records still need to close.

Slice 1244 closes the runtime MCP live-result receipt-order blocker. The public
MCP control surface now calls `executeRuntimeMcpLiveBackend()` before
`commitRuntimeReceiptState()` or `commitRuntimeMcpLiveResultState()` can run,
then commits only the Rust backend service's returned control/receipt/result
truth. `RuntimeAgentService::execute_runtime_mcp_live_backend()` now binds the
actual driver-result hash into the public result payload, recomputes the result
payload hash, updates the control and receipt hash bindings, and records
`runtime_mcp_live_backend_driver_result_hash` plus
`runtime_mcp_live_backend_rust_driver_executed` evidence before JS can persist
or replay live-result truth. Tests and conformance guard the
backend-execution-before-receipt/result-commit order, the old planner-direct
payload hash no longer remains terminal, and missing backend execution now fails
closed before any live-exit receipt-state or result-state commit. This remains
non-terminal because stable SDK/IDE/CLI protocol APIs over Rust replay records
still need to close.

Slice 1245 closes the broader runtime MCP serve admission blocker. Rust
`RuntimeMcpServeToolCallPlanCore` now requires wallet authority grant refs,
wallet authority receipt refs, cTEE custody refs, and transport containment
refs before it can plan a served `tools/call`; missing refs fail closed before
the coding-tool invocation surface can run. The Rust planner binds those refs
into the served StepModule invocation request and the Rust result projector
requires the same refs before emitting the `runtime.mcp_serve`
`ioi.runtime.mcp-live-result.v1` record. The JS MCP serve surface passes only
canonical snake_case admission refs to Rust, rejects incomplete Rust plans or
live results that omit the refs, commits only the Rust-authored live result,
and returns only replayed Rust protocol payloads. Tests and conformance guard
the authority/custody/containment refusal paths, retired fallback-proof field
rejection, and replay-before-return path. This remains non-terminal because stable
SDK/IDE/CLI protocol APIs over Rust replay records still need to close.

Slice 1246 closes the SDK/public-route MCP serve protocol gap. The public
daemon now implements the advertised
`/v1/threads/{thread_id}/mcp/serve` route before the generic thread dispatcher,
unwraps stable `ioi.runtime.mcp-serve-client.v1` protocol envelopes, and
forwards body-carried wallet authority grant/receipt refs, cTEE custody refs,
and transport containment refs into the Rust-owned MCP serve context. The SDK
clients at that cut required those admission refs, sent them in the protocol
body instead of query-string transport, and kept raw JSON-RPC as the message
being served. Tests and conformance guard the stable SDK body, the advertised
thread route, absence of admission refs in query strings, and Rust replay
context handoff. At that cut this remained
non-terminal because IDE/CLI protocol APIs and broader SDK route-family coverage
over Rust replay records still need to close.

Slice 1247 closes the IDE MCP serve client split. React Flow MCP serve state
nodes no longer carry an editable endpoint override or duplicate camelCase MCP
protocol body fields. The IDE builder now emits the canonical
`/v1/threads/{thread_id}/mcp/serve` daemon request with
`ioi.runtime.mcp-serve-client.v1`, body-carried allowed tools, wallet authority
grant/receipt refs, cTEE custody refs, containment refs, and a raw JSON-RPC
`tools/list` message. Tests and conformance guard the endpoint override
retirement, canonical IDE body, and admission-ref fields. At that cut this
remained non-terminal because CLI protocol APIs and broader SDK route-family
coverage over Rust replay records still need to close.

Slice 1248 closes the CLI MCP serve client split. The Rust CLI TUI now treats
`/mcp serve` as a stable daemon protocol client for
`/v1/threads/{thread_id}/mcp/serve`, emits
`ioi.runtime.mcp-serve-client.v1` with allowed tools, wallet authority
grant/receipt refs, cTEE custody refs, containment refs, and a raw JSON-RPC
`tools/list` message, and rejects endpoint overrides, top-level
`/v1/mcp/serve`, query-string admission, and duplicate endpoint body fields.
Tests and conformance guard that the old CLI command transport cannot return.
At that cut this remained non-terminal because broader SDK route-family coverage
over Rust replay records still needed to close.

Slice 1249 retires the top-level MCP serve compatibility path. The public
daemon no longer handles `GET` or `POST /v1/mcp/serve`, the SDK no longer
exports the global `serveMcpRpc()` client or `RuntimeMcpServeRpcInput`, and MCP
serve JSON-RPC now enters through the canonical thread-scoped
`/v1/threads/{thread_id}/mcp/serve` protocol route. Tests and conformance guard
that `/v1/mcp/serve`, query-carried `thread_id` serve transport, the global SDK
client, and the global SDK request type cannot return. This remains
non-terminal because broader non-MCP SDK route-family coverage over Rust replay
records still needs to close.

Slice 1270 retires the rest of the runtime MCP top-level route/client family.
The public daemon no longer handles `/v1/mcp*`, the legacy model-mount daemon no
longer exposes `/api/v1/mcp*`, SDK global MCP catalog/control clients are gone,
and the standalone CLI live MCP aliases are deleted instead of being bridged
through compatibility transport. MCP status/search/fetch/serve projections now
advertise only `/v1/threads/{thread_id}/mcp*` daemon protocol routes, while the
thread-scoped MCP routes remain mounted surface clients over Rust-owned
admission, Agentgres replay, receipt/state-root binding, wallet authority, and
cTEE custody checks. Tests and conformance guard that the old route families,
SDK globals, CLI aliases, and projection route strings cannot return. This
remains non-terminal because broader non-MCP SDK route-family coverage over Rust
replay records still needs to close.

Slice 1271 retires the runtime doctor/readiness missing-core compatibility
fallback. `/v1/doctor` still calls the mounted doctor aggregate directly, but
the aggregate no longer catches `runtime_tool_catalog_rust_core_required` or
`runtime_skill_hook_registry_rust_core_required` to synthesize degraded tool,
runtime-node, or skill/hook readiness rows. Missing Rust projection APIs now
fail closed, and tests/conformance guard that the old degraded fallback message,
synthetic tool ids, empty runtime-node list fallback, and skill/hook fallback
catalog cannot return. This remains non-terminal because richer Rust-owned
diagnostic/readiness projections and stable Workbench/CLI/SDK protocol APIs still need
to close.

Slice 1272 deletes the remaining runtime-service bridge-named profile helper.
The live daemon imports `runtime-profile.mjs` for runtime profile normalization;
`runtime-api-bridge.mjs` and `runtime-api-bridge.test.mjs` are gone; and
conformance guards both the deleted old path and the absence of
`RuntimeApiBridge` adapter exports. This prevents the retired runtime-service
command/binary bridge from persisting as a harmless-looking JS compatibility
module while runtime-service execution and replay move toward stable Rust
daemon-core protocol/API ownership.

Slice 1273 hard-cuts runtime doctor/readiness onto a positive Rust daemon-core
projection API. `/v1/doctor` now calls
`contextPolicyCore.projectRuntimeDoctorReport()` with only request context facts,
and Rust `runtime_doctor_report.rs` owns readiness checks, model_mount route/MCP
replay, runtime tool/runtime-node catalog projection, skill/hook catalog
projection, Agentgres state-dir/run/memory evidence, wallet.network redaction,
and provider-key redaction before public truth returns. The JS
`runtime-doctor-report.mjs` facade and test are deleted, daemon store no longer
constructs `runtimeDoctorReport`, and conformance rejects any return to
`store.runtimeDoctorReport`, the daemon-store `doctorReport()` wrapper,
doctor-specific mounted JS tool/skill surface composition, missing-core degraded
fallback strings, or the deleted facade files. This remains non-terminal because
broader stable Workbench/CLI/SDK protocol APIs and remaining route-family coverage over
Rust replay records still need to close.

Slice 1274 hard-cuts Studio intent-frame routing onto a positive Rust
daemon-core projection API. `/v1/studio/intent-frame` now calls
`contextPolicyCore.projectStudioIntentFrame()` with only canonical request facts,
and Rust `studio_intent_frame.rs` owns artifact/retrieval/workspace/runtime-action
classification, effect-contract construction, required capability selection,
prompt hashing, and canonical `execution_mode` handling before public intent
truth returns. The JS `studio-intent-frame.mjs` classifier facade and test are
deleted, daemon startup no longer imports or injects `resolveStudioIntentFrame`,
and conformance rejects any return to the JS resolver, daemon-store route
wrapper, deleted facade files, or retired `executionMode` input alias passthrough.
Slice 1433 extends the same authority cut through Workbench Studio: the adapter
now sends canonical snake_case daemon protocol fields, validates the Rust
decision material in the returned frame, blocks when projection is unavailable,
and no longer exposes `fallbackStudioPromptIntentFrame()`, the fallback schema,
the local fallback source marker, or prompt-regex artifact/runtime-cockpit route
overrides as a JS truth path. This remains non-terminal because downstream
wallet/cTEE admission, Agentgres receipt/state-root binding for consequential
intent execution, and broader stable CLI/SDK protocol coverage still need to
close.

Slice 1275 hard-cuts public computer-use provider/discovery projections onto a
positive Rust daemon-core API. `/v1/computer-use/providers` and
`/v1/computer-use/browser-discovery` now call
`contextPolicyCore.projectRuntimeComputerUse()` with only canonical request
facts, and Rust `runtime_computer_use.rs` owns provider-registry and
browser-discovery public truth before route responses return. The Rust projection
reuses the StepModule provider registry in `coding_tool_computer_use.rs`, shapes
host browser-process/CDP discovery in Rust, emits Rust receipt/evidence refs, and
ignores retired camelCase request aliases. The JS
`computer-use-provider-registry.mjs` and `browser-discovery.mjs` facades/tests
are deleted, daemon startup no longer imports or injects those route
dependencies, and conformance rejects any return to the JS facades or retired
route dependency names. This remains non-terminal because concrete provider
execution, direct Rust computer-use event materialization, cTEE custody, durable
Agentgres expected-head/state-root binding, replay/projection, and stable
IDE/CLI/SDK APIs still need to close.

Slice 1276 hard-cuts computer-use run materialization into Rust run-create
planning. The public run-create hot path no longer imports or calls the JS
`computer-use-projection.mjs` facade; `buildRun()` forwards only canonical
request facts in `computer_use_materialization_request`, and Rust
`RunCreateStateUpdateCore` consumes that request during
`plan_run_create_state_update`. Rust now rejects prebuilt JS `computerUse` or
`computer_use_projection` candidates, materializes `trace.computerUse`,
computer-use events, a `computer_use_trace` receipt, task-state evidence refs,
and the redacted `computer-use-trace.json` artifact before the run-create
projection is committed. The old JS facade/test are deleted, the remaining JS
event-contract module is non-authoritative protocol scaffolding, and
conformance rejects any return to JS-authored run materialization. This remains
non-terminal because concrete provider execution beyond run-create
materialization, direct provider/backend event admission, cTEE custody, durable
Agentgres expected-head/state-root binding across replay/projection, and stable
IDE/CLI/SDK APIs still need to close.

Slice 1277 retires the root `daemonCoreApi` compatibility mount for the
authority/governed-admission family. External capability authority, cTEE Private
Workspace, worker/service package admission, L1 settlement admission, and
governed-improvement proposal admission now accept only their explicit typed
daemon-core API handles (`daemonCoreAuthorityApi`, `daemonCoreCteeApi`,
`daemonCoreWorkerServiceApi`, or `daemonCoreGovernedAdmissionApi`). Supplying a
flat `daemonCoreApi` object, even one carrying the right method, fails closed as
a retired compatibility option before Rust invocation. Conformance now guards
that those five cores cannot recover the root compatibility mount, nested
`daemonCoreApi.*` fallback, command/env fallback, or generic invoker path. This
remains non-terminal because richer projection/replay records, deeper
Agentgres receipt/state-root binding, and stable Workbench/CLI/SDK read APIs still
need terminal Rust-owned coverage.

Slice 1278 retires the remaining root `daemonCoreApi` compatibility mount for
the approval, Agentgres, workspace restore, and context-policy cluster.
Coding-tool approval, approval state, runtime Agentgres admission, workspace
restore/snapshot, and runtime context-policy now accept only their explicit typed
daemon-core API handles. Flat `daemonCoreApi` and nested `daemonCoreApi.*`
fallbacks fail closed before Rust invocation, even when they carry the matching
method. Conformance guards the retired root mount, the old nested selectors, the
generic invoker path, and command/env fallback for this cluster. This remains
non-terminal because durable replay/storage, richer wallet/cTEE authority,
deeper Agentgres receipt/state-root binding, and stable Workbench/CLI/SDK read APIs
still need terminal Rust-owned coverage across the remaining hot paths.

Slice 1279 hard-cuts the mounted runtime bridge turn/control lifecycle facade.
Public runtime-service resume and turn submission no longer call
`agentRunLifecycleSurface.createRuntimeBridgeThreadControl` or
`agentRunLifecycleSurface.createRuntimeBridgeTurn`; the public thread-turn
surface now calls the direct Rust lifecycle adapter with typed
`daemonCoreThreadLifecycleApi` planning through `RuntimeContextPolicyCore`,
explicit run-builder/provider dependencies, Agentgres-backed `writeAgent` /
`writeRun` commits, and Rust thread/turn projection validation. The mounted
lifecycle surface no longer exposes those two facade methods, focused tests
prove the methods are absent, and conformance rejects any return to those
public-surface facade calls. This remains non-terminal because runtime-service
thread start still enters through the create-thread lifecycle surface, and
broader lifecycle completion still needs deletion/cancellation replay/projection,
durable wallet/cTEE authority, and stable Workbench/CLI/SDK lifecycle APIs over
Rust-owned records.

Slice 1280 deletes the remaining mounted agent/run lifecycle facade from the
daemon hot path. Public agent/thread/run create routes, agent
archive/unarchive/resume/close/reload/delete routes, non-runtime thread
resume/turn creation, diagnostics repair retry-run creation, subagent
spawn/input/resume, and runtime-service thread creation now call direct
Rust-backed lifecycle functions with explicit planner, run-builder,
provider-gate, Agentgres commit, and projection dependencies. The daemon store
no longer constructs `agentRunLifecycleSurface`, `createRuntimeAgentRunLifecycleSurface`
is absent, focused tests prove the store property is absent, and conformance
rejects production source that restores that facade. This remains non-terminal
because durable lifecycle deletion/cancellation replay/projection, deeper
wallet/cTEE lifecycle authority, and stable Workbench/CLI/SDK lifecycle protocol APIs
still need Rust-owned records across the remaining hot paths.

Slice 1281 hard-retires the public model route-control JS route-map truth path.
Public route upsert/test still require Rust `planModelMountRouteControl` and
Rust Agentgres model_mount record-state commit before returning, but they no
longer write Rust-planned records back into `state.routes` or pass JS
route-map `current_route` candidates to Rust. Mounted route selection now builds
its route/endpoints/providers candidate set from Rust read-projection list APIs
instead of `this.routes`, `state.endpoints`, or `state.providers` maps.
Focused route tests assert the JS route map remains untouched and public
write/test requests carry no JS current-route candidate, while conformance
rejects restored route-map writeback, route-map current-route reads, raw
mounted route lookup, and raw endpoint/provider map candidate transport in the
route-control builder. This remains non-terminal because hosted/provider
transport materialization, deeper wallet/cTEE route authority, Rust-owned
topology joins, and stable Workbench/CLI/SDK route APIs still need to close.

Slice 1282 hard-retires provider lifecycle JS endpoint-map subject truth.
Public provider health/start/stop still require Rust
`planModelMountProviderLifecycle` and Rust Agentgres model_mount record-state
commit before lifecycle truth can return, but implicit endpoint/model subjects
are now selected from the Rust `endpoints` read-projection list instead of
`state.endpoints`. Focused provider tests seed a map-only endpoint and prove it
cannot produce a lifecycle request before Rust planning, while conformance
rejects restored `state.endpoints` enumeration in the provider lifecycle
request builder. This remains non-terminal because live hosted/provider
transport materialization, deeper receipt/state-root binding, Rust-owned
topology joins, and stable Workbench/CLI/SDK provider lifecycle APIs still need to
close.

Slice 1283 hard-retires conversation-artifact control JS artifact-candidate
transport. Public create/action/export/promote still call Rust
`planRuntimeConversationArtifactControl` and Rust Agentgres artifact-state
commit before truth; action/export/promote now send runtime `state_dir`, Rust
`runtime_conversation_artifact_control.rs` replays admitted `artifacts/*.json`
records, rejects `artifact`/`artifacts` control candidates, and requires
`state_dir` for existing-artifact controls. The mounted JS surface no longer
calls `ConversationArtifactStore.list()` or sends artifact candidates for
control planning, and focused Rust/JS tests plus conformance guard that the
retired candidate path cannot return. This remains non-terminal because durable
ArtifactRef/PayloadRef admission, richer replay/storage, wallet/cTEE authority,
and stable SDK/IDE artifact APIs still need to close.

Slice 1284 hard-retires public subagent read JS subagent/run candidate
transport. Public subagent list/get/result still call Rust
`projectRuntimeSubagentProjection`; the mounted JS surface now sends runtime
`state_dir` instead of a `{subagents,runs}` projection bundle, Rust
`runtime_subagent_projection.rs` replays admitted `subagents/*.json` and
`runs/*.json` records, rejects the old projection candidate transport, and
requires `state_dir` for valid read projections. Focused Rust/JS tests and
conformance guard that the deleted `candidateSubagentProjectionFacts()` path and
candidate error cannot return. This remains non-terminal because subagent
control still coordinates current subagent/run mutation facts, and direct
StepModuleRouter delegation/execution, wallet authority, durable replay/storage,
and stable SDK/IDE subagent APIs still need to close.

Slice 1285 deletes the empty Rust daemon-core command-protocol substrate. The
kernel no longer exports `pub mod command_protocol`, and
`crates/services/src/agentic/runtime/kernel/command_protocol.rs` is absent
instead of preserving an empty `DAEMON_CORE_OPERATIONS` catalog or
`CommandEnvelope` validator as terminal scaffolding. Hypervisor conformance now
uses a virtual retired-marker surface only after proving the source file and
module export are absent, so old command operation strings, command-dispatch
arms, bridge binaries, command-env fallbacks, and command-envelope compatibility
paths cannot return as daemon hot-path authority. This command substrate is
terminally retired; the broader master guide remains non-terminal until durable
replay/storage, richer wallet/cTEE authority, model_mount/MCP materialization,
and stable Workbench/CLI/SDK protocol APIs close over Rust-owned records.

Slice 1286 hard-cuts runtime bridge turn-submit projection-candidate
transport. The runtime-service turn-submit path no longer calls
`store.turnForRun(candidateRun)` before Rust planning and no longer sends a
JS-authored `projection` candidate into `planRuntimeBridgeTurnRunStateUpdate`;
the Rust `RuntimeBridgeTurnRunStateUpdateRequest` denies unknown fields and
focused Rust tests reject the retired `projection` field. The daemon now commits
only the Rust-planned `turn.runtime_bridge.submit` run through Agentgres-backed
`writeRun` before requesting the Rust-authored turn projection from the
committed run. Conformance guards absence of the pre-plan candidate projection,
the retired request field, and the old projection-mismatch compatibility path.
This removes a duplicate JS turn-projection truth handoff; broader lifecycle
completion remains non-terminal until run creation itself is Rust-authored from
canonical request facts, durable replay/storage, wallet/cTEE lifecycle
authority, and stable Workbench/CLI/SDK lifecycle APIs close.

Slice 1287 hard-cuts runtime thread-event projection/replay cache transport.
`RuntimeThreadEventProjectionRequest` now requires runtime `state_dir`, denies
unknown fields, and derives latest sequence, current head, state root, and
existing idempotency keys by replaying admitted `events/*.jsonl` Agentgres
records in Rust before admitting any projected `thread.started` or run event.
`RuntimeThreadEventReplayRequest` also denies unknown fields and no longer
accepts caller-supplied `latest_seq`; replay derives the latest sequence from
the same admitted event log. The daemon projection path no longer reads
`store.runtimeEventStream()` or `store.latestRuntimeEventSeq()` to send
`latest_seq`, `expected_head`, or `existing_idempotency_keys`, and replay no
longer forwards a JS latest-seq candidate. Conformance guards the Rust state-dir
requirement, rejected retired projection cache fields, rejected replay
`latest_seq`, and the absence of the old JS cache-derived request fields. This
removes the duplicate event-head/idempotency truth handoff; broader thread-event
completion remains non-terminal until stable Workbench/CLI/SDK event APIs consume Rust
projection/replay records without the temporary local hydration cache.

Slice 1288 hard-cuts runtime thread-event projection fact transport.
`RuntimeThreadEventProjectionRequest` no longer accepts `workspace_root`,
`agent`, or `runs`; Rust derives synthetic `thread.started` and run-event source
facts by reading admitted Agentgres `agents/*.json` and `runs/*.json` records
from `state_dir` before event admission. The daemon projection wrapper now sends
only `projection_kind`, canonical `thread_id`, `event_stream_id`, optional
`run_id`, and `state_dir`, and the thread-event replay surface routes
thread-start, whole-thread, and run projections through those protocol IDs
instead of forwarding JS agent/run objects. The retired
`runtimeThreadProjectionAgent`, `runtimeThreadProjectionRun`, and
`runtimeThreadProjectionRunEvent` helpers are deleted, Rust rejects the old fact
transport under `deny_unknown_fields`, and conformance guards the absent JS
helpers, absent `agent`/`runs`/`workspace_root` request fields, and the new
state-dir Agentgres source loader. This removes the duplicate JS agent/run fact
handoff for the runtime thread-event projector; the broader master guide remains
non-terminal until local replay-cache hydration, durable protocol read APIs, and
remaining IDE/CLI/SDK consumers move fully onto Rust-owned projection/replay
records.

Slice 1289 hard-cuts runtime thread-event admission cache transport.
`RuntimeThreadEventAdmissionRequest` now denies unknown fields, requires runtime
`state_dir`, and no longer accepts caller-supplied `latest_seq`,
`expected_head`, or `state_root_before`. Direct generic event append now sends
only the candidate event plus daemon state dir; Rust reads admitted
`events/*.jsonl` Agentgres records to derive latest sequence, current head, and
state root before admission, receipt/storage binding, projection watermarking,
and state-root-after calculation. The old JS path no longer calls
`store.latestRuntimeEventSeq()` or formats an expected head for this migrated
admission hot path, and conformance guards the fail-closed Rust request shape,
state-dir requirement, rejected cache fields, and scoped JS absence. This removes
the generic runtime-event head/state handoff as an authority input; the remaining
non-terminal work is to retire the temporary local replay-cache hydration and
move remaining SDK/IDE event reads fully onto Rust-owned protocol projection and
replay records.

Slice 1290 hard-cuts coding-tool event admission cache transport.
`CodingToolResultEventAdmissionRequest` and
`CodingToolCommandStreamAdmissionRequest` now deny unknown fields, require
runtime `state_dir`, and reject caller-supplied `latest_seq`, `expected_head`,
and `state_root_before`. The daemon result-event and command-stream admission
wrappers no longer call `store.latestRuntimeEventSeq()` or format expected heads;
they send only canonical event/request facts plus daemon state dir. Rust
`coding_tool_event.rs` reads admitted `events/*.jsonl` Agentgres records to
derive latest sequence, current head, and state root before result-event or
command-stream admission, storage binding, receipt binding, and projection
watermarking. Conformance guards both fail-closed request structs, state-dir
requirements, rejected cache fields, Rust state loaders, and scoped JS absence.
This removes the remaining coding-tool Agentgres admission head/state handoff as
a JS authority input; remaining coding-tool work is now durable read/projection
cleanup and stable API consumption rather than command/env, binary bridge, or
cache-head admission fallback.

Slice 1291 hard-cuts coding-tool duplicate-result replay out of the JS local
event cache. `CodingToolResultEventAdmissionCore` now checks admitted
`events/*.jsonl` Agentgres records for an existing result event with the same
idempotency key and returns a Rust `replayed` admission record with the
existing event, operation ref, storage admission evidence, state root, head,
receipt refs, payload refs, artifact refs, and projection watermark. The
coding-tool invocation surface no longer reads
`store.runtimeEventStream(...).idempotency` and is no longer wired to
`codingToolInvocationResultFromEvent` before workload execution/result-event
admission; duplicate handling is owned by Rust admission over admitted
Agentgres truth. Conformance guards the Rust replay path, the focused Rust
idempotency replay test, the focused JS no-cache-preflight test, and the
absence of the invocation-surface cache read or duplicate replay shaper. This
removes the last coding-tool result duplicate-truth shortcut before Rust
admission; remaining coding-tool work is durable read/projection cleanup and
stable API consumption rather than JS idempotency authority.

Slice 1292 hard-cuts pending diagnostics feedback off the JS local event
cache. `pendingDiagnosticsFeedbackForNextTurn()` now calls
`runtimeEventsForStream(..., { since_seq: 0 })`, which routes through the Rust
runtime thread-event replay API over admitted Agentgres `events/*.jsonl`
records, before selecting diagnostic completion events for feedback compaction.
It fails closed when the replay API is absent and no longer reads
`store.runtimeEventStream()` for pending diagnostics truth. Conformance guards
the Rust replay call, the focused no-local-cache test, and the absence of a
direct runtime event stream cache read in the diagnostics feedback surface.
This removes another diagnostics/runtime feedback duplicate truth path; broader
diagnostics completion remains non-terminal until wallet-governed repair
authority, durable diagnostics projection/replay storage, and stable SDK/IDE
diagnostics APIs close.

Slice 1293 hard-cuts workspace-trust acknowledgement replay and sequencing out
of the JS local event cache. `WorkspaceTrustControlStateUpdateCore` now accepts
runtime `state_dir`, replays admitted Agentgres `events/*.jsonl` records inside
Rust to resolve warning truth, and rejects restored `events` candidate transport
or caller-supplied `seq` transport. The JS workspace-trust state client sends
only the `state_dir` replay handle plus canonical request facts, no longer calls
`runtimeEventsForStream()` or `latestRuntimeEventSeq()`, and still admits only
the Rust-planned warning/acknowledgement event through Rust runtime-event
Agentgres admission. Conformance guards the Rust state-dir replay tests, the
retired `events`/`seq` transports, and the absence of local replay/sequence
cache reads in the workspace-trust state module. This removes another
workspace-trust split-brain replay boundary; deeper wallet/cTEE authority and
stable protocol APIs remain non-terminal.

Slice 1294 hard-cuts runtime-control state-event sequence cache transport out
of the JS facade cluster. The Rust policy core now shares
`latest_runtime_event_seq_from_state_dir()`, which reads admitted Agentgres
`events/*.jsonl` records under runtime `state_dir` and derives the latest
sequence for a thread or event stream before planning thread-control,
operator interrupt/steer, context-compaction, or MCP-control state updates.
Those Rust request structs now reject caller-supplied `seq`, and context
compaction rejects caller-supplied `previous_latest_seq`; missing `state_dir`
fails closed before planning. The JS thread-control, thread-turn
operator-control, context-policy, and MCP-control surfaces no longer call
`latestRuntimeEventSeq()` for these migrated paths and no longer send sequence
or previous-latest fields. Context-policy event admission also stops
preassigning the sequence and consumes only the Rust Agentgres admission result.
Conformance now guards the shared Rust replay helper, the retired request
fields, focused fail-if-called tests, and production-source absence of the JS
latest-sequence cache. Remaining work is durable runtime-control projection and
stable protocol API cleanup, not a JS sequence authority fallback.

Slice 1295 hard-cuts run-memory command resolution out of the JS memory cache
and fail-closed mutation placeholders. `resolveRunMemory()` now requires the
mounted thread-memory surface, calls Rust-owned public memory policy/path/list
projections before run construction, and uses the same Rust
`plan_runtime_memory_control` plus Agentgres `commitRuntimeMemoryState` path for
chat/API remember, edit, delete, enable, and disable commands. The old
`store.memory.pathProjection()`, `store.memory.effectivePolicy()`,
`store.memory.list()`, and run-memory mutation refusal path can no longer
author run memory truth; missing Rust projection/control fails closed before JS
cache reads. The daemon-store memory pass-through methods for remember, list,
policy, path, edit/delete, status/validation, and direct memory control-event
append are deleted, so migrated memory routes and run construction cannot
return through those compatibility handles. Remaining work is wallet/policy authority, cTEE private-memory
custody, durable memory replay/projection depth, and stable Workbench/SDK memory APIs.

Slice 1296 hard-cuts runtime task/job runner injection scaffolding.
`createRuntimeTaskJobApi()` no longer accepts `taskJobCreateRunner`,
`taskJobCancelRunner`, or `taskJobProjectionRunner`; task create, task/job
cancel, and task/job read projection moved onto the Rust daemon-core task/job
planners/projector before Agentgres-backed run persistence or route projection.
Daemon construction no longer wires parallel task/job runner handles, and
conformance guards that the retired alias names cannot return; Slice 1314
removes the remaining store-mounted planner/projector fallback. Remaining work
is durable task/job replay/projection depth, wallet/cTEE task authority, direct
lifecycle APIs, and stable Workbench/CLI/SDK task/job clients, not a JS runner
fallback.

Slice 1297 hard-cuts diagnostics repair runner injection scaffolding.
`createRuntimeDiagnosticsRepairApi()` no longer accepts
`diagnosticsRepairRunner`; diagnostics repair decision execution, direct
repair/override/retry event append, operator override state update, retry-run
planning, retry-result projection, decision projection, and repair policy
projection resolve only `store.contextPolicyCore` before entering the Rust
daemon-core diagnostics repair planners/projectors. Daemon construction no
longer wires a parallel diagnostics repair runner handle, focused tests mount
fake Rust planners/projectors only under `store.contextPolicyCore`, and
conformance guards that the retired alias name cannot return. Remaining work is
durable diagnostics repair replay/storage, wallet-governed repair authority,
cTEE custody where repair work touches private workspace state, and stable
IDE/CLI/SDK diagnostics clients, not a JS runner fallback.

Slice 1298 hard-cuts workflow-edit runner injection scaffolding.
`createRuntimeWorkflowEditApi()` no longer accepts `workflowEditRunner`;
public workflow-edit proposal and apply controls resolve only
`store.contextPolicyCore` before Rust daemon-core workflow-edit control
planning and Rust runtime-event admission. Daemon construction no longer wires
a parallel workflow-edit runner handle, focused tests mount fake Rust planners
only under `store.contextPolicyCore`, and conformance guards that the retired
alias name cannot return. Remaining work is wallet approval authority depth,
workflow mutation custody, durable workflow-edit projection/replay,
ArtifactRef/PayloadRef binding where needed, and stable Workbench/CLI/SDK
workflow-edit clients, not a JS runner fallback.

Slice 1299 hard-cuts run-cancel runner injection scaffolding. `cancelRun()` no
longer reads `state.runCancelRunner`; cancellation state planning now resolves
through the Rust daemon-core mount that the auxiliary surface passes explicitly
before Agentgres-backed `writeRun` persistence. Missing state planning fails
closed without an alternate JS runner. Conformance guards that the retired
runner alias cannot return. Remaining work is wallet/operator authority depth,
cancellation replay/projection storage, and direct Rust lifecycle APIs, not a JS
runner fallback.

Slice 1300 hard-cuts coding-tool budget recovery runner injection scaffolding.
`createRuntimeCodingToolBudgetRecoveryApi()` no longer accepts
`codingToolBudgetRecoveryRunner`; retry completion, request-approval control,
and approve-override control resolve only `store.contextPolicyCore` before Rust
daemon-core budget recovery planning, wallet authority binding, and
Agentgres-backed `writeRun` persistence. Daemon construction no longer wires a
parallel budget recovery runner handle, focused tests mount fake Rust planners
only under `store.contextPolicyCore`, and conformance guards that the retired
alias name cannot return. Remaining work is durable recovery replay/projection
depth and stable Workbench/CLI/SDK recovery clients, not a JS runner fallback.

Slice 1301 hard-cuts runtime tool catalog runner injection scaffolding.
`createRuntimeToolApi()` no longer accepts `toolCatalogRunner`; account,
runtime-node, and tool catalog projections mount the positive
`contextPolicyCore` API directly before Rust daemon-core catalog projection.
Daemon construction no longer wires a parallel tool catalog runner handle,
focused tests mount fake Rust projectors only through `contextPolicyCore`, and
conformance guards that the retired alias name cannot return. Remaining work is
direct Rust catalog storage/replay depth, wallet/network authority on external
exposure, receipt/state-root binding, and stable protocol APIs, not a JS runner
fallback.

Slice 1302 hard-cuts skill/hook registry runner injection scaffolding.
`createRuntimeSkillHookApi()` no longer accepts `skillHookRunner`; catalog,
skills, and hooks projections mount the positive `contextPolicyCore` API
directly before Rust daemon-core registry projection. Daemon construction no
longer wires a parallel skill/hook runner handle, focused tests mount fake Rust
projectors only through `contextPolicyCore`, and conformance guards that the
retired alias name cannot return. Remaining work is direct Rust governance and
catalog storage/replay depth, wallet authority where applicable,
receipt/state-root binding, and stable protocol APIs, not a JS runner fallback.

Slice 1303 hard-cuts repository workflow runner injection scaffolding.
`createRuntimeRepositoryApi()` no longer accepts `repositoryRunner`;
repository workflow projections mount the positive `contextPolicyCore` API
directly before Rust daemon-core repository projection. Daemon construction no
longer wires a parallel repository runner handle, focused tests mount fake Rust
projectors only through `contextPolicyCore`, and conformance guards that the
retired alias name cannot return. Remaining work is durable Agentgres-backed
repository workflow storage/replay, wallet authority for external exits,
receipt/state-root binding, and stable protocol APIs, not a JS runner fallback.

Slice 1304 hard-cuts runtime lifecycle projection runner injection scaffolding.
The historical `createRuntimeLifecycleProjectionSurface()` no longer accepted
`lifecycleRunner`; Slice 1422 later deletes that surface outright. Public
lifecycle projections now enter through the store-owned
`projectRuntimeLifecycleProjection()` API, which delegates to the positive
`contextPolicyCore` Rust daemon-core Agentgres replay projector. Daemon
construction no longer wires a parallel lifecycle runner handle, focused tests
mount fake Rust projectors only through `contextPolicyCore`, and conformance
guards that the retired alias and surface names cannot return. Remaining work is wallet/cTEE authority on lifecycle exits,
receipt/state-root binding for every lifecycle read projection, richer
ArtifactRef/PayloadRef-aware artifact projection, and stable Workbench/CLI/SDK
protocol APIs, not a JS runner fallback.

Slice 1305 hard-cuts the route-level lifecycle admission fallback. Public
agent/thread create routes and native agent status/delete/run-create routes no
longer accept a `lifecycleAdmissionRunner` handler option or fall back through
`store.contextPolicyCore ?? lifecycleAdmissionRunner`; those route families pass
only `store.contextPolicyCore` into the direct Rust-backed lifecycle functions.
Conformance now guards that the route fallback option and nullish fallback
shape cannot return. Remaining work is wallet/cTEE policy depth,
receipt/state-root binding, lifecycle replay/projection storage, and stable
protocol APIs, not an alternate JS route runner.

Slice 1306 hard-cuts thread-turn surface runner aliases.
`createRuntimeThreadTurnApi()` no longer accepts `threadLifecycleRunner`,
`threadTurnAdmissionRunner`, or `operatorTurnControlAdmissionRunner`;
runtime-service resume/turn submit, public non-runtime resume/turn create, and
operator interrupt/steer planning all resolve through the single positive
`contextPolicyCore` mount. Conformance now guards that the retired aliases
cannot return. Remaining work is durable lifecycle replay/projection,
wallet/cTEE runtime-service authority, receipt/state-root binding, and stable
thread-turn protocol APIs, not alternate surface runners.

Slice 1307 hard-cuts runtime subagent runner wrappers.
`createRuntimeSubagentApi()` no longer routes projection/control through
`subagentProjectionRunner`, `subagentControlRunner`, or
`store.contextPolicyCore ?? contextPolicyCore`; subagent list/get/result,
spawn, wait, input, resume, assign, cancel, propagated cancel, direct
control-event append, and child lifecycle composition resolve through the
single positive `contextPolicyCore` mount injected by daemon startup.
Conformance now guards that the retired wrappers and fallback cannot return.
Remaining work is direct Rust subagent admission/storage/replay,
StepModuleRouter delegation/execution authority, wallet/cTEE policy depth,
receipt/state-root binding, and stable SDK/IDE subagent protocol APIs, not
alternate subagent runners.

Slice 1308 hard-cuts diagnostics repair surface runner wrappers.
`createRuntimeDiagnosticsRepairApi()` no longer routes diagnostics repair
decision control, retry-run planning, retry-result projection, decision
projection, or operator-override state update through
`diagnosticsRepairControlRunner`, `diagnosticsRepairRetryRunRunner`,
`diagnosticsRepairRetryResultProjectionRunner`, `diagnosticsRepairProjectionRunner`,
`diagnosticsOperatorOverrideStateUpdateRunner`, or
`store.contextPolicyCore ?? null`; decision execution, direct
decision/retry/operator event append, retry turn creation, retry-result
projection, decision projection, and operator override execution resolve
through the single positive `contextPolicyCore` mount injected by daemon
startup. Diagnostics retry lifecycle composition also passes that same core into
the direct Rust run-create path, so retry creation cannot recover by reading a
store-level fallback. Conformance now guards that the retired wrappers and
fallback cannot return. Remaining work is wallet-governed repair policy depth,
durable diagnostics repair projection/replay, receipt/state-root binding, cTEE
custody where repair work touches private workspace state, and stable SDK/IDE
diagnostics APIs, not alternate diagnostics repair runners.

Slice 1309 hard-cuts runtime agent/run lifecycle helper runner fallbacks.
`createAgent()`, `createThread()`, and `createRun()` no longer accept
per-operation state-update runner deps or recover through `store.contextPolicyCore
?? null`; agent create, thread create, run create, and runtime-service bridge
thread start resolve through the explicit `lifecycleAdmissionRunner` dependency
supplied by the daemon route/surface caller. Conformance now guards that the
retired per-operation runner deps and store fallback cannot return. Slice 1420
later deletes the standalone runtime-service thread-control and turn-submit
helper exports entirely. Remaining work is wallet/cTEE lifecycle policy depth,
durable lifecycle replay/projection, receipt/state-root binding, and stable
protocol APIs, not alternate lifecycle helper runners.

Slice 1310 hard-cuts conversation-artifact surface runner wrappers.
`createRuntimeConversationArtifactApi()` no longer routes artifact
create/action/export/promote control or list/get/revision projection through
`conversationArtifactControlRunner`, `conversationArtifactProjectionRunner`, or
the `store.contextPolicyCore ?? contextPolicyCore` fallback shape. Public and
thread-scoped conversation-artifact read/control routes now resolve through the
store-owned conversation-artifact API backed by the single positive
`contextPolicyCore` mount injected by daemon startup before Rust control
planning, Rust projection, and Agentgres artifact-state commit. Slice 1426
later deletes the route-visible conversation-artifact surface outright while
keeping store-owned conversation-artifact API methods as route entry points.
Conformance now guards that the retired wrappers and fallback cannot return.
Remaining work is durable Agentgres-backed artifact replay/projection,
ArtifactRef/PayloadRef admission depth, wallet/cTEE authority where needed, and
stable protocol APIs, not alternate conversation-artifact runners.

Slice 1311 hard-cuts the runtime MCP serve store-core fallback. MCP serve
`tools/call` planning, Rust result projection, and live-result replay now
resolve only through the positive `contextPolicyCore` mount supplied to
`createRuntimeMcpServeApi()` by daemon startup. The MCP serve API and
focused tests no longer read or model `store.contextPolicyCore`, and the old
`store.contextPolicyCore ?? contextPolicyCore` fallback cannot return.
Conformance now guards the absence of that store-mounted planner path. Remaining
work is broader SDK route-family protocol coverage and deeper MCP replay/storage
cleanup, not an alternate MCP serve planner mount.

Slice 1312 hard-cuts the coding-tool artifact surface store-core fallback.
Artifact draft materialization and artifact read/retrieve projection now resolve
only through the positive `contextPolicyCore` mount supplied to
`createRuntimeCodingToolArtifactSurface()` by daemon startup. The artifact
surface no longer reads `store.contextPolicyCore ?? contextPolicyCore`, so draft
records, read projections, and result retrieval cannot return through a
store-mounted artifact planner/projector fallback. Conformance now guards that
the retired fallback cannot return. Remaining work is durable artifact
projection/replay depth, ArtifactRef/PayloadRef admission depth, and stable
protocol APIs, not an alternate artifact core mount.

Slice 1313 hard-cuts the coding-tool budget recovery surface store-core
fallback. Retry-approved state update, request-approval control, and
approve-override control now resolve only through the positive
`contextPolicyCore` mount supplied to
`createRuntimeCodingToolBudgetRecoveryApi()` by daemon startup. The budget
recovery surface and focused tests no longer read or model
`store.contextPolicyCore` or `store.contextPolicyCore ?? null`, so
budget-recovery run truth cannot return through a store-mounted planner
fallback. Conformance now guards that the retired fallback cannot return.
Remaining work is retry-event materialization, durable replay/projection, and
deeper approval authority projection, not an alternate budget recovery planner
mount.

Slice 1314 hard-cuts the runtime task/job API store-core fallback. Task
create, task/job cancel, and task/job list/get projection now resolve only
through the positive `contextPolicyCore` mount supplied to
`createRuntimeTaskJobApi()` by daemon startup. The task/job API and
focused tests no longer read or model `store.contextPolicyCore` or
`store.contextPolicyCore ?? null`, so task/job run truth and read projection
cannot return through a store-mounted planner/projector fallback. Conformance
now guards that the retired fallback cannot return. Remaining work is durable
task/job replay/projection depth, wallet/cTEE task authority, direct lifecycle
APIs, and stable protocol clients, not an alternate task/job core mount.

Slice 1315 hard-cuts the runtime auxiliary compositor store-core fallback.
Managed-session projection/control, workspace-change projection/control, and
thread-fork control now resolve only through the positive `contextPolicyCore`
mount supplied to `createRuntimeThreadAuxiliaryApi()` by daemon startup.
The auxiliary API passes that mount into the helper modules explicitly, and
the helper modules plus focused tests no longer read or model
`deps.contextPolicyCore ?? store.contextPolicyCore`, `store.contextPolicyCore`,
or `store?.contextPolicyCore`. Managed-session, workspace-change, and
thread-fork truth therefore cannot return through a store-mounted
planner/projector fallback after Rust daemon-core parity is present.
Conformance now guards the retired fallback and the daemon-mounted auxiliary
core dependency. Slice 1425 later deletes the route-visible auxiliary surface
outright while keeping store-owned auxiliary API methods as route entry points.
Remaining work is durable replay/projection depth,
wallet/cTEE authority expansion, StepModuleRouter delegation execution, and
stable protocol clients, not an alternate auxiliary core mount.

Slice 1316 hard-cuts the runtime context-policy API store-core fallback.
`compactThread()`, thread/run context-budget event planning, and
thread compaction-policy event planning now resolve only through the positive
`contextPolicyCore` mount supplied to `createRuntimeContextPolicyApi()` by
daemon startup. The internal API and focused tests no longer read or model
`store?.contextPolicyCore ?? contextPolicyCore`, `store.contextPolicyCore`, or
`store?.contextPolicyCore`, so context compaction, context-budget event truth,
and compaction-policy event truth cannot return through a store-mounted
planner/projector fallback. Conformance now guards the retired fallback, the
deleted route-visible surface, store-owned route entry points, the internal
context-policy API, and the focused harness mount. Remaining
work is durable replay/projection depth, richer policy receipt/state-root
binding, wallet/cTEE authority expansion, and stable protocol clients, not an
alternate context-policy core mount.

Slice 1317 hard-cuts the runtime workflow-edit surface store-core fallback.
Workflow-edit proposal and apply controls now resolve only through the positive
`contextPolicyCore` mount supplied to `createRuntimeWorkflowEditApi()` by
daemon startup. The workflow-edit surface and focused tests no longer read or
model `store?.contextPolicyCore ?? null`, `store.contextPolicyCore`, or
`store?.contextPolicyCore`, so workflow-edit proposal/apply event truth cannot
return through a store-mounted planner fallback after Rust daemon-core parity is
present. Conformance now guards the retired fallback, the daemon-mounted
workflow-edit surface, and the focused harness mount. Remaining work is durable
workflow-edit replay/projection depth, richer policy receipt/state-root
binding, wallet/cTEE workflow authority expansion, and stable protocol clients,
not an alternate workflow-edit core mount.

Slice 1318 hard-cuts the thread-memory/lifecycle store-core fallback cluster.
The thread-memory surface is now constructed per daemon instance with the
positive `contextPolicyCore` mount supplied by startup, so public memory
projection/control and memory status/validation event planning resolve only the
constructor-mounted Rust core. `updateAgent()` and `deleteAgent()` now default
their status/delete runners to `null` instead of `store.contextPolicyCore ??
null`; route and focused tests pass the Rust core explicitly. The source and
focused tests no longer model `store?.contextPolicyCore ?? contextPolicyCore`,
`store.contextPolicyCore ?? null`, or store-mounted lifecycle helper planner
fallbacks, and conformance guards the instance-owned memory surface plus null
lifecycle helper defaults. Remaining work is wallet/policy authority depth,
cTEE private-memory custody, durable memory/lifecycle replay and projection,
receipt/state-root binding, and stable Workbench/CLI/SDK protocol clients, not an
alternate store-mounted Rust core fallback.

Slice 1319 hard-cuts the run-cancel state-core fallback. `cancelRun()` now
accepts the positive `contextPolicyCore` mount explicitly from
`createRuntimeThreadAuxiliaryApi()` and from subagent cancellation
composition; it no longer reads `state.contextPolicyCore` or
`state?.contextPolicyCore` for state planning, and missing state planning fails
closed canonically. Focused cancellation tests mount fake Rust planners through
the call dependency object, subagent cancellation tests assert that the mounted
core is forwarded, and conformance guards the absent state lookup plus the
auxiliary surface call. Remaining work is wallet/operator authority depth,
durable cancellation replay/projection storage, direct Rust lifecycle APIs, and
stable protocol clients, not an alternate state-mounted Rust core fallback.

Slice 1320 hard-cuts the runtime MCP single-core mount fallback. Daemon startup
now injects the same positive `contextPolicyCore` mount into MCP catalog,
control, and serve surfaces; the catalog/control surfaces no longer instantiate
their own `RuntimeContextPolicyCore`, and `mcp-manager.mjs` requires an explicit
daemon-mounted core instead of self-creating one from `daemonCoreMcpApi`.
Registry, validation, catalog, status, search/fetch, live-result, and serve
truth therefore cannot return through a duplicate JS-side Rust-core instance
after daemon parity is present. Conformance now guards daemon injection, the
absence of MCP self-core defaults, and the manager's fail-closed explicit-core
requirement. Remaining work is broader non-MCP SDK route-family protocol
coverage and durable MCP replay/storage depth, not another MCP core fallback.

Slice 1321 hard-cuts the runtime context/memory auxiliary self-core and planner
alias fallbacks. Coding-tool invocation now passes the daemon-owned
`contextPolicyCore` into coding-tool budget policy preflight, and the
context-budget policy helpers no longer self-create `RuntimeContextPolicyCore`
for context-budget, coding-tool budget, or compaction-policy evaluation.
Workflow-only context-budget projection likewise requires the constructor-mounted
core instead of silently creating a duplicate helper core. The coding-tool
governance budget-block surface now accepts only the positive
`contextPolicyCore` mount and ignores the retired `codingToolBudgetBlockPlanner`
constructor alias, so budget-block truth cannot return through an alternate
planner. Thread-control construction defaults its core to `null` rather than a
self-created policy core, and memory-manager status/validation helpers require
an explicit daemon-mounted core instead of constructing one locally. Focused
tests and conformance guard the retired self-core defaults, the retired planner
alias, and the daemon injection path. Remaining work is durable policy/memory
replay and wallet/cTEE authority depth, not another helper-owned core fallback.

Slice 1322 hard-cuts the runtime-service thread-turn bridge-adapter constructor
aliases. `runtime-thread-turn-api.mjs` no longer accepts
`runtimeBridgeThreadControl` or `runtimeBridgeTurnRun` overrides; runtime-service
resume and turn submission resolve through route-family code with the
daemon-mounted `contextPolicyCore`. Focused tests mount fake Rust lifecycle cores
through `contextPolicyCore` and install throw-if-called retired aliases to prove
the old injected bridge handles cannot author runtime-service thread or turn
truth. Conformance guards the absent constructor aliases. Slice 1420 later
deletes the standalone helper exports so runtime-service control/turn execution
cannot re-enter through a separate JS lifecycle helper surface. Remaining work is
durable lifecycle replay/projection, wallet/cTEE runtime-service authority, and
stable Workbench/CLI/SDK lifecycle APIs, not another bridge-adapter injection path.

Slice 1323 deletes the model_mount read-projection JS facade boundary.
`ModelMountingState` now calls the mounted `modelMountCore.planReadProjection()`
directly through `modelMountReadProjection()` for public model_mount readbacks,
canonical projection persistence, runtime-engine/catalog/server/backend/MCP/
conversation/topology projection reads, and not-found translations. The
standalone helper module is absent, the focused proof moved to
`read-projection-direct.test.mjs` and calls mounted state methods directly, and
route-family tests mount fake Rust cores only through `modelMountCore`.
Conformance guards the absent helper file/property plus direct
`modelMountReadProjection()` calls. Remaining work is direct Rust Agentgres
topology joins, hosted/provider materialization, backend execution
materialization, and stable SDK/IDE protocol APIs, not a JS read-projection
facade.

Slice 1324 hard-cuts the runtime thread-control existing-model compatibility
fallback. `threadRuntimeControlModelInput()` no longer accepts persisted
camelCase `existingModel` aliases (`routeId`, `reasoningEffort`, `maxCostUsd`,
`workflowGraphId`, or `workflowNodeId`) as model-route truth when building
canonical model-control input for Rust route selection. Focused tests keep the
canonical `route_id` / `workflow_node_id` path live while poisoning the retired
aliases to prove they cannot override the Rust-bound request, and conformance
guards the absence of the `existingModel.*` fallback reads. Remaining work is
wallet/model-route authority depth, durable replay/projection binding, and
stable Workbench/CLI/SDK lifecycle APIs, not a thread-control compatibility fallback.

Slice 1325 hard-cuts the thread runtime-control top-level alias truth path.
`initialThreadRuntimeControls()`, `normalizedAgentRuntimeControls()`,
`RuntimeThreadControlSurface.nextThreadRuntimeControls()`, and the lifecycle
fallback seed now emit only canonical `approval_mode` runtime-control truth,
drop top-level `approvalMode` and `updatedAt`, and read persisted control
approval only from `approval_mode`. Runtime-backed turn requests produced by
`requestWithThreadRuntimeControls()` now scrub poisoned `threadMode` /
`approvalMode` request aliases and forward canonical `thread_mode` /
`approval_mode` into the direct Rust lifecycle path. Coding-tool approval and
repository/workspace-trust consumers read `controls.approval_mode`, focused
tests poison the retired aliases while proving they cannot return as output, and
conformance guards the helper, surface, and lifecycle fallback against restoring
the alias fields. Remaining work is wallet/model-route authority depth, durable
replay/projection binding, and stable Workbench/CLI/SDK lifecycle APIs, not a
thread-control top-level alias truth path.

Slice 1326 hard-cuts the model_mount backend-process JS cache substrate.
`ModelMountingState` no longer constructs `backendProcesses` or
`backendChildProcesses`, no longer exposes `listBackendProcesses()`,
`backendProcessForBackend()`, or `reconciledBackendProcess()`, the
`backend-processes` persistence map and store directory are gone, and
`backend-registry-state.mjs` no longer exports backend-process list/lookup/
reconcile helpers. Rust aggregate `snapshot` and `projection` outputs also no
longer emit the empty `backendProcesses` compatibility slot. Backend-process
and backend-lifecycle planning remain typed Rust daemon-core APIs, backend list
and log readbacks remain Rust read-projection/replay records, and JS process
supervisor entrypoints remain fail-closed before any subprocess authority.
Conformance now guards the absent daemon fields, helper exports, persistence
map, store directory, Rust aggregate compatibility field, and focused absence
assertions. Remaining work is actual Rust live external backend binary spawning/supervision,
hosted/provider transport, the invocation-authority blocker later superseded by Slice 1381, and stable SDK/IDE/CLI
protocol APIs, not a JS backend-process cache fallback.

Slice 1327 hard-cuts the model_mount OAuth session/state JS cache substrate.
`ModelMountingState` no longer constructs `oauthSessions` or `oauthStates`, the
`oauth-sessions` and `oauth-states` persistence map entries and store
directories are gone, and focused OAuth/read-projection tests now assert those
local map fields are absent instead of merely empty. Public
`listOAuthSessions()`, `listOAuthStates()`, `snapshot()`, and `projection()`
continue to return OAuth records through Rust Agentgres read-projection replay;
the Rust aggregate keeps the protocol fields as Rust-authored output, not JS
state. Conformance guards the absent daemon fields, persistence map entries,
store directories, and focused absence assertions while preserving Rust replay
coverage for OAuth session/state records. Remaining work is hosted OAuth/
live cTEE secret injection into outbound hosted network requests, actual Rust live external backend binary spawning/supervision,
hosted/provider transport, the invocation-authority blocker later superseded by Slice 1381, and stable SDK/IDE/CLI
protocol APIs, not a JS OAuth session/state cache fallback.

Slice 1328 hard-cuts the model_mount legacy capability-token JS cache
substrate. `ModelMountingState` no longer constructs a `tokens` map, the
legacy `tokens` persistence entry and store directory are gone, and focused
capability-token/state/store tests assert the JS cache field and directory are
absent rather than merely untouched. Public capability-token
create/list/authorize/revoke still enter Rust daemon-core
`plan_model_mount_capability_token_control`, commit `capability-tokens` records
through Agentgres, and return or replay Rust-owned token authority facts; the
one-time token material remains outside persisted records. Conformance guards
the absent daemon field, persistence map entry, store directory, and focused
absence assertion. Remaining work is deeper wallet authority policy, revocation
epochs, and stable SDK/IDE/CLI capability-token APIs, not a JS `tokens` cache
fallback.

Slice 1329 hard-cuts the model_mount catalog-provider configuration/runtime
material JS cache substrate. `ModelMountingState` no longer constructs
`catalogProviderConfigs` or `catalogProviderRuntimeMaterials`, the legacy
`model-catalog-providers` persistence entry and store directory are gone, and
focused catalog-provider/state/store tests assert those local fields and the
directory are absent instead of seeded and untouched. Public catalog-provider
config list/get/write, private config readback, runtime-material resolution,
and OAuth start/callback/exchange/refresh/revoke still enter Rust
`plan_model_mount_catalog_provider_control` and commit
`model-catalog-provider-controls` records through Agentgres before public
truth returns. Conformance guards the absent daemon fields, persistence map
entry, store directory, and focused absence assertions. Remaining work is cTEE
secret-injection depth for hosted catalog/download edges and stable
SDK/IDE/CLI catalog-provider APIs, not a JS
catalog-provider config or runtime-material cache fallback.

Slice 1330 hard-cuts the model_mount invocation helper compatibility-alias
path. Migrated model invocation, provider execution, and provider-result helper
boundaries now reject retired camelCase selection, route receipt/control,
endpoint/provider, instance/backend-process, token, provider-result, stream,
MCP, and evidence helper fields before shaping provider execution admission or
provider-result admission requests. The helper normalizers read only canonical
snake_case Rust model_mount records, so stale `routeReceipt`, `routeDecision`,
`executionBackend`, `tokenCount`, `streamChunks`, or similar compatibility
fields cannot become route, provider execution, token, stream, or provider
result truth. Focused tests and conformance poison those aliases while keeping
canonical snake_case records live. Remaining work is backend
execution/materialization, hosted/provider transport, invocation authority
depth, and stable SDK/IDE/CLI protocol APIs, not helper-level compatibility
translation on the migrated model_mount invocation hot path.

Slice 1250 retires the top-level runtime memory context route family. The
public daemon no longer handles `/v1/memory`, `/v1/memory/records`,
`/v1/memory/policy`, `/v1/memory/path`, or `/v1/memory/validate`; the daemon
store no longer exports `memoryProjectionForContext`, `memoryStatus`, or
`validateMemory`; and the SDK no longer exports global `getMemoryStatus()` /
`validateMemory()` clients or their context-query input types. Runtime memory
status/validation now enters through explicit
`/v1/threads/{thread_id}/memory/status` and
`/v1/threads/{thread_id}/memory/validate` protocol routes, while memory
list/policy/path remain explicit thread/agent protocol routes over the
Rust-owned projection records. Tests and conformance guard that the retired
top-level memory routes, SDK globals, and daemon-store context helpers cannot
return. This remains non-terminal because wallet/policy authority, cTEE
private-memory custody, richer durable memory replay/projection, and stable Workbench
memory APIs still need to close.

Slice 1251 hard-retires the RuntimeAgentService command/binary bridge
substrate and Slice 1272 deletes the bridge-named JS profile helper module.
`runtime-api-bridge.mjs` is absent, runtime profile normalization lives in
`runtime-profile.mjs`, the `ioi-runtime-bridge` binary and Cargo bin entry are deleted, daemon startup
rejects `runtimeBridge`, Rust service policy no longer reads bridge command-env
overrides, the renamed `apps/hypervisor` app path uses the renamed
inference/model-route helper instead of a bridge helper, and stale
bridge-backed live proof scripts/tests are removed.
Conformance now guards that the JS adapter export, bridge helper, bridge env
fallback, deleted bridge module path, Cargo bridge binary, and service
`runtimeBridge` option cannot return.
This bridge family is terminally retired; the broader master guide remains
non-terminal until runtime-service execution and replay land through stable Rust
daemon-core protocol APIs with Agentgres truth.

Slice 1252 retires the thread/run/subagent lifecycle command-shaped Rust owner
wrapper cluster. Thread control, runtime bridge thread start/control/turn,
subagent record updates, and agent/thread/run create/status/delete now expose
only direct Rust daemon-core request/record APIs in
`policy/thread_lifecycle.rs`; `ThreadLifecycleCommandError`, lifecycle
`*BridgeRequest` structs, `plan_*_state_update_response` wrappers,
`rust_*_state_update_command` source markers, policy facade exports, and
bridge-shaped owner tests are deleted. `RuntimeContextPolicyCore` now names
these as typed API result normalizers with `rust_*_state_update_api` defaults,
and conformance guards that no migrated lifecycle hot path can re-enter through
the retired command-shaped wrapper layer. This bridge-wrapper family is
terminally retired; broader lifecycle completion still depends on moving the
remaining local cache/replay and stable Workbench/CLI/SDK lifecycle read APIs fully
onto Rust-owned Agentgres projection/replay records.

Slice 1253 hard-cuts runtime thread-event replay off JS replay candidates. Rust
`RuntimeThreadEventReplayRequest` now requires runtime `state_dir`, replays
admitted `events/*.jsonl` Agentgres event records in Rust, and rejects
caller-supplied replay `events` transport. The daemon passes only replay kind,
cursor, latest seq, and `state_dir` into
`project_runtime_thread_event_replay`; the old JS
`runtimeThreadReplayCandidateEvents` collector is deleted. Public run lifecycle
replay now reaches the mounted Rust thread-event replay path through
`eventsForRun`, and the duplicate `replayFromCanonicalState` daemon/run-read
facade is retired. Conformance guards the state-dir replay requirement, the
retired event-candidate transport, and absence of the public replay alias. This
removes a split-brain replay boundary for stream/turn/run replay; broader
lifecycle completion still depends on moving the remaining lifecycle projection
candidate facts and stable Workbench/CLI/SDK read APIs fully onto Rust-owned
Agentgres projection records.

Slice 1254 hard-cuts public lifecycle projection off JS cache candidates. Rust
`RuntimeLifecycleProjectionRequest` now requires runtime `state_dir`,
replays admitted `agents/*.json`, `runs/*.json`, and `events/*.jsonl`
Agentgres records in Rust, and derives public agent/thread/run/turn/event,
run replay, usage, trace, computer-use, scorecard, and artifact projections
from those records. Rust rejects retired lifecycle candidate transport fields
such as `agents`, `runs`, `events`, `replay`, `usage`, `trace`, `artifacts`,
and `artifact`; the store-owned lifecycle projection API now sends only route
identifiers plus `state_dir` and no longer calls JS agent/run maps, thread/turn helpers,
usage helpers, event/replay streams, trace helpers, or artifact resolvers before
the Rust projection. Conformance guards the `state_dir` requirement, retired
candidate transport, daemon no-cache-call surface, and the updated run replay
alias retirement. This removes the public lifecycle read split-brain projection
boundary; broader lifecycle completion still depends on wallet/cTEE authority
for lifecycle exits, complete receipt/state-root binding for every lifecycle
read projection, and stable Workbench/CLI/SDK protocol APIs over the Rust-owned
Agentgres replay records.

Slice 1255 folds the remaining top-level usage and authority-evidence public
read family into the Rust lifecycle projector. Rust
`project_runtime_lifecycle` now exposes `usage_list` and
`authority_evidence_summary` projection kinds over runtime `state_dir`, derives
usage rows and authority/preflight evidence from admitted Agentgres
`runs/*.json` and `events/*.jsonl` records, and keeps the projection source
bound to `rust_runtime_lifecycle_state_dir_replay`. Public `/v1/usage`,
`/v1/authority-evidence`, and `/v1/workflow-capability-preflights` call the
store-owned lifecycle projection API; the run-read surface is later deleted,
and the old JS `authority-evidence-summary.mjs` helper/test are deleted.
Conformance now guards the Rust projection kinds, lifecycle route calls,
absent helper files, and absent run-read usage/evidence facade. This removes
the last public lifecycle read exception that still returned through JS
run-read authority;
broader lifecycle completion still depends on wallet/cTEE authority for
lifecycle exits, complete receipt/state-root binding for every lifecycle read
projection, and stable Workbench/CLI/SDK protocol APIs over the Rust-owned Agentgres
replay records.

Slice 1256 retires the authority-evidence native compatibility aliases after
Slice 1255 verified Rust lifecycle projection parity. The daemon no longer
routes `/api/v1/authority-evidence`, `/api/v1/authority-evidence-summaries`,
`/api/v1/workflow-capability-preflight-evidence`, or
`/api/v1/workflow-capability-preflight`; the canonical protocol clients must
use `/v1/authority-evidence` or `/v1/workflow-capability-preflights`.
Conformance now guards the absence of those native aliases so the migrated read
family cannot regain a duplicate compatibility truth path.

Slice 1257 hard-cuts the diagnostics repair retry result facade. Rust
`RuntimeDiagnosticsRepairRetryResultProjectionCore` now owns the retry result
projection through typed
`daemonCoreRuntimeProjectionApi.projectRuntimeDiagnosticsRepairRetryResult`;
the daemon requires that projection API before JS agent lookup/run creation,
admits the Rust-authored retry event, validates the complete Rust-projected
result after admission, rejects partial or mismatched projections, and returns
only the Rust-projected retry result envelope without locally filling missing
fields. The old JS `diagnosticsRepairRetryResultFromEvent`,
`diagnosticsOperatorOverrideResultFromEvent`,
`diagnosticsRepairApplyApprovalKey`, and `diagnosticsRepairExecutionStatus`
helpers plus the stale daemon constructor wiring are deleted.
Command-protocol source absence keeps
`project_runtime_diagnostics_repair_retry_result` out of command transport, and
conformance now guards the positive typed API, the retired helper exports, the
fail-closed missing/partial projection paths, and the absence of JS
retry/operator result helper wiring. This removes the diagnostics repair retry
result split-brain projection fallback; broader diagnostics completion still
depends on durable
diagnostics repair storage/replay, wallet-governed repair policy authority, and
stable Workbench/CLI/SDK diagnostics APIs over Rust-owned records.

Slice 1258 hard-cuts the IDE diagnostics repair client compatibility body. The
React Flow diagnostics repair node now emits only the canonical daemon protocol
body for `/v1/threads/{thread_id}/diagnostics/repair-decisions/{decision_id}/execute`:
snake_case schema, workflow, event, approval, conflict, and idempotency facts
plus the diagnostics repair decision action. The daemon diagnostics repair
surface rejects retired camelCase request aliases such as `decisionId`,
`snapshotId`, `workflowGraphId`, `workflowNodeId`, `approvalGranted`,
`allowConflicts`, `restoreApplyIdempotencyKey`, and `payloadSchemaVersion`
before Rust planning or runtime-event admission, and forwards the canonical
protocol body into Rust diagnostics repair control planning. Conformance now
guards both the daemon alias rejection and the IDE canonical request body. This
removes the diagnostics repair IDE compatibility body as a duplicate client
truth path; broader diagnostics completion still depends on durable diagnostics
repair storage/replay, wallet-governed repair policy authority, and any
remaining CLI/SDK diagnostics read APIs over Rust-owned records.

Slice 1259 hard-cuts runtime-service lifecycle agent projection aliases. Rust
thread-lifecycle start/control planning now scrubs caller-supplied
`runtimeProfile`, `runtimeSessionId`, `runtimeBridgeId`,
`runtimeBridgeStatus`, `runtimeBridgeSource`, and `fixtureProfile` before
returning Agentgres-bound agent projections, emits only canonical snake_case
runtime-service identity/custody fields, and lifecycle/thread-event/workspace
trust Rust replay/projection readers no longer accept those camel aliases as
truth. The JS runtime-service lifecycle normalizers fail closed if Rust returns
any retired alias, and daemon runtime identity/session helpers read only
`runtime_profile`, `runtime_session_id`, and `fixture_profile`. Conformance now
guards Rust alias scrubbing, JS normalizer rejection, and snake-only helper
reads. This removes another runtime-service compatibility truth path; broader
lifecycle completion still depends on durable wallet/cTEE authority,
deletion/cancellation replay/projection, and stable Workbench/CLI/SDK lifecycle APIs
over Rust-owned records.

Slice 1260 hard-cuts diagnostics-blocked non-runtime turn creation out of the
admission-required refusal path. When post-edit diagnostics feedback blocks
continuation, the thread-turn surface now injects the Rust-projected
diagnostics feedback into the canonical turn request, enters the mounted Rust
run-create lifecycle path, commits only the Rust-planned blocked run through
Agentgres-backed `writeRun`, and returns the Rust thread/turn projection for
that run. The retired `thread_turn_diagnostics_block` /
`turn.diagnostics_block` operation is no longer accepted by
`ThreadTurnAdmissionRequiredCore`, and conformance now guards that
diagnostics-blocked turns cannot re-enter that refusal path or direct JS
`createRun()` / `updateAgent()` mutation. This removes a fail-closed-only
lifecycle route edge; deletion/cancellation replay/projection, direct
runtime-control event materialization, durable diagnostics replay/storage,
wallet/cTEE authority, broader run lifecycle, and stable protocol APIs remain
non-terminal.

Slice 1261 hard-cuts public approval request issuance into Rust authority.
`RuntimeApprovalStateCore` now exposes the typed
`authorizeApprovalRequest` approval API, backed by Rust
`ApprovalRequestAuthorityCore::authorize`. The public approval request surface
must call that Rust authority method before `planApprovalRequestStateUpdate`,
and the Rust request state planner now rejects missing request-authority
record/hash/authority-receipt binding. The JS surface forwards the Rust
request-authority receipts/hash into state planning and cannot fall back to
caller receipt truth, JS runtime-event append, JS run/agent target lookup,
command/env fallback, generic command transport, or bridge command wrappers.
Conformance guards the positive API, the failure path without request
authority, command-transport retirement for `authorize_approval_request`, and
the two-step public request ordering. Approval grant issuance, richer authority
projection/replay storage, durable approval read APIs, wallet/cTEE authority
coverage across the remaining routes, and stable Workbench/CLI/SDK protocol APIs
remain non-terminal.

Slice 1265 hard-cuts approval decision authority onto typed wallet.network
approval-grant artifacts. `ApprovalDecisionAuthorityRequest` now accepts
`wallet_approval_grant`, Rust `ApprovalDecisionAuthorityCore` verifies the grant
structure for approve, reject, and revoke decisions, derives the canonical grant
artifact hash/ref, records `wallet_approval_grant_hash` and
`wallet_approval_grant_ref`, and uses that derived ref as the approval wallet
authority. The internal approval API forwards the typed grant object but
always blanks caller `authority_grant_refs`, so approval decisions can no longer
return through JS-minted `wallet.network://grant/...` strings. Conformance guards
the typed field, the approve/reject/revoke missing-grant negative paths, the
facade blanking behavior, the revoke forged-ref regression case, and the Rust
authority-derived state-update grant refs. Broader wallet.network grant issuance
and signature/consumption semantics, richer durable authority projection/replay
storage, and stable Workbench/CLI/SDK approval APIs remain non-terminal.

Slice 1262 deletes the temporary StepModule runner facade from the daemon hot
path. `packages/runtime-daemon/src/step-module-runner.mjs` and its focused test
are absent, `AgentgresRuntimeStateStore` no longer imports or constructs
`createStepModuleRunnerFromEnv()`, and the coding-tool invocation surface calls
`daemonCoreWorkloadApi.runCodingToolStepModule` directly after Rust result
envelope planning returns the StepModule context. The direct request carries the
canonical `ioi.runtime.coding-tool-step-module-request.v1` facts and keeps
command `operation`, command `backend`, JS-supplied `invocation`, command-env
selectors, binary bridge fallback, and generic daemon-core invoker semantics out
of the migrated coding-tool execution path. Workload transport handles remain
daemon composition inputs only (`IOI_WORKLOAD_GRPC_ADDR` and `IOI_SHMEM_ID`);
they do not reintroduce command transport or JS execution authority.
Conformance now guards the deleted runner files, direct typed workload API
usage, missing-API fail-closed behavior, and absence of the retired command/env
selectors. Durable diagnostics replay/storage, remaining model_mount/MCP
materialization, richer authority projection/replay, and stable Workbench/CLI/SDK
protocol APIs remain non-terminal.

Slice 1263 hard-cuts approval lease authority into Rust and deletes the JS
approval lease facade. `RuntimeApprovalStateCore` now expects the typed
`daemonCoreApprovalApi.authorizeApprovalRequest` and
`authorizeApprovalDecision` responses to carry Rust-authored `approval_lease`
records, lease ids, and lease statuses. Rust `approval.rs` owns the
`ioi.runtime.approval-lease.v1` record, hashes it into request/decision
authority records, includes it in request/decision/revoke state updates, and
rejects state planning when the authority record lacks the lease binding. The
internal approval API no longer normalizes decisions locally and no longer
authors lease ids, TTL/expiry facts, policy hashes, or lease state; it simply
requires Rust authority output before persistence. `runtime-approval-lease.mjs`
and `runtime-approval-lease.test.mjs` are absent, and conformance now guards
their absence plus the Rust lease-binding API. Wallet.network grant issuance
semantics, richer authority projection/replay storage, and stable Workbench/CLI/SDK
approval APIs remain non-terminal.

Slice 1264 retires the stale Agentgres MCP live-result pending-transport
fixture truth. Rust Agentgres MCP live-result state commit examples and protocol
tests now use `status: "rust_materialized"`, `result_materialized: true`,
`backend_materialization_status: "rust_driver_contract_bound"`, and no retired
command/binary/compatibility fallback proof fields. Conformance now scans the
Rust Agentgres admission/protocol cores so `admitted_pending_rust_transport`
cannot remain accepted live-result commit truth. Broader non-MCP SDK
route-family protocol coverage over Rust replay records remains non-terminal.

Slice 1330 hard-cuts the model_mount runtime preference/profile JS cache
substrate. `ModelMountingState` no longer constructs `runtimeSelections` or
`runtimeEngineProfiles`, `MODEL_MOUNTING_STATE_MAPS` no longer loads
`runtime-preferences` or `runtime-engine-profiles`, the store no longer creates
those local cache directories, and focused state/store/read-projection tests
assert the cache fields and dirs are absent. Runtime-engine selection/profile
truth remains Rust-owned through typed `planModelMountRuntimeEngine`, Agentgres
`runtime-engine-controls` record commits, and Rust read-projection replay over
runtime `state_dir`. Stable IDE/CLI/SDK runtime-engine APIs and deeper
Rust-owned backend-process binding remain non-terminal; the retired JS
preference/profile maps and local runtime-engine helper materialization must not
return as empty compatibility state or duplicate projection truth.

Slice 1331 hard-cuts the model_mount MCP server JS cache substrate.
`ModelMountingState` no longer constructs `mcpServers`,
`MODEL_MOUNTING_STATE_MAPS` no longer loads `mcp-servers`, the store no longer
creates that local cache directory, and focused MCP/state/store tests assert
the cache field and dir are absent. MCP import, ephemeral registration, tool
invoke, workflow-node execution, and server list truth remain Rust-owned through
typed `planModelMountMcpWorkflow`, Agentgres `mcp-servers` record commits,
materialized MCP workflow receipts, and Rust `mcp_servers` read-projection
replay over runtime `state_dir`. Live external MCP transport/discovery and
stable Workbench/CLI/SDK MCP APIs remain non-terminal; the retired JS `mcpServers`
map must not return as empty compatibility state or duplicate MCP projection
truth.

Slice 1332 hard-cuts the model_mount conversation JS cache substrate.
`ModelMountingState` no longer constructs `conversations`,
`MODEL_MOUNTING_STATE_MAPS` no longer loads `model-conversations`, response-id
collision checks and previous-response lookup now read the Rust
`model_conversation_states` projection, and Rust-authored conversation-state
commits no longer repopulate a local JS map. Conversation truth remains
Rust-owned through typed conversation/stream plans, Agentgres
`model-conversations` commits, receipt/state-root binding, and Rust replay over
runtime `state_dir`. Hosted/stream protocol parity and stable Workbench/CLI/SDK
conversation APIs remain non-terminal; the retired JS `conversations` map must
not return as empty compatibility state or duplicate response-lineage truth.

Slice 1333 hard-cuts the model_mount catalog-search last-search JS cache slot.
`ModelMountingState` no longer constructs `lastCatalogSearch`, catalog-search
tests no longer preserve a null or fixture cache slot, and the direct
read-projection fixture no longer transports stale last-search state. Public
catalog search remains Rust-owned through the `catalog_search` read projection
over Agentgres provider-inventory replay; JS provider iteration, result
aggregation, enrichment, and last-search cache compatibility must not return.

Slice 1334 hard-cuts the model_mount vault-ref JS cache substrate.
`ModelMountingState` no longer constructs `vaultRefs`, the state map loader no
longer hydrates `vault-refs` into JS memory, and daemon startup no longer loads
that map back into the local vault port as accepted metadata. Public vault
bind/list/metadata/status/health/remove truth remains Rust-owned through
`planModelMountVaultControl`, Agentgres `vault-refs` commits, wallet.network
authority evidence, cTEE custody evidence, and Rust custody replay. The
`vault-refs` record directory remains the admitted Agentgres substrate; the
retired JS `vaultRefs` map must not return beside it.

Slice 1335 hard-cuts the model_mount download JS cache substrate.
`ModelMountingState` no longer constructs `downloads`,
`MODEL_MOUNTING_STATE_MAPS` no longer hydrates `model-downloads` into JS
memory, and the store no longer precreates a local `model-downloads` cache
directory. Public download queue/cancel/status/list truth remains Rust-owned
through `planModelMountStorageControl`, Agentgres `model-downloads` commits,
and Rust storage read-projection replay. The `model-downloads` record directory
remains an admitted Agentgres substrate created by record-state commits; the
retired JS `downloads` map must not return beside it.

Slice 1336 hard-cuts the model_mount route JS cache substrate.
`ModelMountingState` no longer constructs `routes`,
`MODEL_MOUNTING_STATE_MAPS` no longer hydrates `model-routes` into JS memory,
default route templates are no longer seeded into a local JS route map, and the
store no longer precreates a local `model-routes` cache directory. Public route
write/test/selection truth remains Rust-owned through `planModelMountRouteControl`,
Agentgres `model-routes`, `model-route-selections`, and
`model-route-endpoint-resolutions` commits, plus Rust read-projection replay
over runtime `state_dir`. The `model-routes` record directory remains an
admitted Agentgres substrate created by record-state commits; the retired JS
`routes` map must not return beside it as empty compatibility state or duplicate
route truth.

Slice 1337 hard-cuts the remaining model_mount topology JS cache substrate.
`ModelMountingState` no longer constructs `providers`, `artifacts`,
`endpoints`, or `instances`; startup no longer calls a local topology loader or
default topology seeder; `state-seeding.mjs` and its test are deleted;
`MODEL_MOUNTING_STATE_MAPS` is empty; the generic `loadModelMountingMap()`
loader is gone; the store no longer precreates local `model-providers`,
`model-artifacts`, `model-endpoints`, or `model-instances` cache directories;
and disabled-fixture cleanup no longer remains as JS topology-map pruning.
Public topology truth remains Rust-owned through typed
provider/artifact-endpoint/instance lifecycle plans, Agentgres record-state
commits, and Rust read-projection replay over runtime `state_dir`. The
`model-*` record directories remain admitted Agentgres substrates created by
record-state commits; local JS topology maps, default seeding, loader
compatibility, and fixture-prune truth must not return beside Rust replay.

Slice 1338 hard-cuts the model_mount canonical projection cache substrate.
`ModelMountingState` no longer exposes `canonicalProjectionWritePlan()` or
`writeProjection()`, daemon startup no longer materializes a canonical projection
file, Rust-authored receipt persistence no longer refreshes projection cache
JSON, and `AgentgresModelMountingStore` no longer exposes `writeProjection()` or
`readProjection()` or creates the local `projections/` directory. Runtime doctor
output now points to Rust model_mount read-projection ownership instead of the
old `model-mounting-canonical` file path. Public model_mount reads remain
Rust-owned through typed read-projection APIs over runtime `state_dir` and
Agentgres replay; the deleted local projection cache must not return as a
Rust-gated compatibility substrate, duplicate truth file, or diagnostic path.

Slice 1339 hard-cuts the model_mount local materialization cache directories.
`AgentgresModelMountingStore.ensureDirs()` no longer precreates local
`provider-health`, `backend-logs`, `server-logs`, `lifecycle-events`, or
`workflow-bindings` directories. Public provider-health, backend lifecycle/log,
server-control, lifecycle, and workflow-binding readback remains Rust-owned
through typed read-projection APIs over runtime `state_dir` plus Agentgres
record replay. The admitted Rust Agentgres record writers may still materialize
canonical record directories when committing records; the deleted JS-created
local materialization caches must not return beside Rust replay as duplicate
health, log, lifecycle, server, or workflow-binding truth.

Slice 1340 hard-cuts runtime projection bridge-shaped public API names.
Runtime tool catalog, repository workflow, and skill/hook registry projection
cores now expose positive Rust daemon-core request/error/result surfaces without
the old `BridgeRequest`, `CommandError`, or JS `BridgeResult` normalizer names.
`RuntimeToolCatalogProjectionRequest`, `RepositoryWorkflowProjectionRequest`,
and `SkillHookRegistryProjectionRequest` remain the public Rust projection
requests; `RuntimeToolCatalogProjectionError`, `RepositoryWorkflowProjectionError`,
and `SkillHookRegistryProjectionError` are the direct Rust errors; and the JS
policy client normalizers use positive projection-result names only. The retired
bridge-shaped request, command-error, and bridge-result names must not return as
compatibility aliases for these Rust-owned public projection families.

Slice 1341 hard-cuts runtime lifecycle projection bridge-shaped public API names.
The public lifecycle read projection family already routes through typed Rust
daemon-core projection over Agentgres `state_dir` replay; its Rust request/error
and JS protocol normalizer no longer carry bridge-shaped names. The public Rust
API is `RuntimeLifecycleProjectionRequest` and `RuntimeLifecycleProjectionError`,
and the JS protocol client uses `normalizeRuntimeLifecycleProjectionResult`.
`RuntimeLifecycleProjectionBridgeRequest`,
`RuntimeLifecycleProjectionCommandError`, and
`normalizeRuntimeLifecycleProjectionBridgeResult` must not return as lifecycle
projection compatibility aliases beside the Rust-owned replay projector.

Slice 1342 hard-cuts context/memory policy bridge-shaped public API names.
The context lifecycle and thread-memory policy families already enter Rust
through typed daemon-core APIs; their remaining adapter request/error/result
names no longer preserve bridge or command-transport shape. The Rust adapter
requests are `ContextBudgetPolicyApiRequest`, `CodingToolBudgetBlockApiRequest`,
`CompactionPolicyApiRequest`, `ContextCompactionPlanApiRequest`,
`ContextCompactionStateUpdateApiRequest`,
`MemoryManagerStatusProjectionApiRequest`,
`MemoryManagerValidationProjectionApiRequest`, and
`ThreadMemoryAgentStateUpdateApiRequest`; the shared adapter errors are
`ContextPolicyApiError` and `McpMemoryApiError`; JS protocol-client
normalizers use positive result names only. The retired bridge request,
command-error, bridge-result normalizer, `*_command` source marker, and
`*_command_response` helper/test names must not return for these Rust-owned
context-policy, compaction, memory-manager, and thread-memory state-update
surfaces.

Slice 1343 hard-cuts runtime memory projection/control bridge-shaped public API
names. Public memory read projection and memory mutation/control already enter
Rust through typed `daemonCoreThreadMemoryApi` methods with runtime `state_dir`
replay and Agentgres memory-state admission; their remaining Rust request/error,
JS normalizer, and source-marker names no longer preserve bridge or command
transport shape. The public Rust APIs are
`RuntimeMemoryProjectionApiRequest`, `RuntimeMemoryProjectionApiError`,
`RuntimeMemoryControlApiRequest`, and `RuntimeMemoryControlApiError`; the JS
protocol client uses `normalizeRuntimeMemoryProjectionResult` and
`normalizeRuntimeMemoryControlResult`; and Rust source markers use
`rust_runtime_memory_projection_api` and `rust_runtime_memory_control_api`.
The retired runtime memory `BridgeRequest`, `CommandError`,
`normalize*BridgeResult`, `_command` source-marker, and
`*_command_response` helper/test names must not return as compatibility aliases
beside the Rust-owned memory projection/control route family.

Slice 1344 hard-cuts workspace-trust control bridge-shaped public API names.
Workspace trust warning/acknowledgement control already enters Rust through the
typed `daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate` API,
with Rust `state_dir` replay, event planning, and Agentgres runtime-event
admission before public truth can return. The remaining adapter request/error,
JS normalizer, and source-marker names now expose positive Rust daemon-core API
shape: `WorkspaceTrustControlStateUpdateApiRequest`,
`WorkspaceTrustControlApiError`,
`normalizeWorkspaceTrustControlStateUpdateResult`, and
`rust_workspace_trust_control_state_update_api`. The retired workspace-trust
`BridgeRequest`, `CommandError`, `normalize*BridgeResult`, `_command` source
marker, and `*_command_response` helper/test names must not return beside this
Rust-owned workspace-trust control route family.

Slice 1345 hard-cuts the runtime memory local cache substrate. Daemon startup no
longer constructs `AgentMemoryStore`, `memory-store.mjs` and its tests are
deleted, and the retired JS memory prompt parser must not return beside the
Rust-owned memory projection/control hot path. Thread-memory state no longer exports private
cache-backed list/policy/path helpers or refreshes `store.memory` after Rust
Agentgres memory-state commits; public thread/agent list, policy, path, status,
and validation readback stays on `projectRuntimeMemoryProjection`. Thread
projection no longer reads the mounted memory projection as a JS side channel;
Slice 1346 moves memory counts into Rust state-dir replay. The retired `AgentMemoryStore`,
`this.memory`, `store.memory.*`, private thread-memory list/policy/path readers,
and temporary memory projection cache refresh must not return beside the
Rust-owned memory projection/control hot path.

Slice 1346 hard-cuts runtime thread/turn projection fact transport. Public
`threadForAgent()` and `turnForRun()` now send only projection kind, thread/run/
turn identity, event stream, schema, and runtime `state_dir` to
`projectRuntimeThreadTurnProjection`; JS no longer enumerates runs, projects
thread/run events, reads event replay caches, calculates latest sequence,
queries memory counts, gathers subagent ids, or shapes agent/run/runtime-control/
usage facts before Rust projection. Rust `RuntimeThreadTurnProjectionRequest`
requires `state_dir`, denies retired caller fact fields and aliases, replays
`agents/*.json`, `runs/*.json`, `memory-records/*.json`, `subagents/*.json`,
and runtime event projection/replay state itself through canonical snake_case
record fields only, then authors thread/turn records and projection hashes from
that Agentgres substrate. The retired JS fact bundle, replay-cache latest
sequence, memory-count side read, runtime identity override, camelCase replay
fallback, and compatibility projection shapers must not return beside the
Rust-owned thread/turn projection hot path.

Slice 1347 hard-cuts runtime MCP serve query/raw JSON-RPC transport
compatibility. SDK `threadMcpServeRpc()` no longer inherits MCP list query
options, no longer builds `mcpServeQuery()`, and rejects retired
`thread_id`/`agent_id`/`server_id`/source-mode query context before transport.
Public and runtime thread MCP serve routes now require the
`ioi.runtime.mcp-serve-client.v1` body envelope on
`/v1/threads/{thread_id}/mcp/serve`, reject query-carried serve context, and
reject raw JSON-RPC bodies instead of merging query facts into the Rust-owned
MCP serve context. The live daemon contract initializes and lists served tools
through the same stable body envelope used for tool calls, and conformance
guards that the retired SDK query builder, query context merge, top-level serve
transport, and raw JSON-RPC compatibility path cannot return.

Slice 1348 hard-cuts stable model_mount read protocol clients. Public
`/v1/models/{id}`, `/v1/models/artifacts`, `/v1/models/endpoints`,
`/v1/models/providers`, `/v1/models/routes`, and
`/v1/models/catalog/search` now call the mounted Rust-owned model_mount read
projections for model-detail, artifact, endpoint, provider, route, and
catalog-search truth. SDK clients expose
`listModelArtifacts()`, `listModelEndpoints()`, `listModelProviders()`,
`listModelRoutes()`, and `searchModelCatalog()` over those stable protocol
routes, while CLI `models ls`, `models get`, `models capabilities`,
`models catalog-search`, and `routes ls` no longer use the older `/api/v1`
model_mount read URLs.
Conformance guards the stable route surface, SDK methods, CLI read-command
URLs, and the absence of the retired client read fallbacks for migrated read
commands. This remains non-terminal because hosted/provider materialization,
live cTEE secret injection into outbound hosted network requests, live external backend binary spawning/supervision,
the invocation-authority blocker superseded by Slice 1381, later stable Workbench and SDK control-client rows still need terminal Rust-owned materialization and replay records.

Slice 1349 retires the legacy model_mount native read aliases for the migrated
stable read family. The daemon no longer routes `GET /api/v1/model-capabilities`,
`GET /api/v1/models/catalog/search`, `GET /api/v1/models/artifacts`,
`GET /api/v1/models/routes`, `GET /api/v1/models/{id}`,
`GET /api/v1/providers`, or `GET /api/v1/routes` to model_mount projection
methods; those reads must use the stable `/v1` protocol routes from Slice 1348.
Focused native-route tests assert the retired aliases return `not_found` without
calling `catalogSearch()`, `getModel()`, `listArtifacts()`,
`listModelCapabilities()`, `listProviders()`, or `listRoutes()`. Conformance
source-scans keep the removed GET handlers absent. This remains
non-terminal because mutation/control routes, live external backend binary spawning/supervision,
hosted/provider transport, live cTEE secret injection into outbound hosted network requests, invocation
authority depth, and later stable client protocol rows had not yet landed at that cut.

Slice 1350 hard-cuts stable model_mount receipt protocol clients and retires the
native receipt read aliases. Public receipt list/get/replay now use
`GET /v1/model-mount/receipts`, `GET /v1/model-mount/receipts/{id}`, and
`GET /v1/model-mount/receipts/{id}/replay` over the mounted model_mount
receipt store and Rust `receipt_replay` read projection; CLI receipt commands
and current proof/autopilot scripts consume those stable protocol routes.
`GET /api/v1/receipts`, `GET /api/v1/receipts/{id}`, and
`GET /api/v1/receipts/{id}/replay` are no longer routed by the native
model_mount handler, focused route tests assert those aliases return `not_found`
without calling receipt methods, and conformance scans keep clients and handlers
off the retired `/api/v1/receipts` family. This remains non-terminal because
mutation/control routes, live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable client protocol rows had not yet landed at that cut.

Slice 1351 hard-cuts stable model_mount read proof and Workbench clients. Current
proof/autopilot scripts, product UI/desktop/workbench clients, and IDE
workflow model-capability binding surfaces no longer name retired
`/api/v1/model-capabilities`, `/api/v1/models/catalog/search`,
`/api/v1/models/artifacts`, or `/api/v1/models/routes` read URLs; they use
`/v1/model-capabilities`, `/v1/models/catalog/search`, and the other stable
`/v1` model read protocols from Slice 1348. The workbench proof route scanner
now checks stable public read routes separately from the still-native
mutation/control aliases, and conformance scans CLI/SDK/proof/IDE client
surfaces plus product source-only clients so the retired read clients cannot
return. This remains non-terminal because mutation/control routes, backend
execution/materialization, hosted/provider transport, OAuth/auth-header
materialization, the invocation-authority blocker later superseded by Slice 1381, and later stable client protocol rows had not yet landed at that cut.

Slice 1352 hard-cuts stable model_mount operational read clients and retires
the native read aliases for that family. Public server status/logs/events,
backend list/logs, runtime-engine list/detail, instance list/loaded, and
authority snapshot reads now use `/v1/model-mount/*` stable daemon protocol
routes over the mounted Rust-owned model_mount read projections. CLI server,
backend, model `ps`, current proof scripts, product UI/desktop clients, and IDE
authority-binding surfaces moved off the older native read URLs. The daemon no
longer exposes `GET /api/v1/server/status`, `GET /api/v1/server/logs`,
`GET /api/v1/server/events`, `GET /api/v1/models/server`,
`GET /api/v1/backends`, `GET /api/v1/backends/{id}/logs`,
`GET /api/v1/models/backends`, `GET /api/v1/runtime/engines`,
`GET /api/v1/runtime/engines/{id}`, `GET /api/v1/models/runtime-engines`,
`GET /api/v1/models/instances`, `GET /api/v1/models/loaded`, or
`GET /api/v1/authority` as native read aliases. The generic
`GET /api/v1/models/:id` detail handler is retired as part of the stable
`GET /v1/models/{id}` read protocol. Conformance scans source-only clients and
focused route tests so these retired read aliases cannot return. This remains
non-terminal because mutation/control routes, live external backend binary spawning/supervision,
hosted/provider transport, live cTEE secret injection into outbound hosted network requests, invocation
authority depth, and later stable control-client rows had not yet landed at that cut.

Slice 1353 hard-cuts stable model_mount server-control protocol clients and
retires the native server-control aliases. Public server start/stop/restart now
use `POST /v1/model-mount/server/start`, `POST /v1/model-mount/server/stop`,
and `POST /v1/model-mount/server/restart`, authorize `server.control:*`, and
return mounted Rust daemon-core server-control records through the same
Agentgres-admitted server-control planner used by the prior record-state cut.
CLI server controls, current proof scripts, product UI actions, and daemon
contract tests moved off `POST /api/v1/server/start`,
`POST /api/v1/server/stop`, `POST /api/v1/server/restart`,
`POST /api/v1/models/server/start`, and `POST /api/v1/models/server/stop`.
The daemon native handler no longer exposes those aliases, focused route tests
assert they return `not_found` without calling server-control methods, and
conformance scans client surfaces so the retired control compatibility path
cannot return. At this cut the migration remained non-terminal because backend
execution/materialization, hosted/provider transport, OAuth/auth-header
materialization, the invocation-authority blocker later superseded by Slice 1381, and later stable control-client
rows had not yet landed.

Slice 1354 hard-cuts stable model_mount backend-control protocol clients and
retires the native backend lifecycle control aliases. Public backend
health/start/stop now use `POST /v1/model-mount/backends/{id}/health`,
`POST /v1/model-mount/backends/{id}/start`, and
`POST /v1/model-mount/backends/{id}/stop` over the mounted Rust daemon-core
backend-lifecycle planner and Agentgres record-state commit path. CLI backend
controls, current proof scripts, product UI/desktop probes, live-provider gates,
and daemon contract tests moved off `POST /api/v1/backends/{id}/health`,
`POST /api/v1/backends/{id}/start`, and
`POST /api/v1/backends/{id}/stop`. The daemon native handler no longer exposes
those aliases, focused route tests assert they return `not_found` without
calling backend lifecycle methods, and conformance scans client surfaces so the
retired backend-control compatibility path cannot return. This remains
non-terminal because live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable control-client rows had not yet landed at that cut.

Slice 1355 hard-cuts stable model_mount runtime-control protocol clients and
retires the native runtime survey/select/profile aliases. Public runtime
survey, selection, engine select-by-id, engine profile update, and profile
remove controls now use `POST /v1/model-mount/runtime/survey`,
`POST /v1/model-mount/runtime/select`,
`POST /v1/model-mount/runtime/engines/{id}/select`,
`PATCH /v1/model-mount/runtime/engines/{id}`, and
`DELETE /v1/model-mount/runtime/engines/{id}` over the mounted Rust
daemon-core runtime-survey/runtime-engine planners and Agentgres receipt or
record-state commit paths. CLI backend runtime controls, daemon contract tests,
validation proofs, product UI actions, and workbench route proofs moved off
`POST /api/v1/runtime/survey`, `POST /api/v1/runtime/select`,
`POST /api/v1/runtime/engines/{id}/select`,
`PATCH /api/v1/runtime/engines/{id}`, and
`DELETE /api/v1/runtime/engines/{id}`. The daemon native handler no longer
exposes those aliases, focused route tests assert they return `not_found`
without calling runtime-control methods, and conformance scans source clients so
the retired runtime-control compatibility path cannot return. This remains
non-terminal because model import/download/mount/load/unload, provider/vault/
catalog OAuth controls, live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable control-client rows had not yet landed at that cut.

Slice 1356 hard-cuts stable model_mount route-control protocol clients and
retires the native route write/test control aliases. Public route upsert and
route test now use `POST /v1/model-mount/routes` and
`POST /v1/model-mount/routes/{id}/test` over the mounted Rust daemon-core
route-control planner and Agentgres record-state commit path, preserving
`route.write:*` and `route.use:{id}` authority gates at the stable protocol
edge. CLI route tests, live/provider gates, desktop probes, validation proofs,
production polish and IDE-launch scripts, product UI route actions, and
inference harnesses moved off `POST /api/v1/routes` and
`POST /api/v1/routes/{id}/test`. The daemon native handler no longer exposes
those aliases, focused route tests assert they return `not_found` without
calling route-control methods, and conformance scans source clients so the
retired route-control compatibility path cannot return. This remains
non-terminal because model import/download/mount/load/unload, provider/vault/
catalog OAuth controls, live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable control-client rows had not yet landed at that cut.

Slice 1357 hard-cuts stable model_mount lifecycle protocol clients and retires
the native model import/mount/load/unload aliases. Public model artifact import
now uses `POST /v1/model-mount/artifacts/import`; endpoint mount, endpoint
load/unload, and endpoint unmount now use `POST /v1/model-mount/endpoints`,
`POST /v1/model-mount/endpoints/{id}/load`,
`POST /v1/model-mount/endpoints/{id}/unload`, and
`DELETE /v1/model-mount/endpoints/{id}`; instance load/unload now use
`POST /v1/model-mount/instances/load`,
`POST /v1/model-mount/instances/unload`, and
`POST /v1/model-mount/instances/{id}/unload`; estimate-only model load now uses
the same stable endpoint/instance load routes with canonical
`load_options.estimate_only`. These stable protocol routes run over the mounted
Rust daemon-core artifact-endpoint and instance-lifecycle planners, preserve
the `model.import:*`, `model.mount:*`, `model.unmount:*`, `model.load:*`, and
`model.unload:*` authority gates, and return Agentgres record-state truth. CLI
lifecycle commands, IDE workbench actions, validation proofs, live-provider
gates, production-polish scripts, product UI lifecycle actions, and inference
harnesses moved off `POST /api/v1/models/import`,
`POST /api/v1/models/mount`, `POST /api/v1/models/estimate-load`,
`POST /api/v1/models/mounts`,
`POST /api/v1/models/mounts/{id}/load`,
`POST /api/v1/models/mounts/{id}/unload`,
`DELETE /api/v1/models/mounts/{id}`,
`POST /api/v1/models/instances/{id}/unload`,
`POST /api/v1/models/load`, and `POST /api/v1/models/unload`. The daemon native
handler no longer exposes those aliases, focused route tests assert they return
`not_found` without calling lifecycle methods, and conformance scans source
clients so the retired lifecycle compatibility path plus retired camelCase
load-policy/load-option request selectors cannot return. This remains
non-terminal because model download/storage controls, provider/vault/catalog
OAuth controls, live external backend binary spawning/supervision, hosted/provider transport,
live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and broader
later stable control-client rows had not yet landed at that cut.

Slice 1358 hard-cuts stable model_mount storage-download protocol clients and
retires the native catalog import-url, model download, artifact delete, and
storage cleanup aliases. Public catalog import-url now uses
`POST /v1/model-mount/catalog/import-url`; model download queue/status/cancel
now uses `POST /v1/model-mount/downloads`,
`GET /v1/model-mount/downloads/{id}/status`, and
`POST /v1/model-mount/downloads/{id}/cancel`; storage cleanup now uses
`POST /v1/model-mount/storage/cleanup`; artifact delete now uses
`DELETE /v1/model-mount/artifacts/{id}`. These stable protocol routes run over
the mounted Rust daemon-core storage-control planner and Agentgres record-state
commit path, preserving `model.download:*`, `model.import:*`, and
`model.delete:*` gates at the stable protocol edge. CLI storage/download
commands, validation proofs, live-provider gates, desktop probes, daemon
contract tests, product UI storage/download actions, and workbench command
tests moved off `POST /api/v1/models/catalog/import-url`,
`POST /api/v1/models/download`, `GET /api/v1/models/download/status/{id}`,
`POST /api/v1/models/download/{id}/cancel`,
`POST /api/v1/models/download/cancel/{id}`,
`POST /api/v1/models/storage/cleanup`, and
`DELETE /api/v1/models/{id}` for artifact delete. The daemon native handler no
longer exposes those aliases, focused route tests assert they return
`not_found` without calling storage/download methods, and conformance scans
source clients so the retired storage/download compatibility path cannot
return. This remains non-terminal because provider/vault/catalog OAuth
controls, live external backend binary spawning/supervision, hosted/provider transport,
live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and broader
later stable control-client rows had not yet landed at that cut.

Slice 1359 hard-cuts stable model_mount provider-vault-token-catalog protocol
clients and retires the native provider, vault, token, and catalog-provider
control aliases. Public catalog-provider config and OAuth controls now use
`/v1/model-mount/catalog/providers/{id}` and
`/v1/model-mount/catalog/providers/{id}/oauth/{start,callback,exchange,refresh,revoke}`;
provider list/upsert/health/models/loaded/start/stop controls now use
`/v1/model-mount/providers*`; wallet vault refs/status/health controls now use
`/v1/model-mount/vault/*`; and capability-token list/create/revoke plus token
count now use `/v1/model-mount/tokens*`. These stable protocol routes preserve
the provider, vault, provider-control, and tokenizer authority gates at the
daemon protocol edge while forwarding into the mounted Rust daemon-core
model_mount control/projection APIs and Agentgres record-state truth. CLI
provider/vault/token commands, validation proofs, live-provider gates, product
UI actions, IDE workbench actions, and OAuth callback proofs moved off
`/api/v1/models/catalog/providers*`, `/api/v1/providers*`,
`/api/v1/vault*`, and `/api/v1/tokens*`. The daemon native handler no longer
exposes those aliases, focused route tests assert they return `not_found`
without calling provider/vault/token/catalog methods, and conformance scans
source clients so the retired compatibility path cannot return. This remains
non-terminal because live external backend binary spawning/supervision, hosted/provider
transport, live cTEE outbound injection depth, the invocation-authority blocker superseded by Slice 1381,
and later stable control-client rows had not yet landed at that cut.

Slice 1360 hard-cuts stable model_mount SDK control protocol clients. The
agent SDK now exposes named protocol-client methods for the full stable
model_mount control surface: route upsert/test, server start/stop/restart,
backend health/start/stop/logs, runtime survey/select/profile controls,
artifact import/delete, endpoint mount/unmount/load/unload, instance
load/unload, download/status/cancel, storage cleanup, catalog-provider config
and OAuth controls, capability tokens, vault refs/status/health, and provider
upsert/health/models/loaded/start/stop. These methods call only the stable
`/v1/model-mount/*` daemon protocol routes over the Rust-owned daemon-core
planners and Agentgres record/projection truth; the SDK source has no
authoritative `/api/v1` model_mount control request path, and focused SDK tests
drive the whole route family while asserting retired `/api/v1` control routes
do not return through the SDK. At this cut the migration remained non-terminal
because live external backend binary spawning/supervision, hosted/provider transport,
live cTEE outbound injection depth, the invocation-authority blocker later superseded by Slice 1381, and the
then-pending Workbench control surface still needed terminal Rust-owned protocol
coverage.

Slice 1361 hard-cuts stable model_mount Workbench control protocol clients. The agent
IDE now exports a full model_mount control route catalog and request builder for
route upsert/test, server start/stop/restart, backend health/start/stop/logs,
runtime survey/select/profile controls, artifact import/delete, endpoint
mount/unmount/load/unload, instance load/unload, download/status/cancel, storage
cleanup, catalog-provider config and OAuth controls, capability tokens, vault
refs/status/health, and provider upsert/health/models/loaded/start/stop. The
IDE protocol client builds only stable `/v1/model-mount/*` endpoints, rejects
retired camelCase model_mount control request aliases instead of translating
them, exports the surface through `@ioi/hypervisor-workbench`, and focused tests drive the
whole route family while asserting no `/api/v1` control path returns through the
IDE. Workbench actions remain stable protocol clients over the same daemon
routes. This remains non-terminal because live external backend binary spawning/supervision,
hosted/provider transport, live cTEE outbound injection depth, and
the invocation-authority blocker is superseded by Slice 1381.

Slice 1362 hard-cuts hosted provider env secret material fallback retirement.
Hosted provider default records no longer read provider API-key environment
variables to decide whether OpenAI, Anthropic, or Gemini providers are
configured. They publish wallet.network vault refs only, and the provider
registry rejects legacy plaintext secret arguments or camelCase `secretRef`
option shims instead of treating them as configuration. `AgentgresVaultPort`
no longer maps hosted provider vault refs to API-key environment aliases during
secret resolution; an env var can no longer become request-time hosted provider
material or a parallel custody truth path. Vault material must be explicitly
bound through the vault/material-adapter boundary, with plaintext persistence
remaining false and provider env fallback marked retired. Focused tests assert
hosted defaults stay blocked on vault refs, legacy plaintext helper inputs fail
closed, and env values do not resolve provider vault material. Conformance
guards the absence of provider API-key env aliases in the model_mount hosted
provider/vault path so the fallback cannot return. This remains non-terminal
because live external backend binary spawning/supervision, hosted/provider transport, live cTEE secret injection into outbound hosted network requests, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1363 deletes the backend-process supervisor facade stubs. The mounted
model_mount state no longer exposes `ensureBackendProcess()`,
`touchBackendProcess()`, `startBackendProcess()`,
`spawnBackendChildProcess()`, `stopBackendProcess()`, or
`backendProcessSnapshot()` as fail-closed JS compatibility surfaces. Public
backend health/start/stop/log/list paths already go through Rust daemon-core
backend-lifecycle planning, Agentgres record-state commits, and Rust
read-projection replay; this cut removes the leftover JS process-supervisor
method names and the `model_mount_backend_process_supervisor_retired` error
shim rather than preserving them as terminal scaffolding. Focused tests assert
the supervisor/snapshot methods are absent from the mounted facade while backend
lifecycle still commits Rust-authored records and backend logs still project
through Rust replay. Conformance now rejects restoring those method names or the
retired supervisor shim. This remains non-terminal because live external
backend binary spawning/supervision, hosted/provider transport, live cTEE
secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1364 deletes the mounted provider-driver factory facade stub. Provider
execution, provider lifecycle, provider inventory, and provider result admission
already flow through typed Rust daemon-core model_mount APIs and Agentgres
record-state commits; the mounted `ModelMountingState` no longer exposes
`driverForProvider()` as a fail-closed JS driver allocation path, and the
`model_mount_provider_driver_factory_retired` shim is gone. Focused provider
tests assert the facade is absent before any JS driver allocation can occur,
while lifecycle and inventory tests continue to prove fixture, native-local,
and hosted provider calls do not consult the inert JS driver sentinels.
Conformance now rejects restoring the method name, retired error code, or
provider-driver helper shim. This remains non-terminal because hosted/provider
transport, live external backend binary spawning/supervision, live cTEE secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1365 deletes the mounted receipt-authoring facade stubs. The mounted
model_mount state no longer exposes `lifecycleReceipt()` or `receipt()` as
fail-closed JS receipt-authoring compatibility surfaces. Rust-authored receipt
persistence remains available only through `persistRustAuthoredReceipt()` and
`persistRustAuthoredReceiptWithCommit()`, which require Rust receipt-author
markers plus Agentgres receipt-state commit before receipt truth can return.
Focused receipt tests assert the old authoring methods are absent while receipt
reads still delegate to the canonical store and non-Rust receipt persistence
still fails closed. Conformance now rejects restoring those method names,
`model_mount_js_receipt_creation_retired`, or the lifecycle receipt JS facade
evidence shim. This remains non-terminal because hosted/provider transport,
live external backend binary spawning/supervision, live cTEE secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1366 hard-cuts the public/runtime route store-core lifecycle fallback.
Public daemon request handling now receives the Rust `contextPolicyCore` as an
explicit request dependency from daemon service startup, and the public
doctor/computer-use/studio projections plus agent/thread/run lifecycle control
routes require that explicit core before any Rust projection or lifecycle
planner can execute. `runtime-route-handlers.mjs` no longer reads
`store.contextPolicyCore` for agent delete/status/run creation; focused route
tests remove `contextPolicyCore` from their store fixtures and pass the Rust
core explicitly. Conformance now rejects restoring `store.contextPolicyCore` or
`store?.contextPolicyCore` in the public/runtime route files and requires the
service-level explicit core handoff. This remains non-terminal because hosted
provider transport, live external backend binary spawning/supervision,
live cTEE secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1367 hard-cuts the hosted provider invocation JS backend predicate for
non-stream model invocation. This intermediate cut is now superseded by Rust
invocation authority planning: `invocation_authority.rs` builds the canonical
`ioi.model_mount.provider_invocation.v1` request with
`execution_backend: "rust_model_mount_hosted_provider"` for hosted provider
kinds such as OpenAI, Anthropic, Gemini, OpenAI-compatible, Ollama, vLLM,
llama.cpp, LM Studio, custom HTTP, and depin TEE instead of returning through a
JS unsupported-backend predicate. The Rust `provider_execution` owner receives
that hosted request through the direct API boundary. This cut was superseded by
the hosted transport-contract materialization cut below; live external hosted
API execution, live cTEE secret injection into outbound hosted network
requests, live external backend binary spawning/supervision, and the
invocation-authority blocker is superseded by Slice 1381.

Slice 1368 hard-cuts hosted provider invocation out of the generic unsupported
backend lane and into a Rust-owned wallet/vault/cTEE transport gate. Hosted
provider execution admission now carries redacted auth evidence from canonical
vault-ref configuration (`rust_model_mount_hosted_provider_auth_gate`,
`wallet_network_provider_vault_ref_bound`,
`ctee_hosted_provider_secret_not_exposed`, and a vault-ref hash) without
materializing plaintext or leaking the vault ref. Rust `provider_execution`
recognizes `rust_model_mount_hosted_provider` as a first-class hosted invocation
lane, validates the bound provider-execution record, requires wallet authority
grant/receipt refs plus hosted auth/cTEE evidence, and fails missing authority or
auth evidence with named Rust errors before execution. This remains
non-terminal because live cTEE secret injection into outbound hosted network requests, live external hosted API execution, live hosted streaming network I/O, actual Rust
live external backend binary spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1369 hard-cuts the hosted provider invocation temporary transport
boundary. The Rust `provider_execution` owner no longer returns a temporary
transport error after authority/auth validation. Hosted non-stream provider invocation now
materializes a Rust-owned `rust_model_mount_hosted_provider` result contract
with output text, token accounting, invocation hash, provider-auth evidence
refs, backend evidence refs, wallet transport authority evidence, cTEE
no-plaintext evidence, and a hosted auth-header materialization contract marker.
Rust provider-result admission now accepts hosted results only when the
execution backend is `rust_model_mount_hosted_provider`, the response kind is
`rust_model_mount.hosted_provider`, and the wallet/vault/cTEE plus hosted
transport materialization evidence is present; missing evidence or JS-observed
provider-result backends fail closed before accepted truth. Focused JS/Rust
tests and conformance require the positive hosted transport-contract path and
reject restoring the retired pending error. This remains non-terminal because
direct live external provider network I/O, live cTEE secret injection into
outbound hosted network requests, live hosted streaming network I/O, actual Rust
live external backend binary spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1370 hard-cuts hosted provider stream invocation out of the fail-closed
JS stream scaffold. Hosted stream request shaping now selects
`rust_model_mount_hosted_provider_stream` instead of returning
`model_mount_provider_invocation_rust_backend_required`; the Rust
`provider_execution/stream` owner validates the bound provider-execution
admission, wallet authority refs, and redacted vault/cTEE auth evidence before
materializing a Rust-owned hosted stream result contract. The stream result
binds output text, token accounting, stream chunks, invocation hash, provider
auth evidence refs, backend evidence refs, `rust_model_mount.hosted_provider.stream`,
and `rust_hosted_provider_stream_transport_materialized` evidence without
returning through JS provider drivers. Rust provider-result admission now
accepts hosted stream starts only when the execution backend is
`rust_model_mount_hosted_provider_stream`, `stream_status` is `started`, and the
wallet/vault/cTEE plus hosted stream transport materialization evidence is
present; JS-observed provider-result backends or missing hosted stream evidence
fail closed before accepted truth. Focused JS/Rust tests and conformance now
require the positive hosted stream path and reject restoring the old hosted
stream Rust-required fallback. This remains non-terminal because live hosted
network I/O, live cTEE secret injection into outbound hosted network requests,
live external backend binary spawning/supervision. The invocation-authority blocker is superseded by Slice 1381.

Slice 1371 hard-cuts hosted provider auth-header materialization into a Rust
daemon-core provider-auth materialization API. Provider upsert now calls
`planModelMountProviderAuthMaterialization` before provider-control truth can
commit; Rust `provider_auth_materialization` emits an Agentgres record under
`model-provider-auth-materializations` with wallet vault-ref binding, cTEE
outbound-header custody, redacted vault/header binding refs,
`auth_header_materialization_status: "rust_ctee_outbound_header_bound"`, and no
returned or persisted header value. Provider-control records bind the provider
to that materialization ref, hosted invocation/stream evidence carries
`rust_provider_auth_materialization_bound` plus
`hosted_provider_auth_header_materialized_by_rust`, and Rust provider
execution/result admission now rejects hosted truth without the bound
auth-materialization evidence. Focused JS/Rust tests and conformance guard the
positive typed API and reject restoring JS auth-header materializers or
command-shaped provider-auth materialization transport. This remains
non-terminal because live hosted network I/O, live cTEE secret injection into
outbound hosted network requests, live external backend binary
spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1372 hard-cuts model-load backend process materialization into a Rust
daemon-core API. `loadModel()` now calls
`planModelMountBackendProcessMaterialization` after Rust provider lifecycle
planning and before instance lifecycle truth can commit; Rust
`backend_process` emits an Agentgres `model-backend-process-materializations`
record with wallet backend-process authority, cTEE process custody, redacted
spawn-contract hash, `process_execution_owner:
"rust_daemon_core.model_mount.backend_process_materialization"`, and explicit
false markers for JS process supervision, command-transport spawn,
binary-bridge spawn, and compatibility spawn fallback. Rust instance lifecycle
`load` requests now require `backend_process_ref` and
`backend_process_materialization_hash`, and model-load record-state commits
write the backend-process materialization record before the model-instance
record. Focused JS/Rust tests and conformance require the positive typed API,
the Agentgres commit, the instance binding, and the absence of restored JS
child-process supervisor, command transport, or binary bridge spawn paths. This
remains non-terminal because live hosted network I/O, live cTEE secret
injection into outbound hosted network requests, live external backend binary
spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1373 hard-cuts hosted provider transport-input binding into the Rust
provider-invocation request contract. Hosted non-stream and stream invocation
requests now carry canonical `base_url`, `provider_auth_materialization_ref`,
`outbound_header_binding_ref`, and
`auth_header_materialization_status: "rust_ctee_outbound_header_bound"` fields
from admitted provider/endpoint records into `ModelMountProviderInvocationRequest`.
Rust `provider_execution` rejects hosted invocation before result materialization
unless the endpoint URL, wallet/cTEE auth-materialization refs, and outbound
header binding are present; Rust result hashes bind `base_url_hash` plus the
auth materialization refs, and evidence now records
`rust_hosted_provider_endpoint_url_bound` and
`ctee_outbound_header_binding_ref_bound`. Focused JS/Rust tests and conformance
guard that hosted invocation cannot rely on evidence-only auth claims or
JS-implied endpoint transport inputs. This remains non-terminal because live
hosted network I/O, live cTEE secret injection into outbound hosted requests,
live external backend binary spawning/supervision. The invocation-authority blocker is superseded by Slice 1381.

Slice 1374 hard-cuts hosted provider transport result binding into the Rust
provider-invocation and provider-result contract. Hosted non-stream and stream
provider results now carry Rust-authored `hosted_transport_request_ref`,
`hosted_transport_request_hash`, `hosted_transport_response_hash`, and
`hosted_transport_status: "rust_hosted_provider_transport_response_bound"`
fields, and Rust provider-result admission rejects hosted truth unless those
hashes and `rust_hosted_provider_transport_{request,response}_bound` evidence
are present beside the wallet/cTEE auth materialization evidence. The old
`deterministic_hosted_provider_output` helper and "Rust hosted provider
invocation contract" success text are retired from the Rust model_mount core, so
hosted success can no longer be proven by a loose deterministic message without
the Rust transport request/response binding. Focused JS/Rust tests and
conformance guard the hash fields, evidence refs, and retired helper/text. This
remains non-terminal because live hosted network I/O, live cTEE secret injection
into outbound hosted requests, live external backend binary
spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1375 hard-cuts backend-process supervision binding into the Rust
backend-process materialization and instance-lifecycle contract. Rust
`planModelMountBackendProcessMaterialization` now emits
`backend_supervision_ref`, `backend_supervision_hash`,
`backend_supervision_status`, `process_supervision_owner:
"rust_daemon_core.model_mount.backend_process_supervisor"`, and a
`supervision_contract` inside the Agentgres
`model-backend-process-materializations` record and public response. The
daemon facade validates those Rust-owned fields, requires
`rust_backend_process_supervision_bound`, and model-instance `load` requests now
fail closed unless they bind the backend supervision ref/hash/status beside
`backend_process_ref` and `backend_process_materialization_hash`. Focused
JS/Rust tests and conformance guard that a model load cannot fall back to the
old process-hash-only boundary or reintroduce JS child-process supervisor,
command-transport spawn, binary-bridge spawn, or compatibility-spawn truth.
This remained non-terminal at the cut because live hosted network I/O, live
cTEE secret injection into outbound hosted requests, backend launch/supervision
implementation,. The invocation-authority blocker is superseded by Slice 1381; backend launch/supervision is superseded by
Slice 1379 below.

Slice 1376 hard-cuts public backend lifecycle start onto the Rust
backend-process materialization/supervision contract. `startBackend()` now
requires a Rust `planModelMountBackendProcessMaterialization` record-state
commit before backend lifecycle truth can commit, resolves backend identity from
canonical request input or Rust backend read projection rather than a JS backend
registry, and forwards only the Rust materialization `backend_process_ref`,
`backend_process_materialization_hash`, `backend_supervision_ref/hash/status`,
and `process_supervision_owner` into the backend-lifecycle request. Rust
`plan_model_mount_backend_lifecycle` rejects `model_mount.backend.start`
without that process/supervision binding, records the binding in the
Agentgres `model-backend-lifecycle-controls` record/public response, and emits
`rust_backend_lifecycle_backend_process_materialization_bound`,
`rust_backend_lifecycle_backend_process_supervision_bound`, and
`backend_lifecycle_start_js_process_control_retired` evidence. Focused
JS/Rust tests and conformance guard the two-record start path, the direct typed
API normalizer, and the absence of restored JS process control. This remained
non-terminal at the cut because backend launch/supervision implementation and
the invocation-authority blocker is superseded by Slice 1381;
backend launch/supervision is superseded by Slice 1379 below, and the cTEE
egress resolver blocker is superseded by Slice 1380.

Slice 1377 hard-cuts hosted provider invocation off the deterministic Rust
transport-contract output and onto a Rust daemon-core live hosted transport
executor. `provider_execution` now uses blocking Rust `reqwest` POST execution
for hosted non-stream and hosted stream lanes, derives provider output from the
live response body, and sends only `provider_auth_materialization_ref`,
`outbound_header_binding_ref`, materialization status, and cTEE no-plaintext
custody headers across the egress boundary. The old hosted success-text path is
gone; focused Rust tests stand up a local HTTP server and assert the Rust core
performs `POST /v1/responses` with the cTEE/header-binding refs instead of
synthesizing output. Hosted result admission now requires
`rust_hosted_provider_live_network_io_executed`,
`rust_hosted_provider_transport_executor_owned`, and
`ctee_outbound_secret_injection_ref_bound` evidence beside the existing
transport request/response hashes, so evidence-only hosted result truth cannot
return. Focused JS/Rust tests and conformance guard the live executor evidence,
the cTEE ref-bound boundary, and the absence of the old deterministic hosted
success text. The cTEE egress resolver blocker is superseded by Slice 1380;
the invocation-authority blocker is superseded by Slice 1381.

Slice 1378 hard-cuts hosted provider stream semantics into the Rust daemon-core
transport owner. Hosted stream invocation no longer calls the non-stream hosted
transport body extractor and no longer slices a buffered hosted response into
deterministic stream frames. `provider_execution/stream` calls the Rust-owned
`hosted_provider_stream_transport_output` executor, sends the same
wallet/cTEE-bound no-plaintext custody headers with an event-stream accept
contract, parses SSE or newline-delimited JSON delta frames in Rust, rejects a
hosted stream response with no deltas, and emits IOI JSONL stream chunks from
those live deltas. Hosted provider-result admission now requires
`rust_hosted_provider_stream_live_chunks_executed`,
`rust_hosted_provider_stream_semantics_owned`, and
`rust_hosted_provider_stream_sse_chunks_bound` beside the existing hosted
transport hashes and cTEE binding evidence, so a hosted stream cannot be
admitted from generic network evidence or body-sliced compatibility output.
Focused Rust tests stand up a local SSE server and assert `POST /v1/responses`,
`Accept: text/event-stream`, cTEE/header-binding refs, live delta chunks, and
the stream evidence; JS protocol tests and conformance guard the result
admission shape and reject restoring `hosted_provider_transport_output(request)?`
inside the stream owner. The cTEE egress resolver blocker is superseded by Slice
1380; the invocation-authority blocker is superseded by Slice 1381.

Slice 1379 hard-cuts live backend-process launch and stop supervision into the
Rust daemon-core model_mount backend-process owner. Rust now exposes
`supervise_model_mount_backend_process` /
`daemonCoreModelMountApi.superviseModelMountBackendProcess` beside the existing
materialization API, keeps a Rust-owned child-process registry, launches
external backend binaries with `std::process::Command`, stops them through the
same Rust registry, and records no raw executable path, spawn args, or pid in
public protocol responses. Backend process materialization now binds the
executable hash, public `startBackend()` commits a Rust
`model-backend-process-supervisions` Agentgres record before lifecycle truth can
commit, public `stopBackend()` commits the Rust stop-supervision record before
backend lifecycle stop truth, and Rust `plan_model_mount_backend_lifecycle`
rejects start/stop lifecycle records without the live runtime
`backend_process_runtime_ref/hash/status` binding. Focused Rust tests start and
stop a live child handle, focused JS tests assert the materialize -> supervise
-> lifecycle commit order, and conformance rejects planner-only starts, JS
child-process supervision, command-transport spawn, binary-bridge spawn, and
compatibility-spawn fallback. The cTEE egress resolver blocker is superseded by
Slice 1380; the invocation-authority blocker is superseded by Slice 1381.

Slice 1380 hard-cuts hosted cTEE egress resolver binding into the Rust
daemon-core model_mount provider-auth and hosted transport owners. Rust
`plan_model_mount_provider_auth_materialization` now emits a redacted
`ctee_egress_resolver_ref`, `ctee_egress_resolver_hash`, and
`ctee_egress_resolution_status: rust_ctee_outbound_egress_resolved` alongside
the provider-auth materialization ref and outbound-header binding ref, records
`rust_ctee_egress_resolver_bound` and
`ctee_outbound_egress_resolver_depth_bound` evidence in the Agentgres
provider-auth materialization record, and provider-control preserves those
fields instead of re-materializing auth in JS. Rust hosted invocation and stream
execution now reject `rust_model_mount_hosted_provider*` requests without the
cTEE egress resolver binding, bind the resolver ref/hash/status into the hosted
transport request/response hashes, and send resolver identity headers without
returning plaintext secret material. Rust provider-result admission now requires
the resolver ref/hash/status and resolver evidence before hosted non-stream or
stream truth can be accepted. JS surfaces are only protocol shapers for these
fields; focused Rust/JS tests and conformance guard the missing-resolver Rust
error, hosted transport headers, provider-result admission fields, and the
absence of command/env or JS provider-auth fallback. The invocation-authority
blocker is superseded by Slice 1381.

Slice 1381 hard-cuts model_mount invocation authority planning into the Rust
daemon-core model_mount owner. Rust now exposes
`plan_model_mount_invocation_authority` /
`daemonCoreModelMountApi.planModelMountInvocationAuthority`, and the model
invocation hot path consumes Rust-authored plans for provider-execution
request shape, provider invocation or stream invocation request shape,
provider-result admission request shape, invocation-admission request shape,
accepted-receipt transition request shape, and receipt-binding StepModule
projection request shape. The production JS hot path no longer calls the old
JS contract constructors for those requests; it only gathers canonical
protocol facts, asks the Rust authority planner for each admitted operation,
and then commits through the existing Rust Agentgres admission, receipt
state-root, replay, and StepModule binding APIs. Hosted/cTEE transport fields
such as endpoint `base_url`, auth materialization refs, outbound-header
binding refs, hosted transport hashes, and cTEE egress resolver refs are
preserved through the JS protocol shaper so Rust provider-result admission
receives the same custody/transport bindings it must verify. Focused Rust and
JS tests cover provider-execution planning, receipt-binding StepModule
projection planning, invocation/stream operation ordering, and missing-plan
fail-closed behavior. Conformance now rejects a model invocation hot path that
returns to JS contract authoring, command/env fallback, binary bridge fallback,
or unguarded compatibility shape for provider execution, provider invocation,
provider-result admission, invocation admission, accepted receipt transition,
or receipt binding.

Slice 1382 deletes the production JS model_mount invocation contract helper
surface after Rust daemon-core parity is verified. `model-invocation-operations.mjs`
no longer exports or implements the old provider-execution, provider-invocation,
provider-stream-invocation, provider-result-admission, invocation-admission,
accepted-receipt-transition, receipt-binding, or provider-invocation
requires-Rust helper constructors/predicates. The public `invokeModel()` and
`startModelStream()` facades now have only one authoritative substrate: gather
canonical protocol facts, require `planModelMountInvocationAuthority()`, consume
the Rust-authored request for each operation, and fail closed before any
provider execution, Agentgres admission, receipt persistence, state-root
transition, replay, or StepModule projection can proceed without that Rust plan.
Focused tests use local test-only Rust-plan fixtures rather than a production JS
contract builder, assert the retired helper exports are absent, and prove the
facade fails closed when the Rust planner is missing. Conformance now rejects
restoring the helper export names, helper alias table, JS receipt-detail builder,
false-predicate exports, or old direct helper tests beside the Rust invocation
authority planner.

Slice 1383 deletes backend-process fallback-proof protocol fields from the
Rust daemon-core model_mount backend-process materialization and live
supervision contracts. Rust `backend_process.rs` no longer serializes
`retired_paths`, `js_process_supervisor`, `command_transport_spawn`,
`binary_bridge_spawn`, or `compatibility_spawn_fallback` fields in
backend-process materialization seeds, Agentgres records, supervision
contracts, public responses, or live-supervision records. The JS daemon facade
and direct model_mount core now reject those fields if a Rust plan attempts to
return them, while preserving positive evidence refs for the retired JS
supervisor, command-transport spawn, and binary-bridge spawn boundaries. Focused
Rust and JS tests assert absence/rejection, and conformance guards that the
old false-field compatibility proof cannot reappear beside the Rust
backend-process owner.

Slice 1384 hard-cuts stable model_mount snapshot, projection, MCP workflow,
and workflow-node protocol clients. Public daemon routes now expose
`GET /v1/model-mount/snapshot`, `GET /v1/model-mount/projection`,
`GET /v1/model-mount/mcp`, `POST /v1/model-mount/mcp/import`,
`POST /v1/model-mount/mcp/invoke`,
`POST /v1/model-mount/workflows/nodes/execute`, and
`POST /v1/model-mount/workflows/receipt-gate` over the mounted Rust-owned
model_mount read projection, MCP workflow, StepModule dispatch, and receipt-gate
planning surfaces. The older native aliases `GET /api/v1/models`,
`GET /api/v1/models/events`, `GET /api/v1/projections/model-mounting`,
`POST /api/v1/workflows/nodes/execute`,
`POST /api/v1/workflows/receipt-gate`, `POST /api/v1/mcp/import`, and
`POST /api/v1/mcp/invoke` no longer route through the daemon native handler or
product/proof/Workbench clients. Rust `workflowBindings` projection records now
advertise the stable `/v1/model-mount/workflows/*` daemon API paths rather than
the retired `/api/v1/workflows/*` paths. Focused route tests assert the stable
routes call the Rust-owned model_mount methods and the retired aliases return
`not_found` without touching snapshot, projection, MCP, workflow, or receipt-gate
methods; conformance scans product/proof/SDK/CLI/IDE/workbench source clients so
the old aliases cannot return as client fallbacks.

Slice 1385 hard-cut shipped workbench workflow-composer generated media in the
retired `ioi-workbench` tree. The historical workflow-composer bundle and
sourcemap were regenerated from the stable protocol client sources and refreshed
`@ioi/hypervisor-workbench` build output, so the shipped webview media now carries
`/v1/model-mount/projection` and
`/v1/model-mount/workflows/nodes/execute` instead of the retired
`/api/v1/projections/model-mounting` or `/api/v1/workflows/*` aliases. This
closes the stale generated-JS facade that could preserve split-brain route
behavior after source parity was verified. Conformance now scans the generated
workbench bundle, sourcemap, and available hypervisor-workbench dist artifacts alongside
source clients, and it requires the stable generated bundle routes while
rejecting the retired aliases.

Slice 1386 hard-cuts the Authority Center product evidence client fallback.
The product Authority Center runtime now calls the canonical
`/v1/authority-evidence` Rust lifecycle projection protocol directly and no
longer tries the retired `/api/v1/authority-evidence`,
`/api/v1/authority-evidence-summaries`,
`/api/v1/workflow-capability-preflight-evidence`, or
`/api/v1/workflow-capability-preflight` compatibility chain. This keeps the
product surface as a non-authoritative protocol client over Rust-owned
Agentgres replay records instead of an alternate native evidence/preflight
truth path. Conformance now scans the product runtime and wiring test so the
retired fallback URLs cannot return.

Slice 1387 hard-cuts runtime tool catalog product and IDE client fallbacks.
The `@ioi/hypervisor-workbench` tool capability binding export now names only the
canonical `/v1/tools` Rust runtime tool catalog projection protocol, workflow
capability repair actions advertise `/v1/tools` instead of the retired
`/api/v1/tools` native route, and the product Authority Center runtime calls the
tool catalog directly through that stable protocol constant. The short-lived
product fallback helper is deleted rather than retained as a compatibility
chain, so model/tool catalog reads in the authority surface are protocol-client
reads over Rust-owned projection records, not alternate native catalog truth.
Focused IDE/product tests and conformance now reject restoring `/api/v1/tools`
or the multi-path fetch helper beside `/v1/tools`.

Slice 1388 hard-cuts the run-create repository workflow JS projection facade.
Run creation and runtime-service turn submission now require the explicit Rust
repository workflow projector and call `projectRepositoryWorkflow` for
repository context, branch policy, GitHub context, PR attempts, issue context,
review gate, and GitHub PR create-plan truth before the run candidate can be
planned through the Rust lifecycle API. The old JS repository context,
projection, and workflow projection modules and tests are deleted rather than
kept as fail-closed compatibility shells. PR branch/diff run artifacts now bind
to Rust-authored artifact metadata and hashes instead of reading the retired JS
`artifactContents` side channel. Conformance tombstones the deleted files,
requires the explicit projector wiring, and rejects restoring the old helper
names beside the Rust projection path. Repository workflow still has terminal
work for durable Agentgres-backed persistence/replay, wallet authority on
external exits, receipt/state-root binding, and stable protocol APIs; this cut
removes the duplicate JS projection truth path from the daemon hot run-create
path.

Slice 1389 hard-deletes the remaining local runtime-engine helper module.
`packages/runtime-daemon/src/model-mounting/local-runtime-engines.mjs` and its
focused test are absent, `model-mounting.mjs` has no local-runtime-engine import,
and conformance now treats JS llama.cpp binary discovery/library-path
materialization as retired. Runtime-engine public mutation/projection truth
remains Rust-owned through `planModelMountRuntimeEngine`, Agentgres
`runtime-engine-controls` replay, and Rust backend-process materialization /
live-supervision records; JS may remain only a protocol client.

Slice 1390 hard-cuts stable model_mount invocation protocol clients. Product,
proof, desktop, live-gate, and daemon-contract callers now use
`POST /v1/chat/completions`, `POST /v1/responses`, and
`POST /v1/embeddings` for admitted model invocation work instead of the retired
daemon-native `POST /api/v1/chat`, `POST /api/v1/responses`, and
`POST /api/v1/embeddings` aliases. The stable protocol response helpers expose
Rust-authored receipt, route, endpoint, backend, route-decision, response,
tool-receipt, and output metadata so replay/projection and receipt-gate probes
do not need the native invocation shape. The native alias handlers and native
embedding response shim are absent, focused route tests require the aliases to
return `not_found` without invoking model execution, and conformance scans the
product/proof/live validation corpus so those compatibility paths cannot return.
Utility protocol clients were still native at this cut and are superseded by
Slice 1391. Live external backend spawning/supervision, hosted/provider
transport materialization, and live cTEE outbound secret injection remain
non-terminal; do not restore `/api/v1` invocation aliases beside the stable
Rust-owned invocation protocol.

Slice 1391 hard-cuts stable model_mount utility protocol clients. Public
tokenize/count/context-fit utility clients now use
`POST /v1/model-mount/tokens/tokenize`, `POST /v1/model-mount/tokens/count`,
and `POST /v1/model-mount/context/fit` over the mounted Rust daemon-core
tokenizer planner and Agentgres record-state commits, while rerank uses
`POST /v1/rerank` and requires Rust/provider-authored ranking output with
receipt metadata instead of any JS ranking fallback. CLI, SDK, daemon-contract,
UI-contract, and live e2e proof clients moved off `POST /api/v1/tokenize` and
`POST /api/v1/context/fit`; the unused `POST /api/v1/rerank` native alias is
also retired. The native utility handlers and the old `nativeInvocationResponse`
helper are absent, focused route tests require all retired utility aliases to
return `not_found` without invoking model execution/tokenizer methods, and
conformance scans runtime, CLI, SDK, proof, and docs so those compatibility paths
cannot return. Live external backend spawning/supervision, hosted/provider
transport materialization, and live cTEE outbound secret injection remain
non-terminal; do not restore `/api/v1` utility aliases, JS ranking fallbacks, or
native invocation response helpers beside stable Rust-owned daemon protocol
routes.

Slice 1392 hard-cuts runtime context-policy adapter bridge-result normalizer
names. `RuntimeContextPolicyCore` no longer exports or calls
`normalize*BridgeResult` JS protocol normalizers for migrated coding-tool,
diagnostics, task/job, doctor/computer-use/studio, MCP serve, workflow-edit,
managed-session, workspace-change, thread-fork, conversation-artifact, or
subagent runtime families; the shared helper is
`requiredContextPolicyOperationKind` instead of
`requiredContextPolicyBridgeOperationKind`. The adapter remains a typed protocol
client over Rust-owned direct daemon-core control/projection APIs, and
conformance rejects restoring the old bridge-shaped normalizer names beside
those APIs. Remaining work is durable replay/projection/storage depth and stable
IDE/CLI/SDK coverage for non-terminal route families, not a JS bridge-result
compatibility layer.

Slice 1393 hard-cuts hosted provider vault-ref record alias fallback. Hosted
provider defaults and provider-registry records now publish canonical
`secret_ref` only, while model invocation and provider-control canonicalization
read only `secret_ref`, `auth_vault_ref`, and `api_key_vault_ref`; stale
provider or endpoint records carrying `secretRef`, `authVaultRef`, or
`apiKeyVaultRef` fail closed before Rust provider-execution admission or
provider-control truth can be planned. This removes the leftover JS record-shape
compatibility path beside Rust provider-auth materialization, wallet.network
vault refs, and cTEE outbound-header custody. Remaining hosted-provider work is
deeper live transport/cTEE egress and durable protocol API depth, not camelCase
vault-ref compatibility.

Slice 1394 hard-cuts repository workflow lifecycle-runner projector fallback.
Run creation and runtime-service turn submission now pass only an explicit
`repositoryWorkflowProjector` into run candidate construction, and public
agent-run routes inject the mounted `contextPolicyCore` repository workflow
projection API directly. The lifecycle state-update runners no longer double as
repository workflow projectors through `deps.repositoryWorkflowProjector ?? ...`
fallbacks, so repository context, branch policy, GitHub context, PR attempt,
issue context, review gate, and GitHub PR create-plan truth cannot return
through the run-create or runtime-bridge lifecycle runner boundary. Focused
tests prove a lifecycle runner with `projectRepositoryWorkflow()` is ignored
unless it is explicitly passed as the repository workflow projector, and
conformance rejects restoring the fallback beside the Rust
`project_repository_workflow` API. Repository workflow remains non-terminal for
durable Agentgres-backed persistence/replay, wallet authority on external
exits, receipt/state-root binding, and broader stable clients; the retired path
is the lifecycle-runner compatibility projector.

Slice 1395 hard-cuts migrated runtime replay state-dir fallback.
Managed-session projection/control, workspace-change projection/control, and
conversation-artifact projection/control now require the daemon Agentgres
`store.stateDir` before Rust planning or projection can run. They no longer
derive `state_dir` from per-family JS stores such as
`store.managedSessions.stateDir`, `store.workspaceChanges.stateDir`, or
`store.conversationArtifacts.stateDir`, so migrated Rust replay/admission
families cannot use a local JS store as a compatibility replay root when the
daemon state root is absent. Focused tests seed those retired per-family
state-dir handles and prove projection/control fails before Rust invocation,
event admission, artifact commit, or JS candidate readback. Conformance guards
the daemon-only state-dir helpers and rejects restoring the per-family fallback
beside Rust Agentgres replay.

Slice 1396 hard-cuts proof contract native route fallbacks.
The live runtime daemon authority-evidence proof now reads canonical
`/v1/authority-evidence` lifecycle projection and asserts retired
`/api/v1/authority-evidence` returns `not_found`. The model_mount daemon
contract keeps MCP import/invoke on `/v1/model-mount/mcp/*` and asserts retired
`/api/v1/mcp` returns `not_found` instead of treating the native alias as a
Rust-required projection path. Conformance scans these proof contracts so
proof/live validation clients cannot preserve native-route split-brain fallback
behavior beside Rust-owned protocol projections.

Slice 1397 hard-cuts model_mount native API metadata.
Rust model_mount server-status and authority projections no longer emit
`nativeBaseUrl`, the Rust runtime doctor report no longer advertises `nativeApi`,
and product/workbench model surfaces no longer render a "Native API" fallback or
derive `/api/v1` from server metadata. The daemon proof now asserts the retired
field is absent while preserving the stable `/v1` OpenAI-compatible protocol
base, and conformance scans Rust producers plus product/proof clients so retired
native endpoint breadcrumbs cannot return as discoverable split-brain metadata.

Slice 1398 hard-cuts run-memory command parsing into Rust daemon core.
`#remember`, `/memory`, `/memory show`, `/memory enable`, `/memory disable`,
`/memory path`, `/memory edit`, and `/memory delete/remove/forget` command
classification now enters Rust through
`daemonCoreThreadMemoryApi.planRuntimeMemoryCommand` and
`RuntimeKernelService::plan_runtime_memory_command` before run-memory
resolution can read policy, write records, edit/delete memory, or inject
records. The daemon resolver calls `planRunMemoryCommand()` and fails closed
with `memory_command_plan` if the Rust planner is missing; daemon startup no
longer imports or injects `memory-command-parser.mjs`, and the file is deleted.
JS remains a protocol client for the Rust-planned command record plus the
existing Rust memory projection/control surfaces. Conformance guards the typed
thread-memory API, Rust parser tests, resolver fail-closed behavior, and parser
file/import absence so the JS grammar facade cannot return as a duplicate truth
path.

Slice 1399 hard-cuts runtime MCP manager config-compatibility transport.
`mcp-manager.mjs` now sends only `source`, `source_path`, and `source_scope`
provenance into Rust MCP validation input, no longer creates inline/global/
workspace `compatibility` source metadata, and no longer forwards
`config_compatibility` into the Rust daemon-core MCP manager catalog path. Rust
`McpServerValidationInputCore` rejects retired `config_compatibility` and
`configCompatibility` fields anywhere in the validation input, strips the field
from manager status/server records, excludes it from MCP evidence refs, and
serializes no `config_compatibility` output. Focused JS/Rust tests and
conformance now require the field to be absent or fail-closed so MCP registry
truth cannot preserve a config-source compatibility side channel beside the
Rust-owned manager/catalog projection.

Slice 1400 hard-cuts the run-cancel admission-required JS direct API. Public
run cancellation now has one JS-facing Rust authority call:
`daemonCoreRuntimeControlApi.planRunCancelStateUpdate`. When that positive
state planner is missing, `cancelRun()` emits the canonical fail-closed
`runtime_run_cancel_rust_core_required` error locally and no longer invokes a
`planRunCancelAdmissionRequired` hook, shapes a returned refusal record, or
keeps the retired request schema/API method on `RuntimeContextPolicyCore`.
Focused cancellation tests prove the old hook is ignored, context-policy tests
prove the direct API method is absent, and conformance now rejects the old JS
method, schema, hot-path call, and positive admission-required test so this
fallback cannot return beside the Rust-owned cancel state-update path.

Slice 1401 hard-cuts active skill/hook run materialization into Rust daemon
core. Run creation now sends only a
`skill_hook_materialization_request` envelope with run/agent/workspace/home and
selection facts; `RunCreateStateUpdateCore` calls the Rust skill/hook catalog
discovery core, materializes the active manifest, hook dry-run plan, invocation
ledger, escalation receipts, runtime events, artifacts, trace bindings, prompt
audit refs, and runtime-task manifest id during Rust run-create planning, then
removes the request before Agentgres persistence. `buildRun()` no longer imports
or calls the JS manifest planner, the `skill-hook-manifest.mjs` facade and test
are deleted, and Rust rejects run candidates that already carry
`activeSkillHookManifest`, `hookDryRunPlan`, or `hookInvocationLedger` truth so
the retired JS authoring path cannot return as a compatibility fallback.
Conformance now guards the deleted JS files/imports/event builders plus the
Rust materializer, retired-candidate rejection, and Rust-authored
manifest/dry-run/invocation artifact outputs.

Slice 1402 hard-cuts runtime task/job/checklist run materialization into Rust
daemon core. Run creation now sends only deterministic ids plus
`rust_daemon_core_runtime_task_job_materialization_request` evidence refs into
`RunCreateStateUpdateCore`; Rust derives the `runtimeTask`, `runtimeJob`, and
`runtimeChecklist` records, receipts, events, artifacts, trace bindings,
task-state facts, and prompt-audit refs during run-create planning. The daemon
`buildRun()` path no longer imports or calls `runtime-record-projections.mjs`,
no longer emits JS-authored runtime task/job/checklist records, receipts,
events, artifacts, or trace truth, and the `runtime-record-projections.mjs`
facade plus focused test are deleted instead of preserved as fail-closed
compatibility scaffolding. Rust rejects prebuilt top-level or trace
`runtimeTask`, `runtimeJob`, and `runtimeChecklist` candidates, while the
run-read projection client uses canonical Rust sidecar ids (`job_${run.id}` and
`checklist_${run.id}`) rather than injected JS record builders. Conformance now
guards the deleted facade/test/import, the missing JS record builders, the Rust
materializer, retired-candidate rejection, and Rust-authored
`runtime-task.json`, `runtime-job.json`, and `runtime-checklist.json` artifacts
so this task/job truth path cannot fall back through JS projection authoring.

Slice 1403 hard-cuts the remaining JS memory-manager projection facade and dead
direct mutation shim. The daemon no longer imports `memory-manager.mjs`, the
`memory-manager.mjs` facade and focused test are deleted, `thread-memory-state`
no longer accepts `memoryRowsForStatus` or exposes `recordThreadMemoryMutation`,
and the route-facing memory status/validation flow enters through the Rust
thread-memory read projection plus Rust memory-control event planner only.
Conformance now requires the deleted files/imports/shim to stay absent while
preserving the typed Rust `planMemoryManagerStatusProjection`,
`planMemoryManagerValidationProjection`, `projectRuntimeMemoryProjection`, and
`planRuntimeMemoryControl` APIs, so status, validation, public memory reads, and
public memory mutation cannot keep a standalone JS facade beside the Rust-owned
thread-memory projection/control spine.

Slice 1404 hard-cuts provider-inventory catalog/evidence materialization out of
the JS request facade. Public provider inventory still enters through the
typed Rust daemon-core `plan_model_mount_provider_inventory` API, but the daemon
request no longer carries `item_refs` or `evidence_refs`; Rust now derives
native-local, fixture, and hosted metadata item refs, owns the inventory evidence
set, writes those refs into the transport contract and Agentgres
`model-provider-inventory` record, and rejects caller-authored inventory refs or
evidence as retired truth transport. The deleted JS `providerInventoryItemRefs`
and `providerInventoryEvidenceRefs` helpers cannot return as compatibility
scaffolding, while conformance guards both the Rust rejection and the JS
request-field absence. This cut removes the duplicate JS catalog/evidence
authoring path from the migrated hot path; Slice 1405 moves hosted `list_models`
live catalog transport itself into Rust.

Slice 1405 hard-cuts hosted provider `list_models` catalog execution into Rust
daemon core. Hosted provider inventory requests now forward only canonical
endpoint, provider-auth materialization, outbound header binding, and cTEE egress
resolver refs; Rust requires a hosted `base_url`, executes the live catalog GET
(`/models` for OpenAI-compatible endpoints and `/api/tags` for Ollama), parses
provider model ids, binds the request/response hashes plus endpoint hash into
the transport contract and `model-provider-inventory` Agentgres record, and
emits live-network and cTEE custody evidence before public inventory truth can
return. The JS edge cannot provide hosted model refs, evidence refs, fallback
proof fields, or deterministic placeholder catalog truth, and conformance now
guards the Rust transport executor, live network evidence, request/response hash
binding, missing-endpoint failure, and JS request-field absence. Slice 1409
hardens this hosted catalog edge so provider-auth materialization plus cTEE
outbound secret-injection binding are required before network I/O. Remaining
model_mount blockers for this lane are deeper wallet/cTEE route authority and
revocation policy, richer provider replay joins, and stable
Workbench/CLI/SDK protocol coverage over the admitted Rust records.

Slice 1406 hard-cuts provider-inventory endpoint materialization into Rust
read-projection ownership. `listEndpoints()` now replays admitted
`model-provider-inventory/*.json` records in Rust, admits hosted inventory only
when the Rust-hosted catalog transport contract and cTEE no-plaintext evidence
are present, materializes stable endpoint records from the Rust provider/model
inventory tuple, carries hosted catalog request/response hashes and endpoint URL
binding into the projection, and filters JS-authored hosted inventory rows before
they can become endpoint truth. The stale gap where hosted provider inventory
could carry model catalog truth without endpoint projection truth is retired; JS
endpoint maps, JS provider inventory rows, command/binary fallback proof fields,
and compatibility endpoint materializers remain absent from the hot path.

Slice 1407 hard-cuts hosted download materialization into Rust storage-control
ownership. `plan_model_mount_storage_control` now recognizes explicit
`download_materialization_kind: "hosted_download"` and related canonical
materialization requests, executes the bounded HTTP GET in Rust, enforces
`max_bytes`, verifies optional `sha256:` checksums, and binds source request,
transport response, and content hashes into the `model-downloads` Agentgres
record before public truth can return. The committed record carries
`rust_hosted_download_materialized`,
`rust_hosted_download_transport_response_bound`, cTEE egress/auth materialization
refs, and a no-plaintext custody policy; it never returns the plaintext source
URL, payload, or artifact bytes to JS. `downloadModel()` only forwards canonical
contract fields to Rust, while Rust storage read projection admits hosted
downloads only when the Rust transport/custody evidence is present and filters
fake JS-hosted materialized rows. Conformance now guards the Rust executor,
bounded transfer, request/response/content hash binding, no-plaintext custody,
JS field forwarding, projection admission filter, and removal of hosted download
materialization from the non-terminal blocker ledger.

Slice 1408 hard-cuts artifact-delete and storage-cleanup filesystem custody
into Rust storage-control ownership. `deleteModelArtifact()` and
`cleanupModelStorage()` now forward only canonical snake_case custody contract
fields; retired camelCase storage/root/path/custody aliases fail before the Rust
boundary. Rust `plan_model_mount_storage_control` validates that each requested
filesystem target exists under the declared `storage_root`, hashes root and
target refs, records cTEE no-plaintext path custody evidence, and executes or
dry-runs the mutation without returning plaintext paths to JS. Conformance now
guards the Rust custody planner, containment check, custody evidence refs,
alias rejection, and absence of JS filesystem mutation truth.

Slice 1409 hard-cuts cTEE outbound secret-injection depth for hosted catalog and
download network edges. Rust `model_mount/lifecycle/inventory.rs` now rejects
hosted provider `list_models` catalog transport unless the request carries a
Rust provider-auth materialization ref, outbound header binding ref,
`rust_ctee_outbound_header_bound` status, cTEE egress resolver ref/hash, and
`rust_ctee_outbound_egress_resolved` status before any HTTP client is built. The
hosted catalog transport contract and Agentgres `model-provider-inventory`
record persist those refs plus `ctee_outbound_secret_injection_ref/hash/status`,
and the evidence set includes provider-auth materialization, cTEE egress
resolver, outbound secret-injection, and hosted catalog no-plaintext custody
proof. Rust `model_mount/storage_control.rs` applies the same preflight to
hosted downloads before the bounded GET, persists the secret-injection binding
into `model-downloads`, and emits the matching evidence. The JS provider
inventory facade no longer translates retired camelCase auth/egress fields, and
the provider-inventory result validator rejects hosted catalog truth without the
Rust cTEE/auth binding before Agentgres commit. Focused Rust and Node tests cover
the positive hosted catalog/download paths and the missing-auth/missing-cTEE
fail-closed cases, while conformance guards the hard requirement and the removed
compatibility translation. Remaining model_mount work is deeper wallet/cTEE route
authority and revocation policy, conversation replay depth
where still adapter-shaped, and stable Workbench/CLI/SDK protocol APIs over the
Rust records.

Slice 1410 hard-cuts the run-memory command parser store-core fallback. The
daemon now passes the already-mounted `contextPolicyCore` into
`createRunMemoryResolution()` as the direct `runtimeMemoryCommandPlanner`, and
`run-memory-resolution.mjs` calls only that dependency before memory
projection/control can run. A missing direct planner fails closed with
`memory_command_plan`, while a stale `store.contextPolicyCore` cannot become a
fallback command parser. Focused tests prove the direct planner is used, a
hostile store-mounted core is ignored, and the missing-direct-planner path fails
before JS command parsing, while conformance guards the retired store lookup
beside the already-deleted JS regex parser.

Slice 1411 hard-cuts operator turn-control JS run-candidate transport. Public
operator interrupt/steer still call the typed Rust daemon-core
`planOperatorInterruptStateUpdate` / `planOperatorSteerStateUpdate` APIs through
the mounted `contextPolicyCore`, but the request now sends only `state_dir`,
`event_stream_id`, turn identity, and operator intent. Rust
`policy/operator_control.rs` replays the target run from admitted
`runs/*.json`, derives the next event sequence from `events/*.jsonl`, rejects
retired `run`/`runs`/`agent`/candidate-run fields, and returns the only
mutable run projection that JS may commit through Agentgres `writeRun()`. The
thread-turn surface no longer calls `agentForThread()` or
`resolveRunForThreadTurn()` before operator-control planning, and focused JS
tests assert that `run`, `run_id`, `agent`, and candidate transports are absent
from the planner request. Conformance now guards the Rust state-dir replay
helper, the retired candidate-field rejection tests, and the absence of the JS
resolver/candidate request path so the operator-control hot path cannot return
to JS run truth while keeping the old command/binary bridge deleted.

Slice 1412 hard-cuts the pre-Hypervisor JS facade roots. The former product app
root and former embedded Workbench implementation root are deleted instead of
kept as compatibility aliases. The product client now lives under
`apps/hypervisor` as `@ioi/hypervisor-app`, Code editor adapter code lives under
`packages/hypervisor-adapter-targets/code-editors/vscode-extension`, root scripts and conformance scan those new
roots, and active Rust/Node tests no longer include or execute the deleted
paths. The remaining JS there is product/workbench protocol-client surface over
daemon `/v1` APIs; conformance now fails if the retired live JS facade roots,
embedded Workbench facade root, old generated-contract carveout, or root
workspace script path returns.

Slice 1413 hard-cuts the runtime MCP/model_mount legacy fallback-proof field
protocol from production hot paths. MCP serve, MCP control, model_mount MCP
workflow, provider inventory/lifecycle, and backend-process materialization
validators no longer enumerate the exact retired JS/command/binary bridge/
compatibility fallback proof fields as a compatibility contract. The live
validators enforce the positive Rust result contract and reject any retired
authority key by shape, while focused tests and conformance keep the old fields
as negative fixtures only. Rust MCP live-result replay/backend validators use
the same generic retired-authority-key rejection, so migrated MCP and
model_mount truth cannot return through a false-valued fallback-proof schema
beside Rust-owned admission, receipt/state-root binding, Agentgres commit, and
replay.

Slice 1414 hard-cuts runtime thread-fork source candidate transport. Public
thread fork still enters through the daemon-mounted auxiliary protocol client,
but JS now sends only `thread_id`, `event_stream_id`, daemon `state_dir`, and
canonical operator request facts to `plan_runtime_thread_fork_control`. Rust
`runtime_thread_fork_control.rs` replays the source agent from admitted
`agents/*.json`, derives the source thread association from canonical Agentgres
state, rejects restored `source_agent`/`source_thread` candidate transport, and
fails closed without `state_dir` or a replayed source agent before planning a
forked agent, thread projection, and `thread.forked` runtime event. The JS
thread-fork state helper no longer calls `agentForThread()` or builds a
source-thread candidate before Rust planning, and focused JS/Rust tests plus
conformance guard the state-dir replay requirement and retired candidate
transport so thread-fork truth cannot return through JS agent/thread lookup
beside Rust-owned Agentgres replay, event admission, and projection.

Slice 1415 hard-cuts model_mount wallet/cTEE state-dir authority for
capability-token and vault control. Public capability-token
create/list/authorize/revoke and vault bind/list/metadata/status/health/remove
now require daemon Agentgres `stateDir` before any Rust planning call; the old
`stateDir ?? null` handoff is retired. Rust `capability_token_control.rs` and
`vault_control.rs` also reject every direct control operation without
`state_dir`, so wallet authority and cTEE custody truth cannot be planned from a
no-replay compatibility path. Focused Node/Rust tests and conformance guard the
JS fail-closed boundary, the Rust `state_dir` requirement, and absence of the
optional JS state-dir transport. This remains non-terminal because deeper
wallet/cTEE route revocation policy, projection/replay depth, and stable
protocol API coverage remain active blockers.

Slice 1417 hard-cuts model_mount route-control topology candidate transport.
Mounted route selection and explicit-model endpoint resolution no longer gather
`listRoutes()`, `listEndpoints()`, or `listProviders()` in JS to send
`current_route`, `endpoints`, or `providers` candidates into Rust. JS sends only
canonical route/model request facts plus daemon Agentgres `state_dir`; Rust
`route_control.rs` requires `state_dir`, rejects restored candidate fields,
replays `model-routes`, `model-route-endpoint-resolutions`/`model-endpoints`,
and `model-providers` through Rust read-projection planning, and then selects or
resolves endpoints from the replayed Agentgres topology before record-state
commit. Focused Node/Rust tests and conformance guard the state-dir replay path,
candidate-field rejection, and absence of the old mounted JS topology request
shaping. Remaining blockers stay deeper wallet/cTEE route revocation policy,
projection/replay depth, and stable protocol API coverage over admitted records.

Slice 1418 hard-cuts model_mount instance-lifecycle topology candidate
transport. Model load/unload/estimate and loaded-instance maintenance no longer
send JS-shaped endpoint/provider/instance/backend/driver truth into the Rust
instance-lifecycle planner. JS sends only canonical endpoint/model/instance ids
or instance refs plus daemon Agentgres `state_dir`; Rust
`lifecycle/instance.rs` requires `state_dir`, rejects restored `endpoint`,
`provider`, `instance`, `endpoints`, `providers`, and `instances` candidate
fields, replays admitted endpoints/providers/instances through Rust
read-projection planning, derives endpoint/provider/model/backend/driver truth
and maintenance provider-lifecycle hashes from Agentgres replay, and owns
estimate id plus missing-instance subject binding before record-state commit. The obsolete
JS estimate-id helper and maintenance endpoint/provider enrichment helpers are
deleted. Focused Node/Rust tests and conformance guard the replay boundary,
candidate-field rejection, deleted helper surface, and absence of JS
candidate-enrichment request shaping. Remaining blockers stay deeper
wallet/cTEE route revocation policy, conversation replay depth, and
stable protocol API coverage over admitted records.

Slice 1419 hard-cuts model_mount provider-lifecycle topology candidate
transport. Provider health/start/stop no longer resolve endpoint/model/backend
truth in JS before calling the Rust provider-lifecycle planner. JS sends only
provider identity, action, execution backend, evidence refs, receipt refs, and
daemon Agentgres `state_dir`; Rust `lifecycle/provider.rs` requires `state_dir`,
rejects restored `provider`, `endpoint`, `providers`, and `endpoints`
candidate fields, replays admitted providers/endpoints through Rust
read-projection planning, and derives provider kind, endpoint, model, backend,
driver, status, lifecycle hash, transport contract, and evidence before
Agentgres record-state commit can return public lifecycle truth. The obsolete
JS provider-lifecycle subject and endpoint-selection helpers are deleted, and
focused Node/Rust tests plus conformance guard state-dir replay, candidate
rejection, absent `js_*` proof fields, and absence of JS endpoint-map lifecycle
subject transport. Remaining blockers stay deeper wallet/cTEE route revocation
policy, conversation replay depth, and stable protocol API coverage over
admitted records.

Slice 1420 hard-cuts the runtime-service thread-turn standalone helper exports.
`runtime-agent-run-lifecycle.mjs` no longer exports
`createRuntimeBridgeThreadControl()` or `createRuntimeBridgeTurnRun()` as
callable JS lifecycle surfaces. Public runtime-service resume/control and
turn-submit now live inside the mounted `RuntimeThreadTurn` route family, which
uses the daemon-mounted `contextPolicyCore` for typed Rust
`daemonCoreThreadLifecycleApi` planning, commits only Rust-planned agent/run
records through Agentgres-backed writes, and validates Rust thread/turn
projections before returning route truth. Focused tests prove lifecycle
create/thread/run coverage no longer imports the deleted helpers, runtime-service
control/turn coverage remains on the mounted route surface, and operator
turn-control test doubles no longer smuggle JS run candidates beside Rust
`state_dir` replay. Conformance now guards that the standalone helper exports,
direct helper tests, and route-surface helper calls cannot return. Remaining
blockers stay durable lifecycle replay/projection depth, wallet/cTEE
runtime-service authority, receipt/state-root binding, and stable lifecycle
protocol clients over Rust-owned records.

Slice 1421 hard-deletes the computer-use direct event append JS facade.
`AgentgresRuntimeStateStore` no longer exposes `admitComputerUseRuntimeEvent()`
as a callable store method or fail-closed compatibility shim. Public
computer-use invocation stays on the Rust-owned `computer_use.request_lease`
StepModule path, while run-create materialization stays owned by Rust
`RunCreateStateUpdateCore`; there is no separate JS event-admission surface
left beside those paths. Focused tests no longer poison or reference the deleted
method, and conformance now guards the absence of the method, the retired
`computer_use_event_admission` operation string, and the old
`runtime_computer_use_invocation_rust_core_required` marker from daemon
production source. Remaining blockers stay concrete provider execution, direct
Rust computer-use event materialization/admission, cTEE custody, durable
Agentgres expected-head/state-root binding, replay/projection, and stable
Workbench/CLI/SDK APIs over Rust-owned records.

Slice 1422 hard-deletes the public lifecycle projection JS surface.
`runtime-lifecycle-projection-surface.mjs`, its focused test, and the mounted
`lifecycleProjectionSurface` daemon-store property are absent. Public
agent/thread/run detail and list reads, top-level usage, and authority-evidence
routes now call the store-owned `projectRuntimeLifecycleProjection()` API with
canonical snake_case route facts; that API delegates to Rust
`project_runtime_lifecycle` with runtime `state_dir` and returns only the Rust
projection. Focused tests prove the public route family no longer calls the
surface, and conformance guards the deleted file path, property, factory name,
and old route call patterns from returning. Remaining lifecycle blockers stay
wallet/cTEE authority on lifecycle exits, complete receipt/state-root binding
for every lifecycle read projection, richer artifact projection, and stable
Workbench/CLI/SDK protocol clients over Rust-owned Agentgres replay records.

Slice 1423 hard-deletes the public task/job JS surface.
`runtime-task-job-surface.mjs`, its focused test, and the mounted
`taskJobSurface` daemon-store property are absent. Daemon startup mounts
`runtime-task-job-api.mjs` as `taskJobApi`, and public `/v1/tasks` and
`/v1/jobs` routes enter through store-owned `createRuntimeTask()`,
`listRuntimeTasks()`, `getRuntimeTask()`, `cancelRuntimeTask()`,
`listRuntimeJobs()`, `getRuntimeJob()`, and `cancelRuntimeJob()` methods.
Those methods delegate to the positive Rust-backed task/job API and preserve
the Rust planner/projector, Agentgres-backed write, state-dir replay, and
mismatch guards. Focused tests prove the public route family no longer reaches
a mounted route-visible task/job surface, and conformance guards the deleted
file path, factory name, property, and old route call patterns from returning.
Remaining task/job blockers stay durable task/job replay and projection depth,
receipt/state-root binding, wallet/cTEE task authority, direct lifecycle API
depth, and stable Workbench/CLI/SDK protocol clients over Rust-owned Agentgres
task/job records.

Slice 1434 hard-cuts the duplicate runtime task-create planner. Public task
creation now enters through the store-owned Rust run-create lifecycle and then
returns the Rust task replay projection; `runtime-task-job-api.mjs` no longer
accepts `buildRun` or `ensureProviderAvailable`, no longer calls
`planRuntimeTaskJobCreateStateUpdate()`, and fails closed before `createRun`
when the Rust task/job projector is missing. Rust `task_job.rs`, the policy
facade, and `RuntimeKernelService` no longer expose
`RuntimeTaskJobCreateStateUpdate*` or
`plan_runtime_task_job_create_state_update`; conformance guards those retired
symbols, schema constants, direct API wrapper, and old task-create normalizer
from returning.

Slice 1435 hard-deletes the workflow/diagnostics/workspace/thread-turn
internal surface module names. The previously route-demoted delegates are now
internal protocol/API delegates only:
`runtime-workflow-edit-api.mjs`, `runtime-diagnostics-repair-api.mjs`,
`runtime-workspace-snapshot-api.mjs`, and `runtime-thread-turn-api.mjs`.
The old `runtime-workflow-edit-surface.mjs`,
`runtime-diagnostics-repair-surface.mjs`,
`runtime-workspace-snapshot-surface.mjs`, and
`runtime-thread-turn-surface.mjs` files, their focused tests, and their
`createRuntime*Surface()` factories are absent. Daemon startup imports only the
positive `createRuntime*Api()` factories, and conformance guards the retired
surface files/factories so they cannot return as unverified compatibility
facades beside the store-owned route methods.

Slice 1436 hard-deletes the public projection facade names for catalog,
skill/hook registry, and repository workflow. The Rust-owned public projection
families now mount only internal API delegates:
`runtime-tool-api.mjs`, `runtime-skill-hook-api.mjs`, and
`runtime-repository-api.mjs`. Public `/v1/account`, `/v1/runtime/nodes`,
`/v1/tools`, `/v1/skills`, `/v1/hooks`, and repository workflow routes call the
mounted `toolApi`, `skillHookApi`, and `repositoryApi` protocol clients, which
delegate to the typed Rust daemon-core projection APIs and validate the returned
projection or registry kind before route truth can return. The former
Surface-named files, tests, factories, store properties, and route calls are
absent, and conformance rejects their return as a compatibility anchor beside
Rust-owned Agentgres projection/replay records.

Slice 1437 hard-deletes the runtime run-read JS surface. Daemon startup no
longer imports or mounts `runtime-run-read-surface.mjs`, its focused test is
absent, and `AgentgresRuntimeStateStore` no longer exposes a `runReadSurface`
property or `createRuntimeRunReadSurface()` factory. Public run, usage,
authority-evidence, replay, trace, scorecard, and artifact reads remain on the
Rust lifecycle projection API over daemon `state_dir`; internal run-state
mutation plumbing calls explicit thread-store helpers for admitted state
records, and the only local canonical projection helper left is a private
Agentgres run-state commit payload builder that derives task/job/checklist
sidecar paths from the canonical run id. Conformance now guards that the
deleted surface file, factory, daemon property, and public route calls cannot
return beside the Rust-owned lifecycle projection path.

Slice 1438 hard-deletes the runtime thread-event JS surface. Daemon startup no
longer imports or mounts `runtime-thread-event-surface.mjs`, its focused test
is absent, and `AgentgresRuntimeStateStore` no longer exposes a
`threadEventSurface` property or `createRuntimeThreadEventSurface()` factory.
Public turn/event readback, runtime-event append, thread-start/run-event
projection, replay helpers, event-stream paths, and thread/turn projections
remain store-owned methods that call `threads/thread-replay.mjs` and
`thread-turn-projection.mjs` directly. Those helpers still fail closed through
Rust Agentgres admission/projection/replay over daemon `state_dir`; JS no
longer preserves a mounted route-visible event facade beside that Rust-owned
thread-event spine. Conformance now guards the deleted surface file, test,
factory, daemon property, direct store method wiring, and absence of production
source references.

Slice 1424 hardens the active Hypervisor client/product vocabulary boundary.
Developer-facing app docs now describe Hypervisor as a native operator client
over Hypervisor Core and the IOI daemon, not as an Autopilot/Tauri desktop
product. Active docs point at `HypervisorShellWindow`, and configured local
llama.cpp preloads use `hypervisor-workbench-configured-llama-cpp` instead of
an `autopilot-ide` identifier. `check:runtime-layout` and Hypervisor
conformance guard the stale Autopilot IDE/Tauri product copy and preload marker
from returning in active paths.

Slice 1425 hard-deletes the public thread auxiliary JS surface.
`runtime-thread-auxiliary-surface.mjs` and the mounted `threadAuxiliarySurface`
daemon-store property are absent. Daemon startup mounts
`runtime-thread-auxiliary-api.mjs` as `threadAuxiliaryApi`, and thread fork,
managed-session inspection/control, workspace-change inspection/control, and run-cancel
routes enter through store-owned `forkThread()`,
`inspectManagedSessionsForThread()`, `controlManagedSessionForThread()`,
`inspectWorkspaceChangeReviewsForThread()`,
`controlWorkspaceChangeForThread()`, and `cancelRun()` methods. Those methods
delegate to the positive Rust-backed auxiliary API while preserving the
Rust managed-session, workspace-change, thread-fork, and run-cancel planners,
Agentgres-backed writes/admission, state-dir replay, and mismatch guards.
Conformance rejects the old surface file, factory, property, and route call
patterns from returning. Remaining blockers stay durable auxiliary-family
replay/projection depth, wallet/cTEE/workspace authority expansion,
StepModuleRouter delegation execution where applicable, receipt/state-root
binding, and stable Workbench/CLI/SDK protocol clients over Rust-owned records.

Slice 1426 hard-deletes the public conversation-artifact JS surface.
`runtime-conversation-artifact-surface.mjs`, its focused test, and the mounted
`conversationArtifactSurface` daemon-store property are absent. Daemon startup
mounts `runtime-conversation-artifact-api.mjs` as `conversationArtifactApi`,
and thread-scoped plus public conversation-artifact list/get/revision and
create/action/export/promote routes enter through store-owned
`listConversationArtifacts()`, `createConversationArtifact()`,
`getConversationArtifact()`, `listConversationArtifactRevisions()`,
`performConversationArtifactAction()`, `exportConversationArtifact()`, and
`promoteConversationArtifact()` methods. Those methods delegate to the positive
Rust-backed conversation-artifact API while preserving Rust projection/control
planning, Agentgres artifact-state admission, daemon `state_dir` replay, and
mismatch guards. Conformance rejects the old surface file, factory, property,
and route call patterns from returning. Remaining blockers stay durable
ArtifactRef/PayloadRef admission depth, richer Agentgres-backed artifact
replay/projection storage, wallet/cTEE authority where needed, receipt/state-root
binding, and stable Workbench/CLI/SDK artifact clients over Rust-owned records.

Slice 1427 hard-deletes the public subagent JS surface.
`runtime-subagent-surface.mjs`, its focused test, and the mounted
`subagentSurface` daemon-store property are absent. Daemon startup mounts
`runtime-subagent-api.mjs` as `subagentApi`, and public subagent list/get/result,
spawn/wait/input/resume/assign/cancel/propagation, and direct control-event paths
enter through store-owned subagent methods. Those methods delegate to the
positive Rust-backed subagent API while preserving Rust subagent projection,
control planning, runtime-event admission, record state-update planning,
Agentgres-backed persistence, and daemon `state_dir` replay. Conformance rejects
the old surface file, factory, property, and route call patterns from returning.
Remaining blockers stay direct Rust delegation/execution admission, durable
subagent replay/projection storage, wallet authority, receipt/state-root binding,
and stable Workbench/CLI/SDK subagent clients over Rust-owned records.

Slice 1428 hard-deletes the thread MCP route-visible JS surfaces.
`runtime-mcp-control-surface.mjs`, `runtime-mcp-catalog-surface.mjs`,
`runtime-mcp-serve-surface.mjs`, their focused tests, the
`createRuntimeMcp*Surface()` factories, and the mounted `mcp*Surface`
daemon-store properties are absent. Daemon startup mounts
`runtime-mcp-control-api.mjs`, `runtime-mcp-catalog-api.mjs`, and
`runtime-mcp-serve-api.mjs` as internal delegates, while public thread MCP
control/catalog/serve routes enter through store-owned methods such as
`importThreadMcp()`, `searchThreadMcpTools()`, `mcpServeStatus()`, and
`handleMcpServeJsonRpc()`. Those methods delegate to the positive Rust-backed
MCP APIs while preserving Rust control planning, catalog projection, MCP serve
planning/result projection, live-result Agentgres commit/replay, wallet
authority refs, cTEE custody refs, containment refs, and daemon `state_dir`
replay. Conformance rejects the old surface files, factories, properties, and
route call patterns from returning. Remaining blockers stay broader stable
SDK/CLI/IDE protocol coverage over Rust-owned records plus deeper MCP
replay/storage depth.

Slice 1429 hard-deletes the governed admission route-visible JS surface shape.
The committed `runtime-governed-improvement-api.mjs`,
`runtime-external-capability-authority-api.mjs`,
`runtime-worker-service-package-api.mjs`,
`runtime-ctee-private-workspace-api.mjs`, and
`runtime-l1-settlement-api.mjs` modules are internal Rust-backed product-route
delegates, not public route facades. Public governed improvement, external
capability, worker/service package, cTEE private workspace, and L1 settlement
thread routes now enter through store-owned daemon APIs, and conformance guards
that the old `*Surface` files, factories, store properties, and direct route
calls into mounted delegate APIs cannot return. Remaining blockers stay deeper
projection/replay storage, receipt/state-root binding, stable Workbench/CLI/SDK
protocol clients, and any residual non-terminal governed admission custody or
authority materialization.

Slice 1430 hard-deletes the approval route-visible JS surface shape.
`runtime-approval-surface.mjs`, `createRuntimeApprovalSurface()`, and the
mounted `approvalSurface` daemon-store property are absent. Daemon startup
mounts `runtime-approval-api.mjs` as the internal `approvalApi` delegate, while
public approval queue, request, decision, approve/reject shortcut, and revoke
routes enter through store-owned `listThreadApprovals()`,
`requestThreadApproval()`, `decideThreadApproval()`, and
`revokeThreadApproval()` methods. Those methods delegate to the Rust-backed
approval API while preserving Rust approval authority, wallet grant/lease
binding, Agentgres replay/projection, and fail-closed admission behavior.
Conformance rejects the old surface file, factory, property, and direct route
calls into mounted approval delegates from returning. Remaining blockers stay
wallet.network grant issuance/signature semantics, richer durable approval
authority projection/replay storage, receipt/state-root binding, and stable
Workbench/CLI/SDK approval clients over Rust-owned records.

Slice 1431 hard-cuts the workflow/diagnostics/workspace route-visible JS
surface shape. Daemon startup now mounts workflow edit, diagnostics repair, and
workspace snapshot delegates as internal `workflowEditApi`,
`diagnosticsRepairApi`, and `workspaceSnapshotApi` members. Public thread
workflow-edit proposal/apply, diagnostics repair decision execution, workspace
snapshot list, and workspace restore preview/apply routes enter through
store-owned daemon methods instead of `store.*Surface` or direct mounted API
calls, and `file.apply_patch` snapshot capture also enters through
`prepareWorkspaceSnapshotForPatch()` on the store. Focused tests poison the
internal delegates and prove the route family uses the store-owned API, while
conformance guards the old route-visible surface references, direct mounted API
route calls, and workspace-snapshot capture surface call from returning.
Remaining blockers stay durable workflow mutation custody, diagnostics and
workspace replay/projection depth, wallet/cTEE authority expansion where
applicable, receipt/state-root binding, and stable Workbench/CLI/SDK protocol
clients over Rust-owned records.

Slice 1432 hard-cuts the thread-turn route-visible JS surface shape. Daemon
startup now mounts the runtime thread-turn delegate as internal `threadTurnApi`
instead of `threadTurnSurface`, and public thread resume, turn create, turn
interrupt, and turn steer routes enter through store-owned daemon methods.
Focused route tests poison the internal delegate and prove route calls use
`resumeThread()`, `createTurn()`, `interruptTurn()`, and `steerTurn()` on the
daemon store, while store-delegate tests prove those methods are positive API
owners over `threadTurnApi` rather than legacy pass-through wrappers.
Conformance rejects the old route-visible `store.threadTurnSurface.*` calls and
the mounted `this.threadTurnSurface` property from returning. Remaining blockers
stay broader runtime-service/thread-turn execution dispatch, durable
replay/projection, wallet/cTEE authority policy, Agentgres expected-head/state-root
binding, and stable Workbench/CLI/SDK lifecycle clients over Rust-owned records.

Slice 1439 hard-cuts the thread-control route-visible JS surface shape. Daemon
startup now mounts the runtime thread-control delegate as internal
`threadControlApi` instead of `threadControlSurface`, and public thread mode,
model, thinking, and workspace-trust acknowledgement routes enter through
store-owned daemon methods. Focused route tests poison the retired
`threadControlSurface` and prove route calls use `updateThreadMode()`,
`updateThreadModel()`, `updateThreadThinking()`, and
`acknowledgeWorkspaceTrustWarning()` on the daemon store. Conformance guards
the deleted surface file/test, retired factory/property names, and old
route-call patterns from returning. Remaining blockers stay deeper
workspace-trust wallet/cTEE authority enforcement, model-route authority,
durable thread-control replay/projection storage, receipt/state-root binding,
and stable Workbench/CLI/SDK thread-control clients over Rust-owned records.

Slice 1440 hard-cuts the thread-memory route-visible JS surface shape. Daemon
startup now mounts `createThreadMemoryState()` as internal `threadMemoryApi`
instead of `threadMemorySurface`, and public agent/thread memory list, policy,
path, write, edit, delete, status, and validation routes enter through
store-owned daemon methods. Run-memory resolution now requires those same
store-owned memory APIs instead of discovering a memory surface on the store.
Focused route tests poison the retired `threadMemorySurface`, and conformance
rejects restored `this.threadMemorySurface`, direct `store.threadMemorySurface.*`
route calls, and run-memory surface discovery. Remaining blockers stay deeper
wallet/policy authority, cTEE private-memory custody, durable memory
replay/projection storage, receipt/state-root binding, and stable
Workbench/CLI/SDK memory clients over Rust-owned records.

## Final Doctrine

Hypervisor is the product/control layer for private autonomous work. The
Hypervisor Daemon owns execution semantics and authority boundaries. Workflow
Compositor shapes high-level workflow/service graphs and step contracts.
Selected HarnessProfiles resolve scoped steps; the Default Harness Profile is
the reference/fallback profile, not the only admissible harness or a
meta-harness. The existing Rust/WASM workload/kernel substrate should become
the authoritative backend for admitted step and module execution. Agentgres
records admitted truth. wallet.network authorizes secrets, scopes, approvals,
leases, and declassification. Private Workspace backed by cTEE keeps protected
plaintext out of untrusted compute by default. Hypervisor Workbench composes,
governs, and replays the same graph the daemon and kernel execute. IOI L1
receives only selected public, economic, rights, dispute, registry, or
cross-domain commitments.

In one line:

> **The daemon decides, the kernel executes, Agentgres admits, wallet.network
> authorizes, cTEE protects custody, and Hypervisor Workbench makes the whole machine
> governable.**
