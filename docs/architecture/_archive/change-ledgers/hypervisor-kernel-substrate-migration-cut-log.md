# Hypervisor Kernel Substrate Migration — Per-Cut Pruning Log

Status: archived change ledger (verbatim extraction).
Doctrine status: archived
Implementation status: n/a (historical record)
Archived from: `docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md` on 2026-07-05.
Canonical owner: `docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md` (live doctrine); this file is history, not authority.
Superseded by: the canonical owner doc. Git history retains the original placement.

---

Last matrix pruning pass: 2026-06-15, after the direct typed workload API
StepModule runner-facade deletion cut, StepModule command-env selector deletion,
the Rust approval-lease authority cut with JS lease facade deletion,
the Rust Agentgres MCP live-result pending-transport fixture marker retirement,
and Rust approval-request authority issuance cut,
coding-tool approval-satisfaction JS gate retirement, the Rust approval
satisfaction/projection positive API cut, the Rust-owned coding-tool patch
snapshot capture cut, and the Rust-planned/Agentgres-admitted coding-tool
budget-block governance cut, the public coding-tool budget recovery retry
Rust-planning/Agentgres-commit cut, the budget-recovery request/override
Rust-control and wallet-authority cut, the diagnostics repair retry-run
Rust-planning cut, the context lifecycle typed Rust daemon-core API cut for
context-budget, coding-tool budget/block, compaction-policy, and context
compaction plus command-transport retirement, the runtime-control typed Rust
daemon-core API cut for coding-tool budget recovery, diagnostics operator
override, operator interrupt/steer, and run-cancel plus command-transport
retirement, the coding-tool budget recovery/operator-control/run-cancel
command-shaped Rust owner wrapper retirement, the coding-tool result envelope/context
Rust planning cut, the Rust-owned coding-tool artifact draft planning plus
Agentgres artifact-state commit cut, and the public thread runtime-control Rust planner
cut, the generic runtime thread-event Rust Agentgres admission cut, the direct
runtime thread-event admission cache-transport retirement cut, the coding-tool
event admission cache-transport retirement cut, and the runtime
thread-event projection Rust Agentgres cut, and the public runtime
thread-event replay positive API cut, and the public runtime thread/turn
projection positive API cut, and the public agent status-control Rust
planning/Agentgres commit cut, and the public agent delete Rust tombstone
planning/Agentgres commit cut, and the public agent create Rust
planning/Agentgres commit cut, and the public run create Rust
planning/Agentgres commit cut, and the public top-level thread create Rust
planning/Agentgres commit/projection cut, and the public non-runtime
resume/turn-create Rust lifecycle/projection cut, the diagnostics-blocked
turn-create Rust run-planning/projection cut, and the public task/job
cancel Rust planning/Agentgres commit cut, and the public task/job read
projection positive API plus state_dir replay/candidate-transport retirement
cut, and the public task create Rust
planning/projection/Agentgres commit cut, and the workspace-trust
warning/ack Rust planning plus runtime-event Agentgres admission cut, and the
public runtime account/node/tool catalog Rust projection positive API cut, and
the public skill/hook registry Rust projection positive API cut, the public
model_mount catalog-status Rust read-projection positive API cut, the public
memory route projection Rust positive API cut, the public conversation artifact
read projection Rust positive API cut, the public conversation-artifact control
Rust planning plus Agentgres artifact-state commit cut, and the runtime subagent
read projection Rust positive API cut, and the public subagent wait control Rust planning plus
Agentgres commit cut, the public subagent input/resume Rust run-create/control
planning plus Agentgres commit cut, the public subagent assign/cancel
direct-control Rust planning plus Agentgres commit cut, and the public subagent
spawn Rust agent-create/run-create/control planning plus Agentgres commit cut,
and the public subagent cancellation propagation Rust propagated-cancel/control
planning plus Agentgres commit cut, and the public runtime memory
write/edit/delete/policy Rust planning plus Agentgres memory-state commit cut,
and the public memory mutation current-record/policy `state_dir` replay cut,
and the public managed-session inspection/control Rust projection/planning plus
runtime-event admission cut, and the public workspace-change inspection/control
Rust projection/planning plus runtime-event admission cut, and the public
thread-fork Rust planning plus Agentgres commit/projection/runtime-event
admission cut, the public thread-fork source-agent `state_dir` replay cut, the
public model load/unload Rust instance-lifecycle planning
plus Agentgres model-instance commit cut, and the public model-instance
maintenance Rust planning plus Agentgres model-instance commit cut, and the
public provider inventory Rust positive API cut, the public model tokenizer
record replay Rust positive API cut, and the public catalog-search Rust
projection cut, the public model-capability projection positive API cut, the
public runtime-engine control/projection positive API cut, the public
runtime-survey capture Rust planning plus Agentgres receipt-state commit cut, the public
backend-lifecycle control positive API cut, the public
provider-lifecycle record-state positive API cut, the public model
artifact/endpoint typed daemon-core API command-transport retirement cut, the public model
storage/download control positive API cut, the model_mount receipt-replay
read-projection state_dir authority cut, the public backend log read Rust
read-projection positive API cut, the public runtime-survey capture Rust
positive API cut, the public catalog-provider OAuth session/state Rust
read-projection replay cut, the OpenAI-compatible stream cancellation Rust
positive API cut, the public computer-use request-lease Rust StepModule
positive API cut, the L1 settlement state-root Rust derivation/client-truth
retirement cut, the MCP serve tool-result Rust projection cut, the runtime
MCP live-result Agentgres replay/projection cut, the MCP catalog search/fetch
Rust projection cut, the runtime MCP control/catalog direct daemon-core API
command-transport retirement cut, the MCP serve typed daemon-core API
command-transport retirement cut, the Rust daemon-core command-protocol module
deletion cut, the model_mount
invocation/provider/lifecycle/result typed daemon-core API command-transport
retirement cut, the runtime-service lifecycle agent-alias retirement cut, the
model_mount tokenizer/required-control typed daemon-core
API command-transport retirement cut, the model_mount conversation/stream typed daemon-core API
command-transport retirement cut, and the model_mount MCP workflow typed daemon-core API
command-transport retirement cut, the model_mount server-control typed
daemon-core API command-transport retirement cut, and the model_mount runtime-engine/survey typed daemon-core API command-transport retirement cut, the model_mount catalog/provider/capability/vault/receipt-gate typed daemon-core API command-transport retirement cut, the hosted provider metadata transport Rust materialization cut, the model_mount MCP workflow Rust result-payload materialization cut, the runtime MCP control Rust result-payload materialization cut, the runtime MCP catalog live-discovery Rust materialization cut, the runtime MCP control Rust driver-backend contract cut, the backend registry derivation/seeding JS facade deletion cut, the runtime MCP live/serve fallback-proof protocol deletion cut, the runtime MCP top-level route/client family retirement cut, the runtime-control state-event sequence cache transport retirement cut, the run-memory command Rust projection/control plus daemon-store memory wrapper deletion cut, the runtime task/job runner-injection alias deletion cut, the diagnostics repair runner-injection alias deletion cut, the workflow-edit runner-injection alias deletion cut, the run-cancel runner-injection alias deletion cut, the coding-tool budget recovery runner-injection alias deletion cut, the runtime tool catalog runner-injection alias deletion cut, the skill/hook registry runner-injection alias deletion cut, the repository workflow runner-injection alias deletion cut, the runtime lifecycle projection runner-injection alias deletion cut, the lifecycle admission route-fallback deletion cut, the thread-turn surface runner-alias deletion cut, the runtime subagent runner-wrapper deletion cut, the diagnostics repair surface runner-wrapper deletion cut, the runtime agent/run lifecycle helper runner-fallback deletion cut, the conversation-artifact surface runner-wrapper deletion cut, the runtime MCP serve store-core fallback deletion cut, the coding-tool artifact surface store-core fallback deletion cut, the coding-tool budget recovery surface store-core fallback deletion cut, the runtime task/job surface store-core fallback deletion cut, the runtime MCP single context-policy core mount deletion cut, the runtime context/memory auxiliary self-core plus planner-alias deletion cut, the runtime-service thread-turn bridge-adapter constructor alias deletion cut, the model_mount read-projection JS facade deletion cut, the model_mount invocation helper compatibility-alias deletion cut, the hosted provider invocation Rust authority/auth gate cut, the hosted provider invocation Rust transport-contract materialization cut, the hosted provider stream Rust transport-contract materialization cut, the hosted provider auth materialization Rust API cut, the runtime MCP serve query/raw JSON-RPC transport fallback deletion cut, the run-memory command parser Rust-owned API cut, the runtime task/job/checklist run-materialization JS facade deletion cut, the operator turn-control JS run-candidate transport deletion cut, the pre-Hypervisor app/embedded Workbench JS facade-root deletion cut, the runtime MCP/model_mount legacy fallback-proof field protocol deletion cut, the runtime-service thread-turn standalone helper export deletion cut, the computer-use direct event append JS facade deletion cut, the public lifecycle projection JS surface deletion cut, the public task/job JS surface deletion cut, the public thread auxiliary JS surface deletion cut, and the public conversation-artifact JS surface deletion cut.
This pass additionally includes the governed admission, approval,
workflow/diagnostics/workspace, thread-turn, and thread-control route-visible
JS surface deletion cuts.
Slice 1415 additionally hard-cuts the model_mount capability-token/vault
`state_dir` authority boundary: public capability-token and vault controls now
require daemon Agentgres replay at the JS edge and Rust direct-planning boundary,
and the old optional `stateDir ?? null` handoff is retired.
Slice 1416 additionally hard-cuts the active Hypervisor probe/adapter-host
language boundary: the retired Hypervisor native desktop tree, the root `ide/`
artifact path,
Tauri product wording, and the retired `Workspace IDE` marker are barred from
active client probes; those probes now target Hypervisor/code-editor-adapter host
windows while Tauri remains legacy-only under `internal-docs/legacy`.
Slice 1417 additionally hard-cuts the model_mount route-control topology
candidate transport: mounted route selection and explicit-model endpoint
resolution now send daemon Agentgres `state_dir` instead of JS
`current_route`/`endpoints`/`providers` candidates, and Rust replays the route,
endpoint, and provider topology before selecting or resolving endpoint truth.
Slice 1418 additionally hard-cuts the model_mount instance-lifecycle topology
candidate transport: model load/unload/estimate and instance maintenance
requests now send daemon Agentgres `state_dir` plus canonical IDs or instance
refs, Rust replays admitted endpoints/providers/instances before deriving
endpoint/provider/model/backend/driver/instance truth, and restored
endpoint/provider/instance candidate fields fail closed.
Slice 1419 additionally hard-cuts the model_mount provider-lifecycle topology
candidate transport: provider health/start/stop requests now send daemon
Agentgres `state_dir` instead of JS endpoint/model/backend subject candidates,
Rust replays admitted providers/endpoints before deriving lifecycle subject
truth, and restored provider/endpoint candidate fields fail closed.
Slice 1420 additionally hard-cuts the runtime-service thread-turn standalone JS
helper exports: `runtime-agent-run-lifecycle.mjs` no longer exports
`createRuntimeBridgeThreadControl()` or `createRuntimeBridgeTurnRun()`, and
the mounted `RuntimeThreadTurn` route-family surface owns runtime-service
resume/control and turn-submit planning internally through the daemon-mounted
`contextPolicyCore`, Agentgres-backed writes, and Rust thread/turn projections.
Slice 1421 additionally hard-deletes the computer-use direct event append JS
facade: `AgentgresRuntimeStateStore` no longer exposes
`admitComputerUseRuntimeEvent()`, public computer-use invocation remains on the
Rust-owned `computer_use.request_lease` StepModule path plus Rust run-create
materialization, and conformance guards that the deleted JS append shim cannot
return as a fail-closed compatibility surface.
Slice 1422 additionally hard-deletes the public lifecycle projection JS surface:
`runtime-lifecycle-projection-surface.mjs`, its focused test, and the mounted
`lifecycleProjectionSurface` daemon-store property are absent. Public
agent/thread/run/usage/authority-evidence reads enter through the store-owned
`projectRuntimeLifecycleProjection()` API, which delegates to the Rust
`project_runtime_lifecycle` daemon-core projector with canonical route facts and
runtime `state_dir`; conformance guards the old surface path and route calls
from returning.
Slice 1423 additionally hard-deletes the public task/job JS surface:
`runtime-task-job-surface.mjs`, its focused test, and the mounted
`taskJobSurface` daemon-store property are absent. Public `/v1/tasks` and
`/v1/jobs` routes enter through store-owned `createRuntimeTask()`,
`listRuntimeTasks()`, `getRuntimeTask()`, `cancelRuntimeTask()`,
`listRuntimeJobs()`, `getRuntimeJob()`, and `cancelRuntimeJob()` methods, which
delegate to the positive Rust-backed task/job API and cannot return through a
mounted JS route facade.
Slice 1425 additionally hard-deletes the public thread auxiliary JS surface:
`runtime-thread-auxiliary-surface.mjs` and the mounted `threadAuxiliarySurface`
daemon-store property are absent. Thread fork, managed-session inspection and
control, workspace-change inspection and control, and run cancellation routes
enter through store-owned `forkThread()`, `inspectManagedSessionsForThread()`,
`controlManagedSessionForThread()`, `inspectWorkspaceChangeReviewsForThread()`,
`controlWorkspaceChangeForThread()`, and `cancelRun()` methods, which delegate
to the positive Rust-backed auxiliary API without a route-visible JS facade.
Slice 1426 additionally hard-deletes the public conversation-artifact JS
surface: `runtime-conversation-artifact-surface.mjs`, its focused test, and
the mounted `conversationArtifactSurface` daemon-store property are absent.
Thread-scoped and public conversation-artifact list/get/revision and
create/action/export/promote routes enter through store-owned
`listConversationArtifacts()`, `createConversationArtifact()`,
`getConversationArtifact()`, `listConversationArtifactRevisions()`,
`performConversationArtifactAction()`, `exportConversationArtifact()`, and
`promoteConversationArtifact()` methods, which delegate to the positive
Rust-backed conversation-artifact API without a route-visible JS facade.
Slice 1429 additionally hard-deletes the governed admission route-visible JS
surface shape: the old governed improvement, external capability authority,
worker/service package, cTEE private workspace, and L1 settlement `*Surface`
files/factories/properties are absent. Public thread routes enter through
store-owned daemon APIs, which delegate to internal Rust-backed product-route
APIs without exposing a mounted route facade or direct mounted-API route call.
Slice 1430 additionally hard-deletes the approval route-visible JS surface
shape: `runtime-approval-surface.mjs`, `createRuntimeApprovalSurface()`, and
the mounted `approvalSurface` store property are absent. Public approval queue,
request, decision, approve/reject shortcut, and revoke routes enter through
store-owned approval methods, which delegate to the internal Rust-backed
`runtime-approval-api.mjs` without exposing a mounted approval route facade or
direct mounted-delegate route call.
Slice 1431 additionally hard-cuts the workflow/diagnostics/workspace
route-visible JS surface shape: daemon startup mounts workflow edit,
diagnostics repair, and workspace snapshot delegates as internal
`workflowEditApi`, `diagnosticsRepairApi`, and `workspaceSnapshotApi` members.
Public thread workflow-edit proposal/apply, diagnostics repair decision
execution, workspace snapshot list, and workspace restore preview/apply routes
enter through store-owned daemon methods, and file patch snapshot capture uses
`prepareWorkspaceSnapshotForPatch()` on the daemon store instead of reaching
into a mounted workspace-snapshot surface. Conformance rejects direct route
calls into the mounted delegates and rejects the old `store.*Surface` route
shape from returning.
Slice 1432 additionally hard-cuts the thread-turn route-visible JS surface
shape: daemon startup mounts the runtime thread-turn delegate as internal
`threadTurnApi`; public resume, turn create, turn interrupt, and turn steer
routes enter through store-owned daemon methods; focused tests poison the
internal delegate; and conformance rejects direct route calls into
`store.threadTurnSurface.*` or a restored mounted `this.threadTurnSurface`
property.
Slice 1439 additionally hard-cuts the thread-control route-visible JS surface
shape: daemon startup mounts the runtime thread-control delegate as internal
`threadControlApi`; public mode, model, thinking, and workspace-trust
acknowledgement routes enter through store-owned daemon methods; focused tests
poison the retired `threadControlSurface`; and conformance rejects the deleted
`runtime-thread-control-surface.mjs` files, retired factory/property names, and
direct route calls into `store.threadControlSurface.*`.
Slice 1433 additionally hard-cut the retired Workbench Studio intent local
fallback in the former `code-editor-adapters/ioi-workbench` tree: that historical
adapter sent canonical snake_case protocol fields to `/v1/studio/intent-frame`,
validated the returned Rust-authored `ioi.studio_intent_frame`, and blocked the
Studio turn when Rust projection is unavailable instead of calling a local JS
prompt classifier.
The retired `fallbackStudioPromptIntentFrame()` resolver, fallback schema,
`local_fallback_feature_resolver` source marker, and prompt-regex
artifact/runtime-cockpit route override are absent from production Workbench
source and guarded by focused plus conformance checks.
Slice 1434 additionally hard-cuts the duplicate runtime task-create planner:
public task creation now enters through store-owned Rust run-create lifecycle
and returns the Rust task replay projection, while
`RuntimeTaskJobCreateStateUpdate*`,
`plan_runtime_task_job_create_state_update`,
`planRuntimeTaskJobCreateStateUpdate()`, task-create schema constants,
task-create normalizer, and task API `buildRun` / `ensureProviderAvailable`
constructor injection are absent from production source and guarded by focused
plus conformance checks.
Slice 1435 additionally hard-deletes the workflow/diagnostics/workspace/thread-turn internal surface module names:
`runtime-workflow-edit-surface.mjs`,
`runtime-diagnostics-repair-surface.mjs`,
`runtime-workspace-snapshot-surface.mjs`,
`runtime-thread-turn-surface.mjs`, their focused tests, and their
`createRuntime*Surface()` factories are absent. Daemon startup now imports the
internal `runtime-workflow-edit-api.mjs`,
`runtime-diagnostics-repair-api.mjs`, `runtime-workspace-snapshot-api.mjs`,
and `runtime-thread-turn-api.mjs` delegates, and conformance rejects the old
surface files/factories from returning as a compatibility anchor for these
already store-owned route families.
Slice 1436 additionally hard-deletes the public projection facade names for
the catalog, skill/hook registry, and repository workflow route families.
Daemon startup mounts only `runtime-tool-api.mjs`,
`runtime-skill-hook-api.mjs`, and `runtime-repository-api.mjs` as internal
delegates. Public `/v1/account`, `/v1/runtime/nodes`, `/v1/tools`,
`/v1/skills`, `/v1/hooks`, and repository workflow routes call `toolApi`,
`skillHookApi`, and `repositoryApi`; conformance requires those API files and
rejects the retired Surface-named files, factories, store properties, and route
calls from returning beside Rust-owned Agentgres projection/replay records.
Slice 1437 additionally hard-deletes the runtime run-read JS surface:
`runtime-run-read-surface.mjs`, its focused test, `createRuntimeRunReadSurface()`,
and the mounted `runReadSurface` daemon-store property are absent. Public
run/usage/authority/replay/trace/artifact reads remain on Rust lifecycle
projection over daemon `state_dir`, while internal state mutation uses explicit
thread-store helpers and a private Agentgres run-state commit projection helper
for commit payload materialization only.
Slice 1438 additionally hard-deletes the runtime thread-event JS surface:
`runtime-thread-event-surface.mjs`, its focused test,
`createRuntimeThreadEventSurface()`, and the mounted `threadEventSurface`
daemon-store property are absent. Public turn/event readback, event append,
thread-start/run-event projection, replay helpers, event-stream paths, and
thread/turn projection methods now call `threads/thread-replay.mjs` and
`thread-turn-projection.mjs` directly from store-owned methods while preserving
the Rust Agentgres admission/projection/replay boundary over daemon
`state_dir`.
Slice 1388 additionally hard-deletes the run-create repository workflow JS
projection facade: run creation and runtime-service turn submission consume
Rust `project_repository_workflow` projections through an explicit
`repositoryWorkflowProjector`, the old JS repository context/projection modules
are deleted, and run PR artifacts bind to Rust artifact metadata instead of a
JS `artifactContents` side channel.
Implementation Slice Evidence: 1389. Slice 1389 hard-deletes the remaining
local runtime-engine helper module: `local-runtime-engines.mjs` and
`local-runtime-engines.test.mjs` are absent, mounted model_mount no longer
imports that helper, and JS-side llama.cpp binary discovery/library-path
materialization cannot return beside Rust runtime-engine projection plus
backend-process planning/supervision. Scheduled matrix-compaction obligation
from Slice 1389 is now satisfied.
Slice 1324 additionally hard-deletes the runtime thread-control existing-model
compatibility fallback: canonical model-control input for Rust route selection
no longer reads persisted camelCase `existingModel` aliases (`routeId`,
`reasoningEffort`, `maxCostUsd`, `workflowGraphId`, or `workflowNodeId`) as
alternate model-route truth. Focused tests and conformance keep canonical
`route_id` / `workflow_node_id` input live while guarding that the retired
existing-control aliases cannot override the Rust-bound request.
Slice 1325 additionally hard-deletes the runtime thread-control top-level alias
truth path: initial/normalized controls, the public thread-control API, and
the lifecycle fallback seed no longer emit `approvalMode` or `updatedAt`
runtime-control duplicates, runtime-backed turn request shaping scrubs
`threadMode` / `approvalMode` aliases before forwarding canonical
`thread_mode` / `approval_mode`, and focused tests plus conformance keep the
retired aliases poisoned but non-authoritative.
Slice 1330 additionally hard-deletes the model_mount invocation helper
compatibility-alias path: migrated model invocation/provider execution/result
helpers reject retired camelCase selection, route-receipt/control,
endpoint/provider, instance/backend-process, token, provider-result, stream,
MCP, and evidence helper fields before any provider execution admission or
provider-result admission request can be shaped; helper normalizers now read
only canonical snake_case Rust model_mount records, and focused tests plus
conformance keep the retired aliases poisoned.
Slice 1347 additionally hard-deletes runtime MCP serve query/raw JSON-RPC
transport compatibility: SDK `threadMcpServeRpc()` no longer inherits MCP list
query options or builds `mcpServeQuery()`, retired serve query-context options
fail before transport, public and runtime thread MCP serve routes reject query
context plus raw JSON-RPC bodies, and the live daemon contract initializes and
lists served tools through the stable `ioi.runtime.mcp-serve-client.v1`
envelope on `/v1/threads/{thread_id}/mcp/serve`.
Slice 1361 additionally hard-cuts stable model_mount Workbench control protocol
clients: `@ioi/hypervisor-workbench` now exports a full `/v1/model-mount/*` control route
catalog and request builder, rejects retired camelCase control request aliases
instead of translating them, and focused IDE tests drive the full route family
while asserting no `/api/v1` model_mount control path can return.

Slice 1267 additionally hard-deletes the model_mount MCP workflow fallback-proof
protocol shape: Rust no longer serializes the old JS proof, command fallback,
binary-bridge fallback, or compatibility fallback false fields for MCP server,
workflow execution, or result payload contracts, and JS/conformance reject
those retired fields if they return.
Slice 1268 additionally hard-deletes the hosted provider lifecycle/inventory
fallback-proof protocol shape: Rust no longer serializes the old JS/command/
binary-bridge/compatibility fallback false fields for provider metadata
transport contracts, and JS/conformance reject those retired fields if they
return.
Slice 1269 additionally hard-deletes the runtime MCP live/serve fallback-proof
protocol shape: Rust no longer serializes the old JS/backend/command/
binary-bridge/compatibility fallback false fields for MCP live-result,
backend-execution, receipt, Agentgres fixture, or served-tool result records,
and JS/conformance reject those retired fields if they return.
Slice 1270 additionally retires the runtime MCP top-level route/client family:
the public daemon no longer handles `/v1/mcp*`, the legacy model-mount daemon no
longer handles `/api/v1/mcp*`, SDK global MCP catalog/control clients are gone,
CLI live MCP aliases are deleted, and MCP status/search/fetch/serve projections
advertise only `/v1/threads/{thread_id}/mcp*` protocol routes.
Slice 1271 additionally retires the runtime doctor/readiness missing-core
compatibility fallback: `/v1/doctor` no longer synthesizes degraded tool,
runtime-node, or skill/hook readiness rows when Rust projection APIs are absent;
the mounted doctor aggregate now fails closed until Rust-authored projections
are available.
Slice 1272 additionally deletes the remaining runtime-service bridge-named
profile helper artifact: live daemon code now imports `runtime-profile.mjs`,
`runtime-api-bridge.mjs` and its test are absent, and conformance guards that
the retired bridge module filename cannot return as compatibility scaffolding.
Slice 1273 hard-cuts runtime doctor/readiness projection ownership into Rust:
`/v1/doctor` now calls typed
`daemonCoreRuntimeProjectionApi.projectRuntimeDoctorReport`, backed by Rust
`RuntimeKernelService::project_runtime_doctor_report`; the
`runtime-doctor-report.mjs` facade and test are absent; and conformance rejects
any return to the JS doctor aggregate, daemon-store doctor wrapper, or mounted
tool/skill surface composition inside the doctor route.
Slice 1274 hard-cuts Studio intent-frame routing ownership into Rust:
`/v1/studio/intent-frame` now calls typed
`daemonCoreRuntimeProjectionApi.projectStudioIntentFrame`, backed by Rust
`RuntimeKernelService::project_studio_intent_frame`; the
`studio-intent-frame.mjs` classifier facade and test are absent; and conformance
rejects any return to the JS resolver, daemon-store route wrapper, or retired
`executionMode` input alias passthrough. Slice 1433 extends this through the
Workbench client: Workbench no longer falls back to a local Studio prompt
classifier and acts only as a protocol client over the Rust-authored frame.
Slice 1275 hard-cuts public computer-use discovery/provisioning projections into
Rust: `/v1/computer-use/providers` and `/v1/computer-use/browser-discovery` now
call typed `daemonCoreRuntimeProjectionApi.projectRuntimeComputerUse`, backed by
Rust `RuntimeKernelService::project_runtime_computer_use`; the
`computer-use-provider-registry.mjs` and `browser-discovery.mjs` facades/tests
are absent; and conformance rejects any return to those JS route dependencies or
retired camelCase request aliases.
Slice 1276 hard-cuts computer-use run materialization into Rust run-create
planning: JS now supplies only a canonical
`computer_use_materialization_request`, Rust `RunCreateStateUpdateCore`
materializes the computer-use trace/events/receipt/artifact during
`plan_run_create_state_update`, the deleted `computer-use-projection.mjs`
facade/test cannot return, and conformance rejects any JS-authored
`computerUse`/`computer_use_projection` candidate on the migrated run-create hot
path.
Slice 1277 retires the root `daemonCoreApi` compatibility mount for the
authority/governed-admission family: external capability authority, cTEE Private
Workspace, worker/service package admission, L1 settlement admission, and
governed-improvement proposal admission now accept only their explicit typed
daemon-core API handles, reject flat or nested `daemonCoreApi` fallbacks before
Rust invocation, and keep command/env fallback plus generic invoker paths
retired.
Slice 1278 retires the remaining root `daemonCoreApi` compatibility mount for
the approval, Agentgres, workspace restore, and context-policy cluster:
coding-tool approval, approval state, runtime Agentgres admission, workspace
restore/snapshot, and runtime context-policy now accept only their explicit typed
daemon-core API handles, reject flat or nested `daemonCoreApi` fallbacks before
Rust invocation, and keep command/env fallback plus generic invoker paths
retired.
Slice 1279 retires the mounted JS runtime bridge turn/control lifecycle facade:
public runtime-service resume and turn submission now call the direct Rust
thread-lifecycle adapter with typed `daemonCoreThreadLifecycleApi` planning,
Agentgres `writeAgent`/`writeRun` commits, and Rust thread/turn projections,
while `agentRunLifecycleSurface.createRuntimeBridgeThreadControl` and
`agentRunLifecycleSurface.createRuntimeBridgeTurn` are absent and conformance
guards that those mounted JS facade calls cannot return.
Slice 1287 hard-cuts runtime thread-event projection/replay cache transport:
projection and replay requests now send runtime `state_dir` and reject
caller-supplied projection `latest_seq`, `expected_head`,
`state_root_before`, `existing_idempotency_keys`, and replay `latest_seq`;
Rust derives head, state root, latest sequence, and idempotency from admitted
`events/*.jsonl` Agentgres records before projection or replay can return.
Slice 1288 hard-cuts runtime thread-event projection fact transport: projection
requests no longer carry JS `workspace_root`, `agent`, or `runs` facts; Rust
derives thread-start and run-event sources from admitted `agents/*.json` and
`runs/*.json` Agentgres records under `state_dir`, and conformance guards the
deleted JS projection helpers plus the rejected fact fields.
Slice 1289 hard-cuts runtime thread-event admission cache transport: direct
generic event admission no longer carries JS-derived `latest_seq`,
`expected_head`, or `state_root_before`; Rust requires runtime `state_dir`, reads
admitted `events/*.jsonl` Agentgres records, derives latest sequence/head/state
root before admission, and conformance guards the rejected cache fields plus the
absence of JS `latestRuntimeEventSeq()` authority in the migrated admission path.
Slice 1290 hard-cuts coding-tool event admission cache transport: result-event
and command-stream admission requests no longer carry JS-derived `latest_seq`,
`expected_head`, or `state_root_before`; Rust requires runtime `state_dir`, reads
admitted `events/*.jsonl` Agentgres records, derives latest sequence/head/state
root before admission, and conformance guards the rejected cache fields plus the
absence of JS `latestRuntimeEventSeq()` authority in both migrated coding-tool
admission paths.
Slice 1291 hard-cuts coding-tool duplicate-result replay out of the JS local
event cache: Rust result-event admission now replays an existing admitted event
with the same idempotency key from Agentgres `events/*.jsonl`, while the
invocation surface no longer reads `runtimeEventStream(...).idempotency` or
wires `codingToolInvocationResultFromEvent` before Rust admission. Conformance
guards the Rust replay path, focused Rust/JS tests, and the absence of the old
JS cache shortcut.
Slice 1292 hard-cuts pending diagnostics feedback off the JS local event cache:
`pendingDiagnosticsFeedbackForNextTurn()` now uses Rust runtime thread-event
replay through `runtimeEventsForStream(..., { since_seq: 0 })` before selecting
diagnostic completion events and fails closed if that Rust replay API is absent;
conformance guards the Rust replay client call and the absence of the old
`runtimeEventStream()` cache read.
Slice 1293 hard-cuts workspace-trust acknowledgement replay and sequencing off
the JS local event cache: workspace-trust warning/ack planning now sends only
runtime `state_dir` and canonical request facts to Rust, Rust replays admitted
`events/*.jsonl` records to resolve warning truth, Rust rejects restored
`events` candidate transport and caller-supplied `seq`, and the JS
workspace-trust state client no longer calls `runtimeEventsForStream()` or
`latestRuntimeEventSeq()` before Rust planning/admission.
Slice 1294 hard-cuts runtime-control state-event sequence cache transport:
thread-control, operator interrupt/steer, context-compaction planning, and
MCP-control state updates now send runtime `state_dir` and event-stream/thread
identity to Rust, Rust replays admitted `events/*.jsonl` records to derive the
latest sequence, Rust rejects caller-supplied `seq` or `previous_latest_seq`,
and the JS thread-control, thread-turn, context-policy, and MCP-control
surfaces no longer call `latestRuntimeEventSeq()` or send sequence authority
fields before Rust planning/admission.
Slice 1295 hard-cuts run-memory command resolution onto the Rust memory
projection/control spine: `resolveRunMemory()` now requires the mounted
thread-memory surface, reads policy/path/record truth through Rust public memory
projection, sends chat/API remember, edit, delete, enable, and disable commands
through Rust `plan_runtime_memory_control` plus Agentgres memory-state commit,
and fails closed before JS memory cache reads if that Rust surface is absent.
The same cut deletes the daemon-store memory pass-through wrappers for remember,
list, policy, path, edit/delete, status/validation, and direct memory
control-event append so migrated memory hot paths cannot re-enter through
store-level compatibility handles.
Slice 1296 hard-cuts runtime task/job runner injection aliases:
`createRuntimeTaskJobApi()` no longer accepts `taskJobCreateRunner`,
`taskJobCancelRunner`, or `taskJobProjectionRunner`, and task create, task/job
cancel, and task/job read projection moved onto the Rust daemon-core task/job
planners/projector before Agentgres-backed run persistence or route projection.
Daemon construction no longer wires parallel task/job runner handles, and
conformance guards that the retired alias names cannot return; Slice 1314
removes the remaining store-mounted planner/projector fallback.
Slice 1297 hard-cuts diagnostics repair runner injection aliases:
`createRuntimeDiagnosticsRepairApi()` no longer accepts
`diagnosticsRepairRunner`; diagnostics repair decision execution, direct
repair/override/retry event append, operator override state update, retry-run
planning, retry-result projection, decision projection, and repair policy
projection resolve only `store.contextPolicyCore` before entering the Rust
daemon-core diagnostics repair planners/projectors. Daemon construction no
longer wires a parallel diagnostics repair runner handle, focused tests mount
fake Rust planners/projectors only under `store.contextPolicyCore`, and
conformance guards that the retired alias name cannot return.
Slice 1298 hard-cuts workflow-edit runner injection aliases:
`createRuntimeWorkflowEditApi()` no longer accepts `workflowEditRunner`;
public workflow-edit proposal and apply controls resolve only
`store.contextPolicyCore` before Rust daemon-core workflow-edit control
planning and Rust runtime-event admission. Daemon construction no longer wires
a parallel workflow-edit runner handle, focused tests mount fake Rust planners
only under `store.contextPolicyCore`, and conformance guards that the retired
alias name cannot return.
Slice 1299 hard-cuts run-cancel runner injection aliases: `cancelRun()` no
longer reads `state.runCancelRunner`; cancellation state planning and
admission-required refusal shaping now resolve through the Rust daemon-core
mount that the auxiliary surface passes explicitly before Agentgres-backed
`writeRun` persistence. Conformance guards that the retired runner alias cannot
return.
Slice 1300 hard-cuts coding-tool budget recovery runner injection aliases:
`createRuntimeCodingToolBudgetRecoveryApi()` no longer accepts
`codingToolBudgetRecoveryRunner`; retry completion, request-approval control,
and approve-override control moved onto the Rust daemon-core budget recovery
planners before wallet authority binding and Agentgres-backed `writeRun`
persistence. Daemon construction no longer wires a parallel budget recovery
runner handle, and conformance guards that the retired alias name cannot
return; Slice 1313 removes the remaining store-mounted planner fallback.
Slice 1301 hard-cuts runtime tool catalog runner injection aliases:
`createRuntimeToolApi()` no longer accepts `toolCatalogRunner`; account,
runtime-node, and tool catalog projections mount the positive
`contextPolicyCore` API directly before Rust daemon-core catalog projection.
Daemon construction no longer wires a parallel tool catalog runner handle,
focused tests mount fake Rust projectors only through `contextPolicyCore`, and
conformance guards that the retired alias name cannot return.
Slice 1302 hard-cuts skill/hook registry runner injection aliases:
`createRuntimeSkillHookApi()` no longer accepts `skillHookRunner`;
catalog, skills, and hooks projections mount the positive `contextPolicyCore`
API directly before Rust daemon-core registry projection. Daemon construction
no longer wires a parallel skill/hook runner handle, focused tests mount fake
Rust projectors only through `contextPolicyCore`, and conformance guards that
the retired alias name cannot return.
Slice 1303 hard-cuts repository workflow runner injection aliases:
`createRuntimeRepositoryApi()` no longer accepts `repositoryRunner`;
repository workflow projections mount the positive `contextPolicyCore` API
directly before Rust daemon-core repository projection. Daemon construction no
longer wires a parallel repository runner handle, focused tests mount fake Rust
projectors only through `contextPolicyCore`, and conformance guards that the
retired alias name cannot return.
Slice 1304 hard-cuts runtime lifecycle projection runner injection aliases:
the historical `createRuntimeLifecycleProjectionSurface()` no longer accepted
`lifecycleRunner`; Slice 1422 later deletes that surface outright. Public
lifecycle projections now enter through the store-owned
`projectRuntimeLifecycleProjection()` API, which delegates to the positive
`contextPolicyCore` Rust daemon-core Agentgres replay projector. Daemon
construction no longer wires a parallel lifecycle runner handle, focused tests
mount fake Rust projectors only through `contextPolicyCore`, and conformance
guards that the retired alias and surface names cannot return.
Slice 1305 hard-cuts the route-level lifecycle admission fallback:
public agent/thread create routes and native agent status/delete/run-create
routes no longer accept a `lifecycleAdmissionRunner` handler option or fall
back through `store.contextPolicyCore ?? lifecycleAdmissionRunner`; those route
families pass only `store.contextPolicyCore` into the direct Rust-backed
lifecycle functions, and conformance guards that the route fallback cannot
return.
Slice 1306 hard-cuts thread-turn surface runner aliases:
`createRuntimeThreadTurnApi()` no longer accepts
`threadLifecycleRunner`, `threadTurnAdmissionRunner`, or
`operatorTurnControlAdmissionRunner`; runtime-service resume/turn submit,
public non-runtime resume/turn create, and operator interrupt/steer planning
all resolve through the single positive `contextPolicyCore` mount, and
conformance guards that the retired aliases cannot return.
Slice 1307 hard-cuts runtime subagent runner wrappers:
`createRuntimeSubagentApi()` no longer routes subagent projection/control
through `subagentProjectionRunner`, `subagentControlRunner`, or the
`store.contextPolicyCore ?? contextPolicyCore` fallback shape; subagent
list/get/result, spawn, wait, input, resume, assign, cancel, propagated cancel,
direct control-event append, and child lifecycle composition all resolve
through the single positive `contextPolicyCore` mount injected by daemon
startup, and conformance guards that the retired wrappers and fallback cannot
return.
Slice 1308 hard-cuts diagnostics repair surface runner wrappers:
`createRuntimeDiagnosticsRepairApi()` no longer routes diagnostics repair
decision control, retry-run planning, retry-result projection, decision
projection, or operator-override state update through
`diagnosticsRepairControlRunner`, `diagnosticsRepairRetryRunRunner`,
`diagnosticsRepairRetryResultProjectionRunner`, `diagnosticsRepairProjectionRunner`,
`diagnosticsOperatorOverrideStateUpdateRunner`, or the
`store.contextPolicyCore ?? null` fallback shape. Decision execution, direct
decision/retry/operator event append, retry turn creation, retry result
projection, decision projection, and operator override execution all resolve
through the single positive `contextPolicyCore` mount injected by daemon
startup; diagnostics retry lifecycle composition passes that same core into the
direct Rust run-create path, and conformance guards that the retired wrappers
and fallback cannot return.
Slice 1309 hard-cuts runtime agent/run lifecycle helper runner fallbacks:
`createAgent()`, `createThread()`, and `createRun()` no longer accept
per-operation state-update runner deps or recover through `store.contextPolicyCore
?? null`; agent create, thread create, run create, and runtime-service bridge
thread start resolve through the explicit `lifecycleAdmissionRunner` dependency
supplied by the daemon route/surface caller, and conformance guards that the
retired per-operation runner deps plus store fallback cannot return. Slice 1420
later deletes the standalone runtime-service thread-control and turn-submit
helper exports entirely.
Slice 1310 hard-cuts conversation-artifact surface runner wrappers:
`createRuntimeConversationArtifactApi()` no longer routes artifact
create/action/export/promote control or list/get/revision projection through
`conversationArtifactControlRunner`, `conversationArtifactProjectionRunner`, or
the `store.contextPolicyCore ?? contextPolicyCore` fallback shape. Public and
thread-scoped conversation-artifact read/control routes resolve through the
single positive `contextPolicyCore` mount injected by daemon startup before Rust
control planning, Rust projection, and Agentgres artifact-state commit;
conformance guards that the retired wrappers and fallback cannot return.
Slice 1311 hard-cuts runtime MCP serve store-core fallback: MCP serve
`tools/call` planning, result projection, and live-result replay now resolve
only through the single positive `contextPolicyCore` mount supplied to
`createRuntimeMcpServeApi()` by daemon startup. The MCP serve API and focused
tests no longer read or model `store.contextPolicyCore`, so served tool-call
truth cannot return through a store-mounted planner fallback; conformance guards
that the retired store-core fallback cannot return.
Slice 1312 hard-cuts coding-tool artifact surface store-core fallback:
artifact draft materialization and artifact read/retrieve projection now resolve
only through the single positive `contextPolicyCore` mount supplied to
`createRuntimeCodingToolArtifactSurface()` by daemon startup. The surface no
longer reads `store.contextPolicyCore ?? contextPolicyCore`, so draft records,
read projections, and result retrieval cannot return through a store-mounted
artifact planner/projector fallback; conformance guards that the retired
store-core fallback cannot return.
Slice 1313 hard-cuts coding-tool budget recovery surface store-core fallback:
retry-approved state update, request-approval control, and approve-override
control now resolve only through the positive `contextPolicyCore` mount
supplied to `createRuntimeCodingToolBudgetRecoveryApi()` by daemon startup.
The surface and focused tests no longer read or model `store.contextPolicyCore`
or `store.contextPolicyCore ?? null`, so budget-recovery run truth cannot return
through a store-mounted planner fallback; conformance guards that the retired
store-core fallback cannot return.
Slice 1314 hard-cuts runtime task/job API store-core fallback: task create,
task/job cancel, and task/job list/get projection now resolve only through the
positive `contextPolicyCore` mount supplied to `createRuntimeTaskJobApi()`
by daemon startup. The API and focused tests no longer read or model
`store.contextPolicyCore` or `store.contextPolicyCore ?? null`, so task/job run
truth and read projection cannot return through a store-mounted
planner/projector fallback; conformance guards that the retired store-core
fallback cannot return.
Slice 1423 hard-deletes the mounted public task/job JS surface: the tracked
module is now `runtime-task-job-api.mjs`, daemon startup mounts it as
`taskJobApi`, and public task/job HTTP routes enter through store-owned
`createRuntimeTask()`, `listRuntimeTasks()`, `getRuntimeTask()`, `cancelRuntimeTask()`,
`listRuntimeJobs()`, `getRuntimeJob()`, and `cancelRuntimeJob()` methods instead of a
route-visible `taskJobSurface` object. Conformance guards that the old
`runtime-task-job-surface.*` files, factory name, and public route call pattern
do not return.
Slice 1424 hardens the active Hypervisor client/product vocabulary boundary:
the developer-facing app docs describe Hypervisor as a native operator client
over Hypervisor Core and the IOI daemon, active sources point at
`HypervisorShellWindow`, configured local llama.cpp preload metadata uses the
`hypervisor-workbench-configured-llama-cpp` identifier, and
`check:runtime-layout` plus Hypervisor conformance reject legacy Autopilot
IDE/Tauri product copy or preload identifiers in active paths.
Slice 1425 hard-deletes the route-visible runtime thread auxiliary JS surface:
the tracked module is now `runtime-thread-auxiliary-api.mjs`, daemon startup
mounts it as `threadAuxiliaryApi`, and thread/run routes enter through
store-owned methods for managed-session inspection/control, workspace-change
review/control, thread fork, and run cancel. Conformance guards that the old
`runtime-thread-auxiliary-surface.*` file/factory/property and direct route
calls cannot return as a parallel route-visible facade.
Slice 1426 hard-deletes the route-visible conversation-artifact JS surface:
the tracked module is now `runtime-conversation-artifact-api.mjs`, daemon
startup mounts it as `conversationArtifactApi`, and public/thread-scoped
conversation-artifact routes enter through store-owned list/create/get/revision
and action/export/promote methods. Conformance guards that the old
`runtime-conversation-artifact-surface.*` file/factory/property and direct
route calls cannot return as a parallel route-visible facade.
Slice 1315 hard-cuts runtime auxiliary compositor store-core fallback:
managed-session projection/control, workspace-change projection/control, and
thread-fork control now resolve only through the positive `contextPolicyCore`
mount supplied to `createRuntimeThreadAuxiliaryApi()` by daemon startup.
The auxiliary API passes that mount to the helper modules explicitly, and
the helper modules plus focused tests no longer read or model
`deps.contextPolicyCore ?? store.contextPolicyCore`, `store.contextPolicyCore`,
or `store?.contextPolicyCore`; conformance guards that the retired store-core
fallback cannot return.
Slice 1425 later deletes the route-visible auxiliary surface outright; the
store-owned auxiliary API methods remain as the route entry points.
Slice 1316 hard-cuts runtime context-policy API store-core fallback:
`compactThread()`, thread/run context-budget event planning, and thread
compaction-policy event planning now resolve only through the positive
`contextPolicyCore` mount supplied to `createRuntimeContextPolicyApi()` by
daemon startup. The internal API and focused tests no longer read or model
`store?.contextPolicyCore ?? contextPolicyCore`, `store.contextPolicyCore`, or
`store?.contextPolicyCore`; conformance guards that the retired store-core
fallback cannot return.
Slice 1317 hard-cuts runtime workflow-edit surface store-core fallback:
workflow-edit proposal and apply controls now resolve only through the positive
`contextPolicyCore` mount supplied to `createRuntimeWorkflowEditApi()` by
daemon startup. The surface and focused tests no longer read or model
`store?.contextPolicyCore ?? null`, `store.contextPolicyCore`, or
`store?.contextPolicyCore`; conformance guards that the retired store-core
fallback cannot return.
Slice 1318 hard-cuts the thread-memory/lifecycle store-core fallback cluster:
the thread-memory surface is now constructed per daemon instance with the
positive `contextPolicyCore` mount supplied by startup, memory projection/control
runners resolve only that constructor mount, and `updateAgent()` / `deleteAgent()`
default their status/delete runners to `null` instead of
`store.contextPolicyCore ?? null`. Focused tests pass the Rust core explicitly,
and conformance guards that the retired memory surface and lifecycle helper
store-core fallbacks cannot return.
Slice 1366 extends the lifecycle route cut to the public/runtime request
boundary: daemon service startup now passes the Rust `contextPolicyCore` as an
explicit request dependency, public doctor/computer-use/studio projections and
agent/thread/run lifecycle controls require that explicit core, and
`public-runtime-routes.mjs` plus `runtime-route-handlers.mjs` no longer read or
model `store.contextPolicyCore` / `store?.contextPolicyCore` as a route fallback.
Focused route tests remove the core from store fixtures, and conformance guards
that the route-family store-core fallback cannot return.
Slice 1319 hard-cuts the run-cancel state-core fallback: `cancelRun()` now
receives the positive `contextPolicyCore` mount explicitly from the auxiliary
surface and subagent cancellation composition. The cancellation helper and
focused tests no longer read or model `state.contextPolicyCore` or
`state?.contextPolicyCore`, and conformance guards that the retired state-core
fallback cannot return.
Slice 1320 hard-cuts the runtime MCP single context-policy core mount:
daemon startup now injects one positive `contextPolicyCore` into MCP catalog,
control, and serve surfaces; the MCP catalog/control surfaces no longer
self-create `RuntimeContextPolicyCore`; and `mcp-manager.mjs` requires an
explicit mounted core instead of constructing a duplicate core from
`daemonCoreMcpApi`. Registry, validation, catalog, status, search/fetch,
live-result, and serve truth cannot return through a manager/surface self-core
fallback, and conformance guards the daemon injection plus the retired self-core
defaults.
Slice 1321 hard-cuts runtime context/memory auxiliary self-core and planner
aliases: coding-tool invocation passes the daemon-owned `contextPolicyCore` into
budget-policy preflight; context-budget, coding-tool budget, and
compaction-policy helpers require explicit mounted runners instead of
self-creating `RuntimeContextPolicyCore`; workflow-only context-budget projection
also requires the constructor mount; coding-tool governance budget-block accepts
only `contextPolicyCore` and ignores the retired `codingToolBudgetBlockPlanner`
alias; thread-control defaults the constructor core to `null`; and
memory-manager status/validation helper self-core fallback was removed before
Slice 1403 deleted the helper facade entirely.
Conformance guards the retired helper self-core defaults, planner alias, and
daemon injection path.
Slice 1404 hard-cuts provider-inventory request-side catalog/evidence truth:
public provider inventory requests no longer carry `item_refs` or
`evidence_refs`, Rust `plan_model_mount_provider_inventory` derives native,
fixture, and hosted metadata item refs plus the evidence set, and Rust rejects
caller-authored inventory refs/evidence as retired transport before an
Agentgres `model-provider-inventory` record can be returned.
Slice 1405 hard-cuts hosted provider catalog `list_models` live transport:
hosted provider inventory requests forward only endpoint/auth/cTEE binding refs,
Rust requires `base_url`, executes the hosted catalog GET, derives model refs
from the live response, binds hosted catalog request/response hashes and endpoint
hashes into the transport contract plus Agentgres `model-provider-inventory`
record, and conformance guards that deterministic JS placeholder catalog truth,
request-side refs/evidence, command/binary/compatibility fallback proof fields,
or missing-endpoint success cannot return.
Slice 1322 hard-cuts runtime-service thread-turn bridge-adapter constructor
aliases: `runtime-thread-turn-api.mjs` no longer accepts
`runtimeBridgeThreadControl` or `runtimeBridgeTurnRun` overrides; runtime-service
resume and turn submission resolve through route-family code with the
daemon-mounted `contextPolicyCore`; focused tests mount fake Rust cores only
through `contextPolicyCore` and install throw-if-called retired aliases; and
conformance guards the absent constructor aliases. Slice 1420 later deletes the
standalone helper exports so runtime-service control/turn execution cannot
re-enter through a separate JS lifecycle helper surface.
Slice 1323 hard-cuts the model_mount read-projection JS facade boundary:
`ModelMountingState` now calls the mounted `modelMountCore.planReadProjection()`
directly through `modelMountReadProjection()` for public model_mount readbacks,
canonical projection persistence, runtime-engine/catalog/server/backend/MCP/
conversation/topology projection reads, and not-found translations. The
standalone helper module is deleted, the focused proof calls mounted state
methods directly, route-family tests mount fake Rust cores only through
`modelMountCore`, and conformance guards the absent helper file/property plus
direct `modelMountReadProjection()` calls.
Slice 1226 additionally retired the runtime compositor/task-job command
transport family: task/job create/cancel/projection, workflow-edit control,
managed-session projection/control, workspace-change projection/control,
thread-fork control, conversation-artifact projection/control, and subagent
projection/control now use typed runtime-control/projection daemon-core APIs,
while Rust command-protocol source is deleted and conformance source-scans keep
the old command operations and dispatch wrappers absent.
Slice 1227 additionally retired the coding-tool result/artifact and
diagnostics-repair command transport family: coding-tool result envelope,
artifact draft/read projection, post-edit diagnostics feedback,
diagnostics-repair control/retry-run, diagnostics-repair decision projection,
and diagnostics repair policy projection now use typed runtime
control/projection daemon-core APIs, while Rust rejects the old command
operations and dispatch wrappers. Slice 1228 retires the remaining
`run_coding_tool_step_module` command transport, and Slice 1262 deletes the
temporary JS StepModule runner facade: the coding-tool invocation surface now
calls typed `daemonCoreWorkloadApi.runCodingToolStepModule` directly, Rust
exposes `RuntimeKernelService::run_coding_tool_step_module`,
`command_protocol.rs` is deleted and `pub mod command_protocol` is absent, and
conformance guards the deleted runner files. Slice 1233 deletes the retired
`ioi-step-module-bridge` binary and the
empty `ioi_step_module_bridge/mod.rs` tombstone; conformance now guards their
absence instead of accepting a fail-closed bridge artifact.
Slice 1234 deletes the remaining Rust service-kernel command-dispatch transport
module: `crates/services/src/agentic/runtime/kernel/command_dispatch.rs` is
absent, `kernel/mod.rs` no longer exports `command_dispatch`, and Slice 1285
deletes `command_protocol.rs` instead of preserving the empty retired-operation
catalog as terminal substrate.
Slice 1235 retires the daemon-wide generic `daemonCoreInvoker` pass-through:
`startRuntimeDaemonServiceWithStore()` and `AgentgresRuntimeStateStore` fail
closed if the top-level option is supplied, and the coding-tool approval policy
factory constructs the default core only from typed `daemonCoreApprovalApi`
instead of forwarding a generic invoker handle.
Slice 1236 binds MCP serve `tools/call` public result truth to Rust-authored
Agentgres live-result replay: Rust emits materialized `runtime.mcp_serve`
`ioi.runtime.mcp-live-result.v1` records with protocol payloads and no-fallback
facts, JS must commit/replay those records before JSON-RPC return, and Rust
replay accepts `runtime.mcp_serve` while continuing to filter JS-authored live
results.
Slice 1237 hard-cuts hosted provider lifecycle/inventory metadata transport out
of the old refusal marker: Rust now emits contained provider metadata transport
contracts with `rust_materialized` execution status, cTEE no-plaintext custody,
wallet.network transport authority, and no retired JS/command/binary-bridge/
compatibility fallback proof fields; the JS protocol edge rejects the retired
`hosted_provider_transport_not_executed` evidence marker before public truth can
return.
Slice 1238 hard-cuts model_mount MCP workflow execution out of the admitted-but-
pending result lane: Rust now materializes deterministic protocol result payloads
and hashes for MCP tool invocation and workflow-node execution receipts,
StepModuleRouter results carry those hashes, JS rejects stale pending
materialization, and receipt/store guards require the Rust materialized result
binding before public execution truth or receipt persistence can return.
Slice 1239 hard-cuts runtime MCP control live invoke/discovery exits out of the
admitted-but-pending transport-result lane: Rust now materializes deterministic
`ioi.runtime.mcp-live-result-payload.v1` protocol payloads and hashes, binds the
hash through the live-exit receipt, control record, Agentgres live-result record,
and replay path, and JS rejects the retired pending Rust transport marker before
result-state commit or public truth can return.
Slice 1240 hard-cuts runtime MCP catalog live-discovery out of the deferred
projection lane: Rust now emits `rust_mcp_live_discovery_materialized` summaries
and `runtime_mcp_live_discovery_rust_materialized` evidence for declared catalog
rows, keeps the retired deferred marker false, and JS/conformance no longer
accept the deferred marker as live-discovery success truth.
Slice 1241 hard-cuts runtime MCP control live results out of the generic backend
materialization lane: Rust now embeds an
`ioi.runtime.mcp-backend-execution.v1` contract in MCP-control live payloads,
binds receipts/results/replay to `ioi_drivers::mcp::McpManager` plus
`ioi_drivers::mcp::transport::McpTransport`, stamps
`rust_driver_contract_bound`, and JS/conformance reject missing driver-backend
contracts before public live-result truth can return.
Slice 1242 hard-cuts runtime MCP control live results out of the planner-direct
terminal-result lane: the surface now requires
`daemonCoreMcpApi.executeRuntimeMcpLiveBackend`, requires
`runtime_mcp_live_backend_rust_driver_executed` evidence and
`rust_driver_executed` backend-execution observation details on the committed
result, and fails closed before receipt/result commit, replay, or agent write
if the backend executor is absent or unbound.
Slice 1243 wires the required MCP live-backend API to real Rust MCP process
I/O: `RuntimeAgentService::execute_runtime_mcp_live_backend()` validates the
typed backend execution request, calls the mounted `McpManager` for
`tools/call` or admitted live `tools/list`, records
`runtime_mcp_live_backend_actual_mcp_manager_io`, and `McpTransport` now
retains its spawned child instead of dropping the `kill_on_drop` process after
pipe extraction.
Slice 1244 closes the runtime MCP live-result receipt-order blocker:
`executeRuntimeMcpLiveBackend()` now runs before receipt/result state commits,
the Rust backend service returns executed control/receipt/result truth, the
actual driver-result hash is bound into the public result payload and recomputed
payload hash, and JS commits only that Rust-returned receipt/result pair before
replay and agent projection.
Slice 1264 additionally removes the stale `admitted_pending_rust_transport`
fixture truth from the Rust Agentgres MCP live-result state commit examples and
protocol tests: runtime MCP live-result commit fixtures now carry
`status: "rust_materialized"`, `result_materialized: true`,
`backend_materialization_status: "rust_driver_contract_bound"`, and no retired
command/binary/compatibility fallback proof fields, while conformance scans
the Agentgres Rust admission/protocol cores to keep the pending-transport marker
out of accepted live-result commit truth.
Slice 1245 closes broader runtime MCP serve admission: Rust
`RuntimeMcpServeToolCallPlanCore` requires wallet authority grant/receipt refs,
cTEE custody refs, and transport containment refs before served `tools/call`
planning; the Rust result projector binds those refs into the
`runtime.mcp_serve` live-result record, and JS commits/replays only that
Rust-authored result.
Slice 1246 closes the SDK/public-route MCP serve protocol gap: the advertised
`/v1/threads/{thread_id}/mcp/serve` route now reaches the mounted Rust-owned
MCP serve surface, stable SDK clients send `ioi.runtime.mcp-serve-client.v1`
protocol bodies with wallet authority refs, cTEE custody refs, and containment
refs, and admission refs no longer ride query-string transport where arrays
could collapse.
Slice 1247 closes the IDE MCP serve client split: React Flow MCP serve state
nodes no longer expose a configurable endpoint override or duplicate camelCase
protocol body fields. The IDE builder now emits the canonical
`/v1/threads/{thread_id}/mcp/serve` daemon protocol request with
`ioi.runtime.mcp-serve-client.v1`, body-carried allowed tools, wallet authority
grant/receipt refs, cTEE custody refs, and containment refs.
Slice 1248 closes the CLI MCP serve client split: the Rust CLI TUI now exposes
`/mcp serve` as a canonical daemon protocol client for
`/v1/threads/{thread_id}/mcp/serve`, emits
`ioi.runtime.mcp-serve-client.v1` bodies with allowed tools, wallet authority
grant/receipt refs, cTEE custody refs, containment refs, and a raw JSON-RPC
`tools/list` message, and carries no endpoint override, top-level
`/v1/mcp/serve`, or query-string admission fallback.
Slice 1249 retires the top-level MCP serve compatibility path: the public
daemon no longer handles `GET` or `POST /v1/mcp/serve`, the SDK no longer
exports the global `serveMcpRpc()` client or `RuntimeMcpServeRpcInput`, and
tests/conformance require MCP serve JSON-RPC to enter through the canonical
thread-scoped `/v1/threads/{thread_id}/mcp/serve` protocol route.
Slice 1250 retires the top-level runtime memory context route family: public
`/v1/memory*` query/body-context routes, daemon-store memory context helpers,
and SDK global memory status/validation clients are gone; explicit
`/v1/threads/{thread_id}/memory*` and `/v1/agents/{agent_id}/memory*` routes are
the protocol surface over Rust-owned memory projection/control records.
Slice 1251 hard-retires the RuntimeAgentService command/binary bridge
substrate and Slice 1272 deletes the bridge-named JS helper module:
`runtime-api-bridge.mjs` is absent, runtime profile normalization lives in
`runtime-profile.mjs`, the `ioi-runtime-bridge` Cargo bin is deleted, daemon startup rejects
`runtimeBridge`, Rust service policy no longer reads bridge command-env
overrides, Agent Studio launch/proof scripts use inference/model-route helper
APIs instead of the deleted helper, and stale retired runtime-service proof
scripts/tests are removed.
Slice 1252 retires the thread/run/subagent lifecycle command-shaped Rust owner
wrapper cluster: `policy/thread_lifecycle.rs` now exposes only direct
`*Core::plan()` request/record APIs for thread control, runtime bridge
thread-start/control/turn, subagent records, and agent/thread/run
create/status/delete; `ThreadLifecycleCommandError`, the lifecycle
`*BridgeRequest` structs, `plan_*_state_update_response` wrappers,
`rust_*_state_update_command` source markers, and bridge-shaped owner tests are
deleted. JS context-policy normalizers are typed API normalizers with
`rust_*_state_update_api` defaults, and conformance forbids the command
wrappers from returning.
Slice 1253 hard-cuts runtime thread-event replay off JS replay candidates:
Rust replay now requires runtime `state_dir`, reads admitted Agentgres
`events/*.jsonl` records itself, rejects caller-supplied replay `events`
transport, and the daemon passes only replay kind, cursor, latest seq, and
`state_dir` into the typed replay API. The old
`runtimeThreadReplayCandidateEvents` collector and public
`replayFromCanonicalState` run-read facade are deleted, and lifecycle run replay
now enters through `eventsForRun` over the mounted Rust thread-event replay
path.
Slice 1254 hard-cuts public lifecycle projection off JS cache candidates:
Rust `project_runtime_lifecycle` now requires runtime `state_dir`, replays
admitted `agents/*.json`, `runs/*.json`, and `events/*.jsonl` records itself,
derives agent/thread/run/turn/event/replay/usage/trace/artifact projections from
those Agentgres records, and rejects caller-supplied lifecycle candidate fields
such as `agents`, `runs`, `events`, `replay`, `usage`, `trace`, and `artifact`.
The store-owned lifecycle projection API passes only route identifiers plus `state_dir`; it
no longer calls JS agent/run maps, thread/turn helpers, usage helpers, event
streams, replay helpers, trace helpers, or artifact resolvers before invoking
Rust.
Slice 1255 folds the remaining public usage and authority-evidence read edges
into that Rust lifecycle projector: Rust projection kinds `usage_list` and
`authority_evidence_summary` derive top-level usage and authority/preflight
evidence from admitted Agentgres `runs/*.json` and `events/*.jsonl` records,
public `/v1/usage`, `/v1/authority-evidence`, and
`/v1/workflow-capability-preflights` call the lifecycle surface, and the old JS
authority summary helper plus run-read `listUsage` / `authorityEvidenceSummary`
facade are retired.
Slice 1256 retires the migrated authority-evidence native compatibility path:
`/api/v1/authority-evidence`, `/api/v1/authority-evidence-summaries`,
`/api/v1/workflow-capability-preflight-evidence`, and
`/api/v1/workflow-capability-preflight` are no longer routed. The canonical
Rust-owned daemon protocol surface for this family is `/v1/authority-evidence`
and `/v1/workflow-capability-preflights`, and conformance now guards that the
native aliases cannot return.
Slice 1257 retires the diagnostics repair retry result JS facade:
`RuntimeDiagnosticsRepairRetryResultProjectionCore` now projects retry result
envelopes through typed
`daemonCoreRuntimeProjectionApi.projectRuntimeDiagnosticsRepairRetryResult`,
the daemon requires that Rust projection API before JS agent lookup/run
creation, validates the complete Rust projection after event admission, rejects
partial or mismatched projections instead of locally filling fields, and the old
JS retry/operator result helpers plus stale daemon constructor wiring are
deleted. Rust rejects
`project_runtime_diagnostics_repair_retry_result` as command transport, and
conformance guards the positive API, missing/partial projection failure paths,
and absence of the deleted helpers.
Slice 1258 retires the IDE diagnostics repair compatibility body: React Flow
diagnostics repair nodes now send only canonical snake_case daemon protocol
fields for decision execution, the public diagnostics repair surface rejects
retired camelCase request aliases before Rust planning/admission, and
conformance guards both the canonical IDE body and daemon alias rejection.
Slice 1259 retires runtime-service lifecycle agent aliases: Rust bridge
start/control planning scrubs retired camel runtime-service identity fields,
emits only canonical snake_case projections, JS lifecycle normalizers reject any
aliased Rust response, daemon runtime identity/session helpers read snake_case
state only, and conformance guards the retired compatibility path.
Slice 1229 additionally retires the model_mount generic daemon-core invoker
shim: `ModelMountCore` rejects `daemonCoreInvoker`, stores only
`daemonCoreModelMountApi`, deletes `invokeDaemonCore()`, removes the command
schema marker from the mounted core, and `ModelMountingState` no longer forwards
the daemon-wide invoker into model_mount.
