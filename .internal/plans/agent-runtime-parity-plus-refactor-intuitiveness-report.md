# Agent Runtime Parity Plus Refactor And Intuitiveness Report

Date: 2026-06-03

Scope: first refactor leg after the parity-plus audit guide. This pass prioritized behavior-preserving extractions that improve ownership boundaries without changing public command ids, request/response envelopes, data-testids, retry-limit semantics, or generated evidence handling.

## Completed Splits

### Live GUI Proof Harness

- Added `scripts/lib/live-gui-proof-harness/` with shared process, network, bridge, file, Playwright, screenshot, and cleanup helpers.
- Migrated Stage 8 managed-session reconnect proof and Stage 9 historic replay proof to the shared harness.
- Moved Stage 8/Stage 9 workbench bridge `/state`, `/commands`, and `/requests` server boilerplate into shared harness bridge helpers while preserving the public bridge envelopes.
- Added checked-in Stage 9 replay fixtures so the live replay proof can run from a clean checkout without relying on ignored `docs/evidence` artifacts.
- Hardened the Stage 8 managed-session control click path to reacquire the Studio webview frame/card across VS Code webview swaps.
- Renamed the Stage 8 synthetic browser card from a spoof-like login-gate label to a manual authentication handoff fixture so the proof reads as operator-control state, not a fake approval surface.
- Renamed lingering private test/proof fixture ids and reasons from `login_gate` to `manual_auth_handoff`; public data-testids and response envelopes are unchanged.
- Kept generated proof outputs ignored under `docs/evidence/`.

### Agent Studio Workbench Extension

- Added `apps/autopilot/openvscode-extension/ioi-workbench/bridge/client.js` for daemon endpoint/token/base-url and JSON request helpers.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/public-text-sanitizer.js` for product-facing assistant/tool text sanitization.
- Replaced remaining Studio public-text sanitizer pass-through wrappers in `extension.js` with direct destructured helpers from the sanitizer factory.
- Replaced pure Studio work-summary and model-completion pass-through wrappers in `extension.js` with direct named helper imports/destructuring while leaving projection-aware composition local.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-state.js` for the initial Agent Studio runtime projection shape.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/migration.js` for migration-assistant command registration.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/quick-input.js` for fork-native QuickInput handoff commands.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/chat.js`.
- Moved IOI Chat command registration and artifact-review chat handoff registration out of `extension.js` while preserving public `ioi.chat.*` and `ioi.artifacts.review` command ids and bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-quick-input.js`.
- Moved Agent Studio native context/tool QuickPick command registration out of `extension.js` while preserving `ioi.studio.openContextPicker` and `ioi.studio.openToolPicker` command ids and bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-managed-sessions.js` for managed browser/computer session projection, daemon inspection application, and reconnect proof bridge reporting.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-replay.js` for replay-step projection from runtime events and receipts.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-test-hooks.js` for parity-plus/test-hook command registration while preserving public command ids.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/context-snapshot.js` for workbench context snapshots, SCM/task state, diagnostics, and inspection-target index projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/modes.js`.
- Moved Agent Studio Ask/Agent execution-mode and permission-mode normalization, labels, option rows, thread-mode mapping, and daemon mapping out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio mode pass-through wrappers and duplicated mode constants in `extension.js` with direct named imports from `studio/modes.js`.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/source-refs.js`.
- Moved Studio runtime-event JSON parsing, partial JSON source recovery, source-chip normalization, source-reference traversal, and excerpt selection out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio source-reference pass-through wrappers and stale local compatibility-key constant in `extension.js` with direct named imports from `studio/source-refs.js`.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-intent.js`.
- Moved Studio artifact/canvas prompt classification, local intent-frame fallback routing, artifact class/title/summary derivation, and intent-frame payload projection out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio artifact-intent pass-through wrappers in `extension.js` with direct destructured helpers from the artifact-intent factory.
- Added focused artifact-intent tests for generated website artifacts, browser observation captures, Ask-mode routing, runtime-cockpit routing, injected retrieval/workspace predicates, and snake/camel payload normalization.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-preview.js`.
- Moved Studio conversation artifact class labels, output modality detection, preview label/srcdoc shaping, inline preview rendering, and artifact row HTML out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio artifact-preview pass-through wrappers in `extension.js` with direct destructured helpers from the artifact-preview factory.
- Added focused artifact-preview tests for website/generic labels, media-type preview labels, CSP nonce injection, source preview escaping, and stable artifact row data-testids.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/managed-session-view.js`.
- Replaced the remaining Studio managed-session-view pass-through wrappers in `extension.js` with direct destructured helpers from the managed-session-view factory.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/pending-work.js`.
- Moved Studio pending-work filtering, concrete tool row normalization, command-output excerpt projection, pending worklog upsert/de-dupe behavior, runtime-event pending-step projection, runtime-event seen-id tracking, and tool-label mapping out of `extension.js`.
- Added focused pending-work tests for abstract row filtering, command-output redaction/preservation, row update behavior, runtime-event projection, source chips, and seen-id de-duping.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/work-record-projection.js`.
- Moved sanitized command-output projection, workspace-path bounding, command label/status shaping, diff-hunk projection, command/work-row duplicate filtering, and public work-record webview projection out of `extension.js`.
- Added focused work-record projection tests for command trace/path redaction, workspace-relative hunk paths, generic command-row filtering, richer command output preservation, managed-session passthrough, and public output redaction.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/response-metrics.js`.
- Moved Studio response token/latency metrics projection, response-metrics rows, reasoning split, thinking rows, answer content rows, and receipt-backed verified badge rendering out of `extension.js`.
- Added focused response-metrics tests for provider usage aliases, estimated token fallback, escaped metrics HTML, thinking extraction, verified/pending badge rendering, and response usage alias projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/source-chip-renderer.js`.
- Moved Studio answer-source footer rendering, source-chip URL/icon sanitization, favicon fallback selection, chip HTML rendering, and direct/artifact source de-duping out of `extension.js`.
- Added focused source-chip renderer tests for URL sanitation, explicit and fallback favicon handling, safe anchor/span rendering, escaped labels, duplicate source removal, and fallback icon data URIs.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/code-execution.js`.
- Moved Studio fenced-code extraction, plan-only code execution policy classification, and chat code-execution card rendering out of `extension.js`.
- Added focused code-execution tests for executable fence language aliases, network/host-write blocking, plan-only payload projection, disabled blocked actions, and empty non-executable turns.
- Moved managed browser/computer session work-record attachment and card row rendering out of `extension.js` behind compatibility wrappers.
- Added focused managed-session view tests for bounded session-card attachment, waiting-for-user handoff rendering, control-state data-testids, HTML escaping, and default sandbox browser state.
- Kept compatibility wrappers in `extension.js` where existing tests or local call sites expect the old function names.

Status: `extension.js` is still a composition-heavy file and remains larger than the guide's ideal target. The safe next extractions are Studio projection events, remaining test hooks, panel lifecycle, and command grouping by Studio/workflows/models/runs.

### Runtime Daemon

- Added `packages/runtime-daemon/src/runtime-request-metadata.mjs`.
- Moved request base URL, runtime event cursor parsing, usage request metadata projection, and usage metadata application out of `index.mjs`.
- Passed `RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION` into the helper explicitly so the module stays decoupled from the daemon constants bundle.
- Added `packages/runtime-daemon/src/threads/thread-runtime-controls.mjs`.
- Moved thread mode/approval normalization, initial and normalized runtime controls, request control injection, model-control update shaping, model policy/workflow context projection, reasoning-effort normalization, and model route receipt binding out of `index.mjs`.
- Added `packages/runtime-daemon/src/threads/context-budget-policy.mjs`.
- Moved context-budget telemetry selection, threshold normalization, context-budget evaluation, coding-tool budget policy shaping, and compaction-policy decisions out of `index.mjs`.
- Added `packages/runtime-daemon/src/repository-context.mjs`.
- Moved read-only repository context projection, branch policy projection, GitHub remote context projection, workspace-trust warning projection, git porcelain counting, and remote credential redaction helpers out of `index.mjs`.
- Added focused repository-context tests for porcelain counting, GitHub remote redaction/metadata, read-only branch/GitHub policy projection, and UI trust override ignoring.
- Added `packages/runtime-daemon/src/http/public-runtime-routes.mjs`.
- Moved the public daemon HTTP request dispatcher, CORS preflight handling, top-level route table, delegated thread/agent/run route dispatch, MCP serve thread requirement, and public route error boundary out of `index.mjs`.
- Added focused public-runtime route tests for preflight, top-level daemon projection dispatch, delegated thread subroutes, and MCP serve validation.
- Added `packages/runtime-daemon/src/threads/managed-session-state.mjs`.
- Moved runtime-backed managed-session inspection/control bridge behavior out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegator methods.
- Added focused managed-session thread-state tests for fixture fallback snapshots, runtime bridge inspection normalization, control command construction, and missing session-id validation.
- Added `packages/runtime-daemon/src/threads/workspace-change-state.mjs`.
- Moved runtime-backed workspace-change review inspection/control bridge behavior out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegator methods.
- Added focused workspace-change thread-state tests for fixture fallback snapshots, runtime bridge inspection normalization, control command construction, and missing change-id validation.
- Added `packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs`.
- Moved runtime-service thread start orchestration, runtime-service turn submit orchestration, runtime-service control-thread bridge calls, start-result normalization, submit-turn normalization, and live-event normalization out of `index.mjs` behind existing `createRuntimeBridgeThread`, `createRuntimeBridgeTurn`, `resumeThread`, `interruptTurn`, `normalizeRuntimeBridgeThreadStart`, `normalizeRuntimeBridgeTurnSubmit`, and `normalizeRuntimeBridgeLiveEvent` compatibility methods.
- Added focused runtime bridge thread tests for bridge input shaping, updated-agent persistence, event append behavior, bridge-unavailable error mapping, turn submit max-step clamping, in-flight cleanup, run persistence, control-thread input/error handling, event default projection, start-contract failures, submit-turn projection defaults, submit-turn contract failures, and live-event envelope normalization.
- Added `packages/runtime-daemon/src/bridges/runtime-agent-bridge.mjs`.
- Moved runtime bridge capability checks and runtime-service external-blocker shaping out of `index.mjs` behind existing `assertRuntimeBridgeAvailable` and `runtimeBridgeUnavailable` compatibility methods.
- Added `packages/runtime-daemon/src/computer-use-inputs.mjs`.
- Moved computer-use action kind normalization, approval/control input parsing, browser session-mode selection, CDP timeout/endpoint checks, visual GUI observation metadata projection, media-type inference, and controlled-relaunch unavailable execution shaping out of `index.mjs` behind compatibility wrappers.
- Added `packages/runtime-daemon/src/runtime-mcp-helpers.mjs`.
- Moved MCP server/tool resolution, MCP serve tool descriptor/result shaping, JSON-RPC envelopes, live transport mode metadata, registry enrichment, catalog summary/exposure shaping, mutation-input normalization, config-source filtering, and catalog/tool search limit helpers out of `index.mjs` behind compatibility wrappers.
- Added focused runtime MCP helper tests for server/tool identity resolution, MCP serve descriptor/result metadata, JSON-RPC error mapping, live transport inference, deferred catalog exposure, mutation input normalization, and registry projection counts.
- Added `packages/runtime-daemon/src/skill-hook-catalog.mjs`.
- Moved skill/hook source discovery, SKILL.md metadata parsing, hook definition normalization, redacted command hashing, validation issue projection, and active catalog hashing out of `index.mjs`.
- Added focused skill-hook catalog tests for workspace/global compatibility sources, filesystem discovery, command redaction, validation degradation, metadata parsing, and compatibility alias normalization.
- Added `packages/runtime-daemon/src/skill-hook-manifest.mjs`.
- Moved active skill/hook manifest selection, dry-run policy planning, preview invocation ledger projection, blocked-hook escalation shaping, and hook escalation receipt projection out of `index.mjs`.
- Added focused skill-hook manifest tests for explicit/configured selection normalization, redacted manifest projection, dry-run blocked/would-run decisions, invocation ledger counts, and escalation receipt details.
- Added `packages/runtime-daemon/src/threads/thread-replay.mjs`.
- Moved runtime event append/idempotency, thread-start/run-event projection, cursor bounds, stream lookup, replay-by-stream/turn, persisted event registration, and stream-path helpers out of `index.mjs` behind existing replay compatibility methods.
- Added `packages/runtime-daemon/src/threads/thread-store.mjs`.
- Moved agent list/get/update/delete, thread-to-agent lookup, in-flight runtime turn registration, and thread-turn resolution helpers out of `index.mjs` behind existing store compatibility methods.
- Extended `thread-store.mjs` to own run list/get and run/thread usage projection helpers while preserving existing `AgentgresRuntimeStateStore` method names.
- Added `packages/runtime-daemon/src/threads/thread-persistence.mjs`.
- Moved agent/run record persistence, run projection writes, and persisted run operation terminal-event summarization out of `index.mjs` behind existing `writeAgent` and `writeRun` compatibility methods.
- Added `packages/runtime-daemon/src/runtime-tool-catalog.mjs`.
- Moved runtime account/node/tool catalog projections, tool governance metadata normalization, and doctor-safe runtime node redaction out of `index.mjs` while preserving existing public methods and MCP serve descriptor behavior.
- Added `packages/runtime-daemon/src/repository-projections.mjs`.
- Moved public repository/GitHub projection wrapper orchestration for repository lists, repository context, branch policy, GitHub context, PR attempts, issue context, review gates, and GitHub PR create plans out of `index.mjs` behind existing store methods.
- Added `packages/runtime-daemon/src/repository-workflow-projections.mjs`.
- Moved concrete GitHub issue-context, PR-attempt, review-gate, PR branch/diff artifact, and GitHub PR create-plan builders out of `index.mjs` behind dependency-injected workflow projection helpers while preserving existing store method behavior.
- Added `packages/runtime-daemon/src/runtime-artifacts.mjs`.
- Moved runtime artifact record construction and run artifact reference resolution out of `index.mjs` while preserving route-handler artifact lookup and runtime-record projection injection.
- Added focused runtime artifact tests for stable artifact ids/content serialization, string content preservation, id/name/ref lookup, `artifact:` prefixed lookup, and missing artifact tolerance.
- Added `packages/runtime-daemon/src/runtime-coding-tool-approval.mjs`.
- Moved coding-tool effect approval classification, workflow approval policy projection, approval manifest creation, and approval retry-manifest matching out of `index.mjs`.
- Added focused coding-tool approval tests for local-read bypass, nested workflow policy controls, manifest schema aliases, ignored UI override detection, omitted no-gate manifests, and snake/camel retry matching.
- Added `packages/runtime-daemon/src/runtime-invocation-results.mjs`.
- Moved coding-tool invocation result projection plus computer-use browser discovery, control, and native-browser multi-event result projection out of `index.mjs`.
- Added focused invocation-result tests for coding-tool replay aliases, browser discovery object normalization, control handoff/cleanup aliases, ordered native-browser event merging, receipt/artifact/rollback de-duping, and projection payload precedence.
- Added `packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.mjs`.
- Moved coding-tool budget recovery action normalization, target-node selection, recovery-policy shaping, retry-limit bounding, budget-blocked event detection, and recovery result envelope projection out of `index.mjs`.
- Added focused coding-tool budget recovery tests for action aliases, invalid action rejection, target-node de-duping, default policy shaping, blocked-event detection, retry-limit bounds, and snake/camel result aliases.
- Added `packages/runtime-daemon/src/runtime-approval-lease.mjs`.
- Moved approval lease metadata construction/recovery, approval lease expiry state derivation, approval decision normalization, and approval decision reason mapping out of `index.mjs`.
- Added focused approval lease tests for TTL expiry calculation, policy hash/default lease ids, nested/top-level payload aliases, decision lease precedence, expired lease detection, approve/reject aliases, and invalid decision errors.
- Added `packages/runtime-daemon/src/diagnostics-repair-execution.mjs`.
- Moved diagnostics repair execution result projection, operator override approval shaping, restore-apply approval/conflict/status/policy-ref helpers, and restore-apply summary text out of `index.mjs` behind dependency-injected helper exports.
- Added focused diagnostics repair execution tests for approval/conflict policy refs and public snake/camel retry and operator-override envelopes.
- Added `packages/runtime-daemon/src/runtime-usage-events.mjs`.
- Moved runtime bridge usage-delta insertion, usage delta payload shaping, context-pressure delta/alert payload shaping, and context pressure rounding/status helpers out of `index.mjs` behind dependency-injected helper exports.
- Added focused runtime usage event tests for telemetry aliases, context-pressure alert actions, insertion order after `turn.started`, and public event kinds.
- Added `packages/runtime-daemon/src/runtime-memory-helpers.mjs`.
- Moved runtime memory policy override aliases, memory write approval/blocking, list filter aliases, memory operation vocabulary, and subagent memory inheritance policy/receipt helpers out of `index.mjs` behind dependency-injected helper exports.
- Added focused runtime memory helper tests for policy aliases, write blocking, operation/event vocabulary, subagent inheritance evidence, and filter alias normalization.
- Added `packages/runtime-daemon/src/runtime-run-helpers.mjs`.
- Moved run result text, mode-to-task-family/strategy mapping, capability sequence construction, and run-event id/cursor construction out of `index.mjs` behind dependency-injected helper exports.
- Added focused runtime run helper tests for mode vocabulary, memory-specific result text, capability sequence additions, and stable event id/cursor shaping.
- Added `packages/runtime-daemon/src/runtime-run-event-helpers.mjs`.
- Moved run-event status mapping, policy decision ref extraction, string payload record conversion, component/workflow-node mapping, receipt/artifact refs, and computer-use artifact ref extraction out of `index.mjs`.
- Added focused runtime run-event helper tests for status mapping, policy ref de-duping, payload conversion, receipt/artifact refs, workflow nodes, and computer-use artifacts.
- Added `packages/runtime-daemon/src/runtime-identifiers.mjs`.
- Moved runtime thread/agent/run/turn/session id derivation, runtime-backed agent detection, fixture profile defaults, and lifecycle/thread status normalization out of `index.mjs`.
- Added focused runtime identifier tests for prefix compatibility, event stream ids, runtime session fallback, fixture profile override/null preservation, runtime profile detection, and lifecycle status aliases.
- Replaced leftover `computer-use-inputs` pass-through wrappers in `index.mjs` with direct named imports, keeping the controlled-relaunch unavailable wrapper only where `index.mjs` injects canonical `uniqueStrings`.
- Replaced leftover `runtime-mcp-helpers` pass-through wrappers in `index.mjs` with direct named imports, keeping MCP implementation ownership in `runtime-mcp-helpers.mjs`.

Status: `index.mjs` still owns the large state store and public route composition. Safe next extractions are daemon service lifecycle, thread store/control/replay persistence, and route registration glue.

### Model Mounting

- Added `packages/runtime-daemon/src/model-mounting/environment.mjs`.
- Moved LM Studio discovery gates, internal fixture exposure gates, live catalog/download gates, and catalog/download timeout parsing out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-registry.mjs`.
- Moved catalog provider port ordering and provider status projection out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-entries.mjs`.
- Moved fixture catalog records, local manifest payload normalization, Hugging Face catalog entry shaping, Ollama artifact catalog entry shaping, variant projection, and catalog entry enrichment out of `model-mounting.mjs`.
- Moved model quantization parsing into `catalog-helpers.mjs` so catalog entries and local artifact metadata share one parser.
- Added `packages/runtime-daemon/src/model-mounting/provider-auth.mjs`.
- Moved provider secret input detection, vault ref sanitization, hosted-provider fail-closed checks, provider auth header normalization, and vault-backed provider header resolution out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/oauth-boundary.mjs`.
- Moved OAuth vault-ref construction, PKCE challenge generation, authorization URL redaction, token expiry/refresh predicates, public OAuth session/state projection, OAuth boundary projection, and token response validation out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs`.
- Moved configurable catalog provider checks, catalog provider config updates, source material vault binding, catalog auth scheme normalization, catalog auth header resolution, and request-time catalog auth header construction out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-ports.mjs`.
- Moved fixture, local manifest, Ollama, Hugging Face, and custom HTTP catalog provider port construction plus catalog provider health helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/protocol-responses.mjs`.
- Moved OpenAI chat/completions/responses/embeddings and Anthropic message response shaping plus deterministic embedding vector generation out of `model-mounting.mjs`, while preserving compatibility re-exports from `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/provider-protocol.mjs`.
- Moved provider request body shaping, provider output extraction, usage normalization, public trace summarization, deterministic fixture text/token helpers, and safe truncation helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/local-system-probes.mjs`.
- Moved public command execution wrappers, LM Studio CLI parsers/projections, local artifact inspection and metadata parsing, hardware snapshots, file readers, executable discovery, and native-local resource estimates out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/provider-driver-helpers.mjs`.
- Moved provider-kind driver mapping, default backend mapping, response-state protocol checks, and deterministic low-variance invocation coalescing helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/load-policy.mjs`.
- Moved load-policy normalization, load-option normalization, runtime-engine default load options, TTL detection, LM Studio CLI load-argument shaping, and loaded-instance expiry calculation out of `model-mounting.mjs`.
- Added focused load-policy tests for string policies, snake/camel aliases, runtime-engine defaults, explicit TTL detection, expiration semantics, and LM Studio public CLI args.
- Added `packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs`.
- Moved native-local query extraction, deterministic native fixture output, native-local JSONL stream record shaping, JSONL stream construction, and deterministic stream delay handling out of `model-mounting.mjs`.
- Added focused native-local fixture tests for query extraction, deterministic embedding/mode output, stream records, stream abort handling, and bounded stream delay overrides.
- Added `packages/runtime-daemon/src/model-mounting/provider-transport.mjs`.
- Moved provider JSON/stream HTTP transport, provider-open retry operation recording, provider HTTP error shaping, and provider command error shaping out of `model-mounting.mjs`.
- Added focused provider-transport tests for local JSON fetch, tolerated HTTP failures, local-only endpoint rejection, provider error redaction, and command stderr hashing.
- Added `packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs`.
- Moved native-local and deterministic fixture provider driver classes out of `model-mounting.mjs`.
- Added focused provider-local-driver tests for fixture invocation, native-local load lifecycle, native-local JSONL streaming, and stream-abort backend logging.
- Added `packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs`.
- Moved the OpenAI-compatible provider driver out of `model-mounting.mjs` while preserving the same driver dispatch seam for hosted-compatible, LM Studio, vLLM, and llama.cpp callers.
- Added focused OpenAI-compatible driver tests for model listing, chat completion invocation, and responses-to-chat fallback.
- Added `packages/runtime-daemon/src/model-mounting/provider-ollama-driver.mjs`.
- Moved the Ollama provider driver out of `model-mounting.mjs` while preserving the same driver dispatch seam.
- Added focused Ollama driver tests for model listing, loaded model projection, chat invocation, embedding invocation, and load/unload probes.
- Added `packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs`.
- Moved the vLLM and llama.cpp provider driver wrappers out of `model-mounting.mjs` while preserving the shared OpenAI-compatible driver composition.
- Added focused backend-driver tests for backend URL promotion, supervised load/unload evidence, and loaded instance projection.
- Added `packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs`.
- Moved the LM Studio public CLI provider driver out of `model-mounting.mjs` while preserving OpenAI-compatible invoke/stream composition.
- Added focused LM Studio driver tests for absent CLI fail-closed behavior and public CLI health/start/stop/load/unload lifecycle commands.
- Added `packages/runtime-daemon/src/model-mounting/wallet-authority.mjs`.
- Moved the Agentgres wallet authority capability grant/authorization/revocation adapter out of `model-mounting.mjs`.
- Added focused wallet authority tests for grant creation, authorization, policy denial, revocation, vault-ref redaction, and remote boundary status.
- Added `packages/runtime-daemon/src/model-mounting/vault-port.mjs`.
- Moved the Agentgres local vault port, encrypted keychain vault material adapter, env adapter factory, and vault-ref env alias helper out of `model-mounting.mjs`.
- Added focused vault port tests for encrypted persistence without plaintext, partial env fail-closed status, env alias resolution, public metadata redaction, audit redaction, bind/list/remove behavior, and non-persistent metadata serialization.
- Added `packages/runtime-daemon/src/model-mounting/oauth-credential-provider.mjs`.
- Moved OAuth authorization, token exchange, refresh, revoke, and access-header orchestration out of `model-mounting.mjs` while reusing the existing OAuth boundary helpers.
- Added focused OAuth credential provider tests for vault-bound authorization state, redacted authorization URLs, callback fail-closed behavior, client-secret vault policy, and revoke cleanup.
- Added `packages/runtime-daemon/src/model-mounting/projections.mjs`.
- Moved model-mounting product projection assembly, authority snapshot assembly, adapter-boundary projection, receipt replay linkage, and route-decision projection derivation out of `model-mounting.mjs`.
- Added focused projection tests for category bucketing, operation watermarking, authority summaries, adapter boundaries, receipt replay links, and route-decision derivation.
- Added `packages/runtime-daemon/src/model-mounting/read-model.mjs`.
- Moved read-only model-mounting list accessors, product/OpenAI model list projections, provider health listing, and snapshot category assembly out of `model-mounting.mjs` behind existing `ModelMountingState` methods.
- Added `packages/runtime-daemon/src/model-mounting/provider-registry.mjs`.
- Moved hosted provider shaping, public provider redaction/vault-boundary projection, and route string validation helpers out of `model-mounting.mjs` behind compatibility wrappers.
- Added `packages/runtime-daemon/src/model-mounting/server-control.mjs`.
- Moved model gateway/server status, start/stop/restart control state, lifecycle operation receipts, redacted server log/event projection, and server log ring-buffer writes out of `model-mounting.mjs` behind existing `ModelMountingState` methods.
- Added focused server-control tests for status projection, lifecycle state/receipt/log writes, restart previous-state capture, redacted log/event reads, and limit bounding.
- Added `packages/runtime-daemon/src/model-mounting/schema-relations.mjs`.
- Moved model-mounting relation schema metadata out of `ModelMountingState.writeSchemaRelationSchemas()` and added focused tests for canonical relation names and compatibility-critical fields.
- Added `packages/runtime-daemon/src/model-mounting/default-records.mjs`.
- Moved default provider, fixture artifact, fixture endpoint, route, LM Studio detected artifact, and backend registry record construction out of `model-mounting.mjs` while keeping stateful discovery/pruning/persistence on `ModelMountingState`.
- Added focused default-record tests for compatibility ids, hosted/local boundary status, route denials, provider-derived LM Studio artifact state, and backend process status projection.
- Added `packages/runtime-daemon/src/model-mounting/validation.mjs`.
- Moved continuation route/endpoint/model safety checks and workflow Receipt Gate validation out of `model-mounting.mjs` behind compatibility-preserving `ModelMountingState` wrappers.
- Added focused validation tests for continuation modes, unsafe route mismatch blocking, Receipt Gate pass receipts, and Receipt Gate mismatch/tool-link failures.
- Added `packages/runtime-daemon/src/model-mounting/routes.mjs`.
- Moved route record normalization, explicit model endpoint ordering/mount fallback, route policy selection, and model route-selection receipt shaping out of `model-mounting.mjs` behind compatibility-preserving `ModelMountingState` wrappers.
- Added focused route helper tests for route aliases, fallback endpoint ordering, explicit-model auto-mount, policy rejection reasons, route blocker details, and route-decision receipt metadata.

Status: `model-mounting.mjs` still owns seeding orchestration, state-machine behavior, route persistence wrappers, and some product projection glue. Safe next extractions are state-machine slices and remaining route HTTP glue.

### Rust Runtime Hot Spot

- Added `crates/services/src/agentic/runtime/service/decision_loop/retry_limits.rs`.
- Moved the explicit retry failure ceiling and terminal retry-limit status into a named helper module.
- Preserved the important contract: zero budget remains an unset budget and does not trip retry-limit failure before the consecutive-failure ceiling.
- Added `crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply_product_handoff.rs`.
- Moved final-reply product handoff sanitization, direct-chat reply unwrapping/cycle collapse, internal runtime marker redaction, disposable path/URL cleanup, and product-facing raw-output rejection reasons out of `final_reply.rs`.
- Preserved the existing `cognition` module re-exports so final-reply tests and call sites keep using the same internal function names while the implementation now lives behind a focused module.
- Added `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/tool_outcome/terminal_reply_classification.rs`.
- Moved terminal chat reply/source-candidate/tool-plan classification, workspace contextual-answer detection, and file-mutation policy-report detection out of the `tool_outcome` support include while preserving the parent-module helper names used by tests and outcome handling.
- Added `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/finalize_action_processing/completion_guards.rs`.
- Moved finalize-action duplicate/no-op guards, read-only workspace duplicate detection, browser-surface release predicate, web-pipeline completion labels, product handoff violation message construction, and file-edit patch-miss receipt evidence shaping out of `finalize_action_processing.rs` while preserving parent-module helper names for tests.
- Added `crates/services/src/agentic/runtime/service/queue/support/pipeline/facts/market_quote.rs`.
- Moved market-quote source grading, structured metric coverage counts, comparison-context counts, quote-grounding floors, and pending quote-grounding readiness out of `facts.rs` behind a crate-visible re-export so existing queue/final-reply call sites keep their public path.
- Added `crates/services/src/agentic/runtime/execution/filesystem/handler/policy.rs`.
- Moved filesystem handler patch failure classification, workspace read/write boundary wrappers, and safe regular-file read/write target guards out of `handler.rs` while preserving handler-module helper names used by policy tests and filesystem tool handling.
- Added `crates/services/src/agentic/runtime/substrate/semantic_impact.rs`.
- Moved substrate semantic-impact projection, changed-path classification, mutating-tool detection, and targeted test-selection hints out of `substrate.rs` while preserving the public `RuntimeSubstrateSnapshot` projection API and substrate test behavior.

## Naming And Vocabulary Decisions

- Kept public/product names stable: Agent Studio command ids, `ioi.*` command ids, data-testids, daemon routes, and request/response envelopes were not renamed.
- Treat the Stage 8 manual-auth handoff fixture as managed-session/operator-control and reconnect coverage only. It is intentionally not a real login, credential, CAPTCHA, payment, or approval-policy proof; future auth durability should use a separate local HTTP auth fixture with cookie/session behavior.
- Added `internal-docs/prompts` to `.gitignore` and removed tracked prompt files from the next tree so local prompt material stays out of `master`.
- Introduced private/module-level names that describe ownership boundaries:
  - `public-text-sanitizer`
  - `studio/projection-managed-sessions`
  - `studio/projection-replay`
  - `commands/studio-test-hooks`
  - `workbench/context-snapshot`
  - `runtime-request-metadata`
  - `threads/thread-runtime-controls`
  - `threads/context-budget-policy`
  - `repository-context`
  - `http/public-runtime-routes`
  - `model-mounting/environment`
  - `model-mounting/provider-auth`
  - `model-mounting/oauth-boundary`
  - `repository-workflow-projections`
  - `model-mounting/catalog-provider-config`
  - `model-mounting/catalog-provider-ports`
  - `model-mounting/protocol-responses`
  - `model-mounting/provider-protocol`
  - `model-mounting/local-system-probes`
  - `model-mounting/provider-driver-helpers`
  - `model-mounting/load-policy`
  - `model-mounting/native-local-fixture`
  - `model-mounting/provider-transport`
  - `model-mounting/provider-local-drivers`
  - `model-mounting/provider-openai-compatible-driver`
  - `model-mounting/provider-ollama-driver`
  - `model-mounting/provider-openai-backend-drivers`
  - `model-mounting/provider-lm-studio-driver`
  - `model-mounting/wallet-authority`
  - `model-mounting/vault-port`
  - `model-mounting/oauth-credential-provider`
  - `cognition/final_reply_product_handoff`
  - `tool_outcome/terminal_reply_classification`
  - `finalize_action_processing/completion_guards`
  - `queue/support/pipeline/facts/market_quote`
  - `filesystem/handler/policy`
  - `substrate/semantic_impact`
  - `model-mounting/projections`
  - `decision_loop/retry_limits`
  - `live-gui-proof-harness`
- Deferred disruptive mass renames until after larger ownership modules are extracted and compatibility shims can be added deliberately.

## CLI/TUI Adapter Status

CLI/TUI surfaces were not hardened in this leg because the active parity-plus product proof path remains the OpenVSCode/Agent Studio GUI plus daemon runtime. The CLI/TUI adapters should stay separately gated unless they become active product commitments. If activated, they need the same stream/replay/redaction/policy/managed-session contract checks used by the GUI proof path.

## Remaining Follow-Ups

- Reduce `extension.js` further by moving Studio projection events, managed-session controls, panel lifecycle, and feature command groups.
- Reduce `packages/runtime-daemon/src/index.mjs` by extracting service lifecycle, route registration, thread store/control, replay, and managed-session state.
- Reduce `model-mounting.mjs` further by moving provider registry/drivers, wallet/vault ports, state machine, validation, and routes.
- Continue Rust hot-spot splits around final reply contract, tool outcome classification, finalize action processing, queue facts, filesystem handler, and substrate lifecycle.
- Run longer integrated sessions to watch for retry-limit regressions and replay/reconnect durability under real use.
- Keep watching the product UI for raw trace/tool/path leakage after every projection or panel lifecycle extraction.
