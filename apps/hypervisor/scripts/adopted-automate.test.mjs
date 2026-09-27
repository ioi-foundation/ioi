// The adopted Automate seed's pure adapters (R-241, ADR 0056 P3 cut 3b): the GraphQL resolver's field
// merge, the function-registry facts, the save-location facts and the wizard's create translation.
import test from "node:test";
import assert from "node:assert/strict";
import { answerDocument } from "./adopted-graphql.mjs";
import * as FUNCTIONS from "./adopted-functions.mjs";
import * as AUTOMATE from "./adopted-automate.mjs";

const released = {
  function_ref: "function://fn_0123456789abcdef", revision_ref: "function://fn_0123456789abcdef/revision/1", ordinal: 1,
  version: "1.0.0", status: "released", tool_operable: true, content_hash: "sha256:" + "a".repeat(64),
  display_name: "Double", api_name: "double", documentation: "doubles",
  inputs: [{ name: "amount", description: "", required: true, data_type: { type: "integer", element_type: null } }, { name: "tags", description: "", required: false, data_type: { type: "list", element_type: "string" } }],
  output: { data_type: { type: "integer", element_type: null }, description: "" },
  implementation: { runtime: "python3" },
};
const family = { function_ref: released.function_ref, display_name: "Double", api_name: "double", released_revision: released };

test("repeated selections of one response key merge, as GraphQL requires", () => {
  const q = "query Q { f { ...A v { a } } } fragment A on F { v { b } }";
  assert.deepEqual(answerDocument(q, { f: { __typename: "F", v: { a: 1, b: 2 } } }), { f: { v: { b: 2, a: 1 } } });
});

test("the function registry offers released, operable revisions only, scoped to the function a request names", () => {
  const draftFamily = { function_ref: "function://fn_1111111111111111", display_name: "Draft", released_revision: null };
  const revoked = { ...family, function_ref: "function://fn_2222222222222222", released_revision: { ...released, tool_operable: false } };
  const root = FUNCTIONS.functionFactsRoot([family, draftFamily, revoked], () => null, {});
  assert.equal(root.defaultOrGlobalBranch.functions.values.length, 1);
  const rid = FUNCTIONS.functionRidOf(family.function_ref);
  assert.equal(FUNCTIONS.functionIdOf(rid), "fn_0123456789abcdef");
  const scoped = FUNCTIONS.functionFactsRoot([family], () => [released], { rid, version: "1.0.0" });
  assert.equal(scoped.function.rid, rid);
  assert.deepEqual(scoped.function.version.inputs.map((i) => i.type.__typename), ["FunctionDataType_Integer", "FunctionDataType_List"]);
  assert.equal(scoped.function.version.inputs[1].type.elementType.__typename, "FunctionDataType_String");
  const answered = answerDocument("query getFunctionParameters($rid: RID!) { function(rid: $rid) { version(version: $v) { inputs { name required type { ... on FunctionDataType_List { elementType { __typename } } __typename } } } } }", scoped);
  assert.deepEqual(answered.function.version.inputs[0], { name: "amount", required: true, type: { __typename: "FunctionDataType_Integer" } });
});

test("the registry resolves a version range to the released spec in conjure types", () => {
  const { specs } = FUNCTIONS.functionSpecs(family, [released], "1.0.0", 1);
  assert.equal(specs.length, 1);
  assert.deepEqual(specs[0].inputs[1].dataType, { type: "list", list: { elementsType: { type: "string", string: {} } } });
  assert.deepEqual(FUNCTIONS.functionSpecs(family, [released], "9.9.9", 1).specs, []);
});

const projects = [{ project_id: "project:acme", name: "acme" }];
const request = (overrides = {}) => ({
  name: "nightly double",
  parentRid: AUTOMATE.projectFolderRid("project:acme"),
  logic: { type: "schedule", schedule: { cronExpression: "0 9 * * *", additionalCronExpressions: [], timeZone: "America/New_York" } },
  metadata: {
    expiry: { expireOn: "2026-12-27T00:00:00Z" },
    subscribers: [{ triggerEffects: { e1: { type: "function", function: { functionLocator: { functionRid: FUNCTIONS.functionRidOf(family.function_ref), functionVersion: "1.0.0" }, functionInputs: { amount: { type: "staticValue", staticValue: { type: "integer", integer: 20 } }, tags: { type: "staticValue", staticValue: { type: "list", list: { values: [{ type: "string", string: "a" }] } } } } } } }, recoveryEffects: {} }],
  },
  ...overrides,
});
const releasedRevisionOf = (rid, version) => (rid === FUNCTIONS.functionRidOf(family.function_ref) && version === "1.0.0" ? released : null);

test("the wizard's request becomes the Hypervisor automation it describes, by exact revision", () => {
  const t = AUTOMATE.automationFromMonitorRequest(request(), { projects, releasedRevisionOf });
  assert.equal(t.issue, undefined);
  assert.deepEqual(t.body, {
    project_ref: "project:acme", name: "nightly double", trigger: { kind: "time" }, trigger_kind: "time",
    schedule_spec: { type: "cron", cron: "0 9 * * *", timezone: "America/New_York" },
    expires_at: "2026-12-27T00:00:00.000Z",
    steps: [{ kind: "function", function_revision_ref: released.revision_ref, content_hash: released.content_hash, inputs: { amount: 20, tags: ["a"] } }],
  });
  assert.deepEqual(t.unenforced, [], "the expiry is the automation's expires_at, which the daemon enforces");
});

test("what the Hypervisor automation cannot carry is refused by name, never dropped", () => {
  const refuse = (r) => AUTOMATE.automationFromMonitorRequest(r, { projects, releasedRevisionOf }).issue;
  assert.match(refuse(request({ parentRid: "ri.compass.main.folder.elsewhere" })), /projects/);
  assert.match(refuse(request({ logic: { type: "event", event: {} } })), /event condition/);
  assert.match(refuse(request({ logic: { type: "schedule", schedule: { cronExpression: "0 9 * * *", additionalCronExpressions: ["0 10 * * *"] } } })), /one cron/);
  const action = request();
  action.metadata.subscribers[0].triggerEffects.e1 = { type: "action", action: {} };
  assert.match(refuse(action), /action effect/);
  const dynamicInput = request();
  dynamicInput.metadata.subscribers[0].triggerEffects.e1.function.functionInputs.amount = { type: "objectParameter" };
  assert.match(refuse(dynamicInput), /static value/);
  const retrying = request();
  retrying.metadata.globalEffectExecutionSettings = { longTermRetryConfig: { maxRetries: 3 } };
  assert.match(refuse(retrying), /retries are not supported/);
  const effectRetry = request();
  effectRetry.metadata.subscribers[0].triggerEffects.e1.function.retryConfiguration = { type: "constant" };
  assert.match(refuse(effectRetry), /retries are not supported/);
  const unknownVersion = request();
  unknownVersion.metadata.subscribers[0].triggerEffects.e1.function.functionLocator.functionVersion = "2.0.0";
  assert.match(refuse(unknownVersion), /not a released revision/);
});

test("a save location is one of the caller's projects, and a name is valid there once", () => {
  const rid = AUTOMATE.projectFolderRid("project:acme");
  const automations = [{ project_id: "project:acme", name: "taken" }];
  const root = (name) => AUTOMATE.saveLocationFactsRoot(projects, { locationRid: rid, name }, automations);
  assert.equal(root("fresh").resourceMetadata.childNameValid, true);
  assert.equal(root("Taken").resourceMetadata.childNameValid, false);
  assert.equal(root("").resourceMetadata.childNameValid, false);
  assert.equal(AUTOMATE.saveLocationFactsRoot(projects, { parentRid: "ri.compass.main.folder.other" }).resourceMetadata, null);
  assert.equal(root("x").resourceMetadata.ancestors.length, 2, "root and namespace: a project is a valid save location");
  const resources = AUTOMATE.compassProjectResources(projects, [rid, "ri.compass.main.folder.tenant"], "user://a");
  assert.deepEqual(Object.keys(resources), [rid], "a rid that is not the caller's project gets no entry");
});

test("the editor's record carries function steps only; the detail page shows every step, in order", () => {
  const a = { automation_id: "auto_0123456789abcdef", steps: [{ kind: "command", command: "echo" }, { kind: "function", function_revision_ref: released.revision_ref, content_hash: released.content_hash, inputs: { amount: 20, tags: ["a"] } }] };
  const info = new Map([[released.revision_ref, { function_ref: released.function_ref, version: "1.0.0", display_name: "Double", api_name: "double", inputs: released.inputs }]]);
  const conjure = Object.values(AUTOMATE.triggerEffectsOf(a, info));
  assert.equal(conjure.length, 1, "a command step has no reference effect");
  assert.deepEqual(conjure[0].function.functionLocator, { functionRid: FUNCTIONS.functionRidOf(family.function_ref), functionVersion: "1.0.0" });
  assert.deepEqual(conjure[0].function.functionInputs.amount, { type: "staticValue", staticValue: { type: "integer", integer: 20 } });
  assert.deepEqual(conjure[0].function.functionInputs.tags.staticValue, { type: "list", list: { values: [{ type: "string", string: "a" }] } });
  const [command, effect] = AUTOMATE.mergedEffectsOf(a, info);
  assert.equal(command.__typename.startsWith("ObjectSetMonitor"), false, "a command step is an effect the app does not know (\"Unknown effect\"), never hidden");
  assert.equal(effect.__typename, "ObjectSetMonitorFunctionEffect");
  const agent = AUTOMATE.mergedEffectsOf({ automation_id: "auto_1", steps: [{ kind: "agent", prompt: "summarize" }] }, info)[0];
  assert.equal(agent.__typename, "ObjectSetMonitorAgentEffect");
  assert.deepEqual(answerDocument("query Q { e { ... on ObjectSetMonitorAgentEffect { effectInputs { ... on ObjectSetMonitorAgentEffectCreateSessionInputs { inputs { name input { ... on ObjectSetMonitorStaticValueEffectInput { value { ... on ObjectSetMonitorStaticValueEffectInput_String { value } } } } } } } } } }", { e: agent }).e.effectInputs.inputs[0], { name: "prompt", input: { value: { value: "summarize" } } });
  assert.equal(AUTOMATE.effectOrderingOf([effect]), null, "one step states no order");
  assert.equal(AUTOMATE.effectOrderingOf([command, effect]).length, 2, "steps run in order: an effect ordering");
  const answered = answerDocument("query Q { e { ... on ObjectSetMonitorFunctionEffect { functionV2 { range versions { values { function { displayName } } } } effectInputs { name input { ... on ObjectSetMonitorStaticValueEffectInput { value { ... on ObjectSetMonitorStaticValueEffectInput_Integer { intValue: value } } } } } } } }", { e: effect });
  assert.equal(answered.e.functionV2.range, "1.0.0");
  assert.equal(answered.e.functionV2.versions.values[0].function.displayName, "Double");
  assert.deepEqual(answered.e.effectInputs[0], { name: "amount", input: { value: { intValue: 20 } } });
});

test("the user directory the adopted app reads names only the Hypervisor's principals", () => {
  const principals = [{ ref: "user://alice", name: "Alice Smith", email: "alice@acme.example" }];
  const aliceId = AUTOMATE.principalUserId("user://alice");
  const [alice] = AUTOMATE.principalsFor([aliceId], principals);
  assert.equal(alice.id, aliceId);
  assert.deepEqual(alice.attributes["multipass:given-name"], ["Alice"]);
  assert.deepEqual(alice.attributes["multipass:email:primary"], ["alice@acme.example"]);
  const all = AUTOMATE.principalsFor(["00000000-0000-0000-0000-000000000000"], principals);
  assert.deepEqual(all, [], "an id no Hypervisor principal carries answers nothing (never a recorded directory entry)");
  assert.deepEqual(AUTOMATE.principalsFor([], principals), []);
});

test("a principal's user id is a name-based UUID the app's validator accepts, so its profile is looked up", () => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i; // the app's own check
  for (const ref of ["user://alice", "user://bob", "principal://operator", ""]) assert.match(AUTOMATE.principalUserId(ref), UUID, ref);
  assert.equal(AUTOMATE.principalUserId("user://alice"), AUTOMATE.principalUserId("user://alice"));
  assert.notEqual(AUTOMATE.principalUserId("user://alice"), AUTOMATE.principalUserId("user://bob"));
});

test("a manual automation has no condition the app knows, never a schedule with no expression", () => {
  const condition = (a) => AUTOMATE.factsRoot({ automation_id: "auto_0123456789abcdef", name: "n", steps: [], ...a }, [], { ref: "user://a" }).objectSetMonitor.branch.latestVersion.monitorLogicV3;
  const manual = condition({ trigger: { kind: "manual" } });
  assert.notEqual(manual.__typename, "ObjectSetMonitorSchedule");
  assert.equal("cronExpression" in manual, false);
  const timed = condition({ schedule_spec: { type: "cron", cron: "0 9 * * *", timezone: "UTC" } });
  assert.deepEqual([timed.__typename, timed.cronExpression], ["ObjectSetMonitorSchedule", "0 9 * * *"]);
});

test("an edit is the automation's PATCH: it stays in its project and never drops steps the editor cannot show", () => {
  const existing = { automation_id: "auto_0123456789abcdef", project_id: "project:acme", steps: [{ kind: "function", function_revision_ref: released.revision_ref, content_hash: released.content_hash, inputs: { amount: 1 } }] };
  const edit = AUTOMATE.automationPatchFromMonitorRequest(existing, request({ name: "renamed" }), { projects, releasedRevisionOf });
  assert.equal(edit.issue, undefined);
  assert.equal(edit.patch.name, "renamed");
  assert.equal("project_ref" in edit.patch, false, "the project is not patched");
  assert.equal(edit.patch.steps[0].inputs.amount, 20);
  const { name: _n, parentRid: _p, ...bare } = request();
  const kept = AUTOMATE.automationPatchFromMonitorRequest({ ...existing, name: "kept" }, bare, { projects, releasedRevisionOf });
  assert.equal(kept.issue, undefined, "updateMonitor sends no name or location");
  assert.equal(kept.patch.name, "kept");
  const moved = AUTOMATE.automationPatchFromMonitorRequest(existing, request(), { projects: [...projects, { project_id: "project:other", name: "other" }], releasedRevisionOf });
  assert.equal(moved.issue, undefined, "same project, other projects exist");
  const elsewhere = AUTOMATE.automationPatchFromMonitorRequest({ ...existing, project_id: "project:other" }, request(), { projects: [...projects, { project_id: "project:other" }], releasedRevisionOf });
  assert.match(elsewhere.issue, /stays in its project/);
  const mixed = AUTOMATE.automationPatchFromMonitorRequest({ ...existing, steps: [...existing.steps, { kind: "command", command: "echo" }, { kind: "agent" }] }, request(), { projects, releasedRevisionOf });
  assert.match(mixed.issue, /command and agent steps/);
});

test("a compass rename renames the automation and nothing else", () => {
  const existing = { automation_id: "auto_0123456789abcdef", project_id: "project:acme", name: "old" };
  const here = AUTOMATE.projectFolderRid("project:acme");
  assert.deepEqual(AUTOMATE.automationRenameFromCompassUpdate(existing, { name: " new ", parentRid: here, markings: [] }), { patch: { name: "new" } });
  assert.deepEqual(AUTOMATE.automationRenameFromCompassUpdate(existing, { name: "old", parentRid: here }), { patch: null });
  assert.match(AUTOMATE.automationRenameFromCompassUpdate(existing, { name: "x", parentRid: AUTOMATE.projectFolderRid("project:other") }).issue, /stays in its project/);
  assert.match(AUTOMATE.automationRenameFromCompassUpdate(existing, { name: "  " }).issue, /needs a name/);
});

test("a manual execution is the automation's Run now: every step or none, and its runs are its events", () => {
  const a = { automation_id: "auto_0123456789abcdef", steps: [{ kind: "function" }, { kind: "command", command: "echo" }] };
  const ids = AUTOMATE.mergedEffectsOf(a, new Map()).map((e) => e.id);
  assert.equal(AUTOMATE.manualSelectionIssue(a, ids), null);
  assert.equal(AUTOMATE.manualSelectionIssue(a, []), null, "no selection yet is the app's own disabled Confirm");
  assert.match(AUTOMATE.manualSelectionIssue(a, [ids[0]]), /every step/);
  assert.equal(AUTOMATE.manualSelectionIssue(a, ["00000000-placeholder"]), null, "the app's placeholder id is not a selection");
  const runs = [
    { execution_id: "aex_1", started_at: "2026-09-27T01:00:00Z", status: "done", activation_kind: "manual", step_results: [] },
    { execution_id: "aex_2", started_at: "2026-09-27T02:00:00Z", status: "failed", activation_kind: "schedule", step_results: [{ kind: "function", status: "failed" }] },
    { execution_id: "aex_0", started_at: "2026-09-26T00:00:00Z", status: "done", step_results: [] },
  ];
  const scheduled = { ...a, schedule_spec: { type: "cron", cron: "0 9 * * *" } };
  const all = AUTOMATE.combinedEventsOf(scheduled, runs, null);
  assert.deepEqual(all.map((v) => v.event.id), ["aex_2", "aex_1", "aex_0"], "newest first");
  assert.equal(all[1].event.__typename, "ObjectSetMonitorHistoryEvent_MonitorManualExecution");
  assert.equal(all[0].event.__typename, "ObjectSetMonitorHistoryEvent_MonitorTriggered");
  assert.equal(all[0].event.triggeredEffectsV2[0].anyEffectFailed, true);
  assert.deepEqual(AUTOMATE.combinedEventsOf(scheduled, runs, null, ["MANUAL_EXECUTION"]).map((v) => v.event.id), ["aex_1"]);
  assert.deepEqual(AUTOMATE.combinedEventsOf(scheduled, runs, null, ["TRIGGERED"]).map((v) => v.event.id), ["aex_2"], "an unstamped run of a scheduled automation is neither");
  assert.deepEqual(AUTOMATE.combinedEventsOf(scheduled, runs, null, ["EFFECT_FAILED", "EVALUATION_FAILED"]).map((v) => v.event.id), ["aex_2"]);
  assert.deepEqual(AUTOMATE.combinedEventsOf(scheduled, runs, null, ["CONDITION_EDITED", "PAUSED"]), [], "no edit history is recorded yet");
  // an automation with no schedule and no webhook can only have been run by hand
  assert.deepEqual(AUTOMATE.combinedEventsOf(a, runs, null, ["MANUAL_EXECUTION"]).map((v) => v.event.id), ["aex_1", "aex_0"]);
});

test("telemetry counts an automation's runs, errors and runtime in each bucket", () => {
  const runs = [
    { started_at: "2026-09-27T01:10:00Z", finished_at: "2026-09-27T01:10:02Z", status: "done" },
    { started_at: "2026-09-27T01:40:00Z", finished_at: "2026-09-27T01:40:05Z", status: "failed" },
    { started_at: "2026-09-27T03:00:00Z", finished_at: "2026-09-27T03:00:01Z", status: "done" },
  ];
  const single = AUTOMATE.telemetryFactsRoot(runs, { fromTimestamp: "2026-09-27T00:00:00Z", toTimestamp: "2026-09-27T04:00:00Z" }, "GetSingleTelemetry").objectSetMonitorAggregateTelemetry.bucketedTelemetry;
  assert.equal(single.length, 1);
  assert.deepEqual([single[0].data.numRuns, single[0].data.numErrors, single[0].data.runtimeMillis], [3, 1, 8000]);
  const hourly = AUTOMATE.telemetryFactsRoot(runs, { fromTimestamp: "2026-09-27T00:00:00Z", toTimestamp: "2026-09-27T04:00:00Z", bucketInterval: "HOUR" }, "GetTelemetry").objectSetMonitorAggregateTelemetry.bucketedTelemetry;
  assert.deepEqual(hourly.map((b) => b.data.numRuns), [0, 2, 0, 1]);
});

test("an operation with no Hypervisor plane is refused by name, never answered from the recording", () => {
  const answer = AUTOMATE.refusedAnswer("ResourceTitleContainerFavoriteMutation");
  assert.equal(answer.data, null);
  assert.match(answer.errors[0].message, /Favorites are not kept by the Hypervisor/);
});

test("effects run in the order the request states; a request for parallel effects is refused by name", () => {
  const two = request();
  const e1 = two.metadata.subscribers[0].triggerEffects.e1;
  two.metadata.subscribers[0].triggerEffects = { e1, e2: { ...e1, function: { ...e1.function, functionInputs: { amount: { type: "staticValue", staticValue: { type: "integer", integer: 5 } } } } } };
  assert.match(AUTOMATE.automationFromMonitorRequest(two, { projects, releasedRevisionOf }).issue, /one after another/);
  two.metadata.globalEffectExecutionSettings = { effectOrdering: { type: "defaultEffectOrdering", defaultEffectOrdering: ["e2", "e1"] } };
  const t = AUTOMATE.automationFromMonitorRequest(two, { projects, releasedRevisionOf });
  assert.equal(t.issue, undefined);
  assert.deepEqual(t.body.steps.map((st) => st.inputs.amount), [5, 20], "the stated order, not the object order");
  const a = { automation_id: "auto_0123456789abcdef", steps: [{ kind: "function", function_revision_ref: released.revision_ref, inputs: {} }, { kind: "function", function_revision_ref: released.revision_ref, inputs: {} }] };
  assert.equal(AUTOMATE.monitorOf(a, [], new Map()).metadata.globalEffectExecutionSettings.effectOrdering.defaultEffectOrdering.length, 2);
});
