// The adopted Data Connection's answers over Hypervisor truth (R-241, Data Connection cut D1).
//
// The reference app (booted by the local capture server, routed at /workspace/data-ingestion-app) lists sources, syncs, agents and
// listeners. Here a source is one of the caller's declared data sources (the data-source plane); its connection type is
// the Hypervisor's kind, answered in the reference's catalog shape under the reference's type id where one names the same
// thing. A source's syncs are the capability-lease plans on it (cut D4: the import ladder), their builds the plans'
// materializing runs. A source runs on no agent, and no listener, agent, export or external stack exists — each answers
// none. Nothing recorded is served: the recorded answers lend STRUCTURE only. Every other read on the surface is fenced by
// the serve as a named gap.
import crypto from "node:crypto";
import { uuidOf } from "./adopted-pipeline.mjs";
import { namespaceRidOf, namespaceNameOf } from "./adopted-ontology.mjs";
import { principalUserId, projectFolderRid } from "./adopted-automate.mjs";

const cid = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");

// A data-source kind as a connection type: the reference's type id where it names the same connector, else the
// Hypervisor's own; its catalog entry in the reference's shape (name, description, capabilities, syncs, exports). No
// kind is explorable or syncs here: a declared source does not ingest.
const KINDS = {
  rest_api: { type: "webhooks-rest", name: "REST API", description: "An HTTP API the Hypervisor calls under a leased credential." },
  s3: { type: "s3-direct", name: "S3", description: "An S3 bucket, declared by its endpoint." },
  postgres: { type: "postgresql-42", name: "PostgreSQL", description: "A PostgreSQL database, declared by its endpoint." },
  kafka: { type: "streaming-kafka-source", name: "Kafka", description: "A Kafka cluster, declared by its endpoint." },
  mysql: { type: "hypervisor-mysql", name: "MySQL", description: "A MySQL database, declared by its endpoint." },
  graphql_api: { type: "hypervisor-graphql-api", name: "GraphQL API", description: "A GraphQL API, declared by its endpoint." },
  object_store: { type: "hypervisor-object-store", name: "Object store", description: "An object store, declared by its endpoint." },
  http_feed: { type: "hypervisor-http-feed", name: "HTTP feed", description: "An HTTP feed, declared by its endpoint." },
  file_drop: { type: "hypervisor-file-drop", name: "File drop", description: "Files dropped for the Hypervisor to pick up." },
  local_folder: { type: "hypervisor-local-folder", name: "Local folder", description: "A folder on the Hypervisor's host." },
};
export const sourceTypeOf = (kind) => KINDS[kind]?.type || `hypervisor-${String(kind || "source").replace(/[^a-z0-9]+/gu, "-")}`;
// GET /magritte-coordinator/api/managed-sources/sources — the connection types, one per Hypervisor kind
export const MANAGED_SOURCE_TYPES = Object.fromEntries(Object.values(KINDS).map((k) => [k.type, { name: k.name, description: k.description, capabilities: [], syncs: {}, exports: {} }]));
export const sourceRidOf = (sourceId) => `ri.magritte..source.${uuidOf(`data-source:${sourceId}`)}`;

// The caller's data sources: the ones they declared, and the ones filed in a project they can see. (The plane's list is
// not caller-scoped; the adopted layer never shows another principal's source.)
export function callerSourcesOf(sources, principalRef, projectRefs) {
  const projects = new Set(projectRefs || []);
  // only its declarer may change a source (the data-source plane refuses anyone else), so only theirs is offered as editable
  return (sources || []).filter((s) => s && s.source_id && ((principalRef && s.declared_by_principal_ref === principalRef) || (s.project_ref && projects.has(s.project_ref))))
    .map((s) => ({ ...s, caller_may_change: !!principalRef && s.declared_by_principal_ref === principalRef }));
}

function sourceNodeOf(src, syncs = []) {
  const rid = sourceRidOf(src.source_id);
  return {
    __typename: "MagritteSource", _id: cid(`MagritteSource:${rid}`), rid, type: sourceTypeOf(src.kind), name: src.name || src.source_id, description: "",
    // a declared source is reached by the Hypervisor itself, on no agent; its syncs are its lease plans (cut D4)
    runtimePlatform: { __typename: "CloudRuntimePlatform" }, numberOfExtracts: (syncs || []).filter((y) => y.plan.data_source_id === src.source_id).length,
    metadata: {
      __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${rid}`), rid, favorited: null, trashedStatus: "NOT_TRASHED", tags: [], markings: [], defaultBranch: null,
      classification: { __typename: "Classification", resourceClassificationBanner: null, containerClassificationBanner: null },
      project: { __typename: "Project", _id: cid(`Project:${src.project_ref || "none"}`), usageAccountEnrollment: { __typename: "Enrollment", _id: cid(`Enrollment:${src.project_ref || "none"}`), magritteDirectorySourceTypeConfigV2: { __typename: "MagritteDirectorySourceTypeConfig", enabled: false } } },
    },
  };
}

// REST: GET /magritte-coordinator/api/source-store/sources/types — each connection type's sources
export function sourceTypesOf(sources) {
  const out = {};
  for (const s of sources || []) (out[sourceTypeOf(s.kind)] ||= []).push(sourceRidOf(s.source_id));
  return out;
}

// ---- syncs (cut D4): a sync is a capability-lease plan on one of the caller's data sources, the rung of the import
// ladder that says what a run may obtain (data source → connector mapping → policy-bound view → transformation run →
// ontology projection → lease plan). Its builds are the plan's materializing runs; its output dataset is the plan's
// own (a stable rid), holding the object set its latest executed run materialized, or nothing before one. No schedule
// exists (a run is admitted by hand), so the next run is Manual. A revoked plan is withdrawn, as a deleted sync is, and
// is not listed. The plane's lists are not caller-scoped: only plans on the caller's sources, and their runs, are shown.
export const extractRidOf = (planId) => `ri.magritte..extract.${uuidOf(`lease-plan:${planId}`)}`;
export const syncDatasetRidOf = (planId) => `ri.foundry.main.dataset.${uuidOf(`lease-plan-dataset:${planId}`)}`;
export const buildRidOf = (runId) => `ri.foundry.main.build.${uuidOf(`materializing-run:${runId}`)}`;
const jobRidOf = (runId) => `ri.foundry.main.job.${uuidOf(`materializing-run-job:${runId}`)}`;
// the sync's source adapter names what it is: a capability-lease plan
export const SYNC_ADAPTER = "capability-lease-plan";
const BRANCH = "master";
// (cut D6) The folder a source's syncs write their datasets into: the folder of the project the source is filed in, when
// that is one of the caller's projects, else the owner's organization folder. Either exists already: a sync creates no
// folder. `projects` are the daemon's project rows.
const projectRefOf = (p) => p?.project_ref || (p?.project_id ? `project://${p.project_id}` : null);
export function outputFolderOf(src, ownerRef, projects = []) {
  const p = src?.project_ref ? (projects || []).find((x) => projectRefOf(x) === src.project_ref) : null;
  if (p) return { rid: projectFolderRid(p.project_id), name: p.project_name || p.name || p.project_id, projectRef: projectRefOf(p) };
  return ownerRef ? { rid: namespaceRidOf(ownerRef), name: namespaceNameOf(ownerRef), projectRef: null } : null;
}
export function callerSyncsOf(plans, runs, sources, ownerRef = null, projects = []) {
  const bySource = new Map((sources || []).map((s) => [s.source_id, s]));
  return (plans || []).filter((p) => p && p.id && p.status !== "revoked" && bySource.has(p.data_source_id)).map((plan) => {
    const own = (runs || []).filter((r) => r && r.id && r.capability_lease_plan_id === plan.id).sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
    const held = own.find((r) => r.status === "executed" && r.execution?.materialized_set_ref);
    const datasetName = `${plan.name || plan.id} objects`;
    const source = bySource.get(plan.data_source_id);
    const folder = outputFolderOf(source, ownerRef, projects);
    return { plan, source, rid: extractRidOf(plan.id), datasetRid: syncDatasetRidOf(plan.id), datasetName,
      datasetPath: folder ? `/${folder.name}/${datasetName}` : `/${datasetName}`, folder: folder ? { rid: folder.rid, name: folder.name } : null, runs: own,
      // the dataset rid the new-sync page was answered for this sync (its name in its source's output folder, cut D6)
      reservedDatasetRid: folder ? reservedDatasetRidOf(folder.rid, plan.name || plan.id) : null,
      set: held ? { ref: held.execution.materialized_set_ref, objects: Number(held.execution.object_instances) || 0 } : null };
  });
}
// A materializing run as the reference's build: its job status (what the Syncs list shows) and its build status. A
// planned run waits for its lease (a wallet grant); one holding its lease is running; an executed run registered its
// object set; a run whose last execute ended without registering one failed — refused (no authority, a stale binding or
// credential), its source contact failed, or its batch was rejected — and it may be tried again while it holds its lease;
// a run cancelled, or whose lease was released unexecuted, is canceled.
const FAILED_EXECUTE_OPS = new Set(["execution_refused", "source_contact_failed", "validation_result"]);
export function runStatusOf(run) {
  const last = (run?.history || []).at(-1)?.op;
  switch (run?.status) {
    case "planned": return { build: "RUNNING", job: "WAITING" };
    // (a validated batch goes on to register its set in the same execute, so a held lease whose last act was a
    // validation result was rejected)
    case "lease_obtained": return FAILED_EXECUTE_OPS.has(last) ? { build: "FAILED", job: "FAILED" } : { build: "RUNNING", job: "RUNNING" };
    case "executed": return { build: "SUCCEEDED", job: "SUCCEEDED" };
    case "cancelled": case "lease_released": return { build: "CANCELED", job: "CANCELED" };
    default: return { build: null, job: null };
  }
}
function buildOf(sync, run) {
  const { build, job } = runStatusOf(run);
  const finished = build === "SUCCEEDED" || build === "FAILED" || build === "CANCELED" ? run.updated_at || null : null;
  const buildId = buildRidOf(run.id);
  const output = { datasetRid: sync.datasetRid, securedProperties: { name: sync.datasetPath, hidden: false } };
  // who admitted a run is not recorded on it, so no user is named
  return { buildId, user: null, userId: null, startedTime: run.created_at || null, finishedTime: finished, outputDatasets: [output], buildStatus: build,
    jobs: [{ buildId, jobId: jobRidOf(run.id), jobSpecId: `ri.foundry.main.jobspec.${uuidOf(`lease-plan-jobspec:${sync.plan.id}`)}`, startedWaitingTime: run.created_at || null, submittedTime: run.created_at || null,
      finishedTime: finished, outputDatasets: [output], inputDatasetRids: [sourceRidOf(sync.plan.data_source_id)], outputTransactions: [], syncDetails: null, vectorDetails: null, jobStatus: job,
      jobQueues: {}, canceledAttribution: null, securedProperties: { jobType: "materializing-run", transformType: null, statusDetails: (run.history || []).length ? { message: String(run.history.at(-1).summary || run.history.at(-1).op || "") } : null },
      branchId: BRANCH, projectRids: [], dockerArtifactIds: [], outputMediaSetWriteContexts: [] }],
    syncs: [], vectorDetails: [], statusDetails: null, securedProperties: { branchId: BRANCH }, restrictedJobCount: 0, scheduleId: null, projectRids: [], dockerArtifactIds: [] };
}
// REST: POST job-tracker/api/builds/bulk (and bulkV2) — per asked filter, a sync's runs as builds, newest first
export function buildsBulkOf(requests, syncs) {
  const byDataset = new Map((syncs || []).map((y) => [y.datasetRid, y]));
  return (Array.isArray(requests) ? requests : []).map((q) => {
    const f = q?.buildFilter?.filter || q?.buildFilter || {};
    const found = [...new Set([...(f.jobDatasetRids || []), ...(f.datasetRids || [])])].map((r) => byDataset.get(r)).filter(Boolean);
    const branches = f.branchIds || [];
    const runs = branches.length && !branches.includes(BRANCH) ? [] : found.flatMap((y) => y.runs.map((r) => buildOf(y, r)));
    const wanted = (f.buildStatuses || []).length ? runs.filter((b) => f.buildStatuses.includes(b.buildStatus)) : runs;
    return { buildDetails: wanted.slice(0, Math.max(1, Number(q?.limit) || 50)), buildCount: wanted.length };
  });
}
// REST: GET job-tracker/api/builds/<rid> — one of the caller's runs as its build
export function buildByRidOf(rid, syncs) {
  for (const y of syncs || []) for (const r of y.runs) if (buildRidOf(r.id) === rid) return buildOf(y, r);
  return null;
}
// REST: POST extract-store/extracts/bulk — the asked syncs, each its plan as the reference's extract
function extractOf(sync) {
  const p = sync.plan;
  return { sourceId: sourceRidOf(p.data_source_id), datasetId: sync.datasetRid, branchName: BRANCH, extractName: p.name || p.id,
    // the plan's import ladder (cut D5: a new sync names the ladder it plans a lease on) and its lease shape: what a run
    // may obtain, for whom and why
    extractConfig: { sourceAdapter: { type: SYNC_ADAPTER, ontology: p.ontology_ref || null, objectType: p.object_type_id || null,
      connectorMapping: p.connector_mapping_id || null, policyView: p.policy_view_id || null, transformationRun: p.transformation_run_id || null, ontologyProjection: p.ontology_projection_id || null,
      subject: p.subject || null, purpose: p.purpose || null, operations: p.requested_operations || [], properties: p.requested_properties || [], leaseTtlSeconds: p.ttl_seconds ?? null }, transforms: [], completionStrategies: [],
      outputOptions: { transactionType: "SNAPSHOT", outputConstraints: [], schemaOptions: { timestampOptions: { useTimestampType: false } } } },
    maxAllowedDuration: null, sparkProfiles: [] };
}
export function extractsBulkOf(rids, syncs) {
  const byRid = new Map((syncs || []).map((y) => [y.rid, y]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => [r, extractOf(byRid.get(r))]));
}
// REST: POST extract-store/extracts/metadata — when each asked sync's plan was declared and last changed (by whom is not
// recorded on a plan)
export function extractsMetadataOf(rids, syncs) {
  const byRid = new Map((syncs || []).map((y) => [y.rid, y]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => { const p = byRid.get(r).plan;
    return [r, { created: { time: p.created_at || null, userId: null }, lastModified: (p.revision || 1) > 1 ? { time: p.updated_at || null, userId: null } : null, displayOptions: null }]; }));
}
// REST: POST extract-store/extract/history — a sync's versions from its plan's history. The history records what each
// revision did, not the plan's shape at the time, so only the current revision is shown with its content.
export function extractHistoryOf(rid, syncs, history) {
  const y = (syncs || []).find((x) => x.rid === rid);
  if (!y) return null;
  const rev = Number(history?.revision ?? y.plan.revision) || 1;
  const at = (history?.history || y.plan.history || []).filter((h) => h && h.revision === rev).at(-1)?.at || y.plan.updated_at || y.plan.created_at || null;
  return { storedExtractHistories: { [rev]: { storedExtract: extractOf(y), versionMetadata: { time: at, userId: null }, extractVersionNumber: rev } } };
}
// REST: GET /magritte-coordinator/api/extract-store/extracts/source — each source's syncs: its lease plans
export const extractsBySourceOf = (sources, syncs = []) => Object.fromEntries((sources || []).map((s) => [sourceRidOf(s.source_id), (syncs || []).filter((y) => y.plan.data_source_id === s.source_id).map((y) => y.rid)]));
// a sync's output dataset as a resource the app names and places (its name, path and one branch)
function syncDatasetResourceOf(y, base) {
  const at = { time: y.plan.created_at || null, userId: null };
  return base(y.datasetRid, y.datasetName, at, { path: y.datasetPath, urlVariables: { "compass:isProject": "false" },
    branches: [{ name: BRANCH, rid: `ri.foundry.main.branch.${uuidOf(`lease-plan-dataset:${y.plan.id}`)}.${Buffer.from(BRANCH).toString("base64")}`, urlVariables: { build: {} }, classificationRids: [] }] });
}
// A sync is run or deleted only through the ladder's own planes, never from this page. A run needs a wallet-authority
// grant to obtain its lease. (409, never 403: the app words every 403 as "You do not have sufficient permissions", a false
// reason, and prints a 409's top-level message.) Saving a sync's configuration and adding a sync are bound (cut D5, below).
export const SYNC_WRITE_REFUSALS = {
  run: { status: 409, code: "Hypervisor:DataConnectionRunNeedsApproval", message: "A sync's run is a materializing run: it obtains its lease only with a wallet-authority grant, issued through the Hypervisor's approval flow — never from this page. Nothing was run." },
  write: { status: 409, code: "Hypervisor:DataConnectionSyncWriteNotBound", message: "A sync is a capability-lease plan on the import ladder: deleting one, or changing it outside its configuration, is not bound here yet. Nothing was changed." },
  // (and a preview of inbound data, which would read the source)
  preview: { status: 409, code: "Hypervisor:DataConnectionPreviewNeedsLease", message: "A preview reads the source, and reading a source needs a materializing run holding its lease (a wallet-authority grant). Nothing was read." },
};
// the refusal as the reference's error body, its message also at the top level (where the app reads it)
export const syncRefusalBodyOf = (refusal) => ({ errorCode: "CONFLICT", errorName: refusal.code, errorInstanceId: "", parameters: { message: refusal.message }, message: refusal.message });
// (cut D8) "On a schedule". The reference's schedule editor (chunk 51877) checks each cron expression it composes with the
// scheduler service — POST scheduler/api/scheduler/validate-cron-expression, a bare JSON string, answered { error } (none
// when valid). The Hypervisor's cron parser is the daemon's own, the one its automation scheduler fires by (GET
// /v1/hypervisor/cron-preview), so the answer is the daemon's: no error when it finds a next fire, else its reason.
// preview: the daemon's { ok, runs } or { ok: false, error }.
export const cronValidationOf = (preview) => ({ error: preview?.ok === true && (preview.runs || []).length ? null : String(preview?.error || "the Hypervisor's cron parser found no next run") });
// …but no schedule runs a sync. A sync's run is its plan's materializing run, and every run obtains its lease with its
// own exact wallet-authority grant (no standing execution authority exists for a schedule to hold). The Hypervisor's
// scheduler is the automation plane's (ADR 0056 put Builds and Schedules under Automations): its Time triggers fire an
// automation's steps — agent, command, function, proposal — and none admits a materializing run. So saving a sync on a
// schedule is refused by name, before anything is written; Manually stays what is true.
export const SCHEDULE_REFUSAL = { status: 409, code: "Hypervisor:DataConnectionScheduleNotBound",
  message: "No schedule runs a sync here: each run is its plan's materializing run, and every run obtains its lease with its own wallet-authority grant — no standing authority exists for a schedule to hold. The Hypervisor's scheduler fires automations (agent, command, function and proposal steps), and none admits a materializing run. The sync runs Manually. Nothing was changed." };
// REST: POST scheduler/api/scheduler/get-schedules-by-run-build-dataset — the schedules that build the asked datasets:
// none (no schedule builds any dataset here), so a save on a schedule goes on to create one
export const SCHEDULES_BY_DATASET = [];
// REST: POST scheduler/api/scheduler/create-schedules — each asked schedule's run-build action names the datasets it
// would build (single selections); each must be a sync of the caller's, and then the whole ask is refused by name
export function scheduleCreateRefusalOf(requests, syncs) {
  const rids = (Array.isArray(requests) ? requests : [requests]).flatMap((q) => {
    const sels = q?.action?.type === "runBuild" ? q.action.runBuild?.jobSpecSelections || [] : [null];
    return sels.map((s) => (s?.type === "single" ? s.single?.datasetRid : null));
  });
  // (a new sync's schedule names the dataset its page was answered — its reserved rid — as a sync's own does)
  if (!rids.length || rids.some((rid) => !rid || !syncOfDatasetRid(rid, syncs)))
    return { status: 404, code: "Hypervisor:DataConnectionDatasetNotFound", message: "No sync of yours writes this dataset. Nothing was changed." };
  return SCHEDULE_REFUSAL;
}
// (cut D7) Edit syncs' "Run N syncs" asks the build service to build the selected syncs' datasets (POST
// build2/api/manager/submitBuild) rather than triggering each sync: a sync's dataset is built only by its plan's
// materializing run, so the same refusal applies — each named dataset must be one a sync of the caller's writes.
export function submitBuildRefusalOf(request, syncs) {
  const rids = (request?.jobSpecSelections || []).flatMap((s) => (s?.type === "datasets" ? s.datasets?.datasetRids || [] : [s?.type || "untyped"]));
  if (!rids.length || rids.some((rid) => !(syncs || []).some((y) => y.datasetRid === rid)))
    return { status: 404, code: "Hypervisor:DataConnectionDatasetNotFound", message: "No sync of yours writes this dataset. Nothing was run." };
  return SYNC_WRITE_REFUSALS.run;
}
export function syncWriteRefusalOf(method, route) {
  if (method === "POST" && /^build\/trigger\/ri\.magritte\.\.extract\.[0-9a-f-]{36}$/u.test(route)) return SYNC_WRITE_REFUSALS.run;
  if (method === "POST" && route === "preview/source-adapter") return SYNC_WRITE_REFUSALS.preview;
  // (a configuration's Save — PUT extract-store/extract/<rid> — and a new sync — POST build/add-extract — are bound)
  if (method === "PUT" && /^extract-store\/extract\/ri\.magritte\.\.extract\.[0-9a-f-]{36}$/u.test(route)) return null;
  if ((method === "DELETE" && /^build\/delete-extract\//u.test(route))
    || (/^extract-store\/extract(\/|$)/u.test(route) && ["POST", "PUT", "DELETE"].includes(method) && route !== "extract-store/extract/history")) return SYNC_WRITE_REFUSALS.write;
  return null;
}

// ---- a sync's writes (cut D5). A sync's configuration IS its plan, so a configuration's Save re-declares the plan (the
// daemon's PATCH, which re-validates the whole plan against its current ladder and receipts the revision), and a new
// sync — Duplicate's, or New's — declares a plan on the ladder its configuration names (the daemon's create, validated
// the same way). The daemon's refusals come back under their own codes. Only a source's declarer changes its syncs here
// (as only they change its connection details), and what a plan does not hold — another adapter, transforms, another
// transaction type, a duration or Spark profile, another dataset or source — is refused by name, never dropped.
const LADDER_KEYS = { connectorMapping: "connector_mapping_id", policyView: "policy_view_id", transformationRun: "transformation_run_id", ontologyProjection: "ontology_projection_id" };
const SHAPE_KEYS = { subject: "subject", purpose: "purpose", operations: "requested_operations", properties: "requested_properties", leaseTtlSeconds: "ttl_seconds" };
const refuseSync = (code, message) => { throw new DataConnectionRefusal(`Hypervisor:${code}`, message); };
function checkPlanShaped(extract, done = "changed") {
  const cfg = extract?.extractConfig || {};
  const adapter = cfg.sourceAdapter || {};
  // (cut D6) the reference's own adapters — a bucket's file sync, the custom editor's starting "custom" — are refused with why
  if (adapter.type !== SYNC_ADAPTER) refuseSync("DataConnectionSyncAdapterFixed", `A sync here is a capability-lease plan: its adapter is ${SYNC_ADAPTER}, not ${adapter.type || "none"} — the Hypervisor never lists or copies a source's files or tables; a run obtains a lease and registers one object set. Name the plan's import ladder in its configuration. Nothing was ${done}.`);
  const extra = [];
  if ((cfg.transforms || []).length) extra.push("transforms");
  if ((cfg.completionStrategies || []).length) extra.push("completion strategies");
  if (cfg.outputOptions?.transactionType && cfg.outputOptions.transactionType !== "SNAPSHOT") extra.push(`the ${cfg.outputOptions.transactionType} transaction type`);
  if ((cfg.outputOptions?.outputConstraints || []).length) extra.push("output constraints");
  if (extract?.maxAllowedDuration != null) extra.push("a maximum duration");
  if ((extract?.sparkProfiles || []).length) extra.push("Spark profiles");
  if (extract?.branchName && extract.branchName !== BRANCH) extra.push(`the branch ${extract.branchName}`);
  if (extra.length) refuseSync("DataConnectionSyncFieldNotBound", `A capability-lease plan holds none of ${extra.join(", ")}: a run obtains a lease and registers one object set. Nothing was ${done}.`);
  return adapter;
}
// the plan fields an extract's configuration names (only those present), ladder refs and lease shape
function planFieldsOf(adapter) {
  const out = {};
  for (const [k, f] of Object.entries({ ...LADDER_KEYS, ...SHAPE_KEYS })) if (adapter[k] !== undefined) out[f] = adapter[k];
  return out;
}
const sameJson = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
// PUT extract-store/extract/<rid> → the plan's PATCH body: only what changed ({} when nothing did)
export function planPatchOf(extract, sync) {
  if (!sync) refuseSync("DataConnectionSyncNotFound", "No sync of yours has this id.");
  if (!sync.source?.caller_may_change) refuseSync("DataConnectionSyncNotYours", "Only the declarer of a sync's source changes its syncs here. Nothing was changed.");
  const adapter = checkPlanShaped(extract);
  if ((extract.sourceId && extract.sourceId !== sourceRidOf(sync.plan.data_source_id)) || (extract.datasetId && extract.datasetId !== sync.datasetRid))
    refuseSync("DataConnectionSyncFieldNotBound", "A sync keeps its source and its output dataset (its plan's own). Nothing was changed.");
  if ((adapter.ontology !== undefined && !sameJson(adapter.ontology, sync.plan.ontology_ref || null)) || (adapter.objectType !== undefined && !sameJson(adapter.objectType, sync.plan.object_type_id || null)))
    refuseSync("DataConnectionSyncDerivedField", "A sync's ontology and object type follow its connector mapping: name another mapping to change them. Nothing was changed.");
  const patch = {};
  const name = String(extract.extractName ?? "").trim();
  if (extract.extractName !== undefined && name !== (sync.plan.name || "")) { if (!name) refuseSync("DataConnectionSyncNameRequired", "A sync needs a name. Nothing was changed."); patch.name = name; }
  for (const [f, v] of Object.entries(planFieldsOf(adapter))) if (!sameJson(v, sync.plan[f] ?? null)) patch[f] = v;
  return patch;
}
// POST build/add-extract → the plan plane's declaration body: a plan on the caller's source, over the ladder its
// configuration names. (cut D6) The dataset the page names is the one it was answered for the new sync — its name in its
// source's output folder, which becomes the plan's own dataset; syncing into another dataset (an existing one, or one
// placed elsewhere or named apart from the sync) is refused by name before anything is declared.
export function planDeclarationOf(extract, sources, { ownerRef = null, projects = [] } = {}) {
  const src = sourceOf(sources, extract?.sourceId);
  if (!src) refuseSync("DataConnectionSourceNotFound", "No source of yours has this id. Nothing was created.");
  if (!src.caller_may_change) refuseSync("DataConnectionSyncNotYours", "Only a source's declarer adds syncs to it here. Nothing was created.");
  const adapter = checkPlanShaped(extract, "created");
  const RUNG = { connectorMapping: "connector mapping (connectorMapping)", policyView: "policy-bound view (policyView)", transformationRun: "transformation run (transformationRun)", ontologyProjection: "ontology projection (ontologyProjection)" };
  const missing = Object.keys(LADDER_KEYS).filter((k) => !String(adapter[k] || "").trim());
  if (missing.length) refuseSync("DataConnectionSyncLadderRequired", `A sync is a lease plan over its import ladder: its configuration names its ${missing.map((k) => RUNG[k]).join(", ")}. Nothing was created.`);
  const name = String(extract?.extractName ?? "").trim();
  if (!name) refuseSync("DataConnectionSyncNameRequired", "A sync needs a name. Nothing was created.");
  if (extract?.datasetId != null) {
    const folder = outputFolderOf(src, ownerRef, projects);
    if (!folder || extract.datasetId !== reservedDatasetRidOf(folder.rid, name))
      refuseSync("DataConnectionSyncDatasetNotBound", `A new sync writes its own plan's dataset, placed in its source's output folder${folder ? ` (${folder.name})` : ""} and named for the sync: choose a new dataset there named "${name}". Nothing was created.`);
  }
  return { data_source_id: src.source_id, name, ...planFieldsOf(adapter) };
}
// (cut D6) Where a new sync's destination sits: a project's folder (a project-filed source's output folder) is that
// project, under the owner's organization folder. The owner's organization folder itself belongs to no project, so it
// is not answered (the destination's project crumb stays unnamed — a named gap). `projectResources` are the caller's
// project folders as compass resources; `orgResource` the organization folder's.
export function projectHierarchiesOf(rids, projectResources, orgResource) {
  const out = {};
  for (const rid of Array.isArray(rids) ? rids : []) {
    const p = projectResources?.[rid];
    if (p && orgResource) out[rid] = { organization: { resource: orgResource, permissions: {} }, project: { resource: { ...p, branches: p.branches || [] }, permissions: {}, operations: [] } };
  }
  return out;
}
// (cut D6) The writes that follow a new sync's declaration, on the dataset it was answered: its build policy and its
// branch. A plan keeps no build policy — a run is admitted by hand, so once admitted it may always run — and its dataset
// has one branch, master. So "always" and "master" are what is already true and change nothing; anything else is refused
// by name. Only a caller's sync's dataset (its own rid, or the one its new-sync page was answered) is answered.
export const syncOfDatasetRid = (rid, syncs) => (syncs || []).find((y) => y.datasetRid === rid || (y.reservedDatasetRid && y.reservedDatasetRid === rid)) || null;
export function branchCreatedOf(rid, branch, syncs) {
  const y = syncOfDatasetRid(rid, syncs);
  if (!y) refuseSync("DataConnectionDatasetNotFound", "No sync of yours writes this dataset. Nothing was created.");
  if (branch !== BRANCH) refuseSync("DataConnectionBranchNotBound", `A sync's dataset has one branch, ${BRANCH}: another branch is not kept here. Nothing was created.`);
  return { id: BRANCH, rid: `ri.foundry.main.branch.${uuidOf(`lease-plan-dataset:${y.plan.id}`)}.${Buffer.from(BRANCH).toString("base64")}`, ancestorBranchIds: [], creationTime: y.plan.created_at || null, transactionRid: null };
}
export function buildPoliciesSetOf(requests, syncs) {
  for (const q of Array.isArray(requests) ? requests : []) {
    if (!syncOfDatasetRid(q?.datasetRid, syncs)) refuseSync("DataConnectionDatasetNotFound", "No sync of yours writes this dataset. Nothing was changed.");
    if ((q?.branch ?? BRANCH) !== BRANCH) refuseSync("DataConnectionBranchNotBound", `A sync's dataset has one branch, ${BRANCH}. Nothing was changed.`);
    const type = q?.buildPolicy?.type;
    if (type !== "always") refuseSync("DataConnectionBuildPolicyNotBound", `A sync keeps no build policy: its run is admitted by hand and, once admitted, may always run — the ${type || "untyped"} policy is not kept here. Nothing was changed.`);
  }
  return true;
}

// (cut D6) The reference asks, before a sync's writes, which justification checkpoints apply (keyed on the sync's source).
// The Hypervisor's checkpoints are the daemon's justification-checkpoint plane (ADR 0056 P5), and a checkpoint can only
// be configured for an interaction the daemon gates (its catalog). A sync's writes are the capability-lease plan's PATCH
// and declaration: while the daemon's catalog names neither, no checkpoint can apply, and the answer is none. When it names
// one and an enabled checkpoint configures it, the prompt is not carried here yet, so the read is refused by name rather
// than answered "none" (which would let the write skip an obligation).
export const SYNC_CHECKPOINT_INTERACTIONS = { DATA_CONNECTION_SYNC_EDIT: "capability_lease_plan.patch", DATA_CONNECTION_SYNC_CREATE: "capability_lease_plan.declare", DATA_CONNECTION_SYNC_BULK_CREATE: "capability_lease_plan.declare" };
export const NO_CHECKPOINTS = { checkpointConfigs: [], classificationInferabilityStatus: { type: "uninferableClassifcation", uninferableClassifcation: "CBAC_NOT_ENABLED" } };
// plane: the daemon's GET /v1/hypervisor/justification-checkpoints answer ({ checkpoints, catalog })
export function syncCheckpointConfigsOf(request, sources, plane) {
  // (cut D8) a save on a schedule first asks which checkpoints gate creating the schedule: the schedule is refused by name
  // at that first step, as its create is (no schedule runs a sync)
  if (request?.checkpointType === "SCHEDULE_CREATE") throw new DataConnectionRefusal(SCHEDULE_REFUSAL.code, SCHEDULE_REFUSAL.message);
  const kind = SYNC_CHECKPOINT_INTERACTIONS[request?.checkpointType];
  if (!kind) throw new DataConnectionRefusal("Hypervisor:DataConnectionCheckpointTypeNotBound", `The checkpoint type ${request?.checkpointType || "(none)"} is not a Data Connection sync write here.`);
  const items = (request?.checkpointedItems || []).map((i) => i?.checkpointedItemId?.checkpointedResourceRid);
  if (!items.length || items.some((rid) => !sourceOf(sources, rid))) throw new DataConnectionRefusal("Hypervisor:DataConnectionSourceNotFound", "No source of yours has this id.");
  if (!(plane?.catalog || []).includes(kind)) return NO_CHECKPOINTS;
  const applicable = (plane?.checkpoints || []).filter((c) => c?.enablement === "enabled" && (c.interaction_kinds || []).includes(kind));
  if (applicable.length) throw new DataConnectionRefusal("Hypervisor:DataConnectionCheckpointPromptNotBound", `${applicable.length} justification checkpoint${applicable.length === 1 ? "" : "s"} the daemon keeps put${applicable.length === 1 ? "s" : ""} an obligation on this write (${kind}), and its prompt is not carried on this page yet. Nothing was changed.`);
  return NO_CHECKPOINTS;
}
// POST foundry-catalog/api/catalog/createDataset2 → a new sync's output dataset is its plan's own, made with the plan by the
// add-extract that follows; nothing is created here, and the answer names the dataset by the folder and name asked
export const reservedDatasetRidOf = (parentRid, name) => `ri.foundry.main.dataset.${uuidOf(`sync-dataset-reservation:${parentRid}:${name}`)}`;
// REST: POST code-assist-proxy/api/error-enhancer/is-enabled — no assistant explains a failed preview here (cut D6)
export const ERROR_ENHANCER = { type: "disabled", disabled: {} };
// REST: the agent and external-stack reads — none exists, and none can be made here
export const EXTERNAL_STACK_PRELOAD = { enabledAsSource: false, enabledAsDestination: false, canCreateExternalStacks: false };
export const AGENTS = [];
export const AGENT_HEALTH = {};
export const BOOTVISOR_STATUS = {};

// REST: POST streaming/extracts/get-for-sources — the asked sources' streaming syncs: none
export function streamingExtractsOf(request, sources) {
  const ours = new Set((sources || []).map((s) => sourceRidOf(s.source_id)));
  return { streamingExtracts: Object.fromEntries((request?.sourceIds || request?.sourceRids || []).filter((r) => ours.has(r)).map((r) => [r, []])) };
}
// REST: POST source-store/sources/description/bulk — the asked sources' names and connection types
export function sourceDescriptionsOf(rids, sources) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => { const s = byRid.get(r); return [r, { type: sourceTypeOf(s.kind), name: s.name || s.source_id, description: "", apiName: null }]; }));
}

// ---- a source's own pages (cut D2): the source by its rid, from the caller's sources. A declared source's configuration
// is its endpoint (a REST API's domain, a bucket's URL); nothing can be exported, synced, explored, registered or
// webhooked from it here, so every such permission is false, and nothing depends on it.
const endpointUrl = (e) => { try { return new URL(String(e || "")); } catch { return null; } };
export function sourceConfigOf(src) {
  const type = sourceTypeOf(src.kind);
  if (type === "webhooks-rest") {
    const u = endpointUrl(src.endpoint);
    const id = uuidOf(`domain:${src.source_id}`);
    return { source: { type, config: { domains: [{ domainId: id, host: u?.host || "", scheme: u?.protocol === "http:" ? "HTTP" : "HTTPS" }] } },
      // a draft's domain has no host yet: its connection URL is the bare scheme, as the reference answers it
      connections: { [id]: { id, config: { type: "http", http: { url: u ? `${u.protocol}//${u.host}` : "https://" } } } }, additionalSecrets: {}, resources: {} };
  }
  return { source: { type, config: { url: src.endpoint || null } }, connections: {}, additionalSecrets: {}, resources: {} };
}
// The enrollment a source runs under is the Hypervisor itself: no compute service, no egress CIDRs, no cloud identity, no
// private link, and no standing network egress policy (the daemon decides each crossing on its own lease), and nothing
// here may create one. Organization-wide, not per source.
export const ENROLLMENT_RID = `ri.multipass..enrollment.${uuidOf("enrollment")}`;
const enrollmentOf = (base) => ({
  ...base, __typename: "Enrollment", _id: cid("Enrollment:hypervisor"), rid: ENROLLMENT_RID, name: "Hypervisor",
  computeEnvironmentDetails: { __typename: "ComputeEnvironmentDetails", cloudPlatformDetails: null, rubixEnvironmentDetails: { __typename: "RubixEnvironmentDetails", egressCidrs: [] } },
  cloudIdentities: [], isPrivateLinkEgressServiceAvailable: false, isSourceBasedNetworkingAvailable: false, networkEgressPolicies: [],
  networkEgressConfiguration: "SELF_SERVICE", isSelfApprovalEnabledForNetworkPolicyApprovalRequests: false, organizations: [],
  permissions: { __typename: "EnrollmentPermissions", _id: cid("EnrollmentPermissions"), canCreateNetworkPolicy: false, canCreateNetworkPolicyApprovalRequest: false, canCreateBcapEgress: false },
});
// A source bound to a wallet credential lease names that lease as its one secret (the secret itself never leaves the
// wallet); any other posture holds none here.
const secretsOf = (src) => src.credential_binding?.credential_lease_ref ? [{ __typename: "MagritteSecret", name: "Credential lease", vaultEntryRid: src.credential_binding.credential_lease_ref }] : [];
// (cut D7) The folder a source is filed in, as the reference names a resource: the folder its syncs write into
// (outputFolderOf — its project's folder, else the owner's organization folder), so the source's page and its syncs'
// datasets place it in one location.
const folderSegmentOf = (folder) => ({ __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${folder.rid}`), rid: folder.rid, name: folder.name, alias: null, openUrl: null, path: `/${folder.name}`,
  collections: [], status: null, trashedStatus: "NOT_TRASHED", type: { __typename: "ResourceType", iconName: null }, autosaved: false, statusInfo: null, ancestors: [],
  permissions: { __typename: "ResourcePermissions", _id: cid(`ResourcePermissions:${folder.rid}`), canEditMetadata: false, canOpenLink: false } });
// folder: outputFolderOf(src, ownerRef, projects), when the operation reads where the source is filed
function sourceDetailOf(src, syncs = [], folder = null) {
  const node = sourceNodeOf(src, syncs);
  // (a source's default output folder is the folder it is filed in, so it is not changed here, cut D7)
  const off = { canCreateExport: false, canCreateExtract: false, canExploreSource: false, canRegisterTable: false, canUpdateSourceConfig: false, canCreateWebhook: false, canUseSourceTerminal: false,
    canUpdateExportControls: false, canUpdateExportMarkings: false, canUpdateDefaultOutputFolder: false };
  // a REST source's connection details are its endpoint, which its declarer may change (cut D3); nothing else is editable
  if (src.caller_may_change && sourceTypeOf(src.kind) === "webhooks-rest") off.canUpdateSourceConfig = true;
  // its declarer may add a sync to it: a lease plan declared on the ladder the new sync's configuration names (cut D6)
  if (src.caller_may_change) off.canCreateExtract = true;
  return {
    // every entity carries a stable _id: the app's cache normalizes by it, and a null id collapses every source's
    // permissions into one entry
    ...node, apiName: null, sourceConfig: sourceConfigOf(src), permissions: { __typename: "MagritteSourcePermissions", _id: cid(`MagritteSourcePermissions:${node.rid}`), ...off }, secrets: secretsOf(src),
    runtimePlatform: { __typename: "CloudRuntimePlatform", clientCertificatesV2: [], serverCertificateBundlesV2: [], migrationToCloudInfo: null },
    // no data leaves through a source here: exports are off and no marking is exportable
    exportState: { __typename: "MagritteSourceExportState", isEnabled: false, isEnabledWithoutMarkingsValidation: false, markingsAllowedForExport: [], markingsAllowedForExportCount: 0 },
    codeResourceImportUsageRestrictionsV2: { __typename: "CodeResourceImportUsageRestrictions", allowStemmaRepositoriesUsage: false, allowDeployedApplicationsUsage: false },
    streamingExtracts: [], exports: [], changeDataCaptureStreamingExtract: null, importingCodeResources: [], streamingMediaExtracts: [], mediaExtracts: [], hyperAutoIntegrations: [],
    tables: { __typename: "MagritteTablePage", values: [], nextPageToken: null }, tableIndexSettings: null, magritteIcebergExtractsV2: { __typename: "MagritteIcebergExtractPage", totalNumberOfResults: 0 },
    webhooks: { __typename: "WebhooksPage", totalNumberOfResults: 0, values: [], nextPageToken: null }, lastKnownCdataOauthAuthenticationStatus: null, userUploadedJdbcDrivers: [],
    // its syncs' datasets are placed in its output folder (cut D6: its project's folder, else the owner's organization
    // folder); answered where the operation reads it (cut D7), never created
    outputFolder: folder ? folderSegmentOf(folder) : null,
    outputFolderV2: folder ? { __typename: "MagritteOutputFolderConfigured", __implements: ["MagritteOutputFolder"], resource: folderSegmentOf(folder) } : null,
    metadata: { ...node.metadata, name: src.name || src.source_id, description: "", permissions: { __typename: "ResourcePermissions", _id: cid(`ResourcePermissions:${node.rid}`), canEditMetadata: false, canAdministerNetworkControls: false },
      project: { ...node.metadata.project, usageAccountEnrollment: enrollmentOf(node.metadata.project.usageAccountEnrollment) } },
  };
}
// REST: POST source-store/sources/config/bulk — the asked sources' configurations
export function sourceConfigsOf(rids, sources) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => [r, sourceConfigOf(byRid.get(r))]));
}
// REST: POST source-store/sources/metadata — when each asked source was declared and last changed, and by whom
export function sourceMetadataOf(rids, sources) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => { const s = byRid.get(r); const who = principalUserId(s.declared_by_principal_ref);
    return [r, { created: { time: s.created_at || null, userId: who }, lastModified: { time: s.updated_at || s.created_at || null, userId: who }, displayOptions: null }]; }));
}
// REST: GET compass/api/resources/<source rid>/parent — the folder the source is filed in: its project's folder when it
// is filed in one of the caller's projects, else the owner's organization folder (the namespace the adopted Ontology
// Manager answers too). (cut D7: the same folder its syncs write into — a project-filed source no longer reads "local")
export function sourceParentOf(rid, sources, ownerRef, projects = []) {
  const s = (sources || []).find((x) => sourceRidOf(x.source_id) === rid);
  const folder = s ? outputFolderOf(s, ownerRef, projects) : null;
  if (!folder) return null;
  const at = { time: s.created_at || null, userId: principalUserId(s.declared_by_principal_ref) };
  return { rid: folder.rid, name: folder.name, created: at, modified: at, lastModified: Date.parse(s.created_at || "") || 0,
    urlVariables: {}, directlyTrashed: false, isAutosave: false, isHidden: false, isPreviewResource: false, status: null };
}
// REST: POST compass/api/batch/resources — the caller's sources (and the owner's organization folder) as the resources
// the app names and places them by: its header, breadcrumbs and path, each under the folder it is filed in (cut D7). No
// operation is granted on them here. (A project's folder is answered by the project plane's own resources.)
export function compassSourceResources(rids, sources, ownerRef, syncs = [], projects = []) {
  const out = {};
  const want = new Set(Array.isArray(rids) ? rids : []);
  const folder = ownerRef ? namespaceRidOf(ownerRef) : null;
  const base = (rid, name, at, extra) => ({ rid, name, created: at, modified: at, lastModified: Date.parse(at.time || "") || 0, description: null, operations: [], urlVariables: {},
    favorite: null, branches: [], defaultBranch: null, longDescription: null, directlyTrashed: false, inTrash: false, isAutosave: false, isHidden: false, isPreviewResource: false,
    deprecation: null, collections: [], namedCollections: [], tags: [], namedTags: [], alias: "", collaborators: [], markings: [], projectAccessMarkings: [],
    linkedItems: [], classification: null, portfolioRid: null, status: null, ...extra });
  for (const s of sources || []) {
    const rid = sourceRidOf(s.source_id);
    if (!want.has(rid)) continue;
    const at = { time: s.created_at || null, userId: principalUserId(s.declared_by_principal_ref) };
    const filed = outputFolderOf(s, ownerRef, projects);
    out[rid] = base(rid, s.name || s.source_id, at, { path: `/${filed ? filed.name : namespaceNameOf(ownerRef)}/${s.name || s.source_id}`, namedAncestors: filed ? [{ rid: filed.rid, name: filed.name }] : [] });
  }
  if (folder && want.has(folder)) out[folder] = base(folder, namespaceNameOf(ownerRef), { time: null, userId: null }, { path: `/${namespaceNameOf(ownerRef)}`, namedAncestors: [] });
  // …and each asked sync's output dataset
  // (named by its path alone, as the reference answers a dataset: its card shows the path's folder)
  for (const y of syncs || []) if (want.has(y.datasetRid)) out[y.datasetRid] = syncDatasetResourceOf(y, (rid, name, at, extra) => base(rid, name, at, { namedAncestors: null, ...extra }));
  return out;
}
// REST: GET source-store/v2/source/<rid>/runtimePlatform — the Hypervisor reaches a source itself (the "cloud" runtime),
// holding no credential there (a credential stays in the wallet), no egress policy, cloud identity, OIDC runtime or
// certificate; and GET source-certificates/source/<rid>/redacted — no certificate
export function sourceRuntimePlatformOf(rid, sources) {
  if (!(sources || []).some((s) => sourceRidOf(s.source_id) === rid)) return null;
  return { type: "cloud", cloud: { credential: null, networkEgressPolicies: { networkEgressPolicies: [] }, cloudIdentity: null, oidcRuntime: null, clientCertificates: [], serverCertificateBundles: [] } };
}
export const SOURCE_CERTIFICATES = { client: {}, server: {} };
// a source as a resource the settings pages name and place (its name, its folder, its path); nothing is editable here.
// Its folder is the one it is filed in (cut D7: its project's, else the owner's organization folder).
function sourceResourceMetadataOf(src, ownerRef, projects = []) {
  const rid = sourceRidOf(src.source_id);
  const filed = outputFolderOf(src, ownerRef, projects);
  const folder = filed ? { ...folderSegmentOf(filed), parent: null } : null;
  return { ...folderSegmentOf({ rid, name: src.name || src.source_id }), path: `/${filed ? filed.name : namespaceNameOf(ownerRef)}/${src.name || src.source_id}`, parent: folder, ancestors: folder ? [folder] : [] };
}
const GLOBAL_PERMISSIONS = { __typename: "GlobalPermissions", _id: cid("GlobalPermissions"), canCreateMagritteSourceV2: true };
export const CREATE_PAGE_OPERATIONS = new Set(["ChooseNewSourceTypePageQuery", "CreateSourcePageQuery", "CreateSourceStepQuery", "ResourceNewNameKnownInvalidQuery", "CheckSourceApiNameQuery"]);

// ---- creating and changing a source (cut D3): the reference's writes as data-source declarations and updates. A REST
// API is the one type created here: its domain becomes the source's endpoint. Any other type is refused by name.
const CREATABLE = { "webhooks-rest": "rest_api" };
export class DataConnectionRefusal extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
// the first domain as an endpoint URL, or null while it has no host (the wizard creates a source before its details)
export function endpointOfDomains(sourceConfig) {
  const d = (sourceConfig?.config?.domains || [])[0];
  const host = String(d?.host || "").trim();
  if (!host) return null;
  if (/[\s/@?#]/u.test(host)) throw new DataConnectionRefusal("Hypervisor:DataConnectionDomainInvalid", "A domain is a host name only (no scheme, path, credentials or query).");
  const scheme = String(d?.scheme || "HTTPS").toUpperCase() === "HTTP" ? "http" : "https";
  const port = Number(d?.port) || null;
  return `${scheme}://${host}${port && port !== (scheme === "https" ? 443 : 80) ? `:${port}` : ""}`;
}
// POST source-store/source/v3 → the data-source plane's declaration body
export function createBodyOf(request) {
  const type = request?.config?.source?.type;
  const kind = CREATABLE[type];
  if (!kind) throw new DataConnectionRefusal("Hypervisor:DataConnectionTypeNotCreatable", `Only a REST API source can be created here; ${type || "this type"} cannot yet.`);
  if ((request?.config?.source?.config?.domains || []).length > 1) throw new DataConnectionRefusal("Hypervisor:DataConnectionOneDomain", "A source here reaches one domain.");
  const endpoint = endpointOfDomains(request.config.source);
  return { name: String(request?.description?.name || "").trim(), kind, ...(endpoint ? { endpoint } : { draft: true }), credential_posture: "no_credentials_required" };
}
// PUT source-store/v2/sources/<rid> → the data-source plane's update body: only a REST source's connection details
export function updateBodyOf(request, src) {
  const patch = request?.patchSourceConfigRequest;
  const other = Object.keys(request || {}).filter((k) => k !== "patchSourceConfigRequest");
  if (!patch || other.length) throw new DataConnectionRefusal("Hypervisor:DataConnectionUpdateNotBound", `Only a source's connection details can be changed here${other.length ? ` (not ${other.join(", ")})` : ""}.`);
  const next = patch.updatedSourceConfig;
  if (!src || sourceTypeOf(src.kind) !== "webhooks-rest" || next?.type !== "webhooks-rest") throw new DataConnectionRefusal("Hypervisor:DataConnectionUpdateNotBound", "Only a REST API source's connection details can be changed here.");
  if ((next?.config?.domains || []).length !== 1) throw new DataConnectionRefusal("Hypervisor:DataConnectionOneDomain", "A source here reaches exactly one domain.");
  if ((next.config.domains[0].auth && next.config.domains[0].auth.type && next.config.domains[0].auth.type !== "none") || Object.keys(patch.additionalSecrets || {}).length)
    throw new DataConnectionRefusal("Hypervisor:DataConnectionCredentialNotBound", "Authentication and secrets are not set here: a source's credential is a wallet lease, bound in Connections.");
  const base = endpointOfDomains(next);
  if (!base) throw new DataConnectionRefusal("Hypervisor:DataConnectionDomainInvalid", "A REST API source needs a domain.");
  // the reference's domain is a host alone; a declared endpoint's path and query are kept when its host changes
  const prior = endpointUrl(src.endpoint);
  const rest = prior && (prior.pathname !== "/" || prior.search) ? `${prior.pathname}${prior.search}` : "";
  return { endpoint: `${base}${rest}` };
}
// the reference's answer to a saved configuration, from the updated source
export function updatedSourceOf(src) {
  const c = sourceConfigOf(src);
  return { updatedSource: { sourceConfig: c.source, connections: c.connections, additionalSecrets: {}, vaultEntries: {}, mavenCoordinates: { userProvided: [], foundryProvided: [] } } };
}
// POST multipass/api/authz/batch/operations — a signed-in caller may add a source (the source root's add-source, which
// gates New source and its catalog), and may change the configuration of a REST source they declared
export const SOURCE_ROOT = "ri.magritte..source.root";
export function authzOperationsOf(rids, sources, { signedIn = false } = {}) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  const opsOf = (r) => {
    if (r === SOURCE_ROOT) return signedIn ? ["magritte:source-store:add-source"] : [];
    const src = byRid.get(r);
    return src?.caller_may_change && sourceTypeOf(src.kind) === "webhooks-rest" ? ["magritte:source-store:update-source-config"] : [];
  };
  return { resourceToOperationsMap: Object.fromEntries((Array.isArray(rids) ? rids : []).map((r) => [r, opsOf(r)])) };
}

export const SOURCE_PAGE_OPERATIONS = new Set(["SourcePageQuery", "SourcePageHelperQuery", "SourceBadConfigurationCalloutQuery", "CdataSourceInformationQuery", "ActiveResourceQuery", "WalkthroughsForResourceQuery", "SourceOutputFolderCondensedQuery",
  "SourceSettingsPageQuery", "SourceEditorQuery", "SourceEgressSelectPanelQuery", "SourceWebhooksPageQuery", "SourceWebhooksSectionQuery", "CodeImportsStepQuery", "ResourceMetadataQuery",
  "ExportConfigurationStepQuery", "SourceVirtualTablesPageQuery", "VirtualTablesForSourceQuery", "SourceExplorerPageQuery", "SourceEditSyncsPageQuery", "SourceOutputFolderPageQuery"]);
// no service a source's settings name exists here: no compute service, no egress or on-prem proxy
const SERVICE_AVAILABILITY = { __typename: "MagritteServiceAvailability", computeService: { __typename: "MagritteServiceAvailabilityResult", isAvailable: false },
  egressProxy: { __typename: "MagritteServiceAvailabilityResult", isAvailable: false }, onPremProxy: { __typename: "MagritteServiceAvailabilityResult", isAvailable: false } };
const sourceOf = (sources, rid) => (sources || []).find((s) => sourceRidOf(s.source_id) === rid) || null;

// a sync's pages (cut D4): its name, its source, its output dataset's health checks, its configuration and whether a
// run of it is in progress
// (and a source's Batch syncs table)
export const SYNC_PAGE_OPERATIONS = new Set(["BatchExtractPageHelperQuery", "SourceNameAndTypeQuery", "ExtractOverviewQuery", "BatchExtractConfigurationPageQuery", "RunningBuildBannerQuery", "BatchExtractsForSourceTableQuery",
  "NewDuplicateExtractPageQuery", "GetOrCreateSourceOutputFolder", "SourceNewBatchExtractPageQuery"]);
const jobReportOf = (y, run) => ({ __typename: "JobReport", _id: cid(`JobReport:${run.id}`), status: runStatusOf(run).job, build: { __typename: "Build", _id: cid(`Build:${run.id}`), rid: buildRidOf(run.id) } });
// a run as the table's build report: its status, and its one job's
const buildReportOf = (run) => ({ __typename: "BuildReport", _id: cid(`BuildReport:${run.id}`), rid: buildRidOf(run.id), status: runStatusOf(run).build,
  jobs: [{ __typename: "JobReport", __implements: ["JobReportResult"], _id: cid(`JobReport:${run.id}`), status: runStatusOf(run).job }] });
// a sync's output dataset as the resource the table names: it cannot be opened here (no dataset app is adopted)
function datasetMetadataOf(y) {
  const seg = (rid, name, path) => ({ __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${rid}`), rid, name, alias: null, openUrl: null, path, collections: [], status: null, trashedStatus: "NOT_TRASHED",
    type: { __typename: "ResourceType", iconName: null }, permissions: { __typename: "ResourcePermissions", _id: cid(`ResourcePermissions:${rid}`), canOpenLink: false }, autosaved: false, statusInfo: null, ancestors: [] });
  const folder = y.folder ? seg(y.folder.rid, y.folder.name, `/${y.folder.name}`) : null;
  return { ...seg(y.datasetRid, y.datasetName, y.datasetPath), ancestors: folder ? [folder] : [] };
}
// a sync as the extract a source's Batch syncs table lists: its name, its plan's lease shape, its dataset and its latest run
const extractNodeOf = (y) => ({ __typename: "MagritteExtract", _id: cid(`MagritteExtract:${y.rid}`), rid: y.rid, extractName: y.plan.name || y.plan.id, extractConfig: extractOf(y).extractConfig,
  dataset: { __typename: "CatalogDataset", _id: cid(`CatalogDataset:${y.datasetRid}`), rid: y.datasetRid, metadata: datasetMetadataOf(y) },
  branch: { __typename: "CatalogBranch", _id: cid(`CatalogBranch:${y.datasetRid}:${BRANCH}`), jobs: { __typename: "JobSearchResultPage", results: y.runs.slice(0, 1).map((r) => ({ __typename: "JobReport", _id: cid(`JobReport:${r.id}`), build: buildReportOf(r) })) } } });
// (cut D7) a sync as Edit syncs lists it: its name, its source's runtime, no schedule (a run is admitted by hand), its
// branch (the dataset's one, master) and its dataset — the plan's own, placed in the source's output folder, made when the
// plan was declared
const editSyncExtractOf = (y) => ({ __typename: "MagritteExtract", _id: cid(`MagritteExtract:${y.rid}`), rid: y.rid, extractName: y.plan.name || y.plan.id,
  source: { __typename: "MagritteSource", _id: cid(`MagritteSource:${sourceRidOf(y.plan.data_source_id)}`), type: sourceTypeOf(y.source.kind), runtimePlatform: { __typename: "CloudRuntimePlatform" } },
  branch: { __typename: "CatalogBranch", _id: cid(`CatalogBranch:${y.datasetRid}:${BRANCH}`), indirectlyRelevantSchedules: [],
    metadata: { __typename: "BranchMetadata", _id: cid(`BranchMetadata:${y.datasetRid}:${BRANCH}`), resourceType: { __typename: "ResourceType", iconName: null }, openUrl: null } },
  dataset: { __typename: "CatalogDataset", _id: cid(`CatalogDataset:${y.datasetRid}`), rid: y.datasetRid, metadata: { ...datasetMetadataOf(y), created: { __typename: "Timestamp", time: y.plan.created_at || null } } } });
// the operations whose answer names the owner's organization folder or the folder a source is filed in (the serve reads
// the owner and the caller's projects for these)
export const OWNER_REF_OPERATIONS = new Set(["ResourceMetadataQuery", "GetOrCreateSourceOutputFolder", "SourceOutputFolderCondensedQuery", "SourceOutputFolderPageQuery"]);
export const DATA_CONNECTION_GRAPHQL_OPERATIONS = new Set([...SOURCE_PAGE_OPERATIONS, ...CREATE_PAGE_OPERATIONS, ...SYNC_PAGE_OPERATIONS,
  "SourcesListQuery", "CreateSourceButtonQuery", "SplashTableQuery", "TargetsListQuery", "GetRemoteStoreRid", "RecentInstallationsPopoverQuery",
  "CommunicationChannelsQuery", "FoundryProvidedDriverQuery", "HasAipEnabledQuery", "CreatePolicyDialogQuery",
]);
// ctx: { sources } (already the caller's)
export function dataConnectionGraphqlFacts(name, variables, ctx) {
  const root = { __typename: "Query" };
  switch (name) {
    case "SourcesListQuery": {
      const want = new Set(variables?.sourceTypes || []);
      const text = String(variables?.name || "").trim().toLowerCase();
      const rows = (ctx.sources || []).filter((s) => (!want.size || want.has(sourceTypeOf(s.kind))) && (!text || String(s.name || "").toLowerCase().includes(text)));
      const from = Math.max(0, Number(variables?.pageToken) || 0);
      return { ...root, sources: { __typename: "MagritteSourcePage", values: rows.slice(from, from + 50).map((s) => sourceNodeOf(s, ctx.syncs)), nextPageToken: from + 50 < rows.length ? String(from + 50) : null } };
    }
    // a source is created as a data-source declaration (cut D3): REST API first; any other type is refused by name at create
    case "CreateSourceButtonQuery": case "CreateSourcePageQuery": return { ...root, globalPermissions: GLOBAL_PERMISSIONS, magritteProvidedJdbcDriver: null };
    case "ChooseNewSourceTypePageQuery": return { ...root, globalPermissions: GLOBAL_PERMISSIONS,
      me: { __typename: "User", _id: cid("User:me"), organization: { __typename: "Organization", _id: cid("Organization:me"), enrollment: { ...enrollmentOf({}), magritteDirectorySourceTypeConfigV2: { __typename: "MagritteDirectorySourceTypeConfig", enabled: false } } } } };
    // Name and location: the new source's folder is the caller's organization folder (a source files into no project here)
    case "CreateSourceStepQuery": return { ...root, resourceMetadata: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${variables?.folderRid}`), rid: variables?.folderRid,
      project: { __typename: "Project", _id: cid("Project:none"), usageAccountEnrollment: { ...enrollmentOf({}), magritteDirectorySourceTypeConfigV2: { __typename: "MagritteDirectorySourceTypeConfig", enabled: false } } },
      namespace: { __typename: "Namespace", _id: cid(`Namespace:${variables?.folderRid}`), rid: variables?.folderRid } } };
    // a name is free unless one of the caller's sources already has it
    case "ResourceNewNameKnownInvalidQuery": { const wip = String(variables?.debouncedResourceNameWip || "").trim().toLowerCase();
      return { ...root, resourceMetadata: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${variables?.parentRid}`), childNameValid: !!wip && !(ctx.sources || []).some((x) => String(x.name || "").trim().toLowerCase() === wip) } }; }
    // the data-source plane keeps no API name, so none is taken
    case "CheckSourceApiNameQuery": return { ...root, namespace: { __typename: "Namespace", _id: cid(`Namespace:${variables?.namespaceRid}`), checkMagritteSourceApiName: { __typename: "CheckMagritteSourceApiNameResult", error: null } } };
    // recently viewed and favorite Data Connection resources: none is kept
    case "SplashTableQuery": return { ...root, recents: [], favorites: [] };
    // listeners (inbound message targets): none exists
    case "TargetsListQuery": return { ...root, searchInboundMessageListenerTargets: { __typename: "InboundMessageListenerTargetPage", values: [], nextPageToken: null } };
    // the reference examples' marketplace store: the Hypervisor has no remote marketplace
    case "GetRemoteStoreRid": return { ...root, remoteStore: null };
    case "RecentInstallationsPopoverQuery": return { ...root, store: null };
    // administrator communication channels: none is configured
    case "CommunicationChannelsQuery": return { ...root, communicationChannelCategories: [],
      me: { __typename: "User", _id: cid("User:me"), organization: { __typename: "Organization", _id: cid("Organization:me"), enrollment: { __typename: "Enrollment", _id: cid("Enrollment:me"), administratorCommunicationControls: { __typename: "AdministratorCommunicationControls", disallowedCommunicationChannels: [] } } } } };
    // a source's page
    case "SourcePageQuery": case "SourcePageHelperQuery": case "SourceBadConfigurationCalloutQuery": case "CdataSourceInformationQuery": case "SourceOutputFolderCondensedQuery":
    case "SourceSettingsPageQuery": case "SourceEditorQuery": case "SourceWebhooksPageQuery": case "SourceWebhooksSectionQuery": case "ExportConfigurationStepQuery":
    // (cut D5) Virtual tables: none is registered on a source here, and none can be (canRegisterTable is false); Explore
    // source: no compute service browses a source (the explorer says so, in words the adopted layer makes true)
    case "SourceVirtualTablesPageQuery": case "VirtualTablesForSourceQuery": case "SourceExplorerPageQuery": case "SourceOutputFolderPageQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid || variables?.rid);
      // (the Overview's Output folder, and its settings page, read where its syncs' datasets are placed, cut D7)
      const folder = src && OWNER_REF_OPERATIONS.has(name) ? outputFolderOf(src, ctx.ownerRef, ctx.projects) : null;
      // no identity provider federates a source's outbound calls
      return { ...root, source: src ? sourceDetailOf(src, ctx.syncs, folder) : null, magritteServiceAvailability: SERVICE_AVAILABILITY, oidcMetadata: null };
    }
    // (cut D7) Edit syncs — the source's syncs to configure, one at a time or in bulk: each is a capability-lease plan on
    // it (its configuration the plan's, saved through the plan's PATCH as a sync's own page saves it), its dataset the
    // plan's own in the source's output folder, and no schedule runs one (a run is admitted by hand). Newest first.
    case "SourceEditSyncsPageQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      if (!src) return { ...root, source: null, magritteServiceAvailability: SERVICE_AVAILABILITY };
      const rows = (ctx.syncs || []).filter((y) => y.plan.data_source_id === src.source_id).sort((a, b) => String(b.plan.created_at || "").localeCompare(String(a.plan.created_at || "")));
      const from = Math.max(0, Number(variables?.pageToken) || 0), size = Math.max(1, Number(variables?.pageSize) || 100);
      return { ...root, magritteServiceAvailability: SERVICE_AVAILABILITY,
        source: { ...sourceDetailOf(src, ctx.syncs), extractsV2: { __typename: "MagritteExtractPage", nextPageToken: from + size < rows.length ? String(from + size) : null, values: rows.slice(from, from + size).map(editSyncExtractOf) } } };
    }
    // the egress panel reads the enrollment through the source's resource metadata
    case "SourceEgressSelectPanelQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      return { ...root, resourceMetadata: src ? sourceDetailOf(src).metadata : null };
    }
    // code imports: no code repository, deployed application or pipeline imports a source here, and none may be allowed
    case "CodeImportsStepQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      if (!src) return { ...root, source: null };
      const d = sourceDetailOf(src);
      return { ...root, source: { ...d, codeResourceImportUsageRestrictionsV2: { ...d.codeResourceImportUsageRestrictionsV2, __typename: "MagritteSourceCodeResourceImportUsageRestrictions", allowEddiePipelinesUsage: false },
        permissions: { ...d.permissions, canManageImportUsageRestrictions: false, canManageImportingCodeResources: false } } };
    }
    case "ResourceMetadataQuery": {
      const src = sourceOf(ctx.sources, variables?.resourceRid || variables?.rid);
      return { ...root, resourceMetadata: src ? sourceResourceMetadataOf(src, ctx.ownerRef, ctx.projects) : null };
    }
    // no AIP assistant runs here
    case "HasAipEnabledQuery": return { ...root, me: { __typename: "User", _id: cid("User:me"), isAipEnabled: false } };
    // the egress policy dialog: the Hypervisor enrollment, where no network policy can be created or requested
    case "CreatePolicyDialogQuery": return { ...root, enrollment: enrollmentOf({}), me: { __typename: "User", _id: cid("User:me"), id: ctx.userId || null, username: null, attributes: [] } };
    // a JDBC driver: no connection type here uses one
    case "FoundryProvidedDriverQuery": return { ...root, magritteProvidedJdbcDriver: null };
    // ---- a sync's pages (cut D4), over the caller's syncs (ctx.syncs)
    case "BatchExtractPageHelperQuery": {
      const y = (ctx.syncs || []).find((x) => x.rid === variables?.extractRid);
      return { ...root, extract: y ? { __typename: "MagritteExtract", _id: cid(`MagritteExtract:${y.rid}`), rid: y.rid, extractName: y.plan.name || y.plan.id } : null };
    }
    case "SourceNameAndTypeQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      return { ...root, source: src ? sourceNodeOf(src, ctx.syncs) : null };
    }
    // the output dataset's health checks: none is kept
    case "ExtractOverviewQuery": {
      const y = (ctx.syncs || []).find((x) => x.datasetRid === variables?.datasetRid);
      const dataset = y ? { __typename: "CatalogDataset", _id: cid(`CatalogDataset:${y.datasetRid}`), rid: y.datasetRid } : null;
      return { ...root, catalogDataset: y ? { ...dataset, branch: { __typename: "CatalogBranch", _id: cid(`CatalogBranch:${y.datasetRid}:${BRANCH}`), name: BRANCH, dataset, healthChecks: [] } } : null };
    }
    // a sync's configuration: no schedule runs it (a run is admitted by hand), and its source's runtime is the Hypervisor's
    case "BatchExtractConfigurationPageQuery": {
      const y = (ctx.syncs || []).find((x) => x.rid === variables?.extractRid);
      return { ...root, extract: y ? { __typename: "MagritteExtract", _id: cid(`MagritteExtract:${y.rid}`), rid: y.rid,
        branch: { __typename: "CatalogBranch", _id: cid(`CatalogBranch:${y.datasetRid}:${BRANCH}`), indirectlyRelevantSchedules: [] },
        source: { __typename: "MagritteSource", _id: cid(`MagritteSource:${sourceRidOf(y.plan.data_source_id)}`), type: sourceTypeOf(y.source.kind), runtimePlatform: { __typename: "CloudRuntimePlatform" } } } : null };
    }
    // Duplicate sync: the original sync (its plan) as the new sync's starting state — no schedule runs it, and its source
    // is the plan's
    case "NewDuplicateExtractPageQuery": {
      const y = (ctx.syncs || []).find((x) => x.rid === variables?.originalExtractRid);
      return { ...root, extract: y ? { __typename: "MagritteExtract", _id: cid(`MagritteExtract:${y.rid}`), rid: y.rid,
        branch: { __typename: "CatalogBranch", _id: cid(`CatalogBranch:${y.datasetRid}:${BRANCH}`), indirectlyRelevantSchedules: [] },
        source: { __typename: "MagritteSource", _id: cid(`MagritteSource:${sourceRidOf(y.plan.data_source_id)}`), type: sourceTypeOf(y.source.kind), runtimePlatform: { __typename: "CloudRuntimePlatform" } } } : null };
    }
    // a new sync's output folder (cut D6): the folder of the project its source is filed in, else the owner's
    // organization folder — where the source's syncs' datasets are placed. Either exists: nothing is created.
    case "GetOrCreateSourceOutputFolder": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      const folder = src ? outputFolderOf(src, ctx.ownerRef, ctx.projects)?.rid || null : null;
      return { ...root, getOrCreateSourceOutputFolderV2: { __typename: "GetOrCreateSourceOutputFolderResult", error: src && folder ? null : "NOT_FOUND",
        source: src ? { __typename: "MagritteSource", _id: cid(`MagritteSource:${sourceRidOf(src.source_id)}`), outputFolder: folder ? { __typename: "CompassFolder", _id: cid(`CompassFolder:${folder}`), rid: folder } : null } : null } };
    }
    // New sync (cut D6), from a source's Batch syncs: the source and its runtime (the Hypervisor's own)
    case "SourceNewBatchExtractPageQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      return { ...root, source: src ? sourceNodeOf(src, ctx.syncs) : null };
    }
    // a source's Batch syncs table: its lease plans, newest first; its declarer may add one (New, cut D6)
    case "BatchExtractsForSourceTableQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      const text = String(variables?.name || "").trim().toLowerCase();
      const rows = src ? (ctx.syncs || []).filter((y) => y.plan.data_source_id === src.source_id && (!text || String(y.plan.name || "").toLowerCase().includes(text))) : [];
      const byName = variables?.sort?.field === "NAME";
      rows.sort((a, b) => (byName ? String(a.plan.name || "").localeCompare(String(b.plan.name || "")) : String(a.plan.created_at || "").localeCompare(String(b.plan.created_at || ""))) * (variables?.sort?.direction === "ASCENDING" ? 1 : -1));
      const from = Math.max(0, Number(variables?.pageToken) || 0), size = Math.max(1, Number(variables?.pageSize) || 100);
      return { ...root, source: src ? { ...sourceNodeOf(src, ctx.syncs), permissions: { __typename: "MagritteSourcePermissions", _id: cid(`MagritteSourcePermissions:${sourceRidOf(src.source_id)}`), canCreateExtract: !!src.caller_may_change } } : null,
        searchMagritteBatchExtracts: { __typename: "MagritteBatchExtractSearchPage", nextPageToken: from + size < rows.length ? String(from + size) : null,
          values: rows.slice(from, from + size).map((y) => ({ __typename: "MagritteBatchExtractSearchResult", magritteExtract: extractNodeOf(y) })) } };
    }
    // a run in progress: one running (holding its lease) or waiting (for its lease)
    case "RunningBuildBannerQuery": {
      const y = (ctx.syncs || []).find((x) => x.datasetRid === variables?.datasetRid);
      const runs = y && (!variables?.branchId || variables.branchId === BRANCH) ? y.runs : [];
      const page = (job) => ({ __typename: "JobSearchResultPage", results: runs.filter((r) => runStatusOf(r).job === job).slice(0, 1).map((r) => jobReportOf(y, r)) });
      return { ...root, "runningJobs:jobs": page("RUNNING"), "waitingJobs:jobs": page("WAITING") };
    }
    // a source as a resource: not promoted, and no walkthrough
    case "ActiveResourceQuery": case "WalkthroughsForResourceQuery": {
      const rid = variables?.rid || variables?.resourceRid;
      const src = sourceOf(ctx.sources, rid);
      return { ...root, resourceMetadata: src ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${rid}`), rid, promotion: null, aipAssistWalkthroughs: [] } : null };
    }
    default: return null;
  }
}

// ---- the reference's own words, made true (cut D5). Where the reference tells a person to do something that does not
// exist here — contact a representative, switch runtime, configure a catalog, enable imports that enable nothing — its
// message is replaced at the wire in the reference's bundle (the seam the brand rewrite uses), matched by its id AND its
// exact default text: a build whose text differs is left alone, and the verifier's assertion on the page goes red.
export const TRUTHFUL_MESSAGES = [
  // a source's Webhooks page, for a source reached directly (every source here)
  { id: "d01b03c8f42d.webhooksDisabledCloudRuntime",
    from: "Webhooks are not supported for this source when connecting via direct connection. To use webhooks, contact your Palantir representative or switch to a different runtime in <link>connection settings</link>.",
    to: "Webhooks are not supported here: the Hypervisor has no webhook plane, so a source never makes a request on behalf of an action, and there is no other runtime to switch to." },
  // Virtual tables: the callout above the page, and the auto-registration card (three builds of it)
  { id: "43b60fbef911.codeRepositoriesCallout",
    from: "To use virtual tables in code repositories you must enable <strong>code imports</strong> and <strong>exports</strong> in the source connection settings and then import the source into your code repository. Go to <here>Connection settings</here> to enable these.",
    to: "Virtual tables are not supported here: the Hypervisor never queries a source in place. A source is read only by a sync run that holds its lease, into that sync's output dataset." },
  ...["14f693b2335f.disabled", "69d8da344657.disabled", "1aeed661f579.disabled"].map((id) => ({ id,
    from: "Auto-registration of tables is not available. No catalog is configured in <href>Connection settings</href>.",
    to: "Auto-registration of tables is not available: no table catalog exists for a source here." })),
  // Explore source, for a source reached directly
  { id: "387c90f6857f.explorationsAreUnavailableDescription",
    from: "This instance of Foundry does not support source exploration with Foundry Worker connections.",
    to: "The Hypervisor never browses a source: it reads one only in a sync run, as one bounded, receipted batch under a wallet-authority lease." },
  // (cut D7) a source's Output folder settings: why Change default output folder is off — not a permission the caller
  // lacks, but where the folder comes from
  { id: "ec37e6b26788.insufficientPermissions",
    from: "You do not have sufficient permissions",
    to: "A source's output folder is the folder it is filed in — its project's, else the organization folder — and is not changed here." },
];
const messageLiteral = (id, text) => `{id:${JSON.stringify(id)},defaultMessage:${JSON.stringify(text)}}`;
export function truthfulBundle(js) {
  if (typeof js !== "string" || !js.includes("defaultMessage")) return js;
  let out = js;
  for (const m of TRUTHFUL_MESSAGES) { const from = messageLiteral(m.id, m.from); if (out.includes(from)) out = out.split(from).join(messageLiteral(m.id, m.to)); }
  return out;
}

// ---- a source's Logs (cut D5): its log is what the daemon receipted for the runs of its syncs — each materializing run's
// receipts (admitted, lease requested, obtained or refused, execution requested, source contact, validation, output,
// cancel), in the reference telemetry viewer's own shape. A source with no run has no log. The viewer asks per time
// range and filter; the filter is evaluated here over the entries. Nothing else is logged: no source process runs.
export const sourceLogContainerRidOf = (sourceId) => `ri.foundry-telemetry-service.main.telemetry-container.${uuidOf(`source-log:${sourceId}`)}`;
export const sourceLogSessionOf = (sourceId) => uuidOf(`source-log-session:${sourceId}`);
// REST: GET /magritte-coordinator/api/source/telemetry/<rid>/details
export function sourceTelemetryDetailsOf(rid, sources) {
  const s = sourceOf(sources, rid);
  return s ? { details: { containerRid: sourceLogContainerRidOf(s.source_id), sessionId: sourceLogSessionOf(s.source_id), sessionTags: [] } } : null;
}
// the caller's source a telemetry container and session name, or null
export const sourceOfLogSession = (containerRid, sessionId, sources) => (sources || []).find((s) => sourceLogContainerRidOf(s.source_id) === containerRid && sourceLogSessionOf(s.source_id) === sessionId) || null;
const ERROR_OPS = new Set(["execution_refused", "source_contact_failed", "lease_refused"]);
export function logLevelOf(receipt) {
  if (ERROR_OPS.has(receipt?.op) || (receipt?.op === "validation_result" && receipt?.outcome !== "ok")) return "ERROR";
  return receipt?.outcome && receipt.outcome !== "ok" ? "WARN" : "INFO";
}
// the source's log entries: runs = [{ run, plan, receipts }] for the source's syncs
export function sourceLogEntriesOf(runs) {
  const out = [];
  for (const { run, plan, receipts } of runs || []) for (const r of receipts || []) {
    if (!r?.at) continue;
    out.push({ level: logLevelOf(r), time: r.at, message: String(r.summary || r.op || ""), origin: "materializing-run",
      params: { sync: String(plan?.name || plan?.id || ""), run: String(run?.name || run?.id || ""), op: String(r.op || ""), outcome: String(r.outcome || ""), receipt: String(r.receipt_ref || "") } });
  }
  return out;
}
// a field by name: a top-level field, a param (by its name or as params.<name>)
const fieldOf = (e, field) => { const f = String(field || ""); if (f in e) return e[f]; const p = f.startsWith("params.") ? f.slice(7) : f; return e.params?.[p]; };
// a contains filter's snippet: *x* contains, x* starts with, *x ends with, x equals (the viewer's own wildcards)
const snippetMatches = (value, snippet) => {
  const v = String(value ?? "").toLowerCase(), sn = String(snippet ?? "").toLowerCase();
  const lead = sn.startsWith("*"), trail = sn.endsWith("*") && sn.length > 1, core = sn.replace(/^\*|\*$/gu, "");
  return lead && trail ? v.includes(core) : trail ? v.startsWith(core) : lead ? v.endsWith(core) : v === core;
};
// A log filter as the viewer sends it (a tagged union); a filter this layer does not know is refused by name rather than
// ignored (an ignored filter would show entries the person excluded).
export class LogFilterRefusal extends Error { constructor(type) { super(`the log filter ${type || "(untyped)"} is not bound here`); this.code = "Hypervisor:DataConnectionLogFilterNotBound"; } }
export function logFilterMatches(filter, e) {
  if (filter == null) return true;
  const inner = filter[filter.type];
  switch (filter.type) {
    case "andLogFilter": return (inner?.filters || []).every((f) => logFilterMatches(f, e));
    case "orLogFilter": return (inner?.filters || []).some((f) => logFilterMatches(f, e));
    case "notLogFilter": return !logFilterMatches(inner?.filter, e);
    case "exactMatchOnFieldLogFilter": return String(fieldOf(e, inner?.field) ?? "") === String(inner?.value ?? "");
    case "containsInFieldLogFilter": return snippetMatches(fieldOf(e, inner?.field), inner?.snippet);
    case "isEmptyLogFilter": { const v = fieldOf(e, inner?.field); return v == null || v === ""; }
    default: throw new LogFilterRefusal(filter.type);
  }
}
const micros = (iso) => { const ms = Date.parse(iso); if (!Number.isFinite(ms)) return null; const frac = /\.(\d+)/u.exec(iso)?.[1] || ""; return ms * 1000 + Number((frac.slice(3, 6) || "0").padEnd(3, "0")); };
// REST: POST /foundry-telemetry-service/api/containers/<c>/sessions/<s>/logs/read/v3 — a page of the entries in
// [fromInclusive, toExclusive) (microseconds) that match the filter, newest first unless chronological
export function sourceLogPageOf(entries, request) {
  const from = Number(request?.fromInclusive), to = Number(request?.toExclusive);
  const chrono = request?.chronological === true;
  const rows = (entries || []).map((e) => ({ e, t: micros(e.time) })).filter(({ e, t }) => t != null && (!Number.isFinite(from) || t >= from) && (!Number.isFinite(to) || t < to) && logFilterMatches(request?.filter, e));
  rows.sort((a, b) => (chrono ? a.t - b.t : b.t - a.t));
  const size = Math.max(1, Math.min(1000, Number(request?.pageSizeLimit) || 100));
  return { logEntries: rows.slice(0, size).map(({ e }) => ({ payload: { type: "serviceLogV1", serviceLogV1: { ...e, unsafeParams: {}, stacktrace: null } } })) };
}
export const LOG_THROTTLE_STATUS = { hasDroppedLogs: false, approximateDroppedRecordCount: 0 };
