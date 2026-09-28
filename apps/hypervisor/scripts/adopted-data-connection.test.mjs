// The adopted Data Connection's pure answers (R-241, Data Connection D1–D4): the caller's data sources as the reference
// app's sources, the bootstrap reads over them, and their syncs (lease plans) with their builds (materializing runs).
import test from "node:test";
import assert from "node:assert/strict";
import { answerDocument } from "./adopted-graphql.mjs";
import * as DC from "./adopted-data-connection.mjs";

const mine = { source_id: "ds_1", name: "Orders API", kind: "rest_api", declared_by_principal_ref: "user://me", project_ref: null };
const bucket = { source_id: "ds_2", name: "Plants bucket", kind: "s3", declared_by_principal_ref: "user://me", project_ref: null };
const teamProject = { source_id: "ds_3", name: "Team feed", kind: "http_feed", declared_by_principal_ref: "user://colleague", project_ref: "project://team" };
const stranger = { source_id: "ds_4", name: "Someone else's", kind: "postgres", declared_by_principal_ref: "user://stranger", project_ref: "project://theirs" };

test("the caller sees the sources they declared and those filed in a project they can see — never another principal's", () => {
  const seen = DC.callerSourcesOf([mine, bucket, teamProject, stranger], "user://me", ["project://team"]);
  assert.deepEqual(seen.map((s) => s.source_id), ["ds_1", "ds_2", "ds_3"]);
  assert.deepEqual(DC.callerSourcesOf([mine, stranger], null, []), [], "no principal: nothing");
});

test("a kind is a connection type: the reference's type id where it names the same connector, else the Hypervisor's own; none syncs", () => {
  assert.equal(DC.sourceTypeOf("rest_api"), "webhooks-rest");
  assert.equal(DC.sourceTypeOf("s3"), "s3-direct");
  assert.equal(DC.sourceTypeOf("http_feed"), "hypervisor-http-feed");
  assert.equal(DC.MANAGED_SOURCE_TYPES["webhooks-rest"].name, "REST API");
  assert.ok(Object.values(DC.MANAGED_SOURCE_TYPES).every((t) => Object.keys(t.syncs).length === 0 && t.capabilities.length === 0), "a declared source ingests nothing");
  assert.deepEqual(DC.sourceTypesOf([mine, bucket]), { "webhooks-rest": [DC.sourceRidOf("ds_1")], "s3-direct": [DC.sourceRidOf("ds_2")] });
  assert.deepEqual(DC.extractsBySourceOf([mine]), { [DC.sourceRidOf("ds_1")]: [] });
});

test("the Sources list answers the caller's sources in the list's own document, filtered by name and type", () => {
  const q = "query SourcesListQuery($name: String, $sourceTypes: [String!]) { sources(filter: {name: $name, types: $sourceTypes}) { values { rid type name numberOfExtracts runtimePlatform { __typename } __typename } nextPageToken __typename } __typename }";
  const all = answerDocument(q, DC.dataConnectionGraphqlFacts("SourcesListQuery", {}, { sources: [mine, bucket] }), null, "SourcesListQuery");
  assert.deepEqual(all.sources.values.map((v) => [v.name, v.type, v.numberOfExtracts]), [["Orders API", "webhooks-rest", 0], ["Plants bucket", "s3-direct", 0]]);
  const s3 = DC.dataConnectionGraphqlFacts("SourcesListQuery", { sourceTypes: ["s3-direct"] }, { sources: [mine, bucket] });
  assert.deepEqual(s3.sources.values.map((v) => v.name), ["Plants bucket"]);
  const named = DC.dataConnectionGraphqlFacts("SourcesListQuery", { name: "orders" }, { sources: [mine, bucket] });
  assert.deepEqual(named.sources.values.map((v) => v.name), ["Orders API"]);
  assert.equal(DC.dataConnectionGraphqlFacts("CreateSourceButtonQuery", {}, {}).globalPermissions.canCreateMagritteSourceV2, true, "a source can be created (as a data-source declaration)");
});

test("the list reads name only the caller's sources", () => {
  const rid = DC.sourceRidOf("ds_1");
  assert.deepEqual(DC.sourceDescriptionsOf([rid, "ri.magritte..source.other"], [mine]), { [rid]: { type: "webhooks-rest", name: "Orders API", description: "", apiName: null } });
  assert.deepEqual(DC.streamingExtractsOf({ sourceIds: [rid, "ri.magritte..source.other"] }, [mine]), { streamingExtracts: { [rid]: [] } });
});

test("a source's own page: its configuration is its declared endpoint, it can do nothing here, and it sits in the owner's folder", () => {
  const rest = { ...mine, endpoint: "https://api.example.test/orders", created_at: "2026-09-28T00:00:00Z" };
  const cfg = DC.sourceConfigOf(rest);
  assert.equal(cfg.source.type, "webhooks-rest");
  assert.equal(cfg.source.config.domains[0].host, "api.example.test");
  assert.equal(Object.values(cfg.connections)[0].config.http.url, "https://api.example.test");
  assert.equal(DC.sourceConfigOf({ ...bucket, endpoint: "s3://plants/" }).source.config.url, "s3://plants/");
  const rid = DC.sourceRidOf("ds_1");
  const page = DC.dataConnectionGraphqlFacts("SourcePageQuery", { sourceRid: rid }, { sources: [rest] });
  assert.ok(Object.values(page.source.permissions).filter((v) => typeof v === "boolean").every((v) => v === false), "no export, sync, explore, table or webhook is offered");
  assert.equal(page.source.outputFolder, null);
  assert.equal(page.magritteServiceAvailability.egressProxy.isAvailable, false);
  assert.equal(DC.dataConnectionGraphqlFacts("SourcePageQuery", { sourceRid: DC.sourceRidOf("ds_4") }, { sources: [rest] }).source, null, "another's source is not answered");
  assert.equal(DC.sourceMetadataOf([rid], [rest])[rid].created.time, "2026-09-28T00:00:00Z");
  assert.equal(DC.sourceParentOf(rid, [rest], "org://local").name, "local");
  const res = DC.compassSourceResources([rid], [rest], "org://local")[rid];
  assert.equal(res.name, "Orders API");
  assert.deepEqual([res.branches, res.tags, res.markings], [[], [], []], "the link component iterates these");
});

test("a source's settings: its runtime is the Hypervisor's own with nothing held there, its imports and webhooks are off, and a wallet lease is its one secret", () => {
  const rid = DC.sourceRidOf("ds_1");
  assert.deepEqual(DC.sourceRuntimePlatformOf(rid, [mine]).cloud, { credential: null, networkEgressPolicies: { networkEgressPolicies: [] }, cloudIdentity: null, oidcRuntime: null, clientCertificates: [], serverCertificateBundles: [] });
  assert.equal(DC.sourceRuntimePlatformOf(DC.sourceRidOf("ds_4"), [mine]), null, "another's source has no runtime answered");
  const editor = DC.dataConnectionGraphqlFacts("SourceEditorQuery", { sourceRid: rid }, { sources: [mine] });
  const enrollment = editor.source.metadata.project.usageAccountEnrollment;
  assert.deepEqual([enrollment.networkEgressPolicies, enrollment.cloudIdentities, enrollment.permissions.canCreateNetworkPolicy], [[], [], false]);
  assert.equal(editor.source.permissions.canUpdateSourceConfig, false, "a declared source cannot be changed (no update route)");
  assert.deepEqual(editor.source.secrets, [], "no lease bound: no secret");
  const leased = { ...mine, credential_binding: { kind: "lease_ref", credential_lease_ref: "lease://wallet/1" } };
  assert.deepEqual(DC.dataConnectionGraphqlFacts("SourceEditorQuery", { sourceRid: rid }, { sources: [leased] }).source.secrets.map((x) => x.vaultEntryRid), ["lease://wallet/1"]);
  const imports = DC.dataConnectionGraphqlFacts("CodeImportsStepQuery", { sourceRid: rid }, { sources: [mine] }).source;
  assert.ok(Object.values(imports.codeResourceImportUsageRestrictionsV2).filter((v) => typeof v === "boolean").every((v) => v === false));
  assert.deepEqual([imports.permissions.canManageImportUsageRestrictions, imports.permissions.canManageImportingCodeResources, imports.permissions.canCreateWebhook], [false, false, false]);
  const meta = DC.dataConnectionGraphqlFacts("ResourceMetadataQuery", { resourceRid: rid }, { sources: [mine], ownerRef: "org://local" }).resourceMetadata;
  assert.deepEqual([meta.name, meta.parent.name, meta.permissions.canEditMetadata], ["Orders API", "local", false]);
  assert.equal(DC.dataConnectionGraphqlFacts("ResourceMetadataQuery", { resourceRid: DC.sourceRidOf("ds_4") }, { sources: [mine], ownerRef: "org://local" }).resourceMetadata, null);
});

test("creating a source is a data-source declaration: a REST API with its domain as its endpoint, a draft until it has one, any other type refused by name", () => {
  const create = (type, domains) => ({ description: { name: " Orders ", description: "", apiName: "Orders" }, config: { source: { type, config: { domains } } }, runtimePlatformRequest: { type: "cloud" }, parentRid: "ri.x" });
  assert.deepEqual(DC.createBodyOf(create("webhooks-rest", [{ domainId: "d", host: "", scheme: "HTTPS" }])), { name: "Orders", kind: "rest_api", draft: true, credential_posture: "no_credentials_required" });
  assert.deepEqual(DC.createBodyOf(create("webhooks-rest", [{ domainId: "d", host: "api.example.test", scheme: "HTTPS", port: 8443 }])).endpoint, "https://api.example.test:8443");
  assert.throws(() => DC.createBodyOf(create("s3-direct", [])), (e) => e.code === "Hypervisor:DataConnectionTypeNotCreatable");
  assert.throws(() => DC.createBodyOf(create("webhooks-rest", [{ host: "user:pw@api.example.test" }])), (e) => e.code === "Hypervisor:DataConnectionDomainInvalid", "credentials never ride in a domain");
  assert.throws(() => DC.createBodyOf(create("webhooks-rest", [{ host: "a.test" }, { host: "b.test" }])), (e) => e.code === "Hypervisor:DataConnectionOneDomain");
});

// ---- syncs (cut D4): a sync is a capability-lease plan on one of the caller's sources; its builds are the plan's runs
const plan = { id: "clp_1", name: "Plants import", status: "declared", data_source_id: "ds_2", revision: 1, created_at: "2026-09-28T01:00:00Z", updated_at: "2026-09-28T01:00:00Z",
  ontology_ref: "ontology://plants", object_type_id: "plant", subject: "agent://materializer", purpose: "plant catalog", requested_operations: ["read", "transform"], requested_properties: ["plant_id"], ttl_seconds: 900,
  history: [{ revision: 1, op: "created", at: "2026-09-28T01:00:00Z", summary: "CapabilityLease plan declared (nothing minted)" }] };
const strangersPlan = { ...plan, id: "clp_9", name: "Not yours", data_source_id: "ds_4" };
const revoked = { ...plan, id: "clp_3", name: "Withdrawn", status: "revoked" };
const run = (id, status, at, extra = {}) => ({ id, capability_lease_plan_id: "clp_1", status, created_at: at, updated_at: at, history: [{ revision: 1, op: "created", summary: "admitted" }], ...extra });

test("a sync is a lease plan on one of the caller's sources — never another principal's, never a revoked one — with its runs newest first", () => {
  const syncs = DC.callerSyncsOf([plan, strangersPlan, revoked], [run("mrun_a", "cancelled", "2026-09-28T02:00:00Z"), run("mrun_b", "planned", "2026-09-28T03:00:00Z")], [bucket], "org://local");
  assert.deepEqual(syncs.map((y) => y.plan.id), ["clp_1"]);
  assert.equal(syncs[0].rid, DC.extractRidOf("clp_1"));
  assert.match(syncs[0].rid, /^ri\.magritte\.\.extract\.[0-9a-f-]{36}$/u);
  assert.deepEqual(syncs[0].runs.map((r) => r.id), ["mrun_b", "mrun_a"]);
  assert.deepEqual([syncs[0].datasetName, syncs[0].datasetPath, syncs[0].set], ["Plants import objects", "/local/Plants import objects", null], "before any executed run, the dataset holds nothing");
  const held = DC.callerSyncsOf([plan], [run("mrun_c", "executed", "2026-09-28T04:00:00Z", { execution: { materialized_set_ref: "materialized-object-set://s1", object_instances: 3 } })], [bucket]);
  assert.deepEqual(held[0].set, { ref: "materialized-object-set://s1", objects: 3 });
  assert.deepEqual(DC.extractsBySourceOf([mine, bucket], syncs), { [DC.sourceRidOf("ds_1")]: [], [DC.sourceRidOf("ds_2")]: [syncs[0].rid] });
});

test("a run's status is the reference build's: planned waits, a held lease runs, executed succeeds, a refused execute fails, cancelled or released cancels", () => {
  assert.deepEqual(DC.runStatusOf({ status: "planned" }), { build: "RUNNING", job: "WAITING" });
  assert.deepEqual(DC.runStatusOf({ status: "lease_obtained", history: [{ op: "lease_obtained" }] }), { build: "RUNNING", job: "RUNNING" });
  assert.deepEqual(DC.runStatusOf({ status: "lease_obtained", history: [{ op: "lease_obtained" }, { op: "execution_refused" }] }), { build: "FAILED", job: "FAILED" });
  assert.deepEqual(DC.runStatusOf({ status: "executed" }), { build: "SUCCEEDED", job: "SUCCEEDED" });
  assert.deepEqual(DC.runStatusOf({ status: "cancelled" }), { build: "CANCELED", job: "CANCELED" });
  assert.deepEqual(DC.runStatusOf({ status: "lease_released" }), { build: "CANCELED", job: "CANCELED" });
  assert.deepEqual(DC.runStatusOf({ status: "something_new" }), { build: null, job: null }, "an unknown status claims nothing");
});

test("a sync's builds, extract, metadata and versions answer from its plan and runs; a plan with no run has no build (Never ran)", () => {
  const never = DC.callerSyncsOf([plan], [], [bucket]);
  const ds = never[0].datasetRid;
  assert.deepEqual(DC.buildsBulkOf([{ buildFilter: { jobDatasetRids: [ds], branchIds: ["master"] }, limit: 1 }], never), [{ buildDetails: [], buildCount: 0 }]);
  const syncs = DC.callerSyncsOf([plan], [run("mrun_a", "cancelled", "2026-09-28T02:00:00Z", { history: [{ op: "created" }, { op: "cancelled", summary: "MaterializingRun cancelled before any crossing" }] })], [bucket]);
  const [bulk] = DC.buildsBulkOf([{ buildFilter: { filter: { jobDatasetRids: [ds] }, type: "filter" }, limit: 1 }], syncs);
  const b = bulk.buildDetails[0];
  assert.deepEqual([bulk.buildCount, b.buildStatus, b.jobs[0].jobStatus, b.securedProperties.branchId, b.jobs[0].outputDatasets[0].datasetRid], [1, "CANCELED", "CANCELED", "master", ds]);
  assert.equal(b.jobs[0].securedProperties.statusDetails.message, "MaterializingRun cancelled before any crossing");
  assert.deepEqual([b.user, b.userId], [null, null], "who admitted a run is not recorded, so no user is named");
  assert.equal(DC.buildByRidOf(b.buildId, syncs).buildId, b.buildId);
  assert.equal(DC.buildsBulkOf([{ buildFilter: { jobDatasetRids: ["ri.foundry.main.dataset.other"] }, limit: 1 }], syncs)[0].buildCount, 0, "another dataset's builds are not answered");
  const x = DC.extractsBulkOf([syncs[0].rid, "ri.magritte..extract.other"], syncs);
  assert.deepEqual(Object.keys(x), [syncs[0].rid]);
  assert.deepEqual([x[syncs[0].rid].extractName, x[syncs[0].rid].sourceId, x[syncs[0].rid].datasetId, x[syncs[0].rid].extractConfig.sourceAdapter.type], ["Plants import", DC.sourceRidOf("ds_2"), ds, DC.SYNC_ADAPTER]);
  assert.deepEqual(x[syncs[0].rid].extractConfig.sourceAdapter.operations, ["read", "transform"], "the plan's lease shape is the sync's configuration");
  assert.deepEqual(DC.extractsMetadataOf([syncs[0].rid], syncs)[syncs[0].rid], { created: { time: plan.created_at, userId: null }, lastModified: null, displayOptions: null });
  const hist = DC.extractHistoryOf(syncs[0].rid, syncs, { revision: 1, history: plan.history });
  assert.deepEqual(Object.keys(hist.storedExtractHistories), ["1"]);
  assert.equal(hist.storedExtractHistories[1].storedExtract.extractName, "Plants import");
  assert.equal(DC.extractHistoryOf("ri.magritte..extract.other", syncs, null), null);
});

test("a sync's pages answer in the reference's own documents: its name, its source, no health check, no schedule, and a run in progress", () => {
  const syncs = DC.callerSyncsOf([plan], [run("mrun_b", "planned", "2026-09-28T03:00:00Z")], [bucket], "org://local");
  const ctx = { sources: [bucket], syncs };
  const y = syncs[0];
  assert.equal(DC.dataConnectionGraphqlFacts("BatchExtractPageHelperQuery", { extractRid: y.rid }, ctx).extract.extractName, "Plants import");
  assert.equal(DC.dataConnectionGraphqlFacts("BatchExtractPageHelperQuery", { extractRid: "ri.magritte..extract.other" }, ctx).extract, null);
  assert.equal(DC.dataConnectionGraphqlFacts("SourceNameAndTypeQuery", { sourceRid: DC.sourceRidOf("ds_2") }, ctx).source.numberOfExtracts, 1);
  assert.deepEqual(DC.dataConnectionGraphqlFacts("ExtractOverviewQuery", { datasetRid: y.datasetRid, branchName: "master" }, ctx).catalogDataset.branch.healthChecks, []);
  assert.deepEqual(DC.dataConnectionGraphqlFacts("BatchExtractConfigurationPageQuery", { extractRid: y.rid }, ctx).extract.branch.indirectlyRelevantSchedules, []);
  const banner = "query RunningBuildBannerQuery($datasetRid: RID!, $branchId: String!) { runningJobs: jobs(filter: {jobStatuses: [RUNNING]}) { results { build { rid __typename } status __typename } __typename } waitingJobs: jobs(filter: {jobStatuses: [WAITING]}) { results { build { rid __typename } status __typename } __typename } __typename }";
  const answered = answerDocument(banner, DC.dataConnectionGraphqlFacts("RunningBuildBannerQuery", { datasetRid: y.datasetRid, branchId: "master" }, ctx), null, "RunningBuildBannerQuery");
  assert.deepEqual([answered.runningJobs.results.length, answered.waitingJobs.results.map((r) => r.status)], [0, ["WAITING"]], "a planned run waits for its lease");
  const table = DC.dataConnectionGraphqlFacts("BatchExtractsForSourceTableQuery", { sourceRid: DC.sourceRidOf("ds_2"), pageSize: 100 }, ctx);
  assert.deepEqual([table.source.numberOfExtracts, table.source.permissions.canCreateExtract], [1, false], "no sync can be created here yet");
  const row = table.searchMagritteBatchExtracts.values[0].magritteExtract;
  assert.deepEqual([row.extractName, row.dataset.metadata.name, row.dataset.metadata.permissions.canOpenLink, row.branch.jobs.results[0].build.status], ["Plants import", "Plants import objects", false, "RUNNING"]);
  const list = DC.dataConnectionGraphqlFacts("SourcesListQuery", {}, { sources: [mine, bucket], syncs });
  assert.deepEqual(list.sources.values.map((v) => [v.name, v.numberOfExtracts]), [["Orders API", 0], ["Plants bucket", 1]]);
  const res = DC.compassSourceResources([y.datasetRid], [bucket], "org://local", syncs)[y.datasetRid];
  assert.deepEqual([res.name, res.path, res.branches[0].name], ["Plants import objects", "/local/Plants import objects", "master"]);
});

test("a sync's writes are refused by name: Run needs a wallet-authority grant (the approval flow), and create, duplicate, change or delete are not bound", () => {
  const rid = DC.extractRidOf("clp_1");
  const run = DC.syncWriteRefusalOf("POST", `build/trigger/${rid}`);
  assert.deepEqual([run.status, run.code], [409, "Hypervisor:DataConnectionRunNeedsApproval"], "never 403: the app words any 403 as a missing permission");
  assert.match(run.message, /wallet-authority grant/u);
  assert.equal(DC.syncRefusalBodyOf(run).message, run.message, "the app prints a refusal's top-level message");
  assert.equal(DC.syncWriteRefusalOf("POST", "preview/source-adapter").code, "Hypervisor:DataConnectionPreviewNeedsLease", "a preview would read the source");
  assert.equal(DC.syncWriteRefusalOf("DELETE", `build/delete-extract/${rid}`).code, "Hypervisor:DataConnectionSyncWriteNotBound");
  assert.equal(DC.syncWriteRefusalOf("POST", "build/add-extract").code, "Hypervisor:DataConnectionSyncWriteNotBound");
  assert.equal(DC.syncWriteRefusalOf("PUT", `extract-store/extract/${rid}`).code, "Hypervisor:DataConnectionSyncWriteNotBound");
  assert.equal(DC.syncWriteRefusalOf("POST", "extract-store/extract/history"), null, "reading a sync's versions is not a write");
  assert.equal(DC.syncWriteRefusalOf("POST", "extract-store/extracts/bulk"), null);
});

test("changing a source: only its declarer, only a REST source's one domain, never authentication or secrets", () => {
  const theirs = DC.callerSourcesOf([mine, teamProject], "user://me", ["project://team"]);
  assert.deepEqual(theirs.map((x) => x.caller_may_change), [true, false], "a source filed in a visible project is not the caller's to change");
  const rid = DC.sourceRidOf("ds_1");
  assert.deepEqual(DC.authzOperationsOf([rid, DC.sourceRidOf("ds_3")], theirs).resourceToOperationsMap, { [rid]: ["magritte:source-store:update-source-config"], [DC.sourceRidOf("ds_3")]: [] });
  assert.deepEqual(DC.authzOperationsOf([DC.SOURCE_ROOT], theirs, { signedIn: true }).resourceToOperationsMap[DC.SOURCE_ROOT], ["magritte:source-store:add-source"], "a signed-in caller may add a source");
  assert.deepEqual(DC.authzOperationsOf([DC.SOURCE_ROOT], theirs).resourceToOperationsMap[DC.SOURCE_ROOT], [], "an anonymous caller may not");
  assert.equal(DC.dataConnectionGraphqlFacts("SourceEditorQuery", { sourceRid: rid }, { sources: theirs }).source.permissions.canUpdateSourceConfig, true);
  const put = (domains, extra = {}) => ({ patchSourceConfigRequest: { updatedSourceConfig: { type: "webhooks-rest", config: { domains } }, ...extra } });
  assert.deepEqual(DC.updateBodyOf(put([{ domainId: "d", host: "example.com", scheme: "HTTPS" }]), theirs[0]), { endpoint: "https://example.com" });
  assert.deepEqual(DC.updateBodyOf(put([{ host: "example.com", scheme: "HTTPS" }]), { ...theirs[0], endpoint: "https://api.example.test/orders?v=2" }), { endpoint: "https://example.com/orders?v=2" }, "a new host keeps the endpoint's path and query");
  assert.throws(() => DC.updateBodyOf(put([{ host: "example.com", auth: { type: "basic" } }]), theirs[0]), (e) => e.code === "Hypervisor:DataConnectionCredentialNotBound");
  assert.throws(() => DC.updateBodyOf(put([{ host: "" }]), theirs[0]), (e) => e.code === "Hypervisor:DataConnectionDomainInvalid");
  assert.throws(() => DC.updateBodyOf({ patchDescription: {} }, theirs[0]), (e) => e.code === "Hypervisor:DataConnectionUpdateNotBound");
  assert.throws(() => DC.updateBodyOf(put([{ host: "x.test" }]), bucket), (e) => e.code === "Hypervisor:DataConnectionUpdateNotBound");
  const saved = DC.updatedSourceOf({ ...mine, endpoint: "https://example.com" });
  assert.equal(saved.updatedSource.sourceConfig.config.domains[0].host, "example.com");
  assert.deepEqual(saved.updatedSource.mavenCoordinates, { userProvided: [], foundryProvided: [] });
});
