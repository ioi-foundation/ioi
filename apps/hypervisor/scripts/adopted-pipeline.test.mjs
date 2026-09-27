// The adopted Pipeline Builder's landing over DataRecipe families and change sets (adopted-pipeline.mjs).
import test from "node:test";
import assert from "node:assert/strict";
import * as PIPELINE from "./adopted-pipeline.mjs";
import { multipassUsersFor } from "./adopted-automate.mjs";

const OP = "user://00000000-0000-4000-8000-000000000001";
const rev = (family, n, name, at) => ({ revision_ref: `data-recipe://${family}/revision/${n}`, name, admitted_at: at, owner_ref: "org://local" });
const cs = (id, family, status, base, extra = {}) => ({
  change_set_ref: `change://cs_${id}`, title: `title ${id}`, status, author_principal_ref: OP, created_at: "2026-09-27T10:00:00Z",
  subject: { kind: "data_recipe", family_ref: `data-recipe://${family}`, base_revision_ref: base, base_head_ref: base ? "sha256:x" : null },
  drafts: [{ ordinal: 1, body: { name: `draft ${id}` }, author_principal_ref: OP, drafted_at: "2026-09-27T10:00:01Z" }], ...extra,
});

const families = [{ family_ref: "data-recipe://acme.intake", revisions: [rev("acme.intake", 1, "intake", "2026-09-27T09:00:00Z"), rev("acme.intake", 2, "intake v2", "2026-09-27T09:30:00Z")] }];
const sets = [
  cs("aaaaaaaaaaaaaaaa", "acme.intake", "merged", null, { created_at: "2026-09-27T08:59:00Z" }),
  cs("bbbbbbbbbbbbbbbb", "acme.intake", "open", "data-recipe://acme.intake/revision/2"),
  cs("cccccccccccccccc", "acme.claims", "proposed", null, { created_at: "2026-09-27T11:00:00Z" }),
  cs("dddddddddddddddd", "acme.dropped", "abandoned", null),
];

test("a pipeline is a DataRecipe family or a family an open change set would found; a closed founding change set founds nothing", () => {
  const ps = PIPELINE.pipelinesOf(families, sets);
  assert.deepEqual(ps.map((p) => p.familyRef), ["data-recipe://acme.claims", "data-recipe://acme.intake"]);
  const intake = ps.find((p) => p.familyRef === "data-recipe://acme.intake");
  assert.equal(intake.name, "intake v2", "the head revision names the pipeline");
  assert.equal(intake.author, OP, "the change set that founded the family names its author");
  assert.deepEqual(intake.openChangeSets.map((c) => c.change_set_ref), ["change://cs_bbbbbbbbbbbbbbbb"]);
  const claims = ps.find((p) => p.familyRef === "data-recipe://acme.claims");
  assert.equal(claims.head, null);
  assert.equal(claims.name, "draft cccccccccccccccc", "a founding-only pipeline is named by its latest draft");
  assert.match(claims.rid, /^ri\.eddie\.main\.pipeline\.[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
});

test("the landing search filters by text and creator; a project filter matches no DataRecipe", () => {
  const ps = PIPELINE.pipelinesOf(families, sets);
  const rids = (v) => PIPELINE.pipelineFactsRoot("PipelineLandingSearchQuery", v, ps, PIPELINE.uuidOf).searchResourcesV2.results.map((r) => r.resource.rid);
  assert.equal(rids({ text: "", pageSize: 50 }).length, 2);
  assert.deepEqual(rids({ text: "DRAFT C", pageSize: 50 }), [ps[0].rid], "case-insensitive, over the name the landing shows");
  assert.equal(rids({ createdByUserIds: [PIPELINE.uuidOf(OP)], pageSize: 50 }).length, 2);
  assert.equal(rids({ createdByUserIds: [PIPELINE.uuidOf("user://someone-else")], pageSize: 50 }).length, 0);
  assert.equal(rids({ inProjects: ["ri.compass.main.folder.x"], pageSize: 50 }).length, 0);
  const rf = PIPELINE.pipelineFactsRoot("PipelineLandingRecentsAndFavoritesQuery", {}, ps, PIPELINE.uuidOf);
  assert.deepEqual([rf.recents, rf.favorites], [[], []], "recents is a LIST (the app maps it) and no record is kept");
});

test("sandboxes: Main is the admitted head and the only published one; each open change set is a draft sandbox", () => {
  const ps = PIPELINE.pipelinesOf(families, sets);
  const intake = ps.find((p) => p.familyRef === "data-recipe://acme.intake");
  const pub = PIPELINE.pipelineFactsRoot("PublishedSandboxesQuery", { pipelineRid: intake.rid, filter: { publishStatus: ["PUBLISHED"] } }, ps, PIPELINE.uuidOf);
  assert.deepEqual(pub.eddiePipeline.sandboxes.map((s) => s.backingBranchName), ["master"]);
  const all = PIPELINE.pipelineFactsRoot("PublishedSandboxesQuery", { pipelineRid: intake.rid }, ps, PIPELINE.uuidOf);
  assert.deepEqual(all.eddiePipeline.sandboxes.map((s) => s.backingBranchName), ["master", "change://cs_bbbbbbbbbbbbbbbb"]);
  const main = PIPELINE.mainSandboxIdOf(intake.familyRef);
  const draft = PIPELINE.changeSetSandboxIdOf("change://cs_bbbbbbbbbbbbbbbb");
  const { sandboxes } = PIPELINE.sandboxesWithSnapshots([{ pipelineRid: intake.rid, sandboxId: main }, { pipelineRid: intake.rid, sandboxId: draft }, { pipelineRid: intake.rid, sandboxId: "nope" }], ps, PIPELINE.uuidOf);
  assert.equal(sandboxes.length, 2, "an unknown sandbox is left out");
  assert.deepEqual([sandboxes[0].sandbox.name, sandboxes[0].sandbox.isPublished, sandboxes[0].version.message], ["Main", true, "Revision 2"]);
  assert.deepEqual([sandboxes[1].sandbox.name, sandboxes[1].sandbox.isPublished, sandboxes[1].version.message], ["title bbbbbbbbbbbbbbbb", false, "Draft 1"]);
  const claims = ps.find((p) => p.familyRef === "data-recipe://acme.claims");
  const root = PIPELINE.sandboxesWithSnapshots([{ pipelineRid: claims.rid, sandboxId: PIPELINE.mainSandboxIdOf(claims.familyRef) }], ps, PIPELINE.uuidOf).sandboxes[0];
  assert.equal(root.version.message, "Root", "a founding-only pipeline's Main holds no revision");
  const dep = PIPELINE.pipelineFactsRoot("CurrentPipelineDeploymentQuery", { pipelineRid: intake.rid, sandboxId: main }, ps, PIPELINE.uuidOf);
  assert.equal(dep.eddiePipeline.sandbox.currentDeployment, null, "never deployed, never the reference's deployment");
});

test("a recipe's declared outputs are its snapshot's targets, and the landing's output pill resolves each dataset by its contract", () => {
  const recipe = { output_object_model_refs: ["object-model://om_patient"], output_dataset_contract_refs: ["schema://acme/rows/v2"] };
  const targets = PIPELINE.targetsOf(recipe);
  assert.deepEqual(targets.map((t) => [t.target.type, t.target.object?.displayName || t.target.dataset?.datasetRid.startsWith("ri.foundry.main.dataset.")]), [["object", "om_patient"], ["dataset", true]]);
  assert.deepEqual(PIPELINE.targetsOf(null), []);
  const ps = PIPELINE.pipelinesOf([{ family_ref: "data-recipe://acme.rows", revisions: [{ ...recipe, revision_ref: "data-recipe://acme.rows/revision/1", name: "rows", admitted_at: "2026-09-27T09:00:00Z" }] }], []);
  const datasetRid = targets[1].target.dataset.datasetRid;
  const named = PIPELINE.compassOutputDatasets([datasetRid, "ri.foundry.main.dataset.00000000-0000-4000-8000-000000000000"], ps, PIPELINE.uuidOf);
  assert.deepEqual(Object.keys(named), [datasetRid], "a dataset no pipeline of theirs declares is left out");
  assert.equal(named[datasetRid].name, "acme/rows/v2");
});

test("details answer only the caller's pipelines", () => {
  const ps = PIPELINE.pipelinesOf(families, sets);
  const foreign = "ri.eddie.main.pipeline.00000000-0000-4000-8000-000000000000";
  const by = PIPELINE.pipelinesByRids([ps[1].rid, foreign], ps, PIPELINE.uuidOf);
  assert.deepEqual(Object.keys(by.pipelines), [ps[1].rid]);
  assert.equal(by.pipelines[ps[1].rid].attribution.user, PIPELINE.uuidOf(OP));
  assert.equal(PIPELINE.pipelineDetails(foreign, ps, PIPELINE.uuidOf), null);
  assert.equal(PIPELINE.pipelineDetails(ps[0].rid, ps, PIPELINE.uuidOf).pipeline.name, ps[0].name);
});

test("the compass project search answers the caller's projects; any other compass search answers nothing", () => {
  const projects = [{ project_id: "p2", name: "Beta", created_at: "2026-09-01T00:00:00Z" }, { project_id: "p1", name: "Alpha", created_at: "2026-09-02T00:00:00Z" }];
  const folder = (id) => `ri.compass.main.folder.${id}`;
  const req = (text) => ({ query: { includeResources: ["FILE"], filter: { isProjectPreview: true, type: "isProjectPreview" }, text }, limit: 50, offset: 0 });
  const all = PIPELINE.compassSearchAnswer(req(""), projects, folder, PIPELINE.uuidOf, OP);
  assert.deepEqual(all.result.map((r) => r.indexedResource.name), ["Alpha", "Beta"]);
  assert.equal(all.result[0].indexedResource.projectRid, "ri.compass.main.folder.p1");
  assert.deepEqual(PIPELINE.compassSearchAnswer(req("bet"), projects, folder, PIPELINE.uuidOf, OP).result.map((r) => r.indexedResource.name), ["Beta"]);
  assert.deepEqual(PIPELINE.compassSearchAnswer({ query: { text: "" } }, projects, folder, PIPELINE.uuidOf, OP).result, []);
});

test("the multipass user lookup names only principals it was given", () => {
  const users = multipassUsersFor([PIPELINE.uuidOf(OP), PIPELINE.uuidOf("user://stranger")], [{ ref: OP, name: "John Doe", email: "john@ioi.local" }]);
  assert.equal(users.length, 1);
  assert.deepEqual([users[0].username, users[0].attributes["multipass:given-name"][0], users[0].attributes["multipass:email:primary"][0]], ["john@ioi.local", "John", "john@ioi.local"]);
});

test("the editor opens a pipeline read-only: all-information carries Main's head, no compute profile, and no direct push", () => {
  const ps = PIPELINE.pipelinesOf(families, sets);
  const intake = ps.find((p) => p.familyRef === "data-recipe://acme.intake");
  const info = PIPELINE.allInformation(intake.rid, null, ps, PIPELINE.uuidOf);
  assert.equal(info.mainSandbox, PIPELINE.mainSandboxIdOf(intake.familyRef));
  assert.deepEqual([info.sandbox.name, info.version.message], ["Main", "Revision 2"]);
  assert.equal(info.settings.settings.protectionsForPublishedSandboxes.allowDirectPush, false, "only a merged change set moves Main");
  assert.deepEqual(info.availableBackendSettings.computeProfiles, []);
  assert.equal(PIPELINE.allInformation("ri.eddie.main.pipeline.00000000-0000-4000-8000-000000000000", null, ps, PIPELINE.uuidOf), null);
  assert.deepEqual(PIPELINE.allSandboxes(intake.rid, ps, PIPELINE.uuidOf).sandboxes.map((s) => s.name), ["Main", "title bbbbbbbbbbbbbbbb"]);
});

test("the editor's GraphQL facts: the pipeline's resource in no project, its sandbox's backend, no branches; an output dataset resolves by its contract", () => {
  const recipe = { output_dataset_contract_refs: ["schema://acme/rows/v2"], output_object_model_refs: [] };
  const ps = PIPELINE.pipelinesOf([{ family_ref: "data-recipe://acme.rows", revisions: [{ ...recipe, revision_ref: "data-recipe://acme.rows/revision/1", name: "rows", admitted_at: "2026-09-27T09:00:00Z" }] }], []);
  const p = ps[0];
  const root = PIPELINE.pipelineEditorFactsRoot({ pipelineRid: p.rid, sandboxId: PIPELINE.mainSandboxIdOf(p.familyRef) }, ps, PIPELINE.uuidOf);
  assert.deepEqual([root.resourceMetadata.name, root.resourceMetadata.project, root.resourceMetadata.markings], ["rows", null, []]);
  assert.equal(root.eddiePipeline.sandbox.latestVersion.backend, "Spark");
  assert.deepEqual(root.globalBranchDropdownSearchByCreatedAtDescending.values, [], "facts are keyed by the FIELD, not the query's alias");
  assert.equal(PIPELINE.pipelineEditorFactsRoot({ pipelineRid: p.rid, sandboxId: "nope" }, ps, PIPELINE.uuidOf).eddiePipeline.sandbox, null);
  const datasetRid = PIPELINE.targetsOf(recipe)[0].target.dataset.datasetRid;
  const ds = PIPELINE.pipelineEditorFactsRoot({ rid: datasetRid, branch: "master" }, ps, PIPELINE.uuidOf);
  assert.deepEqual([ds.resourceMetadata.name, ds.catalogDataset.backsObjectTypes], ["acme/rows/v2", []]);
  const foreign = PIPELINE.pipelineEditorFactsRoot({ rid: "ri.foundry.main.dataset.00000000-0000-4000-8000-000000000000" }, ps, PIPELINE.uuidOf);
  assert.deepEqual([foreign.resourceMetadata, foreign.catalogDataset], [null, null]);
});

test("Create plans a founding change set: the recipe registry as location, standard batch compute, a family slugged from the name", () => {
  const ps = PIPELINE.pipelinesOf(families, sets);
  const REG = "ri.compass.main.folder.registry";
  const plan = (req, extra = {}) => PIPELINE.createPipelinePlan({ createRequest: { parentFolder: REG, backend: "Spark", ...req }, ...extra }, ps, REG);
  assert.deepEqual(plan({ name: "Claims Normalise (v1)" }), { family: "claims-normalise-v1", title: "Claims Normalise (v1)", draft: { name: "Claims Normalise (v1)" } });
  assert.match(plan({ name: "x", parentFolder: "ri.compass.main.folder.project" }).issue, /recipe registry/u);
  assert.match(plan({ name: "x", backend: "DataFusion" }).issue, /DataFusion/u);
  assert.match(plan({ name: "x", backend: "Flink" }).issue, /streaming/u);
  assert.match(plan({ name: "x", backend: "Databricks" }).issue, /external/u);
  assert.match(plan({ name: "" }).issue, /needs a name/u);
  assert.match(plan({ name: "!!!" }).issue, /letter or digit/u);
  assert.match(plan({ name: "ACME.intake" }).issue, /already exists/u, "a family is identified by its slug");
  assert.match(plan({ name: "fresh" }, { initialDisplay: { initialDisplay: { datasets: [{ rid: "ri.foundry.main.dataset.x" }] } } }).issue, /initial datasets/u);
  assert.deepEqual(PIPELINE.createPipelinePlan({ name: "direct", parentFolder: REG }, ps, REG).family, "direct", "the plain create route's request, backend defaulting to standard");
});

test("Create answers the new pipeline with the founding change set's draft sandbox", () => {
  const cs = { change_set_ref: "change://cs_eeeeeeeeeeeeeeee", title: "Fresh", status: "open", author_principal_ref: OP, created_at: "2026-09-27T12:00:00Z", subject: { kind: "data_recipe", family_ref: "data-recipe://fresh", base_revision_ref: null, base_head_ref: null }, drafts: [{ ordinal: 1, body: { name: "Fresh" }, author_principal_ref: OP, drafted_at: "2026-09-27T12:00:00Z" }] };
  const ps = PIPELINE.pipelinesOf([], [cs]);
  const answer = PIPELINE.createPipelineAnswer("data-recipe://fresh", cs, ps, PIPELINE.uuidOf);
  assert.equal(answer.pipeline.name, "Fresh");
  assert.deepEqual([answer.initialSandbox.id, answer.initialSandbox.isPublished], [PIPELINE.changeSetSandboxIdOf(cs.change_set_ref), false]);
});

test("a fragment on ResourceAncestor applies to a ResourceMetadata (the header breadcrumb's folder openUrl)", async () => {
  const { answerDocument } = await import("./adopted-graphql.mjs");
  const q = "query H($r: RID!) { resourceMetadata(rid: $r) { ancestors { rid name ...A __typename } __typename } } fragment A on ResourceAncestor { rid name ... on ResourceMetadata { openUrl __typename } __typename }";
  const root = { __typename: "Query", resourceMetadata: { __typename: "ResourceMetadata", ancestors: [{ __typename: "ResourceMetadata", rid: "ri.compass.main.folder.p", name: "proj", openUrl: "/projects/p" }] } };
  const out = answerDocument(q, root, null, "H");
  assert.equal(out.resourceMetadata.ancestors[0].openUrl, "/projects/p");
});

test("a fragment on Principal applies to a User (the principal chip's names)", async () => {
  const { answerDocument } = await import("./adopted-graphql.mjs");
  const q = "query UserGroupQuery($id: String!) { principal(id: $id) { _id ...P __typename } } fragment P on Principal { ... on User { username displayName __typename } _id __typename }";
  const out = answerDocument(q, { __typename: "Query", principal: { __typename: "User", _id: "u", username: "john@ioi.local", displayName: "John Doe" } }, null, "UserGroupQuery");
  assert.equal(out.principal.displayName, "John Doe");
});

test("a field selected under two aliases answers each alias its own fact (the History compare view)", async () => {
  const { answerDocument } = await import("./adopted-graphql.mjs");
  const q = "query D { s { a: h(limit: 1) { values { id } } b: h(limit: 2) { values { id } } h { values { id } } } }";
  const out = answerDocument(q, { s: { h: { values: [{ id: "all" }] }, "a:h": { values: [{ id: "latest" }] }, "b:h": { values: [{ id: "picked" }, { id: "prev" }] } } }, null, "D");
  assert.deepEqual([out.s.a.values.map((v) => v.id), out.s.b.values.map((v) => v.id), out.s.h.values.map((v) => v.id)], [["latest"], ["picked", "prev"], ["all"]]);
});

test("History: Main's timeline is the family's revisions and runs, newest first; a queued run claims no status; the current deployment is the latest completed run", () => {
  const runs = [
    { transformation_run_id: "transform://trun_1", data_recipe_revision_ref: "data-recipe://acme.intake/revision/1", execution_status: "completed", admitted_at: "2026-09-27T09:10:00Z" },
    { transformation_run_id: "transform://trun_2", data_recipe_revision_ref: "data-recipe://acme.intake/revision/2", execution_status: "queued", admitted_at: "2026-09-27T09:40:00Z" },
  ];
  const withSucc = [{ ...families[0], runs, revisions: [families[0].revisions[0], { ...families[0].revisions[1], succession: { predecessor_revision_ref: "data-recipe://acme.intake/revision/1" } }] }];
  const merged = { ...sets[0], merge: { resulting_revision_ref: "data-recipe://acme.intake/revision/1", merged_by_principal_ref: OP, draft_ordinal: 1 } };
  const p = PIPELINE.pipelinesOf(withSucc, [merged, sets[1]]).find((x) => x.familyRef === "data-recipe://acme.intake");
  const main = PIPELINE.mainSandboxIdOf(p.familyRef);
  const h = PIPELINE.historyFacts(p, main, { pageSize: 20 }, PIPELINE.uuidOf);
  const v1 = PIPELINE.uuidOf("data-recipe://acme.intake/revision/1");
  const v2 = PIPELINE.uuidOf("data-recipe://acme.intake/revision/2");
  assert.deepEqual(h.eventTimeline.values.map((e) => `${e.__typename}:${e.versionId || e.sandboxVersion.versionId}:${e.status === undefined ? "-" : e.status?.__typename || "null"}`), [
    `EddieSandboxDeployment:${v2}:null`, `EddieSandboxVersion:${v2}:-`, `EddieSandboxDeployment:${v1}:EddieSandboxDeploymentStatus_Succeeded`, `EddieSandboxVersion:${v1}:-`,
  ]);
  const [, rev2, , rev1] = h.eventTimeline.values;
  assert.equal(rev2.previousVersion.versionId, v1);
  assert.equal(rev1.previousVersion, null, "genesis: the app says Branch created");
  assert.equal(rev1.proposal.name, "title aaaaaaaaaaaaaaaa", "the merged change set's revision is a merged-proposal row");
  assert.equal(rev2.proposal, null, "a revision admitted directly is a saved version");
  assert.equal(h.currentDeployment.sandboxVersion.versionId, v1, "the queued run of revision 2 is not currently deployed");
  assert.deepEqual(PIPELINE.historyFacts(p, main, { filter: { eventTypesToInclude: ["VERSION"] }, pageSize: 1 }, PIPELINE.uuidOf).eventTimeline, { __typename: "EddieSandboxEventTimelinePage", values: [h.eventTimeline.values[1]], nextPageToken: "1" });
  assert.deepEqual(h["historyFromLatest:versionHistoryV2"].values.map((v) => v.commitMessage), ["Revision 2"]);
  assert.deepEqual(PIPELINE.historyFacts(p, main, { startVersionId: v2 }, PIPELINE.uuidOf)["historyFromVersion:versionHistoryV2"].values.map((v) => v.commitMessage), ["Revision 2", "Revision 1"]);
  // a change set's timeline is its drafts: draft 1 follows the head it was opened on; no deployment
  const sid = PIPELINE.changeSetSandboxIdOf(sets[1].change_set_ref);
  const c = PIPELINE.historyFacts(p, sid, {}, PIPELINE.uuidOf);
  assert.deepEqual(c.eventTimeline.values.map((e) => [e.__typename, e.previousVersion?.versionId]), [["EddieSandboxVersion", v2]]);
  assert.equal(c.currentDeployment, null);
  assert.deepEqual([c.backingBranchName, c.fallbackBranchNames], [sets[1].change_set_ref, ["master"]]);
  assert.deepEqual(PIPELINE.historyFacts(p, sid, { startVersionId: PIPELINE.draftVersionIdOf(sets[1].change_set_ref, 1) }, PIPELINE.uuidOf)["historyFromVersion:versionHistoryV2"].values.map((v) => v.commitMessage), ["Draft 1", "Revision 2"]);
});
