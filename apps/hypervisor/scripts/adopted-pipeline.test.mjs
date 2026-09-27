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
