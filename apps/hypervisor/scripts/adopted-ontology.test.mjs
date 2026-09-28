// The adopted Ontology Manager's pure answers (R-241, Ontology Manager O1): the caller's ODK ontologies as the
// reference app's ontologies, and the GraphQL facts the app's documents are answered over.
import test from "node:test";
import assert from "node:assert/strict";
import { answerDocument } from "./adopted-graphql.mjs";
import * as ONTOLOGY from "./adopted-ontology.mjs";
import { ontologyRidOfFamily } from "./adopted-pipeline.mjs";

const familyOf = (id, owner) => ({ family: `ontology://${owner.replace("org://", "")}/${id}` });
const drafts = [{ id: "ont_1", domain: "Loans", description: "Loan book", canonical_object_model: {
  value_types: [{ id: "money", name: "Money", base: "double" }],
  object_types: [
    { id: "loan", name: "Loan", title_property: "title", properties: [{ id: "loan_id", name: "Loan Id", value_type: "string", required: true }, { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" }] },
    { id: "borrower", name: "Borrower", properties: [{ id: "name", name: "Name", value_type: "string" }] }],
  action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } }];

test("an ODK ontology is one of the app's ontologies, with the Pipeline Builder's rid, its object types and resolved value types", () => {
  const [m] = ONTOLOGY.ontologyModelsOf(drafts, "org://local", familyOf);
  assert.equal(m.rid, ontologyRidOfFamily("ontology://local/ont_1"), "the same rid the builder's picker names");
  assert.deepEqual(m.objectTypes.map((o) => o.id), ["loan", "borrower"]);
  const amount = m.objectTypes[0].properties.find((p) => p.id === "amount");
  assert.equal(amount.base, "double", "a declared value type resolves to its base");
  assert.equal(m.objectTypes[0].titleRid, m.objectTypes[0].properties.find((p) => p.id === "title").rid);
  assert.equal(m.objectTypes[1].titleRid, m.objectTypes[1].properties[0].rid, "no title property: the first property");
  assert.match(m.actionTypes[0].rid, /^ri\.actions\.main\.action-type\./u);
  assert.deepEqual(ONTOLOGY.summaryOf(m).objectTypes.visibleObjectTypes, 2);
  assert.deepEqual(ONTOLOGY.summaryOf(null).actionTypes.visibleEntities, 0);
});

test("the list queries answer the ontology's rids, honoring exclusions and filters; nothing is invented for an unknown ontology", () => {
  const models = ONTOLOGY.ontologyModelsOf(drafts, "org://local", familyOf);
  const rid = models[0].rid;
  const q = "query ObjectTypesListQuery($ontologyRid: RID!) { objectTypesV2(ontologyRids: [$ontologyRid]) { totalNumberOfResults values { objectType { rid __typename } __typename } __typename } __typename }";
  const all = answerDocument(q, ONTOLOGY.ontologyGraphqlFacts("ObjectTypesListQuery", { ontologyRid: rid }, { models }), null, "ObjectTypesListQuery");
  assert.equal(all.objectTypesV2.totalNumberOfResults, 2);
  const excluded = ONTOLOGY.ontologyGraphqlFacts("ObjectTypesListQuery", { ontologyRid: rid, excludedObjectTypeRids: [models[0].objectTypes[0].rid] }, { models });
  assert.equal(excluded.objectTypesV2.totalNumberOfResults, 1);
  const unknown = ONTOLOGY.ontologyGraphqlFacts("ObjectTypesListQuery", { ontologyRid: "ri.ontology.main.ontology.00000000-0000-0000-0000-000000000000" }, { models });
  assert.equal(unknown.objectTypesV2.totalNumberOfResults, 0, "the platform default ontology is not the Hypervisor's");
  assert.equal(ONTOLOGY.ontologyGraphqlFacts("ActionTypesListQuery", { ontologyRid: rid }, { models }).actionTypes.totalNumberOfResults, 1);
  assert.deepEqual(ONTOLOGY.ontologyGraphqlFacts("LoadFavoriteObjectTypeRidsQuery", {}, { models }).favorites, []);
  assert.equal(ONTOLOGY.ontologyGraphqlFacts("IsCurrentBranchProtectedQuery", { ontologyRid: rid }, { models }).ontology.namespace.mainGlobalBranchConfigurationV2.isGlobalBranchProtected, false);
  assert.deepEqual(ONTOLOGY.ontologyGraphqlFacts("RecentlyModifiedObjectTypesQueryOnDefault", { ontologyRid: rid }, { models }).ontology.defaultBranch.history.values, [], "per-revision affected types are not recorded, so none is claimed");
});

test("the Ontology Manager offers no write it would refuse", () => {
  assert.equal(Object.values(ONTOLOGY.ONTOLOGY_PERMISSIONS).every((v) => v === false), true);
  assert.equal(ONTOLOGY.userSettingsOf("ri.x").proposals.enabledStatus.type, "disabled");
});

test("History lists each revision with its recorded changes and its receipt's author; the creation is not a change the app shows", () => {
  const revised = [{ ...drafts[0], revision: 2, history: [
    { revision: 1, op: "created", at: "2026-09-27T01:00:00Z", summary: "DomainOntology draft created", receipt_ref: "r1", affected: { object_types: { loan: "CREATED", borrower: "CREATED" } } },
    { revision: 2, op: "patched", at: "2026-09-27T02:00:00Z", summary: "patched: canonical_object_model", receipt_ref: "r2", affected: { object_types: { borrower: "DELETED", branch: "CREATED" }, action_types: { approve: "UPDATED" } } },
  ] }];
  const [m] = ONTOLOGY.ontologyModelsOf(revised, "org://local", familyOf);
  const h = ONTOLOGY.modificationHistoryOf(m, 100, (ref) => (ref === "r2" ? "user-2" : null));
  assert.deepEqual(h.modificationPageItems.map((i) => i.description), ["patched: canonical_object_model", "DomainOntology draft created"], "newest first");
  const patched = h.modificationPageItems[0];
  assert.equal(patched.attribution.author, "user-2");
  assert.equal(patched.previousOntologyVersion, ONTOLOGY.draftVersionOf("ont_1", 1));
  assert.deepEqual(Object.values(patched.summary.affectedObjectTypes).sort(), ["CREATED", "DELETED"], "a deleted type keeps its rid");
  assert.deepEqual(Object.values(patched.summary.affectedActionTypes), ["UPDATED"]);
  assert.equal(h.modificationPageItems[1].previousOntologyVersion, null);
  const legacy = ONTOLOGY.modificationHistoryOf(ONTOLOGY.ontologyModelsOf([{ ...drafts[0], revision: 2, history: [{ revision: 2, op: "patched", summary: "x" }] }], "org://local", familyOf)[0]);
  assert.deepEqual(legacy.modificationPageItems[0].summary.affectedObjectTypes, {}, "an entry recorded before changes were kept claims none");
});
