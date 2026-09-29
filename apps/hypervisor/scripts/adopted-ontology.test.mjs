// The adopted Ontology Manager's pure answers (R-241, Ontology Manager O1): the caller's ODK ontologies as the
// reference app's ontologies, and the GraphQL facts the app's documents are answered over.
import test from "node:test";
import assert from "node:assert/strict";
import { answerDocument } from "./adopted-graphql.mjs";
import * as ONTOLOGY from "./adopted-ontology.mjs";
import { ontologyRidOfFamily } from "./adopted-pipeline.mjs";
import { principalUserId as principalUserIdOf } from "./adopted-automate.mjs";
import { syncDatasetRidOf } from "./adopted-data-connection.mjs";

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

test("what the pages offer follows the daemon's reading of the caller (caller_may_change): its owner edits types and creates object, link and action types; anyone else edits and creates nothing", () => {
  const withLink = (flag) => [{ ...drafts[0], ...(flag === undefined ? {} : { caller_may_change: flag }), canonical_object_model: { ...drafts[0].canonical_object_model, link_types: [{ id: "held_by", name: "Held by", from: "loan", to: "borrower", cardinality: "one_to_many" }] } }];
  for (const [flag, may] of [[true, true], [false, false], [undefined, false], ["yes", false]]) {
    const models = ONTOLOGY.ontologyModelsOf(withLink(flag), "org://local", familyOf);
    const [m] = models;
    assert.equal(m.mayChange, may, `caller_may_change ${flag} → ${may} (only a daemon true grants)`);
    const ot = ONTOLOGY.objectTypePermissionsOf({ objectTypeRids: [m.objectTypes[0].rid] }, models).objectTypePermissions[m.objectTypes[0].rid];
    assert.deepEqual([ot.canView, ot.canEdit, ot.canDelete, ot.canAddDatasources, ot.canUpdateRoles], [true, may, false, false, false], "deleting, datasources and roles are never offered");
    assert.equal(ONTOLOGY.linkTypePermissionsOf({ linkTypeRids: [m.linkTypes[0].rid] }, models).linkTypePermissions[m.linkTypes[0].rid].canEdit, may);
    assert.equal(ONTOLOGY.actionTypePermissionsOf({ actionTypeRids: [m.actionTypes[0].rid] }, models).actionTypePermissions[m.actionTypes[0].rid].canEdit, may);
    const p = ONTOLOGY.ontologyPermissionsOf(m);
    assert.deepEqual([p.canCreateObjectTypes, p.canCreateLinkTypes, p.canCreateActionTypes], [may, may, may]);
    assert.deepEqual([p.canCreateSharedPropertyTypes, p.canCreateTypeGroups, p.canCreateInterfaceTypes, p.canCreateRuleSets, p.canCreateWorkflows, p.canUpdateOntology, p.canDeleteOntology], [false, false, false, false, false, false, false], "what the model keeps none of, and the ontology's settings and deletion, are never offered");
  }
  assert.equal(Object.values(ONTOLOGY.ontologyPermissionsOf(null)).every((v) => v === false), true, "an ontology that is not the caller's offers nothing");
});

test("an edit's save is refused by name and writes nothing; any other write path is not caught here", () => {
  const rid = "ri.ontology.main.ontology.00000000-0000-0000-0000-00000000000a";
  // (v2/modify — the Review changes save — is answered by ontologySaveStepOf since cut O8: a backed type's edit becomes the daemon's
  // ODK patch, and everything else in it is refused by name there)
  assert.equal(ONTOLOGY.ontologySaveRefusalOf("POST", "/ontology-metadata/api/ontology/v2/modify"), null);
  for (const path of ["/ontology-metadata/api/ontology/ontology/modify", `/ontology-metadata/api/ontology/approvals/experimental/ontology/${rid}/modifyBranch`]) {
    const refusal = ONTOLOGY.ontologySaveRefusalOf("POST", path);
    assert.equal(refusal?.code, "Hypervisor:OntologyEditNotBound", path);
    assert.equal(ONTOLOGY.proposalRefusalBodyOf(refusal).errorName, "Hypervisor:OntologyEditNotBound");
    assert.match(ONTOLOGY.proposalRefusalBodyOf(refusal).parameters.message, /Nothing was changed\.$/u);
  }
  assert.equal(ONTOLOGY.ontologySaveRefusalOf("GET", "/ontology-metadata/api/ontology/v2/modify"), null);
  assert.equal(ONTOLOGY.ontologySaveRefusalOf("POST", "/ontology-metadata/api/ontology/v2/modify/extra"), null);
  assert.equal(ONTOLOGY.ontologySaveRefusalOf("POST", "/ontology-metadata/api/ontology/ontology/bulkLoadEntities"), null);
});

test("the Ontology Manager's page names no object view editor (the Hypervisor keeps no object views); nothing else in its environment changes", () => {
  const escaped = "{&quot;applicationRoutes&quot;:{&quot;hubble&quot;:&quot;/workspace/hubble&quot;,&quot;object-view-editor&quot;:&quot;/workspace/object-view-editor&quot;,&quot;workshop-app&quot;:&quot;/workspace/module&quot;}}";
  assert.equal(ONTOLOGY.ontologyPageOf(escaped), "{&quot;applicationRoutes&quot;:{&quot;hubble&quot;:&quot;/workspace/hubble&quot;,&quot;workshop-app&quot;:&quot;/workspace/module&quot;}}");
  const last = "{&quot;hubble&quot;:&quot;/workspace/hubble&quot;,&quot;object-view-editor&quot;:&quot;/x&quot;}";
  assert.equal(ONTOLOGY.ontologyPageOf(last), "{&quot;hubble&quot;:&quot;/workspace/hubble&quot;}", "the last entry leaves valid JSON");
  assert.deepEqual(JSON.parse(ONTOLOGY.ontologyPageOf('{"a":"/a","object-view-editor":"/o","b":"/b"}')), { a: "/a", b: "/b" });
  assert.equal(ONTOLOGY.ontologyPageOf("<html>no routes</html>"), "<html>no routes</html>");
});

test("the migration assistant finds nothing to move: the caller's object and action types, none in a project, none migratable by anyone; no shared properties or interfaces", () => {
  const models = ONTOLOGY.ontologyModelsOf([{ ...drafts[0], caller_may_change: true }], "org://local", familyOf);
  const rid = models[0].rid;
  const ctx = { models, owner: "org://local" };
  const ots = ONTOLOGY.ontologyGraphqlFacts("ObjectTypesAndLinkTypesWithDatasourcesQuery", { ontologyRid: rid }, ctx).ontology.objectTypesV2;
  assert.equal(ots.totalNumberOfResults, 2);
  assert.deepEqual(ots.values.map((v) => [v.objectType.permissions.canEdit, v.objectType.permissions.canUpdatePermissions, v.objectType.metadata.project, v.objectType.latest.dataSources.length]), [[true, false, null, 0], [true, false, null, 0]]);
  const ats = ONTOLOGY.ontologyGraphqlFacts("ActionTypesRecommendationsQuery", { ontologyRid: rid }, ctx).ontology.actionTypes;
  assert.deepEqual(ats.values.map((v) => [v.actionType.permissions.canUpdatePermissions, v.affectedObjectTypes.map((o) => o.rid)]), [[false, [models[0].objectTypes[0].rid]]]);
  assert.equal(ONTOLOGY.ontologyGraphqlFacts("SharedPropertiesRecommendationsQuery", { ontologyRid: rid }, ctx).ontology.sharedProperties.totalNumberOfResults, 0);
  assert.equal(ONTOLOGY.ontologyGraphqlFacts("InterfacesRecommendationsQuery", { ontologyRid: rid }, ctx).ontology.interfaces.totalNumberOfResults, 0);
  assert.equal(ONTOLOGY.ontologyGraphqlFacts("ActionTypesRecommendationsQuery", { ontologyRid: "ri.ontology.main.ontology.00000000-0000-0000-0000-000000000000" }, ctx).ontology, null, "another ontology is not answered");
  // Review changes' validation reads: the caller's one organization marking, and no entity sits in a protected project
  const marks = ONTOLOGY.ontologyGraphqlFacts("GetAllMarkingPermissions", {}, ctx);
  assert.deepEqual([marks.markingCategories, marks.organizations.map((o) => o.marking.permissions.canUse)], [[], [true]]);
  assert.deepEqual(ONTOLOGY.ontologyGraphqlFacts("GetAllMarkingPermissions", {}, { models }).organizations, [], "signed out: no organization");
  const prot = ONTOLOGY.ontologyGraphqlFacts("IsResourceBranchProtectedByRidQuery", { rid: models[0].objectTypes[0].rid }, ctx).resourceMetadata;
  assert.deepEqual([prot.isProtected, prot.projectRid], [false, null]);
  assert.equal(ONTOLOGY.ontologyGraphqlFacts("IsResourceBranchProtectedByRidQuery", { rid: "ri.ontology.main.object-type.x" }, ctx).resourceMetadata, null);
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

test("an ODK link keeps its cardinality: one-to-one and one-to-many are the reference's one-to-many with a hint, many-to-many stays many-to-many; no join property is invented", () => {
  const withLinks = [{ ...drafts[0], canonical_object_model: { ...drafts[0].canonical_object_model, link_types: [
    { id: "held_by", name: "Held by", from: "loan", to: "borrower", cardinality: "one_to_many" },
    { id: "co", name: "Co-borrows", from: "borrower", to: "loan", cardinality: "many_to_many" },
    { id: "ghost", name: "Ghost", from: "loan", to: "nowhere", cardinality: "one_to_one" }] } }];
  const models = ONTOLOGY.ontologyModelsOf(withLinks, "org://local", familyOf);
  const [m] = models;
  const [held, co, ghost] = m.linkTypes.map((l) => ONTOLOGY.linkTypeOf(m, l));
  assert.equal(held.definition.type, "oneToMany");
  assert.equal(held.definition.oneToMany.cardinalityHint, "ONE_TO_MANY");
  assert.equal(held.definition.oneToMany.objectTypeRidOneSide, m.objectTypes[0].rid, "the link's from type is the one side");
  assert.deepEqual(held.definition.oneToMany.oneSidePrimaryKeyToManySidePropertyMapping, {}, "an ODK link names no joining property");
  assert.equal(co.definition.type, "manyToMany");
  assert.equal(ghost, null, "a link whose endpoint does not resolve is not offered");
  const bulk = ONTOLOGY.bulkLoadEntitiesOf({ linkTypes: [{ identifier: { linkTypeId: "held_by" } }, { identifier: { linkTypeRid: m.linkTypes[1].rid } }] }, models);
  assert.deepEqual(bulk.linkTypes.map((e) => e.linkType.id), ["held_by", "co"], "by id (a link's page) and by rid");
  assert.deepEqual(Object.keys(ONTOLOGY.linkTypePermissionsOf({ linkTypeRids: [m.linkTypes[0].rid, "ri.ontology.main.relation.x"] }, models).linkTypePermissions), [m.linkTypes[0].rid]);
});

test("what a type has nowhere to live answers none for the caller's types only: no index pipeline, datasource, object view, policy or role grant", () => {
  const models = ONTOLOGY.ontologyModelsOf(drafts, "org://local", familyOf);
  const loan = models[0].objectTypes[0].rid, stranger = "ri.ontology.main.object-type.00000000-0000-0000-0000-000000000001";
  assert.equal(ONTOLOGY.objectTypeFunnelStatusOf({ objectType: loan }, models).activePipeline, null, "indexed by no pipeline");
  assert.equal(ONTOLOGY.objectTypeFunnelStatusOf({ objectType: stranger }, models), null, "another type is not answered (it stays fenced)");
  assert.deepEqual(ONTOLOGY.datasourcesOf({ objectTypes: { [loan]: "v", [stranger]: "v" } }, models).objectTypes, { [loan]: [] });
  assert.deepEqual(ONTOLOGY.objectViewsOf({ objectTypes: [{ rid: loan }, { rid: stranger }] }, models).views.map((v) => v.resolved.views), [[]]);
  assert.deepEqual(ONTOLOGY.objectTypePoliciesOf({ objectTypes: [{ rid: loan }] }, models).policies[0].resolved.policies, { row: [], property: {} });
  assert.deepEqual(ONTOLOGY.compassRolesOf({ rids: [loan, stranger] }, models).resourceRolesResultMap[loan].grants, []);
  assert.equal(ONTOLOGY.compassRolesOf({ rids: [stranger] }, models).resourceRolesResultMap[stranger], undefined);
  assert.equal(ONTOLOGY.apiNameOfOntology(models[0]), "ont-1", "the family's name, lowercase and hyphenated");
  const page = ONTOLOGY.allObjectTypesOf(models[0], { pageSizeLimit: 1 });
  assert.equal(page.objectTypes[0].objectType.rid, loan, "each type in its load envelope");
  assert.equal(page.nextPageToken, "1");
  assert.equal(ONTOLOGY.allActionTypesOf(models[0], {}).actionTypes[0].metadata.rid, models[0].actionTypes[0].rid, "each action type itself");
});

// ---- Proposals (cut O6): the caller's ODK ontology proposals as the reference's ontology proposals
const OWNER = "org://local", ME = "user://me";
const propDraft = { ...drafts[0], revision: 2, history: [{ revision: 1, op: "created" }, { revision: 2, op: "patched", affected: { object_types: { borrower: "UPDATED" } } }] };
const describedLoan = { ...propDraft.canonical_object_model, object_types: propDraft.canonical_object_model.object_types.map((o) => (o.id === "loan" ? { ...o, description: "A loan on the book" } : o)) };
const proposals = [
  { id: "ontp_open", ontology_id: "ont_1", based_on_revision: 2, title: "Describe the loan type", rationale: "It needs one", changes: { canonical_object_model: describedLoan }, status: "open", proposed_by: ME, created_at: "2026-09-28T10:00:00Z", caller_may_apply: true, caller_may_withdraw: true },
  { id: "ontp_stale", ontology_id: "ont_1", based_on_revision: 1, title: "Old idea", changes: { description: "Loans and more" }, status: "open", proposed_by: "user://other", created_at: "2026-09-28T09:00:00Z" },
  { id: "ontp_applied", ontology_id: "ont_1", based_on_revision: 1, title: "Borrower wording", changes: { canonical_object_model: propDraft.canonical_object_model }, status: "applied", proposed_by: ME, created_at: "2026-09-28T08:00:00Z", applied: { applied_by: ME, applied_at: "2026-09-28T08:30:00Z", resulting_revision: 2 } },
  { id: "ontp_withdrawn", ontology_id: "ont_1", based_on_revision: 2, title: "Never mind", changes: { domain: "Lending" }, status: "withdrawn", proposed_by: ME, created_at: "2026-09-28T07:00:00Z", withdrawn: { withdrawn_by: ME, withdrawn_at: "2026-09-28T07:10:00Z", reason: "" } },
  { id: "ontp_elsewhere", ontology_id: "ont_not_mine", based_on_revision: 1, title: "Someone else's", changes: { domain: "X" }, status: "open", proposed_by: ME, created_at: "2026-09-28T11:00:00Z" },
];

test("a proposal on the caller's ontology is one of the Proposals section's requests: open is In review, applied is Merged, withdrawn is Closed; another ontology's is not listed", () => {
  const models = ONTOLOGY.ontologyModelsOf([propDraft], OWNER, familyOf);
  const rows = ONTOLOGY.proposalsOf(proposals, [propDraft], models);
  assert.deepEqual(rows.map((r) => [r.id, r.status]), [["ontp_open", "PENDING_APPROVAL"], ["ontp_stale", "PENDING_APPROVAL"], ["ontp_applied", "APPROVED_AND_COMPLETED"], ["ontp_withdrawn", "CLOSED"]]);
  const open = rows[0], applied = rows[2];
  assert.deepEqual(open.affected, { object_types: { loan: "UPDATED" } }, "an open proposal's changes are read against the revision it was made on");
  assert.deepEqual(applied.affected, { object_types: { borrower: "UPDATED" } }, "an applied proposal's changes are the ontology's own history entry for the revision it produced");
  assert.equal(rows[1].stale, true, "the ontology moved on since the proposal was made");
  assert.equal(open.proposed.objectTypes.find((o) => o.id === "loan").description, "A loan on the book", "the ontology as the proposal would leave it");
  assert.equal(open.proposed.objectTypes[0].rid, models[0].objectTypes[0].rid, "at the same entity rids");
  assert.deepEqual(ONTOLOGY.proposalTaskIdsOf(open), [models[0].objectTypes[0].rid], "one review task per entity it touches");
  assert.deepEqual(ONTOLOGY.proposalTaskIdsOf(rows[3]), [models[0].rid], "a change to the ontology's own fields is reviewed as the ontology");
});

test("the Proposals section's search honors every filter it sends, and one it does not know matches nothing", () => {
  const models = ONTOLOGY.ontologyModelsOf([propDraft], OWNER, familyOf);
  const rows = ONTOLOGY.proposalsOf(proposals, [propDraft], models);
  const base = [{ type: "customIndexedData", customIndexedData: { key: "ONTOLOGY_RID", values: [models[0].rid] } }, { type: "taskType", taskType: { taskTypes: ["ontology-metadata:approvals-v2"] } }, { type: "notTitle", notTitle: { contains: "ri.eddie.main.pipeline" } }];
  const titles = (filters) => ONTOLOGY.proposalSearchOf({ filters, sort: { order: "DESC" } }, rows).requests.map((r) => r.title);
  assert.deepEqual(titles([...base, { type: "status", status: { statuses: ["INITIALIZING", "PENDING_APPROVAL", "APPROVED", "INVOKING"] } }]), ["Describe the loan type", "Old idea"]);
  assert.deepEqual(titles([...base, { type: "status", status: { statuses: ["APPROVED_AND_COMPLETED"] } }]), ["Borrower wording"]);
  assert.deepEqual(titles([...base, { type: "status", status: { statuses: ["CLOSED"] } }]), ["Never mind"]);
  assert.equal(titles([...base, { type: "createdBy", createdBy: { userIds: [principalUserIdOf(ME)] } }]).length, 3, "Your proposals: what the caller proposed");
  assert.deepEqual(titles([{ type: "customIndexedData", customIndexedData: { key: "ONTOLOGY_RID", values: ["ri.ontology.main.ontology.00000000-0000-0000-0000-000000000000"] } }]), [], "the platform default ontology holds none");
  assert.deepEqual(titles([{ type: "taskType", taskType: { taskTypes: ["compass:request-access-to-resource"] } }]), [], "another request type is not a proposal");
  assert.deepEqual(titles([{ type: "someFacetNobodyKnows" }]), [], "an unknown filter matches nothing");
  const row = ONTOLOGY.proposalSearchOf({ filters: base }, rows).requests[0];
  assert.equal(row.taskType, "ontology-metadata:approvals-v2");
  assert.deepEqual(row.customIndexedData.ONTOLOGY_RID, [models[0].rid]);
});

test("a proposal's page reads its record: title, rationale, status, one review task per entity, and who may decide it", () => {
  const models = ONTOLOGY.ontologyModelsOf([propDraft], OWNER, familyOf);
  const rows = ONTOLOGY.proposalsOf(proposals, [propDraft], models);
  const q = "query ProposalDetailQuery($approvalTaskId: RID!) { approvalRequest(rid: $approvalTaskId) { status __typename ... on OntologyChangeProposal { rid title description invokeWhenReady branch { rid globalBranch { rid } } latestVersion { subRequests { id status permissions { canFullyApprove } reviews { reviewType } } } } } }";
  const ask = (r, principalRef) => answerDocument(q, ONTOLOGY.proposalGraphqlFacts("ProposalDetailQuery", { approvalTaskId: r.rid }, { rows, principalRef }), null, "ProposalDetailQuery").approvalRequest;
  const open = ask(rows[0], ME);
  assert.equal(open.__typename, "OntologyChangeProposal");
  assert.deepEqual([open.title, open.description, open.status], ["Describe the loan type", "It needs one", "PENDING_APPROVAL"]);
  assert.equal(open.branch.globalBranch, null, "it names no Foundry branch");
  assert.equal(open.invokeWhenReady, true, "approving its review is the apply: it merges when approved");
  assert.deepEqual(open.latestVersion.subRequests.map((s) => [s.id, s.permissions.canFullyApprove]), [[models[0].objectTypes[0].rid, true]], "a caller the daemon reads as one who may apply it may apply an open proposal");
  assert.equal(ask(rows[0], null).latestVersion.subRequests[0].permissions.canFullyApprove, false, "signed out, nobody may");
  // who may apply is the daemon's reading of the caller (caller_may_apply: the ontology's owner or an org admin), never "signed in"
  const [notMine] = ONTOLOGY.proposalsOf([{ ...proposals[0], caller_may_apply: false, caller_may_withdraw: true }], [propDraft], models);
  assert.equal(answerDocument(q, ONTOLOGY.proposalGraphqlFacts("ProposalDetailQuery", { approvalTaskId: notMine.rid }, { rows: [notMine], principalRef: ME }), null, "ProposalDetailQuery").approvalRequest.latestVersion.subRequests[0].permissions.canFullyApprove,
    false, "a caller the daemon would refuse is offered no Approve");
  assert.equal(ask(rows[2], ME).latestVersion.subRequests[0].reviews[0].reviewType, "APPROVE", "applied: approved by whoever applied it");
  assert.deepEqual(ask(rows[3], ME).latestVersion.subRequests[0].reviews, [], "withdrawn: closed, never rejected");
  assert.equal(ONTOLOGY.proposalGraphqlFacts("ProposalDetailQuery", { approvalTaskId: "ri.approvals.main.task-request.x" }, { rows }).approvalRequest, null);
  const branch = ONTOLOGY.branchWithProposalOf(rows[0]);
  assert.deepEqual(branch.ontologyBranchModificationData.affectedObjectTypes, { [models[0].objectTypes[0].rid]: { modificationType: "UPDATED" } });
  assert.equal(branch.latestOntologyVersion, rows[0].proposed.version);
  assert.equal(ONTOLOGY.proposalBranchHistoryOf(rows[0]).modificationPageItems[0].summary.affectedObjectTypes[models[0].objectTypes[0].rid], "UPDATED");
});

test("a proposal's entities are read at its version from the ontology as it would leave it; the revision it was made on, once gone, is not invented", () => {
  const models = ONTOLOGY.ontologyModelsOf([propDraft], OWNER, familyOf);
  const rows = ONTOLOGY.proposalsOf(proposals, [propDraft], models);
  const loanRid = models[0].objectTypes[0].rid;
  const at = (v) => ({ identifier: { objectTypeRid: loanRid, type: "objectTypeRid" }, versionReference: { ontologyVersion: v, type: "ontologyVersion" } });
  const req = { objectTypes: [at(rows[0].proposed.version), at(rows[0].baseVersion)] };
  assert.equal(ONTOLOGY.asksProposalVersion(req, rows), true);
  const out = ONTOLOGY.bulkLoadEntitiesAt(req, models, rows);
  assert.deepEqual(out.objectTypes.map((e) => e.objectType.displayMetadata.description), ["A loan on the book", ""], "proposed, then as it stands");
  const lost = ONTOLOGY.bulkLoadEntitiesAt({ objectTypes: [at(rows[1].baseVersion)] }, models, rows);
  assert.deepEqual(lost.objectTypes, [], "revision 1 is not kept once the ontology moved on");
  assert.equal(ONTOLOGY.asksProposalVersion({ objectTypes: [at(models[0].version)] }, rows), false, "the ontology's own version is answered as before");
});

test("a proposal's decisions: approving or merging is the daemon's apply, closing its withdraw; the rest is refused by name", () => {
  const models = ONTOLOGY.ontologyModelsOf([propDraft], OWNER, familyOf);
  const rows = ONTOLOGY.proposalsOf(proposals, [propDraft], models);
  const step = (name, row, v = {}, who = ME) => ONTOLOGY.proposalMutationStepOf(name, row, v, who);
  assert.equal(step("ReviewApprovalSubRequests", rows[0], { reviewType: "APPROVE" }).daemon.route, "/v1/hypervisor/odk/ontology-proposals/ontp_open/apply");
  assert.equal(step("ReviewSubRequests", rows[0], { reviewType: "APPROVE" }).daemon.route, "/v1/hypervisor/odk/ontology-proposals/ontp_open/apply");
  assert.equal(step("InvokeApprovalRequest", rows[0]).daemon.route, "/v1/hypervisor/odk/ontology-proposals/ontp_open/apply");
  assert.equal(step("ReviewApprovalSubRequests", rows[1], { reviewType: "APPROVE" }).daemon.method, "POST", "a stale proposal goes to the daemon, which refuses it by name");
  assert.equal(step("CloseProposal", rows[0]).daemon.route, "/v1/hypervisor/odk/ontology-proposals/ontp_open/withdraw");
  assert.equal(step("ReviewSubRequests", rows[0], { reviewType: "DISAPPROVE" }).refusal.code, "Hypervisor:OntologyProposalRejectionNotKept");
  assert.equal(step("CloseProposal", rows[2]).refusal.code, "Hypervisor:OntologyProposalDecided");
  assert.equal(step("InvokeApprovalRequest", rows[3]).refusal.code, "Hypervisor:OntologyProposalDecided");
  assert.equal(step("UpdateReviewersMutation", rows[0]).refusal.code, "Hypervisor:OntologyProposalReviewersNotKept");
  assert.equal(step("UpdateProposalTitle", rows[0]).refusal.code, "Hypervisor:OntologyProposalNotEditable");
  assert.equal(step("CreateFoundryBranchMutationV2WithRoleGrants", null).refusal.code, "Hypervisor:OntologyBranchNotKept");
  assert.equal(step("ResolveCombinedBranchRidBranchQuery", rows[0]).refusal.code, "Hypervisor:OntologyBranchNotKept");
  assert.equal(step("ReviewApprovalSubRequests", rows[0], { reviewType: "APPROVE" }, null).refusal.code, "Hypervisor:OntologyProposalSignInRequired");
  assert.equal(step("CloseProposal", null).refusal.code, "Hypervisor:OntologyProposalNotFound");
});

// ---- cut O8: a type backed by its materialized object sets, its objects read by object set, and a backed type's save --------
const O8_OWNER = "org://local";
const o8Draft = { ...drafts[0], ref: "ontology://ont_1", revision: 2, caller_may_change: true, history: [{ revision: 1, op: "created" }, { revision: 2, op: "patched", affected: { object_types: { loan: "UPDATED" } } }] };
const o8Set = (id, planRef, at, objects, extra = {}) => ({ id, ref: `materialized-object-set://${id}`, ontology_ref: "ontology://ont_1", object_type_id: "loan", capability_lease_plan_ref: planRef,
  materializing_run_ref: `materializing-run://run_${id}`, ontology_projection_id: "proj_1", registered_at: at, objects, ...extra });
const o8Obj = (key, title, amount) => ({ object_key: key, title, object_type_id: "loan", properties: { loan_id: key, title, amount }, provenance: { mapped_from: { loan_id: "id", title: "disp", amount: "amt" } } });
const o8Sets = [
  o8Set("s1", "capability-lease-plan://clp_1", "2026-09-29T10:00:00Z", [o8Obj("L-1", "First Loan", 1250.5), o8Obj("L-2", "Second Loan", 90000)]),
  // a later run of the same plan: its newest set is the datasource's contents
  o8Set("s2", "capability-lease-plan://clp_1", "2026-09-29T11:00:00Z", [o8Obj("L-1", "First Loan", 1250.5), o8Obj("L-2", "Second Loan", 90000), o8Obj("L-3", "Third Loan", 42)]),
  // a set of another ontology's type: it backs nothing here
  { ...o8Set("s3", "capability-lease-plan://clp_2", "2026-09-29T12:00:00Z", [o8Obj("X", "x", 1)]), ontology_ref: "ontology://ont_other" },
];
const o8Models = (sets = o8Sets) => ONTOLOGY.ontologyModelsOf([o8Draft], O8_OWNER, familyOf, sets);

test("O8: a type is backed by the materialized sets of its ontology and type — one datasource per lease plan (its sync's dataset), its newest set the contents; an unmaterialized type has none", () => {
  const [m] = o8Models();
  const loan = m.objectTypes.find((o) => o.id === "loan"), borrower = m.objectTypes.find((o) => o.id === "borrower");
  assert.equal(loan.backing.datasources.length, 1, "two runs of one plan are one datasource");
  assert.equal(loan.backing.datasources[0].setRef, "materialized-object-set://s2", "its newest set");
  assert.equal(loan.backing.datasources[0].datasetRid, syncDatasetRidOf("clp_1"), "its dataset is Data Connection's own for the sync (the lease plan)");
  assert.deepEqual(loan.backing.objects.map((o) => o.key), ["L-1", "L-2", "L-3"]);
  assert.equal(loan.primaryKey, "loan_id", "a backed type's primary key is the property its objects are keyed by (not its title)");
  assert.deepEqual(loan.backing.datasources[0].mapping, { loan_id: "id", title: "disp", amount: "amt" });
  assert.deepEqual(borrower.backing.datasources, [], "a set of another type, or of another ontology's, backs nothing here");
  assert.equal(borrower.primaryKey, "name", "an unbacked type keeps its title property as its key");
  const entity = ONTOLOGY.objectTypeEntityOf(m, loan);
  assert.equal(entity.datasources.length, 1);
  assert.equal(entity.datasources[0].datasource.type, "dataset");
  assert.deepEqual(Object.values(entity.datasources[0].datasource.dataset.propertyMapping).sort(), ["amt", "disp", "id"]);
  assert.deepEqual(Object.keys(entity.entityMetadata.entityConfig.objectDbTypeConfigs), ["highbury"], "its objects are held in the object store");
  assert.deepEqual(ONTOLOGY.objectTypeEntityOf(m, borrower).datasources, [], "the reference's own 'Backing datasource is missing' stays true");
  assert.deepEqual(ONTOLOGY.objectTypeEntityOf(m, borrower).entityMetadata.entityConfig.objectDbTypeConfigs, {});
  const views = ONTOLOGY.objectViewsOf({ objectTypes: [{ rid: loan.rid }, { rid: borrower.rid }] }, [m]).views;
  assert.equal(views[0].resolved.views.length, 1); assert.equal(views[1].resolved.views.length, 0);
  assert.equal(ONTOLOGY.objectTypeFunnelStatusOf({ objectType: loan.rid }, [m]).activePipeline.batch.objectDbs[0].bootstrapped, "COMPLETE");
  assert.equal(ONTOLOGY.objectTypeFunnelStatusOf({ objectType: borrower.rid }, [m]).activePipeline, null);
  const loaded = ONTOLOGY.datasourcesOf({ objectTypes: { [loan.rid]: "v", [borrower.rid]: "v" } }, [m]);
  assert.equal(loaded.objectTypes[loan.rid].length, 1); assert.deepEqual(loaded.objectTypes[borrower.rid], []);
  const schema = ONTOLOGY.datasetSchemaOf([m], loan.backing.datasources[0].datasetRid);
  assert.deepEqual(schema.schema.fieldSchemaList.map((f) => `${f.name}:${f.type}`), ["id:STRING", "disp:STRING", "amt:DOUBLE"]);
  assert.equal(ONTOLOGY.datasetSchemaOf([m], "ri.foundry.main.dataset.00000000-0000-0000-0000-000000000000"), null);
});

test("O8: object sets evaluate over the materialized objects — keyword and exact filters, union, subtraction, static rids, temporary sets; an unknown construct is refused by name, never an empty set", () => {
  const models = o8Models();
  const ctx = { models, temporary: new Map() };
  const base = { type: "base", base: { objectTypeId: "loan" } };
  const keys = (os) => ONTOLOGY.evaluateObjectSet(os, ctx).map((e) => e.o.key);
  assert.deepEqual(keys(base), ["L-1", "L-2", "L-3"]);
  assert.deepEqual(keys({ type: "filtered", filtered: { objectSet: base, filter: { type: "multiMatch", multiMatch: { query: "sec", fuzzy: false, propertySet: { type: "allProperties", allProperties: {} } } } } }), ["L-2"], "a keyword begins a word");
  assert.deepEqual(keys({ type: "filtered", filtered: { objectSet: base, filter: { type: "exactMatch", exactMatch: { propertyId: "title", terms: ["Third Loan"] } } } }), ["L-3"]);
  assert.deepEqual(keys({ type: "filtered", filtered: { objectSet: base, filter: { type: "exactMatch", exactMatch: { propertyId: "title", terms: ["loan"] } } } }), [], "an exact match is exact");
  const loanWord = { type: "filtered", filtered: { objectSet: base, filter: { type: "multiMatch", multiMatch: { query: "loan", fuzzy: false, propertySet: { type: "propertyWhitelist", propertyWhitelist: { properties: ["title"] } } } } } };
  assert.deepEqual(keys({ type: "subtracted", subtracted: { objectSets: [base, loanWord] } }), [], "the reference's 'other matches' set");
  assert.deepEqual(keys({ type: "filtered", filtered: { objectSet: base, filter: { type: "not", not: { filter: { type: "hasProperty", hasProperty: { propertyId: "amount" } } } } } }), []);
  const rid = ONTOLOGY.evaluateObjectSet(base, ctx)[1].o.rid;
  assert.deepEqual(keys({ type: "static", static: { objectRids: [rid] } }), ["L-2"]);
  assert.deepEqual(keys({ type: "staticV2", staticV2: { objectIdentifiers: [{ objectRid: rid, type: "objectRid" }] } }), ["L-2"]);
  const t = ONTOLOGY.temporaryObjectSetRidOf("principal://a", base);
  ctx.temporary.set(t, base);
  assert.deepEqual(keys({ type: "referenced", referenced: { objectSetRid: t } }), ["L-1", "L-2", "L-3"]);
  assert.throws(() => keys({ type: "searchAround", searchAround: {} }), ONTOLOGY.ObjectSetNotBound);
  assert.throws(() => keys({ type: "referenced", referenced: { objectSetRid: "ri.object-set.main.versioned-object-set.x" } }), ONTOLOGY.ObjectSetNotBound, "a saved object set is not kept");
  assert.throws(() => keys({ type: "filtered", filtered: { objectSet: base, filter: { type: "geoBoundingBox" } } }), ONTOLOGY.ObjectSetNotBound);
});

test("O8: a page of objects, their aggregates and the types a set spans are the materialized objects' own", () => {
  const models = o8Models(); const ctx = { models, temporary: new Map() };
  const base = { type: "base", base: { objectTypeId: "loan" } };
  const page = ONTOLOGY.objectsPageOf({ objectSet: base, pageSize: 2, responseOptions: { includeObjectSetEntities: true } }, ctx);
  assert.equal(page.totalResults, 3); assert.equal(page.results.length, 2); assert.equal(page.nextPageToken, "2");
  const loan = models[0].objectTypes[0];
  const title = loan.properties.find((p) => p.id === "title"), amount = loan.properties.find((p) => p.id === "amount");
  assert.deepEqual(page.results[0].properties[amount.rid], { type: "double", double: 1250.5 });
  assert.deepEqual(Object.values(page.results[0].primaryKey), [{ type: "string", string: "L-1" }]);
  assert.equal(page.objectSetEntities.objectTypeRids[0], loan.rid);
  const next = ONTOLOGY.objectsPageOf({ objectSet: base, pageSize: 2, pageToken: "2" }, ctx);
  assert.deepEqual(next.results.map((r) => r.title), ["Third Loan"]); assert.equal(next.nextPageToken, null);
  const desc = ONTOLOGY.objectsPageOf({ objectSet: base, pageSize: 5, resultOrdering: { type: "propertyValue", propertyValue: { propertyOrdering: [{ propertyId: "amount", direction: "DESC" }] } } }, ctx);
  assert.deepEqual(desc.results.map((r) => r.title), ["Second Loan", "First Loan", "Third Loan"]);
  assert.deepEqual(ONTOLOGY.objectsPageOf({ objectSet: base, pageSize: 5, propertySet: { type: "selected", selected: { propertySelection: { propertyId: { propertyIds: ["title"] } } } } }, ctx).results[0].properties, { [title.rid]: { type: "string", string: "First Loan" } });
  const agg = ONTOLOGY.aggregateOf({ objectSet: base, aggregation: { metrics: { c: { type: "count", count: {} }, hi: { type: "max", max: { propertyId: "amount" } }, lo: { type: "min", min: { propertyId: "amount" } } },
    subAggregations: {
      byType: { type: "metrics", metrics: { dimension: { type: "objectType", objectType: { bucketing: { maxBuckets: 1 } } }, metrics: { n: { type: "count", count: {} } }, ordering: [], subAggregations: {} } },
      byTitle: { type: "metrics", metrics: { dimension: { type: "propertyValue", propertyValue: { propertyId: "title", bucketing: { type: "exactValue", exactValue: { maxBuckets: 2, valueFilter: { type: "excludeValues", excludeValues: { values: [] } } } } } }, metrics: { n: { type: "count", count: {} } }, ordering: [{ type: "valueOrdering", valueOrdering: { direction: "DESCENDING", metricName: "n" } }], subAggregations: {} } },
      byAmount: { type: "metrics", metrics: { dimension: { type: "propertyValue", propertyValue: { propertyId: "amount", bucketing: { type: "numeric", numeric: { type: "fixedWidth", fixedWidth: { bucketWidth: 1000, excludeEmptyBuckets: true } } } } }, metrics: { n: { type: "count", count: {} } }, ordering: [], subAggregations: {} } },
    } } }, ctx).result;
  assert.deepEqual([agg.metrics.c, agg.metrics.hi, agg.metrics.lo], [3, 90000, 42]);
  assert.deepEqual(agg.subAggregations.byType.buckets.map((b) => [b.key, b.metrics.n]), [["loan", 3]]);
  assert.equal(agg.subAggregations.byTitle.buckets.length, 2); assert.equal(agg.subAggregations.byTitle.itemsInOtherBuckets, 1);
  assert.deepEqual(agg.subAggregations.byAmount.buckets.map((b) => [b.key, b.metrics.n]), [["0.0", 1], ["1000.0", 1], ["90000.0", 1]]);
  assert.deepEqual(ONTOLOGY.objectSetObjectTypesOf({ objectSet: base }, ctx), { objectTypeIds: ["loan"], objectTypeRids: [loan.rid] });
  // no backing: a type's base set holds nothing (not a refusal: the type exists and has no materialized objects)
  assert.equal(ONTOLOGY.objectsPageOf({ objectSet: { type: "base", base: { objectTypeId: "borrower" } } }, ctx).totalResults, 0);
});

test("O8: Object Explorer's reads — the type search, counts, an object and its view — answer over the materialized objects; no link can be followed and no object view is kept", () => {
  const models = o8Models();
  const loan = models[0].objectTypes[0];
  const found = ONTOLOGY.searchObjectTypesOf({ clause: { type: "and", and: [{ type: "status", status: "EXPERIMENTAL" }, { type: "visibility", visibility: "NORMAL" }] }, pageSizeLimit: 250 }, models);
  assert.equal(found.totalResults, 2);
  assert.equal(ONTOLOGY.searchObjectTypesOf({ clause: { type: "and", and: [{ type: "status", status: "ACTIVE" }, { type: "visibility", visibility: "NORMAL" }] } }, models).totalResults, 0, "a draft's types are experimental");
  const facts = (name, variables) => ONTOLOGY.explorerGraphqlFacts(name, variables, { models, owner: O8_OWNER });
  assert.equal(facts("ObjectTypeUsageMetricsQuery", { rid: loan.rid }).objectType.objectCount, 3);
  assert.equal(facts("ObjectTypeCountQuery", { filter: { clauses: [{ objectTypeDisplayNameContains: "loa" }] } }).objectTypesV2.totalNumberOfResults, 1);
  const objects = facts("ObjectsQuery", { objectTypeIdentifier: { rid: loan.rid }, pageSize: 30, searchTerm: "third" }).defaultOrGlobalBranch.objectType.objectsV3.values;
  assert.deepEqual(objects.map((o) => o.title), ["Third Loan"]);
  const rid = objects[0].rid;
  const table = facts("ObjectViewCorePropertiesTableQuery", { objectRid: rid }).defaultOrGlobalBranch.object;
  assert.deepEqual(table.properties.map((p) => p.value.value), ["L-3", "Third Loan", 42]);
  assert.deepEqual(facts("ProminentPropertiesQuery", { objectRid: rid }).defaultOrGlobalBranch.object.properties, [], "no property is marked prominent");
  assert.deepEqual(facts("ObjectLinkTypesQuery", { objectRid: rid }).defaultOrGlobalBranch.object.type.latest.linksIncludingLinksToObjectTypesWithoutSearchableDatasources, []);
  assert.equal(facts("ObjectViewFullVersionQuery", { objectTypeRid: loan.rid }).defaultOrGlobalBranch.objectType.objectViewConfiguration, null, "no object view is saved or published");
  assert.match(facts("ResolveObjectViewRidQuery", { objectTypeRid: loan.rid }).objectType.objectViewConfiguration.rid, /^ri\.hubble-server\.main\.object-view\./u, "the reference's default view");
  assert.deepEqual(ONTOLOGY.linkTypesForObjectTypesOf({ objectTypeVersions: { [loan.rid]: "v" } }, models, { traversableOnly: true }).linkTypes[loan.rid], []);
  assert.deepEqual(ONTOLOGY.objectViewPermissionsOf({ hasEditPermission: ["loan"], hasPublishPermission: ["loan", "nope"] }, models), { hasEditPermission: { loan: false }, hasPublishPermission: { loan: false } });
  assert.equal(facts("ObjectTypeSemanticSearchUnavailableReasonQuery", {}).objectTypeSemanticSearchUnavailableReason !== null, true, "no semantic index is kept");
});

test("O8: a backed type's edit saves as the daemon's ODK patch at the expected revision; what an ODK model does not keep is refused by name", () => {
  const models = o8Models();
  const [m] = models; const loan = m.objectTypes[0];
  const props = Object.fromEntries(loan.properties.map((p) => [p.id, { displayMetadata: { displayName: p.name, description: null, visibility: "NORMAL" }, id: p.id, apiName: ONTOLOGY.camel(p.name), type: ONTOLOGY.baseTypeOf(p.base), typeClasses: ONTOLOGY.renderHintsOf(p), status: { type: "experimental", experimental: {} } }]));
  const edit = (patch = {}, top = {}) => ({ expectedOntologyVersion: m.version, objectTypes: { loan: { type: "update", update: { objectType: { displayMetadata: { description: "A loan on the book", displayName: "Loan", groupDisplayName: null, icon: { type: "blueprint", blueprint: { color: "#5F6B7C", locator: "cube" } }, pluralDisplayName: "Loan", visibility: "NORMAL" },
    id: "loan", apiName: "Loan", primaryKeys: ["loan_id"], propertyTypes: props, status: { type: "experimental", experimental: {} }, titlePropertyTypeId: "title", traits: { workflowObjectTypeTraits: {} }, implementsInterfaces: [], implementsInterfaces2: [], sharedPropertyTypes: {}, typeGroups: [], ...patch } } } }, ...top });
  const ok = ONTOLOGY.ontologySaveStepOf(edit(), models, m.rid);
  assert.equal(ok.refusal, undefined, JSON.stringify(ok.refusal));
  assert.equal(ok.draftId, "ont_1"); assert.equal(ok.body.expected_revision, 2);
  const saved = ok.body.canonical_object_model.object_types.find((o) => o.id === "loan");
  assert.equal(saved.description, "A loan on the book"); assert.equal(saved.title_property, "title");
  assert.deepEqual(saved.properties.map((p) => p.value_type), ["string", "string", "money"], "an unchanged property keeps its declared value type");
  assert.deepEqual(ok.body.canonical_object_model.object_types.find((o) => o.id === "borrower"), drafts[0].canonical_object_model.object_types[1], "another type is untouched");
  const renamed = ONTOLOGY.ontologySaveStepOf(edit({ propertyTypes: { ...props, title: { ...props.title, displayMetadata: { displayName: "Name", description: "What it is called", visibility: "NORMAL" } }, note: { displayMetadata: { displayName: "Note", visibility: "NORMAL" }, type: { type: "string", string: {} }, typeClasses: [{ kind: "render_hint", name: "SELECTABLE" }] } } }), models, m.rid);
  const t = renamed.body.canonical_object_model.object_types.find((o) => o.id === "loan");
  assert.deepEqual(t.properties.map((p) => `${p.id}:${p.name}`), ["loan_id:Loan Id", "title:Name", "amount:Amount", "note:Note"], "a renamed and an added property");
  assert.equal(t.properties.find((p) => p.id === "title").description, "What it is called");
  const refused = (r) => ONTOLOGY.ontologySaveStepOf(r, models, m.rid).refusal?.code;
  assert.equal(refused(edit({ primaryKeys: ["title"] })), "Hypervisor:OntologyEditNotBound", "the key its mapping keys by");
  assert.equal(refused(edit({ propertyTypes: { ...props, amount: { ...props.amount, type: { type: "string", string: {} } } } })), "Hypervisor:OntologyEditNotBound", "a mapped property's type");
  assert.equal(refused(edit({ propertyTypes: { loan_id: props.loan_id, amount: props.amount } })), "Hypervisor:OntologyEditNotBound", "removing a mapped property");
  assert.equal(refused(edit({ status: { type: "active", active: {} } })), "Hypervisor:OntologyEditNotBound");
  assert.equal(refused(edit({}, { actionTypesToUpdate: { x: {} } })), "Hypervisor:OntologyEditNotBound", "only object types are saved here");
  assert.equal(refused(edit({}, { objectTypeDatasources: { loan: [{ type: "update", update: { rid: "x", objectTypeDatasourceDefinition: { type: "datasetV2", datasetV2: { datasetRid: "ri.foundry.main.dataset.x", propertyMapping: {} } } } }] } })), "Hypervisor:OntologyEditNotBound", "the backing is its materialized sets");
  assert.equal(refused({ ...edit(), objectTypes: { newtype: { type: "create", create: {} } } }), "Hypervisor:OntologyEditNotBound", "a new type needs a backing datasource");
  assert.equal(refused({ ...edit(), expectedOntologyVersion: "00000002-deadbeef" }), "Hypervisor:OntologyEditNotBound", "a version that is not this draft's");
  const unbacked = ONTOLOGY.ontologyModelsOf([o8Draft], O8_OWNER, familyOf, []);
  assert.match(ONTOLOGY.ontologySaveStepOf(edit(), unbacked, m.rid).refusal.message, /no backing datasource/u);
  const member = ONTOLOGY.ontologyModelsOf([{ ...o8Draft, caller_may_change: false }], O8_OWNER, familyOf, o8Sets);
  assert.match(ONTOLOGY.ontologySaveStepOf(edit(), member, m.rid).refusal.message, /owner, or an administrator/u);
  // the save's answer and the diff the reference reloads after it
  assert.deepEqual(ONTOLOGY.ontologySaveAnswerOf(m, 3, ["loan"]).createdActionTypes, []);
  const diff = ONTOLOGY.ontologyDiffOf(m, { baseOntologyVersion: ONTOLOGY.draftVersionOf("ont_1", 1), newOntologyVersion: m.version });
  assert.deepEqual(Object.values(diff.diff.affectedObjectTypes), ["UPDATED"]);
  assert.equal(ONTOLOGY.ontologyDiffOf(m, { baseOntologyVersion: "x", newOntologyVersion: m.version }), null);
});
