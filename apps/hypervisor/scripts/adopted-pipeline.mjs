// The adopted reference Pipeline Builder over Hypervisor truth (R-241, ADR 0056 P4). The app is served
// from the local capture server (never vendored); this module answers what its landing reads, in the app's own
// wire shapes, from the DataRecipe and change-set planes.
//
// A PIPELINE is a DataRecipe family (`data-recipe://<family>`). Canon's patch branch is how a family
// changes, so a pipeline's SANDBOXES are: Main — the family's admitted head (backing branch `master`) —
// and one sandbox per open or proposed change set over the family. A family that so far exists only as a
// founding change set is a pipeline whose Main holds no revision. Nothing here writes; nothing is
// taken from the reference's recorded answers except structure (adopted-graphql.mjs).
//
// The GraphQL resolver ignores field arguments, so the facts are scoped HERE from each request's own
// variables (a search's text / creator filters, a pipeline rid, a sandbox id).
import crypto from "node:crypto";

export const PIPELINE_PREFIX = "ri.eddie.main.pipeline.";
const cacheId = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");
const iso = (t) => (t && !Number.isNaN(Date.parse(t)) ? new Date(t).toISOString() : new Date(0).toISOString());
// A name-based UUID (version 5 shape, RFC 4122 variant): the app validates user ids and sandbox ids as
// UUIDs, and the same ref always names the same id.
export const uuidOf = (ref) => {
  const h = crypto.createHash("sha256").update(String(ref || "unknown")).digest("hex");
  const variant = "89ab"[parseInt(h[16], 16) & 3];
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
export const pipelineRidOf = (familyRef) => `${PIPELINE_PREFIX}${uuidOf(familyRef)}`;
export const mainSandboxIdOf = (familyRef) => uuidOf(`${familyRef}#sandbox/main`);
export const changeSetSandboxIdOf = (changeSetRef) => uuidOf(`${changeSetRef}#sandbox`);
const familyToken = (familyRef) => String(familyRef || "").replace(/^data-recipe:\/\//, "");
const OPEN = new Set(["open", "proposed"]);
const latestDraftName = (cs) => {
  const d = (cs.drafts || []).at(-1);
  return d && typeof d.body?.name === "string" && d.body.name ? d.body.name : null;
};

// The caller's pipelines: every DataRecipe family they can read, plus every family an open or proposed
// change set would found. `families` is [{ family_ref, revisions, runs }] (revisions oldest first, as the
// daemon returns them; runs are the family's TransformationRuns, when it has any); `changeSets` is the
// caller's change sets.
export function pipelinesOf(families, changeSets) {
  const byFamily = new Map();
  const ensure = (familyRef) => {
    if (!byFamily.has(familyRef)) byFamily.set(familyRef, { familyRef, revisions: [], runs: [], changeSets: [] });
    return byFamily.get(familyRef);
  };
  for (const f of families || []) Object.assign(ensure(f.family_ref), { revisions: Array.isArray(f.revisions) ? f.revisions : [], runs: Array.isArray(f.runs) ? f.runs : [] });
  for (const cs of changeSets || []) {
    // A pipeline is a DataRecipe family; the change-set plane also carries other subjects (a Studio
    // blueprint, since change-set v2), which are no pipeline.
    if (cs?.subject?.kind !== "data_recipe") continue;
    const familyRef = cs?.subject?.family_ref;
    if (!familyRef) continue;
    const known = byFamily.has(familyRef);
    // a closed change set over a family with no revision founds nothing, so it is no pipeline
    if (!known && !OPEN.has(cs.status)) continue;
    ensure(familyRef).changeSets.push(cs);
  }
  return [...byFamily.values()].map((p) => {
    const head = p.revisions.at(-1) || null;
    const founding = p.changeSets.find((cs) => cs.subject?.base_revision_ref === null) || null;
    const created = p.revisions[0]?.admitted_at || founding?.created_at || null;
    // who made it: the change set that founded the family, when one did; the record itself names no author
    const author = founding?.author_principal_ref || null;
    return {
      ...p,
      rid: pipelineRidOf(p.familyRef),
      name: head?.name || (founding && (latestDraftName(founding) || founding.title)) || familyToken(p.familyRef),
      head,
      createdAt: created,
      author,
      openChangeSets: p.changeSets.filter((cs) => OPEN.has(cs.status)),
    };
  }).sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));
}

// ---- GraphQL: the landing's search, recents and favorites; a pipeline's sandboxes and deployment.
export const PIPELINE_OPERATIONS = new Set([
  "PipelineLandingSearchQuery",
  "PipelineLandingRecentsAndFavoritesQuery",
  "PublishedSandboxesQuery",
  "CurrentPipelineDeploymentQuery",
]);

const resourceNode = (rid, name = null) => ({ rid, name, _id: cacheId(`resource:${rid}`), __typename: "ResourceMetadata" });

export function pipelineFactsRoot(name, variables, pipelines, userIdOf) {
  const v = variables || {};
  if (name === "PipelineLandingSearchQuery") {
    const text = String(v.text || "").trim().toLowerCase();
    const creators = new Set((v.createdByUserIds || []).filter(Boolean));
    // A DataRecipe belongs to no project, so a project filter matches none of them.
    const inProjects = (v.inProjects || []).filter(Boolean);
    const matched = inProjects.length ? [] : pipelines
      .filter((p) => !text || p.name.toLowerCase().includes(text))
      .filter((p) => !creators.size || (p.author && creators.has(userIdOf(p.author))));
    const pageSize = Number.isInteger(v.pageSize) && v.pageSize > 0 ? v.pageSize : 50;
    return {
      __typename: "Query",
      searchResourcesV2: {
        __typename: "ResourceSearchResults",
        results: matched.slice(0, pageSize).map((p) => ({ __typename: "ResourceSearchResult", resource: resourceNode(p.rid, p.name) })),
        nextPageToken: null,
      },
    };
  }
  if (name === "PipelineLandingRecentsAndFavoritesQuery") {
    // No recents or favorites record is kept for a DataRecipe family: both are honestly empty.
    return { __typename: "Query", recents: [], favorites: [] };
  }
  const p = pipelines.find((x) => x.rid === v.pipelineRid);
  if (!p) return { __typename: "Query", eddiePipeline: null };
  const pipelineNode = { __typename: "EddiePipeline", _id: cacheId(`pipeline:${p.rid}`) };
  if (name === "PublishedSandboxesQuery") {
    // Main is the only PUBLISHED sandbox; a change set's sandbox is a draft until it merges.
    const wantsPublishedOnly = (v.filter?.publishStatus || []).includes("PUBLISHED");
    const sandboxes = [{ id: mainSandboxIdOf(p.familyRef), branch: "master" }]
      .concat(wantsPublishedOnly ? [] : p.openChangeSets.map((cs) => ({ id: changeSetSandboxIdOf(cs.change_set_ref), branch: cs.change_set_ref })));
    return {
      __typename: "Query",
      eddiePipeline: { ...pipelineNode, sandboxes: sandboxes.map((s) => ({ __typename: "EddieSandbox", sandboxId: s.id, backingBranchName: s.branch, _id: cacheId(`sandbox:${s.id}`) })) },
    };
  }
  if (name === "CurrentPipelineDeploymentQuery") {
    // A deploy is a TransformationRun of a revision: Main's current deployment is the family's latest completed run
    // (a change set's sandbox is never deployed); none reads as never deployed, never the reference's deployment.
    return { __typename: "Query", eddiePipeline: { ...pipelineNode, sandbox: { __typename: "EddieSandbox", _id: cacheId(`sandbox:${v.sandboxId}`), currentDeployment: v.sandboxId === mainSandboxIdOf(p.familyRef) ? currentDeploymentOf(p) : null } } };
  }
  return null;
}

// ---- REST: a pipeline's details — POST /eddie/api/pipelines-v2/get/by-rids (each requested pipeline the
// caller holds) and GET /eddie/api/pipelines-v2/<rid> (one; null when the caller holds no such pipeline).
const pipelineEntry = (p, userIdOf) => ({
  rid: p.rid,
  name: p.name,
  attribution: { time: iso(p.createdAt), user: userIdOf(p.author || p.head?.owner_ref || "unknown") },
  publishedSandboxes: [mainSandboxIdOf(p.familyRef)],
  heartbeats: {},
  compassDetails: { trashed: false, favorite: false },
});
export function pipelinesByRids(rids, pipelines, userIdOf) {
  const out = {};
  for (const rid of Array.isArray(rids) ? rids : []) {
    const p = pipelines.find((x) => x.rid === rid);
    if (p) out[rid] = pipelineEntry(p, userIdOf);
  }
  return { pipelines: out };
}
export function pipelineDetails(rid, pipelines, userIdOf) {
  const p = pipelines.find((x) => x.rid === rid);
  return p ? { pipeline: pipelineEntry(p, userIdOf) } : null;
}

// ---- REST: POST /eddie/api/pipelines-v2/get-sandboxes-with-snapshots — a sandbox and its snapshot.
// Main's version is the family's head revision ("Root" when the family has none yet); a change set's
// sandbox version is its latest draft. The snapshot's TARGETS are the recipe's declared outputs — each
// output object model an object target, each output dataset contract a dataset target — so the landing
// never says "No outputs set" of a recipe that declares some. Its transforms are not yet derived from the
// recipe's steps (the editor's cut): empty rather than invented.
const tokenOf = (ref) => String(ref || "").replace(/^[a-z-]+:\/\//u, "");
export function targetsOf(recipe) {
  if (!recipe) return [];
  const objects = (recipe.output_object_model_refs || []).map((ref) => ({
    id: uuidOf(`${ref}#target`),
    target: { type: "object", object: { id: tokenOf(ref), displayName: tokenOf(ref), pluralDisplayName: tokenOf(ref), rid: `ri.ontology.main.object-type.${uuidOf(ref)}`, properties: [], primaryKeyPropertyId: null, titleColumnPropertyId: null, icon: { iconName: "cube", iconColor: "#4C90F0" }, interfaceRids: [], implementsInterfaces: {}, expectationChecks: [] } },
    unmarkings: [],
  }));
  const datasets = (recipe.output_dataset_contract_refs || []).map((ref) => ({
    id: uuidOf(`${ref}#target`),
    target: { type: "dataset", dataset: { columns: [], datasetRid: `ri.foundry.main.dataset.${uuidOf(ref)}`, expectationChecks: [] } },
    unmarkings: [],
  }));
  return [...objects, ...datasets];
}
// Compass reads of an output dataset (the landing's output pill resolves its name): each requested dataset
// rid that is a declared output of one of the caller's pipelines, named by its dataset contract.
export function compassOutputDatasets(rids, pipelines, userIdOf) {
  const wanted = new Set(Array.isArray(rids) ? rids : []);
  const out = {};
  for (const p of pipelines) {
    const bodies = [p.head, ...p.openChangeSets.map((cs) => cs.drafts?.at(-1)?.body)].filter(Boolean);
    for (const body of bodies) {
      for (const ref of body.output_dataset_contract_refs || []) {
        const rid = `ri.foundry.main.dataset.${uuidOf(ref)}`;
        if (!wanted.has(rid) || out[rid]) continue;
        const at = { time: iso(p.createdAt), userId: userIdOf(p.author || "unknown") };
        out[rid] = {
          rid, name: tokenOf(ref), created: at, modified: at, lastModified: Date.parse(at.time) || 0, description: `An output dataset contract of ${p.name} (${ref})`,
          operations: [], urlVariables: {}, favorite: null, branches: null, defaultBranch: null, path: `/${p.name}/${tokenOf(ref)}`, longDescription: null,
          directlyTrashed: false, inTrash: false, isAutosave: false, isHidden: false, isPreviewResource: false, deprecation: null, collections: null, namedCollections: [],
          tags: null, namedTags: null, alias: "", collaborators: [], namedAncestors: [{ rid: "ri.compass.main.folder.0", name: "All files" }], markings: null,
          projectAccessMarkings: null, linkedItems: null, contactInformation: null, classification: null, portfolioRid: null, namespaceRid: "ri.compass.main.namespace.hypervisor", status: null,
        };
      }
    }
  }
  return out;
}
// The Hypervisor offers ONE compute profile: a recipe runs as a TransformationRun on its own runtime. No cores or memory
// are claimed. The deploy panel reads the snapshot's profile unguarded (it crashed the editor on a snapshot without one).
export const RUNTIME_PROFILE = Object.freeze({ id: uuidOf("hypervisor://compute/transformation-run"), name: "Hypervisor runtime", description: "A recipe runs as a TransformationRun on the Hypervisor's own runtime; no other compute is offered.", backendSpecificDisplayProperties: {}, availableArguments: {}, argumentAvailability: {}, isDeprecated: false, requiredProfiles: {} });
const snapshotOf = (recipe) => ({ transforms: [], targets: targetsOf(recipe), groups: [], groupedExpressions: [], outputs: [], arguments: {}, backendSettings: { computeProfile: { computeProfileId: RUNTIME_PROFILE.id, arguments: {} }, configuration: {} }, targetSettings: targetSettingsOf(recipe), skippedTransforms: [], persistedTransforms: [] });
export function sandboxesWithSnapshots(requests, pipelines, userIdOf) {
  const sandboxes = [];
  for (const r of Array.isArray(requests) ? requests : []) {
    const p = pipelines.find((x) => x.rid === r?.pipelineRid);
    if (!p) continue;
    let sandbox = null;
    let version = null;
    if (r.sandboxId === mainSandboxIdOf(p.familyRef)) {
      const head = p.head;
      const versionId = uuidOf(head ? head.revision_ref : `${p.familyRef}#root`);
      const author = userIdOf(p.author || head?.owner_ref || "unknown");
      sandbox = { id: r.sandboxId, name: "Main", backingBranch: "master", fallbackBranches: [], attribution: { time: iso(p.createdAt), user: author }, version: versionId, isArchived: false, isPublished: true };
      version = { id: versionId, message: head ? `Revision ${String(head.revision_ref).split("/").pop()}` : "Root", attribution: { time: iso(head?.admitted_at || p.createdAt), user: author }, backend: "Spark" };
      sandboxes.push({ pipelineRid: p.rid, sandbox, version, snapshot: snapshotOf(head) });
      continue;
    } else {
      // every change set of the family answers (a merged or closed proposal's page loads both sides); a closed
      // one is archived, and the branch lists (allSandboxes, PublishedSandboxesQuery) still name only open ones
      const cs = p.changeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === r.sandboxId);
      if (!cs) continue;
      const draft = (cs.drafts || []).at(-1);
      const versionId = uuidOf(`${cs.change_set_ref}#draft/${draft?.ordinal || 0}`);
      const author = userIdOf(cs.author_principal_ref);
      sandbox = { id: r.sandboxId, name: cs.title, backingBranch: cs.change_set_ref, fallbackBranches: ["master"], attribution: { time: iso(cs.created_at), user: author }, version: versionId, isArchived: !OPEN.has(cs.status), isPublished: false };
      version = { id: versionId, message: draft ? `Draft ${draft.ordinal}` : "Root", attribution: { time: iso(draft?.drafted_at || cs.created_at), user: userIdOf(draft?.author_principal_ref || cs.author_principal_ref) }, backend: "Spark" };
    }
    // a change set's sandbox shows its latest draft's declared outputs
    sandboxes.push({ pipelineRid: p.rid, sandbox, version, snapshot: snapshotOf(p.changeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === r.sandboxId)?.drafts?.at(-1)?.body) });
  }
  return { sandboxes };
}

// ---- REST: POST /foundry-search/api/compass/v0/search — the project picker (a project-preview search)
// answers with the caller's projects; any other compass search answers with nothing rather than the
// recorded tenant's index.
export function compassSearchAnswer(request, projects, folderRidOf, userIdOf, callerRef) {
  const q = request?.query || {};
  const isProjectSearch = q.filter?.type === "isProjectPreview" || q.filter?.isProjectPreview === true;
  if (!isProjectSearch) return { result: [], nextPageToken: null };
  const text = String(q.text || "").trim().toLowerCase();
  const limit = Number.isInteger(request?.limit) && request.limit > 0 ? request.limit : 50;
  const offset = Number.isInteger(request?.offset) && request.offset > 0 ? request.offset : 0;
  const matched = (projects || [])
    .filter((p) => !text || String(p.name || "").toLowerCase().includes(text))
    .sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  const user = userIdOf(callerRef || "unknown");
  const result = matched.slice(offset, offset + limit).map((p) => {
    const folder = folderRidOf(p.project_id);
    const locator = folder.replace("ri.compass.main.folder.", "");
    const t = iso(p.created_at);
    const ms = Date.parse(t);
    return {
      indexedResource: {
        type: "project-preview",
        service: "compass",
        name: p.name,
        displayName: "",
        resource: { rid: `ri.compass.main.project-preview.${locator}`, name: p.name, created: { time: t, userId: user }, modified: { time: t, userId: user }, lastModified: ms, urlVariables: {}, directlyTrashed: false, status: null },
        instance: "main",
        locator,
        shortDescription: p.description || "",
        path: "",
        inTrash: false,
        directlyTrashed: false,
        isAutosave: false,
        isPreviewResource: false,
        collections: [],
        tags: [],
        linkedItems: [],
        branchUrlVariables: [],
        deprecation: null,
        markings: [],
        directRoleGrants: [],
        projectRid: folder,
        namespaceRid: "ri.compass.main.folder.hypervisor-namespace",
        portfolioRid: null,
        lastModified: ms,
        resourceUrlVariables: [],
        resourceUrlVariablesKeys: [],
        isResourcePreview: false,
        isPublished: false,
        isProject: false,
        isNamespace: false,
        isProjectPreview: true,
        isEndorsed: false,
      },
      highlights: {},
    };
  });
  return { result, nextPageToken: offset + limit < matched.length ? String(offset + limit) : null };
}

// ---- THE EDITOR (cut 2b): what the pipeline editor reads when it opens a pipeline, READ-ONLY. The caller
// is granted no edit operation (the editor's writes — a draft to a change set — are the next cut), so the
// editor opens in view mode rather than offering edits that would go nowhere. Main's protections forbid a
// direct push: canon's patch branch is the only way a family's head moves (a change set merged).
export const PIPELINE_EDITOR_OPERATIONS = new Set([
  "OntologiesQuery", "BackendTypeForLatestSandboxVersionQuery", "ActiveResourceQuery", "ResourceHeaderQuery",
  "ProjectIcebergStorageQuery", "TargetProjectQuery", "DataConnectionSourceQuery", "ComputeExpressionIfAbsentStoresQuery", "SandboxBackendQuery",
  "CurrentDeploymentQuery", "ResolveEddieSandboxToGlobalBranch", "ResourceProjectQuery", "BranchSelectSearchQuery",
  "IssueBadgeData", "WalkthroughsForResourceQuery", "CommunicationChannelsQuery", "BackingObjectQuery", "CompassResourceViewQuery", "SaveResourceDialogQuery",
  // the proposal page (read); a principal chip
  "UserGroupQuery", "ResolveEddieProposalIdToGlobalBranch", "ResolveEddieProposalRidToGlobalBranch", "ProposalEventsQuery", "BackendTypeForProposalQuery",
  // the output settings' ontology name
  "OntologyQuery",
  // the History page (read): the version timeline and the compare view
  "HistoryPageGlobalBranch", "HistoryVersionListQuery", "HistoryVersionDiffQuery",
]);
// Editor reads that name no pipeline (the caller's organization, a dataset, ontologies, branches).
export const PIPELINE_EDITOR_GLOBAL_OPERATIONS = new Set(["OntologiesQuery", "OntologyQuery", "BranchSelectSearchQuery", "CommunicationChannelsQuery", "BackingObjectQuery", "SaveResourceDialogQuery", "UserGroupQuery"]);
// The operations that read the caller's ontologies (the serve reads the ontology catalog only for these).
export const ONTOLOGY_OPERATIONS = new Set(["OntologiesQuery", "OntologyQuery"]);
// Reads keyed by a dataset rid: answered when it is one of the caller's pipelines' declared output datasets.
export const PIPELINE_EDITOR_DATASET_OPERATIONS = new Set(["BackingObjectQuery", "CompassResourceViewQuery"]);
// Whether an operation is the Pipeline Builder's to answer: its landing reads, and its editor reads when they
// name a pipeline, a dataset (the dataset reads), or nothing at all (the global reads). One predicate for the
// bulk and the single-operation gateways.
export function answersPipelineOperation(name, variables) {
  if (PIPELINE_OPERATIONS.has(name)) return true;
  if (!PIPELINE_EDITOR_OPERATIONS.has(name)) return false;
  // the proposal-rid pre-check names only the proposal
  if (name === "ResolveEddieProposalRidToGlobalBranch") return /^ri\.eddie\.main\.proposal\.[0-9a-f-]{36}$/u.test(String(variables?.proposalRid || ""));
  return !!pipelineRidIn(variables) || PIPELINE_EDITOR_GLOBAL_OPERATIONS.has(name) || (PIPELINE_EDITOR_DATASET_OPERATIONS.has(name) && !!datasetRidIn(variables));
}
export const datasetRidIn = (variables) => (JSON.stringify(variables || {}).match(/ri\.foundry\.main\.dataset\.[0-9a-f-]{36}/u) || [])[0] || null;
export const pipelineRidIn = (variables) => (JSON.stringify(variables || {}).match(/ri\.eddie\.main\.pipeline\.[0-9a-f-]{36}/u) || [])[0] || null;
const ALL_FILES = { __typename: "ResourceMetadata", name: "All files", rid: "ri.compass.main.folder.0", _id: cacheId("folder:0"), openUrl: null, permissions: { __typename: "ResourceMetadataPermissions", _id: cacheId("perm:folder:0"), canOpenLink: false } };
function pipelineResource(p, userIdOf) {
  const at = (t) => ({ __typename: "ResourceTimestamp", time: iso(t), user: { __typename: "User", id: userIdOf(p.author || "unknown"), _id: cacheId(`user:${p.author}`) } });
  return {
    __typename: "ResourceMetadata", _id: cacheId(`meta:${p.rid}`), rid: p.rid, name: p.name, alias: null, description: "",
    path: `/${p.name}`, openUrl: `/workspace/builder/${p.rid}`, autosaved: false, hidden: false, trashedStatus: "NOT_TRASHED",
    favorited: null, status: null, statusInfo: null, collections: [], isProtected: false, created: at(p.createdAt), modified: at(p.head?.admitted_at || p.createdAt),
    ancestors: [ALL_FILES], parent: ALL_FILES, urlVariables: [], actionLinks: [], promotion: null, aipAssistWalkthroughs: [],
    // lists the header reads: no markings, tags or collaborators are kept for a recipe family
    markings: [], projectAccessMarkings: [], tags: [], namedTags: [], namedCollections: [], collaborators: [], linkedItems: [],
    classification: { __typename: "Classification", userConstraintClassificationBanner: null, containerClassificationBanner: null, resourceClassificationBanner: null },
    type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-layout-hierarchy" },
    // A DataRecipe family is held in no project.
    project: null, projectRid: null,
    openIssues: { __typename: "IssuePage", totalNumberOfResults: 0 },
    permissions: { __typename: "ResourceMetadataPermissions", _id: cacheId(`perm:${p.rid}`), canOpenLink: true, canEditMetadata: false, canShare: false, canShareLink: false, canTrash: false, canEditTags: false, canMoveBetweenProjects: false, canMoveWithinProject: false, canRestore: false },
  };
}
export function pipelineEditorFactsRoot(variables, pipelines, userIdOf, caller = null, ontologies = []) {
  const rid = pipelineRidIn(variables);
  const p = rid ? pipelines.find((x) => x.rid === rid) : null;
  const sandboxId = variables?.sandboxId || (p ? mainSandboxIdOf(p.familyRef) : null);
  const known = p && (sandboxId === mainSandboxIdOf(p.familyRef) || p.changeSets.some((cs) => changeSetSandboxIdOf(cs.change_set_ref) === sandboxId));
  const sandbox = known ? {
    __typename: "EddieSandbox", _id: cacheId(`sandbox:${sandboxId}`), sandboxId,
    latestVersion: { __typename: "EddieSandboxVersion", _id: cacheId(`version:${sandboxId}`), backend: "Spark" },
    computeExpressionIfAbsentStores: [], globalBranch: null,
    ...historyFacts(p, sandboxId, variables, userIdOf),
  } : null;
  // A dataset the request names: one of the caller's pipelines' declared output datasets backs no object type.
  const datasetRid = (JSON.stringify(variables || {}).match(/ri\.foundry\.main\.dataset\.[0-9a-f-]{36}/u) || [])[0] || null;
  const ownDataset = datasetRid && pipelines.some((x) => [x.head, ...x.openChangeSets.map((cs) => cs.drafts?.at(-1)?.body)].filter(Boolean)
    .some((body) => (body.output_dataset_contract_refs || []).some((ref) => `ri.foundry.main.dataset.${uuidOf(ref)}` === datasetRid)));
  return {
    __typename: "Query",
    // The caller's organization sets no communication controls, and there are no channel categories.
    me: { __typename: "User", _id: cacheId("me"), id: caller?.ref ? userIdOf(caller.ref) : null, username: caller?.email || null, displayName: caller?.name || null, fullName: caller?.name || null, organization: { __typename: "Organization", _id: cacheId("me:organization"), enrollment: { __typename: "Enrollment", _id: cacheId("me:enrollment"), administratorCommunicationControls: null } } },
    communicationChannelCategories: [],
    // the create form's location dialog: no favorites or recents are kept
    favorites: [], recents: [],
    catalogDataset: ownDataset ? { __typename: "CatalogDataset", _id: cacheId(`dataset:${datasetRid}`), backsObjectTypes: [] } : null,
    // The caller's ontologies, offered as output targets. They are the caller's own (every read is owner-scoped), so the
    // caller may create object and link types in them — the target picker offers only ontologies where that holds.
    allOntologies: (ontologies || []).map((o) => ({ __typename: "Ontology", _id: cacheId(`ontology:${o.rid}`), rid: o.rid, displayName: o.displayName, apiName: o.displayName, permissions: { __typename: "OntologyPermissions", _id: cacheId(`ontology-perm:${o.rid}`), canCreateLinkTypes: true, canCreateObjectTypes: true } })),
    ontology: variables?.ontologyRid ? (() => { const o = (ontologies || []).find((x) => x.rid === variables.ontologyRid); return o ? { __typename: "Ontology", _id: cacheId(`ontology:${o.rid}`), rid: o.rid, displayName: o.displayName, apiName: o.displayName } : null; })() : null,
    // no global branches exist (a change set is a patch branch of one family, not a global branch)
    globalBranchDropdownSearchByCreatedAtDescending: { __typename: "GlobalBranchPage", values: [], nextPageToken: null },
    eddiePipeline: p ? { __typename: "EddiePipeline", _id: cacheId(`pipeline:${p.rid}`), sandbox, proposal: proposalByVariables(pipelines, variables, userIdOf, p.rid) } : null,
    eddiePipelineProposal: variables?.proposalRid ? proposalByVariables(pipelines, variables, userIdOf, null) : null,
    // a principal chip: the caller, or a principal the caller's own records name (a change set's author or merger)
    principal: variables?.id ? principalById(variables.id, pipelines, userIdOf, caller) : null,
    // the History page reads the sandbox through the resource (`… on EddiePipeline { sandbox { globalBranch } }`)
    resourceMetadata: p ? { ...pipelineResource(p, userIdOf), resource: { __typename: "EddiePipeline", _id: cacheId(`pipeline:${p.rid}`), sandbox } } : (ownDataset ? datasetResource(datasetRid, pipelines) : null),
  };
}
function principalById(id, pipelines, userIdOf, caller) {
  if (caller?.ref && userIdOf(caller.ref) === id) return { __typename: "User", _id: cacheId(`user:${caller.ref}`), id, username: caller.email || caller.ref, displayName: caller.name || caller.ref, fullName: caller.name || caller.ref };
  for (const p of pipelines) for (const cs of p.changeSets) for (const ref of [cs.author_principal_ref, cs.merge?.merged_by_principal_ref, ...(cs.drafts || []).map((d) => d.author_principal_ref)]) {
    if (ref && userIdOf(ref) === id) return { __typename: "User", _id: cacheId(`user:${ref}`), id, username: ref, displayName: ref, fullName: null };
  }
  return null;
}
// The proposal a request names (by pipeline + proposalId, or by proposalRid), as GraphQL facts; null when it is
// not the caller's (the page then treats the pre-check as "no global branch", and a read of it as absent).
function proposalByVariables(pipelines, variables, userIdOf, pipelineRid) {
  if (!variables?.proposalId && !variables?.proposalRid) return null;
  const hit = findProposal(pipelines, { pipelineRid, proposalId: variables.proposalId, proposalRid: variables.proposalRid });
  return hit ? proposalFacts(hit.p, hit.cs, userIdOf) : null;
}
// An output dataset as a compass resource: named by its dataset contract, in no folder of its own.
function datasetResource(rid, pipelines) {
  let ref = null;
  for (const x of pipelines) for (const body of [x.head, ...x.openChangeSets.map((cs) => cs.drafts?.at(-1)?.body)].filter(Boolean)) for (const r of body.output_dataset_contract_refs || []) if (`ri.foundry.main.dataset.${uuidOf(r)}` === rid) ref = r;
  const branch = { __typename: "ResourceBranch", _id: cacheId(`branch:${rid}:master`), name: "master", branchName: "master" };
  return {
    __typename: "ResourceMetadata", _id: cacheId(`meta:${rid}`), rid, name: tokenOf(ref), alias: null, path: `/${tokenOf(ref)}`, openUrl: null,
    collections: [], status: null, statusInfo: null, trashedStatus: "NOT_TRASHED", autosaved: false, ancestors: [ALL_FILES],
    type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-dataset" },
    permissions: { __typename: "ResourceMetadataPermissions", _id: cacheId(`perm:${rid}`), canOpenLink: false },
    branch, defaultBranch: branch,
  };
}

// The editor's REST reads. Each answers only a pipeline the caller holds; null means "not theirs".
export function allInformation(rid, sandboxId, pipelines, userIdOf) {
  const p = pipelines.find((x) => x.rid === rid);
  if (!p) return null;
  const main = mainSandboxIdOf(p.familyRef);
  const got = sandboxesWithSnapshots([{ pipelineRid: rid, sandboxId: sandboxId || main }], pipelines, userIdOf).sandboxes[0];
  if (!got) return null;
  return {
    pipeline: pipelineEntry(p, userIdOf), sandbox: got.sandbox, version: got.version, snapshot: got.snapshot,
    availableInstalledTransforms: [], availableInstalledModels: [],
    // The Hypervisor runs a recipe as a TransformationRun on its own runtime: that is its one compute profile.
    availableBackendSettings: { computeProfiles: [RUNTIME_PROFILE], edgeComputeProfiles: [], defaultComputeProfile: RUNTIME_PROFILE.id, configuration: {} },
    settings: { settings: { protectionsForPublishedSandboxes: { allowDirectPush: false } }, version: uuidOf(`${p.familyRef}#settings`) },
    mainSandbox: main,
  };
}
export function allSandboxes(rid, pipelines, userIdOf) {
  const p = pipelines.find((x) => x.rid === rid);
  if (!p) return null;
  const requests = [mainSandboxIdOf(p.familyRef), ...p.openChangeSets.map((cs) => changeSetSandboxIdOf(cs.change_set_ref))].map((sandboxId) => ({ pipelineRid: rid, sandboxId }));
  return { sandboxes: sandboxesWithSnapshots(requests, pipelines, userIdOf).sandboxes.map((s) => s.sandbox) };
}

// ---- CREATE (cut 2c): the create form opens a FOUNDING change set for a new DataRecipe family. A recipe
// family is held in the owner's recipe registry, never in a project, so the form's location dialog offers
// that registry as its one location ("Data recipes") and a project folder is refused by name. A recipe runs
// as a TransformationRun on the Hypervisor's own runtime: the standard batch choice (Spark) is that; the
// faster (DataFusion), streaming (Flink) and external (Databricks, Snowflake) choices have no counterpart and
// are refused by name. The family's token is the name, slugged; a name whose family exists is refused.
export const RECIPE_REGISTRY = {
  project_id: "hypervisor-data-recipes",
  name: "Data recipes",
  description: "The owner's DataRecipe registry: a recipe family is held here, never in a project.",
  open_url: "/data/recipes",
  created_at: "2026-09-27T00:00:00Z",
};
export const familySlugOf = (name) => String(name || "").toLowerCase().replace(/[^a-z0-9._-]+/gu, "-").replace(/^[^a-z0-9]+/u, "").replace(/-+$/u, "").slice(0, 128);
const BACKEND_REFUSALS = {
  DataFusion: "the faster compute (DataFusion) has no Hypervisor counterpart: a recipe runs as a TransformationRun on the Hypervisor's own runtime — choose Standard",
  Flink: "a streaming pipeline has no Hypervisor counterpart: a recipe runs as one TransformationRun at a time — choose a batch pipeline",
  Databricks: "external compute has no Hypervisor counterpart: a recipe runs on the Hypervisor's own runtime — choose Standard",
  Snowflake: "external compute has no Hypervisor counterpart: a recipe runs on the Hypervisor's own runtime — choose Standard",
};
export function createPipelinePlan(body, pipelines, registryFolderRid) {
  const req = body?.createRequest || body || {};
  const name = String(req.name || "").trim();
  if (!name) return { issue: "a pipeline needs a name" };
  if (name.length > 200) return { issue: "a pipeline name is at most 200 characters" };
  if (req.parentFolder !== registryFolderRid) return { issue: "a DataRecipe family is held in the owner's recipe registry, never in a project — choose Data recipes as the location" };
  const backend = req.backend || "Spark";
  if (backend !== "Spark") return { issue: BACKEND_REFUSALS[backend] || `the ${backend} compute has no Hypervisor counterpart — choose Standard` };
  const family = familySlugOf(name);
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(family)) return { issue: "the name must contain a letter or digit" };
  if (pipelines.some((p) => p.familyRef === `data-recipe://${family}`)) return { issue: `a pipeline over the recipe family ${family} already exists — choose another name` };
  // Initial datasets from the form's "add initial datasets" are not a recipe's inputs (a recipe reads
  // connector mappings); they are refused rather than dropped.
  if (Array.isArray(body?.initialDisplay?.initialDisplay?.datasets) && body.initialDisplay.initialDisplay.datasets.length) return { issue: "initial datasets are not a recipe's inputs (a recipe reads connector-mapping revisions) — create the pipeline without them" };
  return { family, title: name, draft: { name } };
}
// The created pipeline and its initial sandbox — the founding change set's draft sandbox.
export function createPipelineAnswer(familyRef, changeSet, pipelines, userIdOf) {
  const p = pipelines.find((x) => x.familyRef === familyRef);
  if (!p) return null;
  const sandboxId = changeSetSandboxIdOf(changeSet.change_set_ref);
  const got = sandboxesWithSnapshots([{ pipelineRid: p.rid, sandboxId }], pipelines, userIdOf).sandboxes[0];
  return got ? { pipeline: pipelineEntry(p, userIdOf), initialSandbox: got.sandbox } : null;
}

// ---- PROPOSALS (read, R-241 / ADR 0056 P4): a change set that has been PROPOSED is an open proposal, a merged one
// is merged (its version ids exact: the draft merged, the head it was opened on, the revision it became), and a
// rejected or abandoned one is closed. An open (never proposed) change set is a branch, not a proposal. What the
// daemon does not keep — reviews, comments, a propose time — is empty or named, never invented.
export const proposalIdOf = (changeSetRef) => uuidOf(`${changeSetRef}#proposal`);
export const proposalRidOf = (changeSetRef) => `ri.eddie.main.proposal.${proposalIdOf(changeSetRef)}`;
export const draftVersionIdOf = (changeSetRef, ordinal) => uuidOf(`${changeSetRef}#draft/${ordinal}`);
export const revisionVersionIdOf = (familyRef, revisionRef) => uuidOf(revisionRef || `${familyRef}#root`);
const PROPOSAL_KIND = { proposed: "open", merged: "merged", rejected: "closed", abandoned: "closed" };
export function proposalOf(p, cs, userIdOf) {
  const kind = PROPOSAL_KIND[cs?.status];
  if (!kind) return null;
  const status = kind === "open" ? { type: "open", open: {} }
    : kind === "closed" ? { type: "closed", closed: {} }
      : { type: "merged", merged: { sourceVersionId: draftVersionIdOf(cs.change_set_ref, cs.merge?.draft_ordinal || (cs.drafts || []).length), targetVersionId: revisionVersionIdOf(p.familyRef, cs.subject?.base_revision_ref), mergedVersionId: uuidOf(cs.merge?.resulting_revision_ref) } };
  return {
    id: proposalIdOf(cs.change_set_ref), proposalRid: proposalRidOf(cs.change_set_ref), pipelineRid: p.rid,
    // the change set's own chain head moves on every transition: the optimistic token a write would send back
    version: cs.admitted_head || uuidOf(`${cs.change_set_ref}#${cs.updated_at}`),
    status,
    details: { name: cs.title, description: cs.description || "", sourceSandbox: changeSetSandboxIdOf(cs.change_set_ref), targetSandbox: mainSandboxIdOf(p.familyRef) },
    // no propose time is kept: "opened on" is the change set's own opening
    attribution: { time: iso(cs.created_at), user: userIdOf(cs.author_principal_ref) },
  };
}
export function proposalsPage(p, body, limit, userIdOf) {
  const want = { OPEN: "open", MERGED: "merged", CLOSED: "closed" }[body?.statusKind] || null;
  const sources = new Set((body?.sourceSandboxIds || []).filter(Boolean));
  const all = [...p.changeSets].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))
    .map((cs) => proposalOf(p, cs, userIdOf)).filter(Boolean)
    .filter((x) => !want || x.status.type === want)
    .filter((x) => !sources.size || sources.has(x.details.sourceSandbox));
  const offset = Number(body?.pageToken) > 0 ? Number(body.pageToken) : 0;
  const n = Number(limit) > 0 ? Math.min(Number(limit), 100) : 20;
  const page = all.slice(offset, offset + n);
  return offset + n < all.length ? { proposals: page, pageToken: String(offset + n) } : { proposals: page };
}
// The caller's proposal a request names — by pipeline and id, or by its rid alone.
export function findProposal(pipelines, { pipelineRid, proposalId, proposalRid }) {
  for (const p of pipelines) {
    if (pipelineRid && p.rid !== pipelineRid) continue;
    for (const cs of p.changeSets) {
      if (!PROPOSAL_KIND[cs.status]) continue;
      if ((proposalId && proposalIdOf(cs.change_set_ref) === proposalId) || (proposalRid && proposalRidOf(cs.change_set_ref) === proposalRid)) return { p, cs };
    }
  }
  return null;
}
// A version of the caller's pipeline by its id: an admitted revision, the family's root, a change set's draft,
// or a change set's root (draft 0: the head it was opened on). null when the caller holds no such version.
export function versionOf(p, versionId, userIdOf) {
  const details = (message, time, user) => ({ id: versionId, message, attribution: { time: iso(time), user: userIdOf(user || "unknown") }, backend: "Spark" });
  for (const r of p.revisions) {
    if (uuidOf(r.revision_ref) !== versionId) continue;
    const merged = p.changeSets.find((cs) => cs.merge?.resulting_revision_ref === r.revision_ref);
    return { details: details(`Revision ${String(r.revision_ref).split("/").pop()}`, r.admitted_at, merged?.merge?.merged_by_principal_ref || merged?.author_principal_ref || r.owner_ref), body: r };
  }
  if (uuidOf(`${p.familyRef}#root`) === versionId) return { details: details("Root", p.createdAt, p.author), body: null };
  for (const cs of p.changeSets) {
    for (const d of cs.drafts || []) {
      if (draftVersionIdOf(cs.change_set_ref, d.ordinal) === versionId) return { details: details(`Draft ${d.ordinal}`, d.drafted_at, d.author_principal_ref || cs.author_principal_ref), body: d.body };
    }
    if (draftVersionIdOf(cs.change_set_ref, 0) === versionId) {
      const base = p.revisions.find((r) => r.revision_ref === cs.subject?.base_revision_ref) || null;
      return { details: details("Root", cs.created_at, cs.author_principal_ref), body: base };
    }
  }
  return null;
}
const EMPTY_DISPLAY = { transforms: [], targets: [], groups: [], datasets: [], mediaSets: [], charts: [], sources: [], clusters: [], colorDisplayNodes: [], displayFolders: [], textNodes: [], colorPalettes: [] };
export function versionConfiguration(v) {
  return { details: v.details, snapshot: { ...snapshotOf(v.body), samplingStrategies: {} }, display: EMPTY_DISPLAY, packaging: null, unitTests: { tests: [], data: [] }, evalSuites: { evalSuites: [], metInputsByEvalSuite: [] } };
}
// The diff between two versions: outputs added or removed (by target id) — a recipe's transforms are not
// derived into the reference's (ADR 0057, proposed), so there are none to compare, and none is claimed.
export function diffBetween(leftBody, rightBody) {
  const left = new Set(targetsOf(leftBody).map((t) => t.id));
  const right = new Set(targetsOf(rightBody).map((t) => t.id));
  const targetChanges = [
    ...[...right].filter((id) => !left.has(id)).map((targetId) => ({ type: "targetAdded", targetAdded: { targetId } })),
    ...[...left].filter((id) => !right.has(id)).map((targetId) => ({ type: "targetDeleted", targetDeleted: { targetId } })),
  ];
  // unit tests and packaging are unions the app visits (with an unknown fallback): a version keeps neither, so "none"
  return { diff: { instantiatedTransformChanges: [], groupedTransformChanges: [], groupedExpressionChanges: [], targetChanges, pipelineArgumentChanges: [] }, displayDiff: { type: "none", none: {} }, unitTestDiff: { type: "none", none: {} }, packagingDiff: { type: "none", none: {} }, backendChange: null };
}
// The GraphQL facts of a proposal: its source sandbox (no global branch; the Spark backend) and its events.
const EVENT = (type, time, userRef, extra, userIdOf, key) => ({ __typename: `EddieProposalEvent_${type}`, __implements: ["EddieProposalEvent"], _id: cacheId(`pevent:${key}`), created: { __typename: "Attribution", time: iso(time), user: userRef ? { __typename: "User", _id: cacheId(`user:${userRef}`), id: userIdOf(userRef), username: null, displayName: null, fullName: null } : null }, ...extra });
export function proposalFacts(p, cs, userIdOf) {
  const sandboxId = changeSetSandboxIdOf(cs.change_set_ref);
  const events = [EVENT("Created", cs.created_at, cs.author_principal_ref, { name: cs.title, description: cs.description || "" }, userIdOf, `${cs.change_set_ref}#created`)];
  for (const d of (cs.drafts || []).filter((x) => x.ordinal >= 2)) {
    events.push(EVENT("CodeChanged", d.drafted_at, d.author_principal_ref, { newVersion: { __typename: "EddieSandboxVersion", _id: cacheId(`version:${draftVersionIdOf(cs.change_set_ref, d.ordinal)}`), versionId: draftVersionIdOf(cs.change_set_ref, d.ordinal) } }, userIdOf, `${cs.change_set_ref}#draft/${d.ordinal}`));
  }
  if (cs.status === "rejected") {
    events.push(EVENT("Reviewed", cs.updated_at, null, { checkId: null, decision: "DENIED", reason: { __typename: "Comment", _id: cacheId(`reason:${cs.change_set_ref}`), id: uuidOf(`${cs.change_set_ref}#reason`), message: cs.decision_note || "", mentionedUsers: [], mentionedGroups: [], reactions: [], created: { __typename: "Attribution", time: iso(cs.updated_at), user: null } } }, userIdOf, `${cs.change_set_ref}#reviewed`));
    events.push(EVENT("Closed", cs.updated_at, null, {}, userIdOf, `${cs.change_set_ref}#closed`));
  }
  if (cs.status === "abandoned") events.push(EVENT("Closed", cs.updated_at, null, {}, userIdOf, `${cs.change_set_ref}#closed`));
  if (cs.status === "merged") events.push(EVENT("Merged", cs.merge?.merged_at || cs.updated_at, cs.merge?.merged_by_principal_ref, {}, userIdOf, `${cs.change_set_ref}#merged`));
  return {
    __typename: "EddiePipelineProposal", _id: cacheId(`proposal:${cs.change_set_ref}`), id: proposalIdOf(cs.change_set_ref),
    // a change set is a patch branch of one family, not a global branch
    sourceSandbox: { __typename: "EddieSandbox", _id: cacheId(`sandbox:${sandboxId}`), sandboxId, globalBranch: null, latestVersion: { __typename: "EddieSandboxVersion", _id: cacheId(`latest:${sandboxId}`), backend: "Spark" } },
    events: { __typename: "EddieProposalEventPage", nextPageToken: null, values: events },
  };
}

// ---- HISTORY (read, R-241): a sandbox's version timeline. Main's versions are the family's admitted revisions
// (one a change set merged is a merged-proposal row; one admitted directly is a saved version) and its deployments
// are the family's TransformationRuns; a change set's versions are its drafts, and it has no deployment. What a
// run does not record — jobs, tasks, a build, who started it — is empty or null, never invented.
const RUN_STATUS = { running: "InProgress", completed: "Succeeded", failed: "Failed", rejected: "Failed" };
const userFact = (ref, userIdOf) => (ref ? { __typename: "User", _id: cacheId(`user:${ref}`), id: userIdOf(ref), username: null, displayName: null, fullName: null } : null);
const attributionFact = (time, ref, userIdOf) => ({ __typename: "Attribution", time: iso(time), user: userFact(ref, userIdOf) });
const versionRefFact = (versionId) => (versionId ? { __typename: "EddieSandboxVersion", _id: cacheId(`version:${versionId}`), versionId } : null);
// The family's runs, one per run id (its latest admission), oldest first.
export function runsOfPipeline(p) {
  const byId = new Map();
  for (const r of p.runs || []) if (r?.transformation_run_id) byId.set(r.transformation_run_id, r);
  return [...byId.values()].sort((a, b) => String(a.admitted_at || "").localeCompare(String(b.admitted_at || "")));
}
function deploymentFact(p, run) {
  const versionId = uuidOf(run.data_recipe_revision_ref);
  const revision = p.revisions.find((r) => r.revision_ref === run.data_recipe_revision_ref) || null;
  const kind = RUN_STATUS[run.execution_status];
  return {
    __typename: "EddieSandboxDeployment", __implements: ["EddieSandboxTimelineEvent"], _id: cacheId(`deployment:${run.transformation_run_id}`),
    id: uuidOf(run.transformation_run_id),
    // a run record names no principal
    created: attributionFact(run.admitted_at, null, null),
    // nothing executes a queued run yet: it carries no status, so its row reads "did not run" rather than "Deployed logic"
    status: kind ? { __typename: `EddieSandboxDeploymentStatus_${kind}`, __implements: ["EddieSandboxDeploymentStatus"], tasks: [] } : null,
    jobsV2: [], stateChanges: null,
    // a run is of an admitted revision: Main's (the editor's deployment watcher reads the sandbox it deployed)
    sandboxVersion: { __typename: "EddieSandboxVersion", _id: cacheId(`version:${versionId}`), versionId, sandbox: { __typename: "EddieSandbox", _id: cacheId(`sandbox:${mainSandboxIdOf(p.familyRef)}`), sandboxId: mainSandboxIdOf(p.familyRef) }, snapshot: { __typename: "EddieSandboxSnapshot", targets: targetsOf(revision).map((t) => ({ __typename: "EddieTarget", id: t.id })) } },
  };
}
// The deployment the family is on: its latest COMPLETED run — "Currently deployed" is claimed only for a revision
// that finished a run, never for one a queued run names.
export function currentDeploymentOf(p) {
  const run = runsOfPipeline(p).filter((r) => r.execution_status === "completed").at(-1);
  return run ? deploymentFact(p, run) : null;
}
// A sandbox's versions, newest first; null when the sandbox is not the pipeline's.
export function versionsOfSandbox(p, sandboxId) {
  if (sandboxId === mainSandboxIdOf(p.familyRef)) {
    return p.revisions.map((r) => {
      const merged = p.changeSets.find((cs) => cs.merge?.resulting_revision_ref === r.revision_ref) || null;
      const prev = r.succession?.predecessor_revision_ref || null;
      // a revision admitted directly names no admitting principal (only its owner, an organization)
      return { versionId: uuidOf(r.revision_ref), previousVersionId: prev ? uuidOf(prev) : null, time: r.admitted_at, user: merged?.merge?.merged_by_principal_ref || null, merged, message: `Revision ${String(r.revision_ref).split("/").pop()}` };
    }).reverse();
  }
  const cs = p.changeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === sandboxId);
  if (!cs) return null;
  const base = cs.subject?.base_revision_ref || null;
  const drafts = [...(cs.drafts || [])].sort((a, b) => a.ordinal - b.ordinal);
  // draft 1 follows the head the change set was opened on (none for a founding change set: "Branch created")
  return drafts.map((d, i) => ({ versionId: draftVersionIdOf(cs.change_set_ref, d.ordinal), previousVersionId: i > 0 ? draftVersionIdOf(cs.change_set_ref, drafts[i - 1].ordinal) : (base ? uuidOf(base) : null), time: d.drafted_at, user: d.author_principal_ref || cs.author_principal_ref, merged: null, message: `Draft ${d.ordinal}` })).reverse();
}
function versionEventFact(v, userIdOf) {
  const cs = v.merged;
  return {
    __typename: "EddieSandboxVersion", __implements: ["EddieSandboxTimelineEvent"], _id: cacheId(`version:${v.versionId}`),
    versionId: v.versionId, previousVersion: versionRefFact(v.previousVersionId), created: attributionFact(v.time, v.user, userIdOf),
    proposal: cs ? { __typename: "EddiePipelineProposal", _id: cacheId(`proposal:${cs.change_set_ref}`), id: proposalIdOf(cs.change_set_ref), name: cs.title, sourceSandbox: { __typename: "EddieSandbox", _id: cacheId(`sandbox:${changeSetSandboxIdOf(cs.change_set_ref)}`), sandboxId: changeSetSandboxIdOf(cs.change_set_ref), name: cs.title } } : null,
  };
}
// The History facts of one sandbox, scoped by the request's variables (the timeline's filter and page; the compare
// view's start version). The compare view selects `versionHistoryV2` twice under two aliases, so those facts are
// keyed `alias:field` (adopted-graphql.mjs).
export function historyFacts(p, sandboxId, variables, userIdOf) {
  const versions = versionsOfSandbox(p, sandboxId) || [];
  const onMain = sandboxId === mainSandboxIdOf(p.familyRef);
  const asked = (variables?.filter?.eventTypesToInclude || []).filter(Boolean);
  const kinds = new Set(asked.length ? asked : ["DEPLOYMENT", "VERSION"]);
  const events = [];
  if (kinds.has("VERSION")) for (const v of versions) events.push({ at: v.time, fact: versionEventFact(v, userIdOf) });
  if (kinds.has("DEPLOYMENT") && onMain) for (const r of runsOfPipeline(p).reverse()) events.push({ at: r.admitted_at, fact: deploymentFact(p, r) });
  events.sort((a, b) => String(b.at || "").localeCompare(String(a.at || "")));
  const offset = Number(variables?.pageToken) > 0 ? Number(variables.pageToken) : 0;
  const n = Number(variables?.pageSize) > 0 ? Math.min(Number(variables.pageSize), 100) : 20;
  const entry = (versionId, message) => ({ __typename: "EddieSandboxVersion", _id: cacheId(`version:${versionId}`), versionId, backend: "Spark", commitMessage: message });
  const page = (values) => ({ __typename: "EddieSandboxVersionPage", values, nextPageToken: null });
  const start = versions.find((v) => v.versionId === variables?.startVersionId) || (variables?.startVersionId ? null : versions[0]);
  const fromVersion = [];
  if (start) {
    fromVersion.push(entry(start.versionId, start.message));
    // the previous version may be Main's (draft 1 follows the head its change set was opened on)
    const prev = start.previousVersionId ? versionOf(p, start.previousVersionId, userIdOf) : null;
    if (prev) fromVersion.push(entry(start.previousVersionId, prev.details.message));
  }
  return {
    currentDeployment: onMain ? currentDeploymentOf(p) : null,
    eventTimeline: { __typename: "EddieSandboxEventTimelinePage", values: events.slice(offset, offset + n).map((e) => e.fact), nextPageToken: offset + n < events.length ? String(offset + n) : null },
    versionHistoryV2: page(versions.map((v) => entry(v.versionId, v.message))),
    "historyFromLatest:versionHistoryV2": page(versions.slice(0, 1).map((v) => entry(v.versionId, v.message))),
    "historyFromVersion:versionHistoryV2": page(fromVersion),
    backingBranchName: onMain ? "master" : (p.changeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === sandboxId)?.change_set_ref || null),
    fallbackBranchNames: onMain ? [] : ["master"],
  };
}

// ---- DEPLOY (named, R-241): a deploy admits a TransformationRun of Main's head revision. The builder admits none
// yet and nothing executes a queued run, so the deploy panel's check answers "not deployable" with the reason (its
// Errors tab prints the message verbatim), and a direct deploy is refused with the same error. No run is admitted.
export const knowsSandbox = (p, sandboxId) => sandboxId === mainSandboxIdOf(p.familyRef) || p.changeSets.some((cs) => changeSetSandboxIdOf(cs.change_set_ref) === sandboxId);
export function deployRefusalOf(p, sandboxId) {
  const message = sandboxId !== mainSandboxIdOf(p.familyRef)
    ? "This branch is a change set: its drafts are not admitted revisions, so there is nothing on it to run. Propose it and merge it into Main; a deploy runs Main's head revision."
    : !p.head
      ? "Main holds no admitted revision yet, so there is nothing to run. Merge a change set into Main first; a deploy runs Main's head revision as a TransformationRun."
      : `A deploy admits a TransformationRun of Main's head revision (Revision ${String(p.head.revision_ref).split("/").pop()}). The Pipeline Builder does not admit runs yet, and nothing executes a queued run. Runs admitted through the transformation-run plane appear in History.`;
  // a type the app does not know: its Errors tab shows "Pipeline cannot be deployed" with Details printing the message
  return { type: "hypervisorDeployNotAdmitted", errorName: "Hypervisor:DeployNotAdmitted", message };
}
export const checkDeployableAnswer = (p, sandboxId) => ({ type: "notDeployable", notDeployable: { errors: [deployRefusalOf(p, sandboxId)], supportedStateOverrides: { supportedStateStrategyOverrides: [] } } });
export const deployAnswer = (p, sandboxId, versionId) => ({ versionId, result: { type: "failed", failed: { errors: [deployRefusalOf(p, sandboxId)] } } });

// ---- THE EDITOR'S WRITES (cut 2d, R-241 / ADR 0056 P4): the caller may edit their own pipelines. A Save is a draft
// on the branch's change set; Main is protected (only a merged change set moves it), so the app's own protected-branch
// Save opens a change set from Main's head first. Proposing validates and proposes the change set under the name the
// dialog gave; merging admits its latest draft as the family's next revision; denying rejects it with the reason. What
// a draft cannot hold is refused by name, never dropped: a recipe keeps no transform graph yet (ADR 0057, proposed),
// and an output with no declared contract has nothing to bind.
export const EDIT_OPERATION = "eddie:edit-pipeline";
const ADMISSION_FIELDS = ["name", "ontology_revision_refs", "input_source_types", "connector_mapping_revision_refs", "output_object_model_refs", "output_dataset_contract_refs", "transformation_steps", "policy_bound_data_view_refs", "receipt_obligations", "effective_policy_hash", "registry_status"];
// A revision or draft body projected back to what a draft may carry (admission-owned fields are the merge's).
export function admissionProjection(body) {
  const out = {};
  for (const k of ADMISSION_FIELDS) if (body && body[k] !== undefined) out[k] = body[k];
  return out;
}
const refusal = (status, errorName, message) => ({ refused: { status, errorName, message } });
// createSandbox (POST …/sandboxes/create-v3): a branch is a change set opened on the family's head, drafted as that head.
export function createSandboxPlan(p, req) {
  const name = String(req?.name || "").trim();
  if (!name || name.length > 200) return refusal(400, "PipelineBuilder:InvalidSandboxName", "a branch has a name of at most 200 characters");
  const main = mainSandboxIdOf(p.familyRef);
  if (req?.fromSandbox && req.fromSandbox !== main) return refusal(400, "Eddie:BranchFromBranchNotSupported", "a branch is a change set opened on its family's head: branch from Main");
  const headVersion = revisionVersionIdOf(p.familyRef, p.head?.revision_ref);
  if (req?.fromVersion && req.fromVersion !== headVersion) return refusal(400, "Eddie:BranchFromOlderVersionNotSupported", "a change set is opened on the family's head revision, never an older one: open it on Main's latest version");
  const draft = p.head ? { ...admissionProjection(p.head), succession_reason: "correction" } : { name: p.name };
  return { family: familyToken(p.familyRef), title: name, draft };
}
const kept = (list) => (Array.isArray(list) ? list : []).filter(Boolean);
const isEmptyish = (v) => v == null || (Array.isArray(v) && v.length === 0) || (typeof v === "object" && !Array.isArray(v) && Object.values(v).every(isEmptyish));
// pushSnapshotToSandbox (POST …/sandboxes/{id}/push): the Save. The draft body starts from the branch's latest draft and
// takes the snapshot's outputs; everything the editor cannot express (ontologies, mappings, steps, policy) is carried.
export function pushPlan(p, sandboxId, req, ontologyCatalog = null) {
  if (sandboxId === mainSandboxIdOf(p.familyRef)) return refusal(409, "PipelineBuilder:SandboxIsProtected", "Main moves only when a change set merges: save to a branch");
  const cs = p.changeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === sandboxId);
  if (!cs) return refusal(404, "Eddie:SandboxNotFound", "no branch of yours is this sandbox");
  if (!OPEN.has(cs.status)) return refusal(409, "PipelineBuilder:SandboxIsArchived", `this branch's change set is ${cs.status}; open a new branch from Main`);
  const drafts = [...(cs.drafts || [])].sort((a, b) => a.ordinal - b.ordinal);
  const latest = drafts.at(-1) || null;
  if (req?.currentVersionId !== draftVersionIdOf(cs.change_set_ref, latest?.ordinal || 0)) return refusal(409, "PipelineBuilder:SandboxEditConflict", "this branch has a newer version than the one you edited");
  if (req?.backend && req.backend !== "Spark") return refusal(400, "Eddie:BackendNotSupported", "a recipe runs as a TransformationRun on the Hypervisor's own runtime (the standard batch backend)");
  const snap = req?.snapshot || {};
  if (kept(snap.transforms).length || kept(snap.groups).length || kept(snap.groupedExpressions).length) return refusal(400, "Eddie:TransformsNotKept", "a DataRecipe revision keeps no transform graph yet (ADR 0057, proposed): only its outputs can be saved; remove the transforms to save");
  if (!isEmptyish(req?.unitTests) || !isEmptyish(req?.evalSuites) || kept(req?.packaging?.inputDatasets).length) return refusal(400, "Eddie:NotKeptByARecipe", "a recipe keeps no unit tests, evaluation suites or packaging");
  const base = latest?.body || p.revisions.find((r) => r.revision_ref === cs.subject?.base_revision_ref) || { name: p.name };
  const objects = new Map(kept(base.output_object_model_refs).map((ref) => [`ri.ontology.main.object-type.${uuidOf(ref)}`, ref]));
  const datasets = new Map(kept(base.output_dataset_contract_refs).map((ref) => [`ri.foundry.main.dataset.${uuidOf(ref)}`, ref]));
  const keepObjects = [], keepDatasets = [];
  for (const t of kept(snap.targets)) {
    const target = t.target || {};
    const ref = target.type === "object" ? objects.get(target.object?.rid) : target.type === "dataset" ? datasets.get(target.dataset?.datasetRid) : undefined;
    if (!ref) return refusal(400, "Eddie:OutputHasNoContract", "a new output names no declared dataset contract or object model: a recipe's outputs bind declared contracts, and minting one from a name would point at nothing");
    (target.type === "object" ? keepObjects : keepDatasets).push(ref);
  }
  const body = admissionProjection(base);
  // an output list the base never declared stays undeclared while it is empty
  if (keepObjects.length || base.output_object_model_refs !== undefined) body.output_object_model_refs = keepObjects;
  if (keepDatasets.length || base.output_dataset_contract_refs !== undefined) body.output_dataset_contract_refs = keepDatasets;
  const requestedOntology = snap.targetSettings?.objectTargetSettings?.ontologyRid || null;
  let ontologyChanged = false;
  if (requestedOntology && ontologyCatalog) {
    const applied = applyTargetOntology(body, requestedOntology, ontologyCatalog);
    if (applied.refused) return applied;
    Object.assign(body, applied.body);
    ontologyChanged = !!applied.changed;
  }
  if (cs.subject?.base_revision_ref) {
    const same = (a, b) => JSON.stringify([...kept(a)].sort()) === JSON.stringify([...kept(b)].sort());
    body.succession_reason = ontologyChanged ? "ontology_revision_change" : !same(base.output_dataset_contract_refs, keepDatasets) ? "output_contract_change" : !same(base.output_object_model_refs, keepObjects) ? "object_model_change" : (base.succession_reason || "correction");
  }
  const unchanged = latest && JSON.stringify(admissionProjection(latest.body)) === JSON.stringify(admissionProjection(body)) && (latest.body?.succession_reason || null) === (body.succession_reason || null);
  return unchanged ? { unchanged: true, versionId: draftVersionIdOf(cs.change_set_ref, latest.ordinal), changeSet: cs } : { draft: body, changeSet: cs };
}
// createProposal (POST …/proposals/create): a branch proposed into Main, under the dialog's name and description.
export function proposalCreatePlan(p, req) {
  const d = req?.proposalDetails || {};
  if (d.targetSandbox !== mainSandboxIdOf(p.familyRef)) return refusal(400, "Eddie:ProposalTargetNotMain", "a change set merges only into its family's head: propose into Main");
  const cs = p.changeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === d.sourceSandbox);
  if (!cs) return refusal(400, "Eddie:ProposalSourceNotABranch", "propose a branch (a change set), never Main itself");
  if (cs.status !== "open") return refusal(409, "Eddie:ProposalAlreadyOpen", cs.status === "proposed" ? "this branch is already proposed" : `this branch's change set is ${cs.status}`);
  const title = String(d.name || "").trim() || cs.title;
  if (title.length > 200) return refusal(400, "Eddie:ProposalNameTooLong", "a proposal's name is at most 200 characters");
  if (String(d.description || "").length > 4000) return refusal(400, "Eddie:ProposalDescriptionTooLong", "a proposal's description is at most 4000 characters");
  return { changeSet: cs, title, description: String(d.description || "") };
}
// The autosave lane: an UNSAVED buffer of the editor (never recipe content), kept per caller, pipeline and branch in
// the serve's memory until it restarts. A version token guards a stale tab, as the reference's own conflict does.
export class WorkStateStore {
  constructor({ maxEntries = 200, maxBytes = 2 * 1024 * 1024 } = {}) { this.entries = new Map(); this.maxEntries = maxEntries; this.maxBytes = maxBytes; }
  key(principal, rid, sandboxId) { return `${principal}\u0000${rid}\u0000${sandboxId}`; }
  get(principal, rid, sandboxId) { return this.entries.get(this.key(principal, rid, sandboxId)) || null; }
  set(principal, rid, sandboxId, request, now = new Date()) {
    const k = this.key(principal, rid, sandboxId);
    const prior = this.entries.get(k);
    if (prior && request?.previousStateVersion !== prior.stateVersion) return { conflict: true };
    const bytes = Buffer.byteLength(JSON.stringify(request?.workState ?? null));
    if (bytes > this.maxBytes) return { tooLarge: true };
    const entry = { workState: request?.workState ?? null, stateVersion: crypto.randomUUID(), savedAt: now.toISOString() };
    this.entries.delete(k);
    this.entries.set(k, entry);
    while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value);
    return { entry };
  }
  clear(principal, rid, sandboxId) { this.entries.delete(this.key(principal, rid, sandboxId)); }
}

// ---- OUTPUT ONTOLOGY (R-240 Arm A: an ontology admitted in the Ontology Manager never reached the builder's picker).
// A recipe's object outputs bind the ontology REVISIONS it declares (`ontology_revision_refs`, each
// `ontology://<namespace>/<name>/revision/<n>`); the builder's "Target ontology" is that revision's ONTOLOGY, named by
// its family. The picker offers the caller's ontologies: every published family (its current version the head
// revision) and every Ontology Manager draft not yet published (no current version: a recipe cannot bind it).
const familyOfRevision = (ref) => String(ref || "").replace(/\/revision\/\d+$/u, "");
export const ontologyRidOfFamily = (family) => `ri.ontology.main.ontology.${uuidOf(family)}`;
// `families` is [{ family, head, name }] (head a revision ref); `drafts` is [{ family, domain, description }].
export function ontologyCatalogOf(families, drafts) {
  const byFamily = new Map();
  for (const f of families || []) if (f?.family) byFamily.set(f.family, { family: f.family, head: f.head || null, displayName: f.name || f.family.replace(/^ontology:\/\//u, ""), description: "" });
  // a draft names the family it publishes into: its domain is the name a person gave it
  for (const d of drafts || []) {
    if (!d?.family) continue;
    const known = byFamily.get(d.family);
    byFamily.set(d.family, { family: d.family, head: known?.head || null, displayName: d.domain || known?.displayName || d.family, description: d.description || "" });
  }
  return [...byFamily.values()].map((o) => ({ ...o, rid: ontologyRidOfFamily(o.family) }));
}
// POST /ontology-metadata/api/ontology/v2/load/all — the builder's ontology map (the picker's names).
export function ontologyLoadAnswer(catalog) {
  return {
    ontologies: Object.fromEntries((catalog || []).map((o) => [o.rid, {
      apiName: o.displayName, displayName: o.displayName, description: o.description || "",
      // an unpublished ontology has no version a recipe could bind
      currentOntologyVersion: o.head, currentSystemOntologyVersion: o.head, defaultBranchRid: null, namespace: o.family,
      ontologyOwnersGroupId: null, ontologyOwnersGroupIds: [], governanceBoardGroupId: null, organizationMarkingIds: [],
      ontologyAdminConfig: { enableUsage: false, suggestProjectsPermissionModel: false }, isShared: false,
      compassNamespaceRid: o.namespaceRid || null, ontologyProjectRid: null, areOrganizationMarkingsInheritedFromNamespace: false, areRolesEnabled: false, roleGrants: [],
      // the rest of the reference's ontology record: no external mappings or restricted grants, no AI search indexing
      restrictedRoleGrants: [], externalMappingConfigurations: [], permissionModel: { type: "rolesEnabled", rolesEnabled: {} },
      isDefaultOntologyMultiOrg: false, semanticSearchIndexingStatus: "AIP_DISABLED", enabledObjectStoragesStatus: "OSV1_DISABLED_FOR_NEW_ENTITIES", ontologyApiNamespaceIdentifier: null,
    }])),
  };
}
// The object target settings a recipe's snapshot carries: the ontology of its first declared ontology revision.
export function targetSettingsOf(recipe) {
  const first = (recipe?.ontology_revision_refs || [])[0];
  return first && (recipe?.output_object_model_refs || []).length ? { objectTargetSettings: { ontologyRid: ontologyRidOfFamily(familyOfRevision(first)) } } : {};
}
// A Save's target ontology, applied to the draft body: unchanged keeps the exact revisions declared; another ontology
// binds its head revision (replacing the revision of the ontology it succeeds), or is refused by name when unpublished.
export function applyTargetOntology(body, requestedRid, catalog) {
  if (!requestedRid) return { body };
  const refs = [...(body.ontology_revision_refs || [])];
  const currentFamily = refs.length ? familyOfRevision(refs[0]) : null;
  if (currentFamily && ontologyRidOfFamily(currentFamily) === requestedRid) return { body };
  const chosen = (catalog || []).find((o) => o.rid === requestedRid);
  if (!chosen) return refusal(400, "Eddie:OntologyNotFound", "the chosen ontology is not one of yours");
  if (!chosen.head) return refusal(400, "Eddie:OntologyNotPublished", `${chosen.displayName} has no published revision yet: publish one in the Ontology Manager (Publish revision), then choose it`);
  const kept = refs.filter((r) => familyOfRevision(r) !== currentFamily);
  return { body: { ...body, ontology_revision_refs: [chosen.head, ...kept] }, changed: true };
}
