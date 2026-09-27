// The adopted reference Pipeline Builder over Hypervisor truth (R-241, ADR 0056 P4). The app is served
// from the local mirror (never vendored); this module answers what its landing reads, in the app's own
// wire shapes, from the DataRecipe and change-set planes.
//
// A PIPELINE is a DataRecipe family (`data-recipe://<family>`). Canon's patch branch is how a family
// changes, so a pipeline's SANDBOXES are: Main — the family's admitted head (backing branch `master`) —
// and one sandbox per open or proposed change set over the family. A family that so far exists only as a
// founding change set is a pipeline whose Main holds no revision. Nothing here writes; nothing is
// borrowed from the reference's recorded answers except structure (adopted-graphql.mjs).
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
// change set would found. `families` is [{ family_ref, revisions }] (revisions oldest first, as the
// daemon returns them); `changeSets` is the caller's change sets.
export function pipelinesOf(families, changeSets) {
  const byFamily = new Map();
  const ensure = (familyRef) => {
    if (!byFamily.has(familyRef)) byFamily.set(familyRef, { familyRef, revisions: [], changeSets: [] });
    return byFamily.get(familyRef);
  };
  for (const f of families || []) ensure(f.family_ref).revisions = Array.isArray(f.revisions) ? f.revisions : [];
  for (const cs of changeSets || []) {
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

const resourceNode = (rid) => ({ rid, _id: cacheId(`resource:${rid}`), __typename: "ResourceMetadata" });

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
        results: matched.slice(0, pageSize).map((p) => ({ __typename: "ResourceSearchResult", resource: resourceNode(p.rid) })),
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
    // A deploy is a TransformationRun of the head revision; none is bound to this sandbox yet, so the
    // pipeline reads as never deployed rather than borrowing the reference's deployment.
    return { __typename: "Query", eddiePipeline: { ...pipelineNode, sandbox: { __typename: "EddieSandbox", _id: cacheId(`sandbox:${v.sandboxId}`), currentDeployment: null } } };
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
const snapshotOf = (recipe) => ({ transforms: [], targets: targetsOf(recipe), groups: [], groupedExpressions: [], outputs: [], arguments: {}, backendSettings: { configuration: {} }, skippedTransforms: [], persistedTransforms: [] });
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
      const cs = p.openChangeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === r.sandboxId);
      if (!cs) continue;
      const draft = (cs.drafts || []).at(-1);
      const versionId = uuidOf(`${cs.change_set_ref}#draft/${draft?.ordinal || 0}`);
      const author = userIdOf(cs.author_principal_ref);
      sandbox = { id: r.sandboxId, name: cs.title, backingBranch: cs.change_set_ref, fallbackBranches: ["master"], attribution: { time: iso(cs.created_at), user: author }, version: versionId, isArchived: false, isPublished: false };
      version = { id: versionId, message: draft ? `Draft ${draft.ordinal}` : "Root", attribution: { time: iso(draft?.drafted_at || cs.created_at), user: userIdOf(draft?.author_principal_ref || cs.author_principal_ref) }, backend: "Spark" };
    }
    // a change set's sandbox shows its latest draft's declared outputs
    sandboxes.push({ pipelineRid: p.rid, sandbox, version, snapshot: snapshotOf(p.openChangeSets.find((x) => changeSetSandboxIdOf(x.change_set_ref) === r.sandboxId)?.drafts?.at(-1)?.body) });
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
  "ProjectIcebergStorageQuery", "TargetProjectQuery", "DataConnectionSourceQuery", "ComputeExpressionIfAbsentStoresQuery",
  "CurrentDeploymentQuery", "ResolveEddieSandboxToGlobalBranch", "ResourceProjectQuery", "BranchSelectSearchQuery",
  "IssueBadgeData", "WalkthroughsForResourceQuery", "CommunicationChannelsQuery", "BackingObjectQuery", "CompassResourceViewQuery", "SaveResourceDialogQuery",
]);
// Editor reads that name no pipeline (the caller's organization, a dataset, ontologies, branches).
export const PIPELINE_EDITOR_GLOBAL_OPERATIONS = new Set(["OntologiesQuery", "BranchSelectSearchQuery", "CommunicationChannelsQuery", "BackingObjectQuery", "SaveResourceDialogQuery"]);
// Reads keyed by a dataset rid: answered when it is one of the caller's pipelines' declared output datasets.
export const PIPELINE_EDITOR_DATASET_OPERATIONS = new Set(["BackingObjectQuery", "CompassResourceViewQuery"]);
// Whether an operation is the Pipeline Builder's to answer: its landing reads, and its editor reads when they
// name a pipeline, a dataset (the dataset reads), or nothing at all (the global reads). One predicate for the
// bulk and the single-operation gateways.
export function answersPipelineOperation(name, variables) {
  if (PIPELINE_OPERATIONS.has(name)) return true;
  if (!PIPELINE_EDITOR_OPERATIONS.has(name)) return false;
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
export function pipelineEditorFactsRoot(variables, pipelines, userIdOf) {
  const rid = pipelineRidIn(variables);
  const p = rid ? pipelines.find((x) => x.rid === rid) : null;
  const sandboxId = variables?.sandboxId || (p ? mainSandboxIdOf(p.familyRef) : null);
  const known = p && (sandboxId === mainSandboxIdOf(p.familyRef) || p.openChangeSets.some((cs) => changeSetSandboxIdOf(cs.change_set_ref) === sandboxId));
  const sandbox = known ? {
    __typename: "EddieSandbox", _id: cacheId(`sandbox:${sandboxId}`), sandboxId,
    latestVersion: { __typename: "EddieSandboxVersion", _id: cacheId(`version:${sandboxId}`), backend: "Spark" },
    computeExpressionIfAbsentStores: [], globalBranch: null, currentDeployment: null,
  } : null;
  // A dataset the request names: one of the caller's pipelines' declared output datasets backs no object type.
  const datasetRid = (JSON.stringify(variables || {}).match(/ri\.foundry\.main\.dataset\.[0-9a-f-]{36}/u) || [])[0] || null;
  const ownDataset = datasetRid && pipelines.some((x) => [x.head, ...x.openChangeSets.map((cs) => cs.drafts?.at(-1)?.body)].filter(Boolean)
    .some((body) => (body.output_dataset_contract_refs || []).some((ref) => `ri.foundry.main.dataset.${uuidOf(ref)}` === datasetRid)));
  return {
    __typename: "Query",
    // The caller's organization sets no communication controls, and there are no channel categories.
    me: { __typename: "User", _id: cacheId("me"), organization: { __typename: "Organization", _id: cacheId("me:organization"), enrollment: { __typename: "Enrollment", _id: cacheId("me:enrollment"), administratorCommunicationControls: null } } },
    communicationChannelCategories: [],
    // the create form's location dialog: no favorites or recents are kept
    favorites: [], recents: [],
    catalogDataset: ownDataset ? { __typename: "CatalogDataset", _id: cacheId(`dataset:${datasetRid}`), backsObjectTypes: [] } : null,
    // The Hypervisor's ontologies are not offered as output targets yet (the editor's outputs cut).
    allOntologies: [],
    // no global branches exist (a change set is a patch branch of one family, not a global branch)
    globalBranchDropdownSearchByCreatedAtDescending: { __typename: "GlobalBranchPage", values: [], nextPageToken: null },
    eddiePipeline: p ? { __typename: "EddiePipeline", _id: cacheId(`pipeline:${p.rid}`), sandbox } : null,
    resourceMetadata: p ? pipelineResource(p, userIdOf) : (ownDataset ? datasetResource(datasetRid, pipelines) : null),
  };
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
    // The Hypervisor runs a recipe as a TransformationRun on its own runtime; it offers no compute profiles.
    availableBackendSettings: { computeProfiles: [], edgeComputeProfiles: [], defaultComputeProfile: null, configuration: {} },
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
