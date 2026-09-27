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
