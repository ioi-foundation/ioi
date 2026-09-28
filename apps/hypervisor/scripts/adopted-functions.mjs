// Function-registry facts for adopted reference apps (R-241, ADR 0056 P3 cut 3b). The adopted Automate
// wizard's Function effect — and, next, Ontology Manager's Functions view — read the reference's function
// registry: GraphQL (FunctionResultsQuery, FunctionPreviewQuery, SelectedFunctionQuery,
// GetFunctionDisplayName, GqlFunctionVersionSelectV2Versions, getFunctionParameters, FavoriteFunctionsQuery)
// and REST (GET /function-registry/api/functions/<rid>/metadata, PUT …/resolve). This module answers
// them from the Hypervisor functions plane — RELEASED revisions only, the same set a function step may pin —
// in the reference's own wire shapes. Every value is daemon truth; the reference's recorded answers lend
// structure at most (adopted-graphql.mjs).
//
// The GraphQL resolver ignores field arguments (the facts are pre-scoped), so the root is scoped HERE
// from the request's own variables: which function (`rid` / `functionRid` / a `functionRid` filter
// clause) and which version.
import crypto from "node:crypto";

export const FUNCTION_PREFIX = "ri.function-registry.main.function.";

// fn_<16 hex> laid into UUID grouping (the app parses the suffix as a UUID); reversible.
export function functionRidOf(functionRef) {
  const hex = String(functionRef || "").replace(/^function:\/\//, "").replace(/^fn_/, "").replace(/[^0-9a-f]/g, "").padEnd(16, "0").slice(0, 16);
  return `${FUNCTION_PREFIX}${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(0, 4)}-${hex.slice(4, 16)}`;
}
export function functionIdOf(rid) {
  const tail = String(rid || "").startsWith(FUNCTION_PREFIX) ? String(rid).slice(FUNCTION_PREFIX.length) : "";
  const hex = tail.replace(/-/g, "").slice(0, 16);
  return /^[0-9a-f]{16}$/.test(hex) ? `fn_${hex}` : null;
}
const cacheId = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");
const iso = (t) => (t && !Number.isNaN(Date.parse(t)) ? new Date(t).toISOString() : new Date(0).toISOString());

// Our type algebra in the reference's two encodings: the conjure `rawType` / `dataType` and the GraphQL
// `FunctionDataType_*` union member.
const TYPENAME = { string: "FunctionDataType_String", integer: "FunctionDataType_Integer", double: "FunctionDataType_Double", boolean: "FunctionDataType_Boolean", date: "FunctionDataType_Date", timestamp: "FunctionDataType_Timestamp", list: "FunctionDataType_List" };
export function rawTypeOf(dataType) {
  const scalar = (t) => ({ type: t, [t]: {} });
  return dataType?.type === "list" ? { type: "list", list: { elementsType: scalar(dataType.element_type) } } : scalar(dataType?.type || "string");
}
function typeNode(dataType) {
  const node = { __typename: TYPENAME[dataType?.type] || TYPENAME.string };
  if (dataType?.type === "list") node.elementType = { __typename: TYPENAME[dataType.element_type] || TYPENAME.string };
  return node;
}

function resourceOf(family) {
  const id = String(family.function_ref || "").replace(/^function:\/\//, "");
  const rid = functionRidOf(family.function_ref);
  const perm = { __typename: "ResourceMetadataPermissions", _id: cacheId(`perm:${rid}`), canOpenLink: true };
  const folder = { __typename: "ResourceMetadata", name: "Functions", rid: "ri.compass.main.folder.hypervisor-functions", _id: cacheId("folder:functions"), openUrl: "/ontology/functions", permissions: perm };
  return {
    __typename: "ResourceMetadata", _id: cacheId(`meta:${rid}`), rid, alias: "", name: family.display_name || family.api_name || id,
    openUrl: `/ontology/functions?function=${encodeURIComponent(id)}`, permissions: perm, collections: [], status: null, trashedStatus: "NOT_TRASHED",
    type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-function" },
    ancestors: [{ __typename: "ResourceMetadata", name: "All files", rid: "ri.compass.main.folder.0", _id: cacheId("folder:0"), openUrl: null, permissions: perm }, folder],
    path: `/Functions/${family.display_name || id}`, statusInfo: null, autosaved: false,
  };
}

function versionNode(family, revision) {
  const rid = functionRidOf(family.function_ref);
  return {
    __typename: "FunctionVersion", _id: cacheId(`version:${revision.revision_ref}`), version: revision.version,
    registeredAt: iso(revision.released_at || revision.created_at), documentation: revision.documentation || "",
    inputs: (revision.inputs || []).map((i) => ({ __typename: "FunctionInput", name: i.name, required: !!i.required, rawType: rawTypeOf(i.data_type), type: typeNode(i.data_type), objectTypes: [] })),
    output: typeNode(revision.output?.data_type),
    outputV2: { __typename: "FunctionOutputV2", rawType: rawTypeOf(revision.output?.data_type), objectTypes: [] },
    customTypes: [], logicalTypes: [], branch: null,
    // where the function lives: outside the platform, in the Hypervisor's function registry (the list reads the
    // locator's kind for its Source column — a null locator had crashed the Ontology Manager's Functions section)
    locatorV2: revision.implementation?.runtime === "python3" ? { __typename: "FunctionLocator_Python3" } : { __typename: "FunctionLocator_External", service: "hypervisor", id: revision.revision_ref || family.function_ref },
    function: { __typename: "Function", _id: cacheId(rid), rid, displayName: family.display_name || family.api_name },
  };
}

// One function family as the reference's `Function`, over its released revisions (newest first).
function functionNode(family, released, wantVersion) {
  const rid = functionRidOf(family.function_ref);
  const latest = released[0];
  const chosen = released.find((r) => r.version === wantVersion) || latest;
  const latestNode = latest ? versionNode(family, latest) : null;
  return {
    __typename: "Function", _id: cacheId(rid), rid, displayName: family.display_name || family.api_name,
    description: latest?.documentation || "", apiName: family.api_name || null, ontologyBindings: [],
    // only released functions are offered; none lives in a code repository or a project here
    status: "ACTIVE", visibility: "VISIBLE", repositoryMetadata: null, metadata: { __typename: "FunctionMetadata", _id: cacheId(`metadata:${rid}`), project: null },
    sourceMetadata: resourceOf(family),
    latestVersion: latestNode, latestVersionV2: latestNode,
    version: chosen ? versionNode(family, chosen) : null,
    branch: { __typename: "FunctionBranch", _id: cacheId(`branch:${rid}`), latestVersion: latestNode },
    versionRangeV2: {
      __typename: "FunctionSemanticVersionRangeV2", _id: cacheId(`range:${rid}`),
      versions: { __typename: "FunctionVersionPage", nextPageToken: null, values: released.map((r) => versionNode(family, r)) },
    },
  };
}

// The function a request names, from its own variables.
export function requestedFunctionRid(variables) {
  const v = variables || {};
  if (v.rid && String(v.rid).startsWith(FUNCTION_PREFIX)) return v.rid;
  if (v.functionRid) return v.functionRid;
  const clause = (v.filter?.clauses || []).find((c) => c && c.functionRid);
  return clause ? clause.functionRid : null;
}

// `families`: GET /v1/hypervisor/functions → functions[]; `revisionsFor(fnId)`: the family's revisions
// (GET /v1/hypervisor/functions/:id → revisions[]). Only RELEASED revisions are offered.
export function functionFactsRoot(families, revisionsFor, variables) {
  const offered = (families || []).filter((f) => f.released_revision && f.released_revision.status === "released" && f.released_revision.tool_operable);
  const wantRid = requestedFunctionRid(variables);
  const wantVersion = (variables || {}).version || (variables || {}).functionVersion || null;
  const releasedOf = (family) => {
    const id = String(family.function_ref || "").replace(/^function:\/\//, "");
    const all = revisionsFor(id) || [family.released_revision];
    return all.filter((r) => r && r.status === "released").sort((a, b) => (b.ordinal || 0) - (a.ordinal || 0));
  };
  const target = wantRid ? offered.find((f) => functionRidOf(f.function_ref) === wantRid) : null;
  const scoped = wantRid ? (target ? [target] : []) : offered;
  const values = scoped.map((f) => functionNode(f, releasedOf(f), wantVersion));
  const targetNode = target ? values[0] : null;
  return {
    __typename: "Query",
    favorites: [],
    allOntologies: [],
    function: targetNode,
    functionsV2: { __typename: "FunctionSearchPage", totalNumberOfResults: values.length, nextPageToken: null, values },
    defaultOrGlobalBranch: {
      __typename: "DefaultGlobalBranch", _id: cacheId("branch:default"),
      functions: { __typename: "FunctionSearchPage", totalNumberOfResults: values.length, nextPageToken: null, values },
      function: targetNode,
    },
  };
}

// REST: GET /function-registry/api/functions/<rid>/metadata.
export function functionMetadata(family) {
  return {
    metadata: {
      rid: functionRidOf(family.function_ref), displayName: family.display_name || family.api_name,
      externalId: { type: "hypervisor", hypervisor: { functionRef: family.function_ref } },
      description: family.released_revision?.documentation || "", visibility: { type: "visible", visible: {} },
      apiName: family.api_name || null, ontologyBindings: [], status: null,
    },
  };
}

// REST: PUT /function-registry/api/functions/<rid>/resolve {range, pageSize} → the released specs, newest
// first (an exact range names one version).
export function functionSpecs(family, releasedRevisions, range, pageSize = 1) {
  const exact = /^\d+\.\d+\.\d+$/.test(String(range || "")) ? String(range) : null;
  const specs = releasedRevisions.filter((r) => !exact || r.version === exact).slice(0, Math.max(1, pageSize || 1)).map((r) => ({
    rid: functionRidOf(family.function_ref), typeCategories: [], version: r.version,
    locator: { type: "hypervisor", hypervisor: { revisionRef: r.revision_ref, contentHash: r.content_hash, runtime: r.implementation?.runtime || null } },
    documentation: r.documentation || "",
    inputs: (r.inputs || []).map((i) => ({ name: i.name, description: i.description || "", dataType: rawTypeOf(i.data_type), required: !!i.required, defaultValue: null, constraints: [] })),
    output: { type: "single", single: { description: r.output?.description || null, dataType: rawTypeOf(r.output?.data_type) } },
    registeredTime: iso(r.released_at || r.created_at), customTypes: {}, ontologyProvenance: null, experimental: {},
  }));
  return { specs };
}

export const FUNCTION_OPERATIONS = new Set([
  "FavoriteFunctionsQuery", "FunctionResultsQuery", "AllOntologiesQuery", "FunctionPreviewQuery",
  "SelectedFunctionQuery", "GetFunctionDisplayName", "GqlFunctionVersionSelectV2Versions", "getFunctionParameters",
  // the adopted Ontology Manager's Functions section and its count
  "SearchAllFunctionsQuery", "FunctionsListSearchFunctionsQuery", "FunctionsListFavoritedFunctionsQuery",
]);
