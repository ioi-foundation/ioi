// The adopted Ontology Manager's answers over Hypervisor truth (R-241, Ontology Manager cut O1).
//
// The reference app (booted by the local mirror, routed at /workspace/ontology) reads the ontology through the
// Ontology Metadata service's REST reads and a handful of GraphQL list queries. Each is answered here from the
// caller's ODK domain ontologies: an ontology per family (the same rids the Pipeline Builder's picker names), each
// with the object types, properties, action types and value types of its canonical object model. What the Hypervisor
// does not keep is answered empty in the reference's own shape, or — for a read not bound yet — refused by the
// serve's ontology fence. Nothing recorded is served: the recorded answers lend STRUCTURE to the GraphQL documents only.
import { uuidOf, ontologyRidOfFamily } from "./adopted-pipeline.mjs";

const rid = (kind, key) => `ri.ontology.main.${kind}.${uuidOf(key)}`;
const pascal = (s) => String(s || "").replace(/[^A-Za-z0-9]+(.)?/gu, (_, c) => (c ? c.toUpperCase() : "")).replace(/^./u, (c) => c.toUpperCase()) || "Unnamed";
const camel = (s) => { const p = pascal(s); return p.charAt(0).toLowerCase() + p.slice(1); };
const list = (v) => (Array.isArray(v) ? v : []).filter((e) => e && e.id);

// An ODK value type (`value_type` on a property, `base` on a value type) as the reference's property base type.
const BASE_TYPE = {
  string: { type: "string", string: { analyzerOverride: null, isLongText: false, supportsExactMatching: true, supportsEfficientLeadingWildcard: null, supportsFullTextRegex: null, supportsPhonetic: null, enableAsciiFolding: null } },
  integer: { type: "integer", integer: {} }, long: { type: "long", long: {} }, double: { type: "double", double: {} },
  boolean: { type: "boolean", boolean: {} }, date: { type: "date", date: {} }, timestamp: { type: "timestamp", timestamp: {} },
};
export const baseTypeOf = (valueType) => BASE_TYPE[String(valueType || "string").toLowerCase()] || BASE_TYPE.string;

// The caller's ontologies: one per ODK domain ontology (its family, as the Pipeline Builder names it), with its model.
export function ontologyModelsOf(domainOntologies, ownerRef, familyOf) {
  return (domainOntologies || []).map((d) => {
    const family = familyOf(d.id, ownerRef)?.family;
    if (!family) return null;
    const model = d.canonical_object_model || {};
    const valueTypes = list(model.value_types);
    // a property's value type is a base type or one of the ontology's declared value types (resolved to its base)
    const baseOf = (vt) => valueTypes.find((v) => v.id === vt)?.base || vt;
    const objectTypes = list(model.object_types).map((ot) => {
      const properties = list(ot.properties).map((p) => ({ ...p, base: baseOf(p.value_type), rid: rid("property", `${family}/${ot.id}/${p.id}`) }));
      const title = properties.find((p) => p.id === ot.title_property) || properties[0] || null;
      return { ...ot, rid: rid("object-type", `${family}/${ot.id}`), properties, titleRid: title?.rid || null, primaryKey: title?.id || null };
    });
    return {
      rid: ontologyRidOfFamily(family), family, draftId: d.id, displayName: d.domain || family, description: d.description || "",
      revision: Number(d.revision) || 1, version: draftVersionOf(d.id, Number(d.revision) || 1),
      updatedAt: d.updated_at || d.created_at || null, objectTypes,
      actionTypes: list(model.action_types).map((a) => ({ ...a, rid: `ri.actions.main.action-type.${uuidOf(`${family}/action/${a.id}`)}` })),
      linkTypes: list(model.link_types).map((l) => ({ ...l, rid: rid("relation", `${family}/link/${l.id}`) })),
      valueTypes,
    };
  }).filter(Boolean);
}
// The version the app loads an ontology at. A draft's is its own revision (the reference's versions read
// "<ordinal>-<uuid tail>"); it is a version of the draft, never a published revision.
export const draftVersionOf = (draftId, revision) => `${Number(revision).toString(16).padStart(8, "0")}-${uuidOf(`draft:${draftId}`).slice(9)}`;
export const modelOf = (models, ontologyRid) => (models || []).find((m) => m.rid === ontologyRid) || null;

// GET /ontology-metadata/api/ontology/featureConfigurations — none of these platform features exist in the Hypervisor.
export const FEATURE_CONFIGURATIONS = {
  allowSharedPropertyTypeUsage: false, allowGothamTypeMappingUsage: false, allowTypeRegistryUsage: false,
  allowNonRoleEntitiesInProposals: false, ontologyProposalsInDefaultOntologyWillBeOrgMarked: false,
};
// POST /ontology-metadata/api/organization/getSettings/user — usage metrics are not kept; proposals are not enabled.
export const userSettingsOf = (organizationRid) => ({ organization: organizationRid, usage: { usageEnabled: false }, proposals: { enabledStatus: { type: "disabled", disabled: {} } } });
// GET /ontology-metadata/api/permissions/ontology/<rid> — the Ontology Manager's writes are not bound yet, so nothing is
// offered that would be refused (an ODK draft is edited in ODK).
export const ONTOLOGY_PERMISSIONS = {
  canCreateObjectTypes: false, canCreateLinkTypes: false, canCreateActionTypes: false, canUseNotificationsWithActionType: false,
  canCreateRuleSets: false, canCreateWorkflows: false, canCreateSharedPropertyTypes: false, canCreateInterfaceTypes: false,
  canCreateTypeGroups: false, canUpdateOntology: false, canDeleteOntology: false,
};
// POST /ontology-metadata/api/ontology/ontology/load/<rid>/summary — the ontology's counts (no platform maximums apply).
export function summaryOf(model) {
  const m = model || { objectTypes: [], linkTypes: [], actionTypes: [] };
  return {
    objectTypes: { visibleObjectTypes: m.objectTypes.length, maximumNumberOfObjectTypes: null, maxVectorDimensionality: null },
    linkTypes: { visibleEntities: m.linkTypes.length, maximumNumberOfOneToManyLinkTypes: null, maximumNumberOfManyToManyLinkTypes: null },
    actionTypes: { visibleEntities: m.actionTypes.length, maximumNumberOfActionTypes: null },
    sharedProperties: { visibleEntities: 0 }, interfaces: { visibleEntities: 0 }, typeGroups: { visibleEntities: 0 },
  };
}
export const ontologyApiNameOf = (model) => pascal(model?.displayName);
export { pascal, camel };

// ---- GraphQL: the list queries (rids; the entities are read over REST), the chrome that names the ontology, and the
// things the Hypervisor keeps none of (favorites of types, repository templates). Answered by the document itself
// (answerDocument walks the query over these facts), so a field the query does not ask for is never sent.
import crypto from "node:crypto";
const cid = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");
export const ONTOLOGY_GRAPHQL_OPERATIONS = new Set([
  "LoadFavoriteObjectTypeRidsQuery", "FavoriteTypeGroupsQuery", "OntologyAsCodeQuery", "SearchAllFunctionsQuery",
  "TopBarStagingSavingQuery", "IsCurrentBranchProtectedQuery", "ObjectTypesListQuery", "LinkTypesListQuery", "ActionTypesListQuery",
  "RecentlyModifiedObjectTypesQueryOnDefault", "ProminentObjectTypesQuery", "TopbarQuery", "BranchSelectTotalNumberOfOntologyBranchesQuery",
  "ObjectTypeStorageStatusQuery",
]);
// an object type of the caller's, by the identifier the app sends ({ rid } or { id })
export const objectTypeOf = (models, identifier) => {
  for (const m of models || []) { const ot = m.objectTypes.find((o) => (identifier?.rid && o.rid === identifier.rid) || (identifier?.id && o.id === identifier.id)); if (ot) return { model: m, ot }; }
  return null;
};
const page = (typename, versionTypename, entityKey, entityTypename, entities, variables, exclKey, filterKey) => {
  const excluded = new Set(variables?.[exclKey] || []);
  const only = Array.isArray(variables?.[filterKey]) ? new Set(variables[filterKey]) : null;
  const kept = entities.filter((e) => !excluded.has(e.rid) && (!only || only.has(e.rid)));
  return { __typename: typename, totalNumberOfResults: kept.length, nextPageToken: null,
    values: kept.map((e) => ({ __typename: versionTypename, _id: cid(`${versionTypename}:${e.rid}`), [entityKey]: { __typename: entityTypename, _id: cid(`${entityTypename}:${e.rid}`), rid: e.rid } })) };
};
export const ontologyNode = (model) => ({
  __typename: "Ontology", _id: cid(`ontology:${model?.rid}`), rid: model?.rid || null,
  namespace: { __typename: "Namespace", _id: cid(`namespace:${model?.rid}`), mainGlobalBranchConfigurationV2: { __typename: "GlobalBranchConfiguration", _id: cid(`branch-config:${model?.rid}`), isGlobalBranchProtected: false } },
});
// ctx: { models, functionCount }
export function ontologyGraphqlFacts(name, variables, ctx) {
  const model = modelOf(ctx.models, variables?.ontologyRid) || null;
  const empty = { objectTypes: [], linkTypes: [], actionTypes: [] };
  const m = model || empty;
  const root = { __typename: "Query" };
  switch (name) {
    case "LoadFavoriteObjectTypeRidsQuery": case "FavoriteTypeGroupsQuery": return { ...root, favorites: [] };
    case "OntologyAsCodeQuery": return { ...root, stemmaRepositoryParentTemplates: [] };
    case "SearchAllFunctionsQuery": return { ...root, functionsV2: { __typename: "FunctionSearchPage", totalNumberOfResults: ctx.functionCount || 0 } };
    case "TopBarStagingSavingQuery": case "IsCurrentBranchProtectedQuery": case "TopbarQuery": return { ...root, ontology: model ? ontologyNode(model) : null };
    case "ObjectTypesListQuery": return { ...root, objectTypesV2: page("ObjectTypeVersionPage", "ObjectTypeVersion", "objectType", "ObjectType", m.objectTypes, variables, "excludedObjectTypeRids", "filterToObjectTypeRids") };
    case "LinkTypesListQuery": return { ...root, linkTypes: page("LinkTypeVersionPage", "LinkTypeVersion", "linkType", "LinkType", m.linkTypes, variables, "excludedLinkTypeRids", "filterToLinkTypeRids") };
    case "ActionTypesListQuery": return { ...root, actionTypes: page("ActionTypeVersionPage", "ActionTypeVersion", "actionType", "ActionType", m.actionTypes, variables, "excludedActionTypeRids", "filterToActionTypeRids") };
    // Discover's "recently modified": an ODK ontology's history records each revision and its summary, not which object
    // types it touched — so none is listed rather than an attribution the record cannot support.
    case "RecentlyModifiedObjectTypesQueryOnDefault": return { ...root, ontology: model ? { ...ontologyNode(model), defaultBranch: { __typename: "OntologyBranch", _id: cid(`branch:${model.rid}`), history: { __typename: "OntologyBranchHistoryPage", values: [] } } } : null };
    // Discover's "prominent" object types: none is marked prominent (every Hypervisor object type has normal visibility).
    case "ProminentObjectTypesQuery": return { ...root, ontology: model ? { ...ontologyNode(model), objectTypesV2: { __typename: "ObjectTypeVersionPage", values: [] } } : null };
    // an ontology branch is an approval request of the ontology-metadata task type: the Hypervisor has none (an ODK draft
    // is edited in ODK, and published through the ontology-versions plane)
    case "BranchSelectTotalNumberOfOntologyBranchesQuery": return { ...root, approvalRequests: { __typename: "ApprovalRequestPage", totalNumberOfResults: 0 } };
    // an object type's object-database storage: it is stored in none
    case "ObjectTypeStorageStatusQuery": {
      const hit = objectTypeOf(ctx.models, variables?.identifier);
      return { ...root, objectTypeV2: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, storage: null } : null };
    }
    default: return null;
  }
}

// ---- An ontology's namespace is its owner tenant (its family is ontology://<owner>/<name>): a compass folder the
// app names in the ontology switcher and keys value types by. It is not a project; nothing is filed in it here.
export const namespaceRidOf = (ownerRef) => `ri.compass.main.folder.${uuidOf(`namespace:${ownerRef}`)}`;
export const namespaceNameOf = (ownerRef) => String(ownerRef || "").replace(/^[a-z][a-z0-9+.-]*:\/\//u, "") || "namespace";
// the compass resource for the namespace (the reference's shape; the caller as its creator — the tenant has no other)
export function namespaceResourceOf(ownerRef, userId, at) {
  const t = at || new Date(0).toISOString();
  return {
    rid: namespaceRidOf(ownerRef), name: namespaceNameOf(ownerRef), created: { time: t, userId }, modified: { time: t, userId }, lastModified: Date.parse(t) || 0,
    description: null, operations: ["compass:read-resource"], urlVariables: { "compass:isProject": "false", "compass:folderType": "namespace" }, favorite: null,
    branches: [], defaultBranch: null, defaultBranchWithMarkings: null, branchesCount: null, hasBranches: null, hasMultipleBranches: null, backedObjectTypes: null,
    path: `/${namespaceNameOf(ownerRef)}`, longDescription: null, directlyTrashed: false, inTrash: false, isAutosave: false, isHidden: false, isPreviewResource: false,
    collections: null, namedCollections: [], tags: null, namedTags: null, alias: namespaceNameOf(ownerRef), collaborators: [], namedAncestors: null, markings: null,
    projectAccessMarkings: null, linkedItems: null, contactInformation: null, classification: null, disableInheritedPermissions: null, propagatePermissions: null,
    resourceLevelRoleGrantsAllowed: null, portfolioRid: null, namespaceRid: null, status: null,
  };
}
// value types are the namespace's (every ontology in it); none may be created here
export function valueTypeFacts(name, variables, ctx) {
  const root = { __typename: "Query" };
  if (name === "CanCreateValueTypesQuery") return { ...root, namespace: { __typename: "Namespace", _id: cid(`namespace:${variables?.compassNamespaceRid}`), permissions: { __typename: "NamespacePermissions", _id: cid(`namespace-permissions:${variables?.compassNamespaceRid}`), canCreateValueTypes: false } } };
  if (name === "SearchAllValueTypesQuery") {
    const nsRids = new Set(JSON.stringify(variables?.filter || {}).match(/ri\.compass\.main\.folder\.[0-9a-f-]{36}/gu) || []);
    const count = nsRids.has(ctx.namespaceRid) ? (ctx.models || []).reduce((n, m) => n + m.valueTypes.length, 0) : 0;
    return { ...root, valueTypes: { __typename: "ValueTypeSearchPage", totalNumberOfResults: count } };
  }
  return null;
}
export const VALUE_TYPE_OPERATIONS = new Set(["CanCreateValueTypesQuery", "SearchAllValueTypesQuery"]);

// ---- Entities (POST /ontology-metadata/api/ontology/ontology/bulkLoadEntities). An ODK draft's types are EXPERIMENTAL
// (a draft is not a published revision); no object type is backed by a datasource here (none is bound to one), and
// none is stored in an object database, so its storage metadata says so.
const DRAFT_STATUS = { type: "experimental", experimental: {} };
const ICON = { type: "blueprint", blueprint: { color: "#5F6B7C", locator: "cube" } };
export const branchRidOf = (model) => `ri.ontology.main.branch.${uuidOf(`branch:${model.family}`)}`;
export function propertyTypeOf(p) {
  return {
    rid: p.rid, id: p.id, apiName: camel(p.name || p.id), sharedPropertyTypeApiName: null,
    displayMetadata: { description: null, displayName: p.name || p.id, visibility: "NORMAL" },
    indexedForSearch: true, ruleSetBinding: null, baseFormatter: null, type: baseTypeOf(p.base), typeClasses: [], status: DRAFT_STATUS,
    inlineAction: null, dataConstraints: null, sharedPropertyTypeRid: null, valueType: null,
  };
}
export function objectTypeEntityOf(model, ot) {
  return {
    objectType: {
      displayMetadata: { description: ot.description || "", displayName: ot.name || ot.id, groupDisplayName: null, icon: ICON, pluralDisplayName: ot.plural_name || ot.name || ot.id, visibility: "NORMAL" },
      id: ot.id, primaryKeys: ot.titleRid ? [ot.properties.find((p) => p.id === ot.primaryKey)?.rid || ot.titleRid] : [],
      propertyTypes: Object.fromEntries(ot.properties.map((p) => [p.rid, propertyTypeOf(p)])),
      rid: ot.rid, titlePropertyTypeRid: ot.titleRid,
      traits: { eventMetadata: null, actionLogMetadata: null, timeSeriesMetadata: null, peeringMetadata: null, sensorTrait: null, workflowObjectTypeTraits: {} },
      apiName: pascal(ot.name || ot.id), status: DRAFT_STATUS, redacted: null,
      implementsInterfaces: [], implementsInterfaces2: [], allImplementsInterfaces: {}, typeGroups: [], editPolicies: null,
    },
    ontologyRid: model.rid, ontologyVersion: model.version, datasources: [],
    entityMetadata: entityMetadataOf(),
    resolvedBranch: { type: "default", default: { rid: branchRidOf(model) } },
    schemaMigrations: { schemaTransitions: [], schemaVersion: 1 },
  };
}
// An object type's storage metadata: stored nowhere yet (no object database, no patches, no edits history).
export function entityMetadataOf() {
  return {
    entityConfig: { objectDbTypeConfigs: {} }, arePatchesEnabled: false,
    targetStorageBackend: { type: "objectStorageV2", objectStorageV2: { migrationConfiguration: null, editsHistoryImportConfiguration: null, archiveState: null } },
    redacted: null, actionLogRequirednessMetadata: null, diffEdits: false, gothamMapping: null, provenance: null,
    editsResolutionStrategies: { strategies: {} }, aliases: [], editsHistory: { type: "none", none: {} }, objectTypeIndexingSettings: null,
    patchApplicationStrategy: { type: "objectScopedLiveness", objectScopedLiveness: {} }, directDatasourceConfiguration: null,
    usesOnlyOsv2ObjectRids: true, interfaceSettings: { enableInterfaceActions: { type: "disabled", disabled: {} } }, owningDirectWriters: {},
  };
}
// POST /ontology-metadata/api/entityMetadata/load — for the caller's object types only
export function entityMetadataLoadOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.objectTypes.map((o) => o.rid)));
  return { objectTypes: (request?.objectTypes || []).filter((r) => ours.has(r.objectTypeRid)).map((r) => ({ objectTypeRid: r.objectTypeRid, objectTypeEntityMetadata: entityMetadataOf() })) };
}
// PUT /ontology-metadata/api/permissions/objectTypes — the caller sees their types; the Ontology Manager edits nothing yet
export function objectTypePermissionsOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.objectTypes.map((o) => o.rid)));
  return { objectTypePermissions: Object.fromEntries((request?.objectTypeRids || []).filter((r) => ours.has(r)).map((r) => [r, {
    canView: true, canEdit: false, canDelete: false, canAddDatasources: false, canUpdateRoles: false, canApplyRestrictedSchemaMigrations: false,
    datasourcePermissions: {}, propertySecurityGroupPermissions: {}, isEditRestrictedByDatasources: false, packageRid: null, permissionModel: { type: "roles", roles: {} },
  }])) };
}
// the requested object types (by rid or by id), each from the ontology that holds it
export function bulkLoadEntitiesOf(request, models) {
  const find = (identifier) => {
    const rid = identifier?.objectTypeRid, id = identifier?.objectTypeId;
    for (const m of models || []) {
      const ot = m.objectTypes.find((o) => (rid && o.rid === rid) || (id && o.id === id));
      if (ot) return objectTypeEntityOf(m, ot);
    }
    return null;
  };
  return {
    objectTypes: (request?.objectTypes || []).map((r) => find(r.identifier)).filter(Boolean),
    linkTypes: [], sharedPropertyTypes: [], interfaceTypes: [], typeGroups: [], actionTypes: [],
  };
}
