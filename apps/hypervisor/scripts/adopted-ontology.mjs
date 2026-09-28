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
      history: (Array.isArray(d.history) ? d.history : []).filter((h) => h && Number(h.revision) > 0),
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
  "LoadFavoriteObjectTypeRidsQuery", "FavoriteTypeGroupsQuery", "OntologyAsCodeQuery",
  "TopBarStagingSavingQuery", "IsCurrentBranchProtectedQuery", "ObjectTypesListQuery", "LinkTypesListQuery", "ActionTypesListQuery",
  "RecentlyModifiedObjectTypesQueryOnDefault", "ProminentObjectTypesQuery", "TopbarQuery", "BranchSelectTotalNumberOfOntologyBranchesQuery",
  "ObjectTypeStorageStatusQuery", "TypeGroupsListQuery", "InterfacesListQuery", "SharedPropertyListQuery", "SearchValueTypesQuery",
  "AdvancedOptionsPageQuery", "OntologyWithOwnerDetailsQuery", "LoadActionsTypesRelatedToObjectTypeRidsQuery",
  "ObjectTypeFavoritedQuery", "SqlPreviewSourceSelectorMaterializationsQuery", "ObjectTypePanelMachineryQuery", "CompassResourceProjectQuery", "ObjectViewConfigurationQuery",
  "ObjectTypeMetadataPanelQuery", "RolesSectionContentQuery", "ObjectTypeMonitorRulesQuery", "AutomationsTabQuery",
]);
// The ontology's details (Ontology configuration, the owner check): its names, its namespace as a resource, no
// markings, and no permission to change settings, permissions or branch protection (none is bound here).
export function ontologyDetailNode(model, ownerRef) {
  const nsRid = namespaceRidOf(ownerRef);
  const nsName = namespaceNameOf(ownerRef);
  const base = ontologyNode(model);
  const nsResource = {
    __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${nsRid}`), rid: nsRid, collections: [], status: null, trashedStatus: "NOT_TRASHED",
    type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-namespace" }, alias: nsName, name: nsName, openUrl: null,
    permissions: { __typename: "ResourceMetadataPermissions", _id: cid(`perm:${nsRid}`), canOpenLink: false }, ancestors: [], path: `/${nsName}`, autosaved: false, statusInfo: null,
  };
  return {
    ...base, displayName: model.displayName, description: model.description || "", apiName: pascal(model.displayName),
    metadata: {
      __typename: "OntologyMetadata", _id: cid(`OntologyMetadata:${model.rid}`), markings: [],
      namespace: { __typename: "Namespace", _id: cid(`namespace:${model.rid}`), metadata: nsResource, permissions: { __typename: "NamespacePermissions", _id: cid(`ns-perm:${model.rid}`), canInstallMarketplaceProduct: false } },
      permissions: { __typename: "OntologyMetadataPermissions", _id: cid(`ont-meta-perm:${model.rid}`), canManagePermissions: false },
    },
    namespace: { ...base.namespace, rid: nsRid, permissions: { __typename: "NamespacePermissions", _id: cid(`ns-perm:${model.rid}`), canEditGlobalBranchConfiguration: false } },
    permissions: { __typename: "OntologyPermissions", _id: cid(`ont-perm:${model.rid}`), canInstallMarketplaceProduct: false, canUpdateOntologySettings: false },
  };
}
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
    case "AdvancedOptionsPageQuery": return { ...root, ontology: model ? ontologyDetailNode(model, ctx.owner) : null };
    case "OntologyWithOwnerDetailsQuery": { const mm = modelOf(ctx.models, variables?.rid); return { ...root, ontology: mm ? ontologyDetailNode(mm, ctx.owner) : null }; }
    // the action types that take an object type as input: the ODK action types that apply to it
    case "LoadActionsTypesRelatedToObjectTypeRidsQuery": {
      const inputs = new Set(JSON.stringify(variables?.actionTypeFilter || {}).match(/ri\.ontology\.main\.object-type\.[0-9a-f-]{36}/gu) || []);
      const excluded = new Set(variables?.excludedActionTypeRids || []);
      const ids = new Set(m.objectTypes.filter((o) => inputs.has(o.rid)).map((o) => o.id));
      const related = m.actionTypes.filter((a) => ids.has(a.applies_to) && !excluded.has(a.rid));
      return { ...root, ontology: model ? { ...ontologyNode(model), actionTypes: { __typename: "ActionTypeSearchPage", nextPageToken: null, values: related.map((a) => ({ __typename: "ActionTypeSearchResult", _id: cid(`ats:${a.rid}`), actionTypeRid: a.rid })) } } : null };
    }
    // an object type's star, exports, machinery dependents and object views: none is kept for it here
    case "ObjectTypeFavoritedQuery": case "SqlPreviewSourceSelectorMaterializationsQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.rid || variables?.objectTypeRid });
      return { ...root, objectType: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, favorited: null, exports: { __typename: "ObjectTypeExportPage", nextPageToken: null, values: [] } } : null };
    }
    case "ObjectTypePanelMachineryQuery": case "ObjectViewConfigurationQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, objectTypeV2: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, dependents: { __typename: "ResourceMetadataPage", values: [] }, objectViewConfiguration: null } : null, globalBranch: null };
    }
    // an object type's backing datasources: none is bound to one here
    case "ObjectTypeMetadataPanelQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, objectType: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, latest: { __typename: "ObjectTypeVersion", _id: cid(`ObjectTypeVersion:${hit.ot.rid}`), dataSources: [] } } : null };
    }
    // no roles are granted on an object type (access is the Hypervisor principal and tenant); no monitor rule watches
    // it; no automation depends on it (Hypervisor automations do not watch object types)
    case "RolesSectionContentQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.rid });
      return { ...root, resourceMetadata: hit ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${hit.ot.rid}`), rid: hit.ot.rid, everyoneRoles: [] } : null };
    }
    case "ObjectTypeMonitorRulesQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.rid });
      return { ...root, objectTypeV2: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, monitorRules: [] } : null };
    }
    case "AutomationsTabQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, objectType: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, dependents: { __typename: "ResourceMetadataPage", values: [] } } : null };
    }
    // an object type is not filed in a project: its parent is its ontology's namespace
    case "CompassResourceProjectQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.resourceRid });
      return { ...root, resourceMetadata: hit ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${hit.ot.rid}`), rid: hit.ot.rid, projectRid: null, project: null, parent: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${namespaceRidOf(ctx.owner)}`), rid: namespaceRidOf(ctx.owner) } } : null };
    }
    // the Hypervisor keeps no type groups, interfaces or shared properties
    case "TypeGroupsListQuery": return { ...root, objectTypeGroups: { __typename: "ObjectTypeGroupPage", totalNumberOfResults: 0, nextPageToken: null, values: [] } };
    case "InterfacesListQuery": return { ...root, ontologyInterfaces: { __typename: "OntologyInterfacePage", totalNumberOfResults: 0, nextPageToken: null, values: [] } };
    case "SharedPropertyListQuery": return { ...root, ontology: model ? { ...ontologyNode(model), sharedProperties: { __typename: "SharedPropertyPage", totalNumberOfResults: 0, nextPageToken: null, values: [] } } : null };
    // the namespace's value types (every ontology's declared value types), by name
    case "SearchValueTypesQuery": {
      const all = (ctx.models || []).flatMap((mm) => mm.valueTypes.map((v) => ({ v, mm }))).sort((a, b) => String(a.v.name || a.v.id).localeCompare(String(b.v.name || b.v.id)));
      return { ...root, valueTypes: { __typename: "ValueTypeSearchPage", nextPageToken: null, totalNumberOfResults: all.length, values: all.map(({ v, mm }) => {
        const vrid = `ri.ontology.main.value-type.${uuidOf(`${mm.family}/value/${v.id}`)}`;
        return { __typename: "ValueType", _id: cid(`ValueType:${vrid}`), rid: vrid, displayName: v.name || v.id,
          latestVersion: { __typename: "ValueTypeVersion", _id: cid(`ValueTypeVersion:${vrid}`), created: { __typename: "Attribution", time: mm.updatedAt || null }, baseType: { __typename: `ValueTypeBaseType_${pascal(v.base || "string")}` } } };
      }) } };
    }
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
// An ODK action type as the reference's action type. It declares its kind and the object type it applies to, not
// rule logic or parameters, so it carries neither (no rule, no parameter, no form) — what it affects is its target.
const ACTION_ICON = { type: "blueprint", blueprint: { color: "#111418", locator: "new-object" } };
export function actionTypeEntityOf(model, a) {
  return {
    actionType: {
      actionTypeLogic: {
        logic: { rules: [], actionLogRule: null },
        validation: { actionTypeLevelValidation: { rules: {}, ordering: [], writeAuthorization: null, readAuthorization: null }, parameterValidations: {}, sectionValidations: {}, actionEditsValidation: null },
        revert: null, webhooks: null, notifications: [], effects: null,
      },
      metadata: {
        rid: a.rid, apiName: camel(a.name || a.id), version: model.version,
        displayMetadata: {
          displayName: a.name || a.id, description: a.description || "", toolDescription: null, icon: ACTION_ICON, typeClasses: [],
          successMessage: [], successMessageEnabled: false, applyingMessage: [], applyingMessageEnabled: false, submitButtonDisplayMetadata: null, undoButtonConfiguration: null,
          configuration: { defaultLayout: "FORM", displayAndFormat: { table: { columnWidthByParameterRid: {}, enableFileImport: false, fitHorizontally: false, frozenColumnCount: 0, rowHeightInLines: 1 } }, enableLayoutUserSwitch: false },
        },
        parameters: {}, returnType: { type: "void", void: {} }, returnConfiguration: null, sections: {}, parameterOrdering: [], formContentOrdering: [],
        actionLogConfiguration: null, status: DRAFT_STATUS,
        entities: { affectedObjectTypes: a.applies_to ? [a.applies_to] : [], affectedLinkTypes: [], affectedInterfaceTypes: [], typeGroups: [] },
        actionApplyClientSettings: null,
        notificationSettings: { renderingSettings: { type: "allNotificationRenderingMustSucceed", allNotificationRenderingMustSucceed: {} }, redactionOverride: null },
        provenance: null, owningResource: null, submissionConfiguration: null, stagingMediaSetRid: null,
        branchSettings: { webhooksMode: { type: "disableWebhooksOnBranches", disableWebhooksOnBranches: {} }, notificationsMode: { type: "disableNotificationsOnBranches", disableNotificationsOnBranches: {} }, functionsWithExternalCallsMode: { type: "disableFunctionsWithExternalCallsOnBranches", disableFunctionsWithExternalCallsOnBranches: {} } },
        scenarioSettings: { scenarioExecutionOnlyMode: { type: "noExecutionRestriction", noExecutionRestriction: {} } },
        isolationSettings: { isolationMode: { type: "default", default: {} }, retrySettings: { type: "default", default: {} } },
      },
    },
    ontologyRid: model.rid, ontologyVersion: model.version, resolvedBranch: { type: "default", default: { rid: branchRidOf(model) } },
  };
}
// PUT /ontology-metadata/api/permissions/actionTypes — the caller sees their action types; none is edited here
export function actionTypePermissionsOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.actionTypes.map((a) => a.rid)));
  return { actionTypePermissions: Object.fromEntries((request?.actionTypeRids || []).filter((r) => ours.has(r)).map((r) => [r, {
    canView: true, canEdit: false, canUseNotifications: false, canUpdateRoles: false, hasRolesApplied: false,
    permissionModel: { type: "roles", roles: {} }, packageRid: null, canOverrideNotificationRedaction: false,
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
  const findAction = (r) => {
    const want = r?.actionTypeRid || r?.identifier?.actionTypeRid || r?.rid || null;
    for (const m of models || []) { const a = m.actionTypes.find((x) => x.rid === want); if (a) return actionTypeEntityOf(m, a); }
    return null;
  };
  return {
    objectTypes: (request?.objectTypes || []).map((r) => find(r.identifier)).filter(Boolean),
    linkTypes: [], sharedPropertyTypes: [], interfaceTypes: [], typeGroups: [],
    actionTypes: (request?.actionTypes || []).map(findAction).filter(Boolean),
  };
}

// ---- POST /ontology-metadata/api/ontology/v2/<rid>/modification/history — the draft's receipted history, newest first.
// Each entry names its revision and summary; it does not record which entities it touched or who made it, so the
// affected-entity maps are empty and the author is not claimed.
const EMPTY_AFFECTED = {
  affectedObjectTypes: {}, affectedObjectTypeDatasources: {}, affectedLinkTypes: {}, affectedManyToManyLinkTypeDatasources: {}, affectedRuleSets: {},
  affectedActionTypes: {}, affectedSharedPropertyTypes: {}, affectedInterfaceTypes: {}, affectedObjectTypeEntityMetadatas: {},
  affectedLinkTypeEntityMetadatas: {}, affectedObjectTypeSchemaMigrations: {}, affectedTypeGroups: {},
};
// A history entry's recorded changes (ODK records, per revision, which types it CREATED / UPDATED / DELETED by id),
// keyed by the rids the app knows (deterministic from family and id, so a deleted type keeps its rid).
function affectedOf(model, affected) {
  const map = (kind, ridOf) => Object.fromEntries(Object.entries(affected[kind] || {}).map(([id, change]) => [ridOf(id), String(change)]));
  const objectTypes = map("object_types", (id) => rid("object-type", `${model.family}/${id}`));
  return {
    ...EMPTY_AFFECTED, affectedObjectTypes: objectTypes, affectedObjectTypeEntityMetadatas: objectTypes,
    affectedLinkTypes: map("link_types", (id) => rid("relation", `${model.family}/link/${id}`)),
    affectedActionTypes: map("action_types", (id) => `ri.actions.main.action-type.${uuidOf(`${model.family}/action/${id}`)}`),
  };
}
// `authorOf(receiptRef)` names the principal a revision's receipt records (ODK receipts carry the acting principal).
// A draft still at its first revision was made by exactly its creation, so that entry created every type it holds;
// for a draft revised since, a revision's touched types are not recorded, and none is claimed.
export function modificationHistoryOf(model, limit = 100, authorOf = () => null) {
  if (!model) return { modificationPageItems: [], nextPageToken: null };
  const createdAll = model.history.length === 1 && Number(model.history[0].revision) === 1 && model.revision === 1;
  const created = (list) => Object.fromEntries(list.map((e) => [e.rid, "CREATED"]));
  const items = [...model.history].sort((a, b) => Number(b.revision) - Number(a.revision)).slice(0, Math.max(1, Number(limit) || 100)).map((h) => ({
    previousOntologyVersion: Number(h.revision) > 1 ? draftVersionOf(model.draftId, Number(h.revision) - 1) : null,
    ontologyVersion: draftVersionOf(model.draftId, Number(h.revision)),
    attribution: { date: h.at || null, author: authorOf(h.receipt_ref) },
    summary: h.affected && typeof h.affected === "object" ? affectedOf(model, h.affected)
      : createdAll && h.op === "created"
        ? { ...EMPTY_AFFECTED, affectedObjectTypes: created(model.objectTypes), affectedObjectTypeEntityMetadatas: created(model.objectTypes), affectedLinkTypes: created(model.linkTypes), affectedActionTypes: created(model.actionTypes) }
        : EMPTY_AFFECTED,
    description: h.summary || h.op || "", sourceOntologyBranchRid: null,
  }));
  return { modificationPageItems: items, nextPageToken: null };
}
// PUT /multipass/api/roles/v2/roleSets — the Hypervisor has no ontology roles (access is its own principal and tenant)
export const roleSetsOf = (ids) => ({ roleSets: Object.fromEntries((ids || []).map((id) => [id, { id, displayName: id, description: "", organizationRid: null, context: id, roles: {} }])) });

// ---- POST /ontology-metadata/api/ontology/linkTypesForObjectTypes(V2) — each requested object type's link types. An
// ODK link type names its two endpoints; one whose endpoints do not resolve to the caller's types is not offered.
const endpointOf = (l, side) => l[side] || l[side === "from" ? "source" : "target"] || l[side === "from" ? "object_type_a" : "object_type_b"] || null;
export function linkTypesForObjectTypesOf(request, models) {
  const out = {};
  for (const otRid of Object.keys(request?.objectTypeVersions || {})) {
    const hit = (models || []).map((mm) => ({ mm, ot: mm.objectTypes.find((o) => o.rid === otRid) })).find((x) => x.ot);
    if (!hit) continue;
    const { mm } = hit;
    const byId = new Map(mm.objectTypes.map((o) => [o.id, o]));
    out[otRid] = mm.linkTypes.filter((l) => [endpointOf(l, "from"), endpointOf(l, "to")].includes(hit.ot.id)).map((l) => {
      const a = byId.get(endpointOf(l, "from")), b = byId.get(endpointOf(l, "to"));
      if (!a || !b) return null;
      const side = (o, name) => ({ displayMetadata: { displayName: name || o.name, groupDisplayName: null, pluralDisplayName: name || o.name, visibility: "NORMAL" }, typeClasses: [], apiName: camel(name || o.name) });
      return {
        description: l.description || null, id: l.id, rid: l.rid, status: DRAFT_STATUS, redacted: null,
        definition: { type: "manyToMany", manyToMany: { objectTypeAToBLinkMetadata: side(b, l.name), objectTypeBToALinkMetadata: side(a, l.inverse_name), objectTypeRidA: a.rid, objectTypeRidB: b.rid, objectTypeAPrimaryKeyPropertyMapping: {}, objectTypeBPrimaryKeyPropertyMapping: {}, peeringMetadata: null } },
      };
    }).filter(Boolean);
  }
  return { linkTypes: out };
}

// ---- POST /ontology-metadata/api/ontology/v2/modification/history/entity — one entity's history: the draft's revisions
// that recorded a change to it (newest first), attributed from their receipts.
export function entityHistoryOf(models, request, authorOf = () => null) {
  const otRid = request?.entityRid?.objectTypeRid;
  const hit = otRid ? objectTypeOf(models, { rid: otRid }) : null;
  const empty = { entityModificationPageItems: [], nextPageToken: null, entityMetadataModificationPageItems: [], entityMetadataNextPageToken: null };
  if (!hit) return empty;
  const items = [...hit.model.history].filter((h) => h.affected?.object_types?.[hit.ot.id]).sort((a, b) => Number(b.revision) - Number(a.revision))
    .slice(0, Math.max(1, Number(request?.limit) || 20))
    .map((h) => ({ ontologyVersion: draftVersionOf(hit.model.draftId, Number(h.revision)), attribution: { date: h.at || null, author: authorOf(h.receipt_ref) }, modificationType: String(h.affected.object_types[hit.ot.id]), description: h.summary || h.op || "" }));
  return { ...empty, entityModificationPageItems: items };
}
export const REGISTRY_ONTOLOGY_ALL = { partialObjectTypeVersions: {}, bidirectionalRelationVersions: {} };
export const ontologyRecentsIdOf = (principalRef) => `ontology-recents-${uuidOf(`recents:${principalRef || "anonymous"}`).replace(/-/gu, "").slice(0, 24)}`;

// PUT /ontology-metadata/api/schemamigrations/load/objecttypes (and /objecttype) — no schema migration is recorded for
// a draft's types (a draft is edited in place, not migrated)
export function schemaMigrationsOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.objectTypes.map((o) => o.rid)));
  return { schemaTransitions: (request?.objectTypeRids || []).filter((r) => ours.has(r?.objectTypeRid)).map((r) => ({ objectTypeRid: r.objectTypeRid, ontologyVersion: r.ontologyVersion, schemaTransitions: [], schemaVersion: 1 })) };
}
export const SCHEMA_MIGRATION_PAGE = { migrationPageItems: [], schemaVersion: 1, nextPageToken: null };
