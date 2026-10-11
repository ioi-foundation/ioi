// The adopted Ontology Manager's answers over Hypervisor truth (R-241, Ontology Manager cut O1).
//
// The reference app (booted by the local capture server, routed at /workspace/ontology) reads the ontology through the
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
// `sets` are the caller's materialized object sets (the daemon's caller-scoped GET /v1/hypervisor/odk/materialized-object-sets):
// each object type carries the ones that materialize it as its backing (cut O8, backingOf below).
export function ontologyModelsOf(domainOntologies, ownerRef, familyOf, sets = []) {
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
      const typed = { ...ot, rid: rid("object-type", `${family}/${ot.id}`), properties, titleRid: title?.rid || null, primaryKey: title?.id || null };
      const backing = backingOf(d, typed, sets);
      // a backed type's primary key is the property its objects are keyed by (its connector mapping's key); an unbacked
      // type's stays its title property, as before
      return { ...typed, ...(backing.keyProperty ? { primaryKey: backing.keyProperty } : {}), backing };
    });
    return {
      ref: d.ref || null,
      history: (Array.isArray(d.history) ? d.history : []).filter((h) => h && Number(h.revision) > 0),
      // whether the caller may change this ontology, as the daemon reads it for them on every read (its owner, or an
      // administrator of its organization: the rule its PATCH, DELETE and apply routes enforce) — never inferred here
      mayChange: d.caller_may_change === true,
      rid: ontologyRidOfFamily(family), family, draftId: d.id, displayName: d.domain || family, description: d.description || "", canonical: model,
      revision: Number(d.revision) || 1, version: draftVersionOf(d.id, Number(d.revision) || 1),
      updatedAt: d.updated_at || d.created_at || null, objectTypes,
      actionTypes: list(model.action_types).map((a) => ({ ...a, rid: `ri.actions.main.action-type.${uuidOf(`${family}/action/${a.id}`)}` })),
      linkTypes: list(model.link_types).map((l) => ({ ...l, rid: rid("relation", `${family}/link/${l.id}`) })),
      valueTypes,
    };
  }).filter(Boolean);
}
// ---- A type's backing (cut O8). An ODK type is backed by the materialized object sets that materialize it: the sets the daemon
// registered, under a held lease and an opened sealed session, for a projection of this ontology's type (each names its
// `ontology_ref` and `object_type_id`, from its run's lease plan). They are the caller's (the daemon's list is caller-scoped:
// the ontology's owner, or whoever sees the source a set came from). Each lease plan — Data Connection's sync — is one backing
// datasource: its dataset is the sync's own output dataset (the same rid Data Connection names), whose contents are its newest
// set (every materializing run registers a new one); the type's objects are its datasources' objects by key, the newest
// registration of a key winning. A type no set materializes has no backing (the reference's own "Backing datasource is missing"
// stays true).
const EMPTY_BACKING = Object.freeze({ datasources: [], objects: [], keyProperty: null });
export function backingOf(d, ot, sets) {
  const refs = new Set([d?.ref, d?.id, d?.id ? `ontology://${d.id}` : null].filter(Boolean));
  const mine = (Array.isArray(sets) ? sets : []).filter((s) => s && s.object_type_id === ot.id && refs.has(String(s.ontology_ref || "")) && Array.isArray(s.objects));
  if (!mine.length) return EMPTY_BACKING;
  const newest = new Map();
  for (const s of mine) {
    const k = String(s.capability_lease_plan_ref || s.ontology_projection_id || s.id).replace(/^capability-lease-plan:\/\//u, "");
    const cur = newest.get(k);
    if (!cur || String(s.registered_at || "") > String(cur.registered_at || "")) newest.set(k, s);
  }
  const declared = new Set(ot.properties.map((p) => p.id));
  const datasources = [...newest.entries()].sort((a, b) => String(a[1].registered_at || "").localeCompare(String(b[1].registered_at || ""))).map(([projection, s]) => {
    // the source field each property is mapped from (the set's own provenance, per object)
    const mapping = {};
    for (const o of s.objects) for (const [pid, field] of Object.entries(o?.provenance?.mapped_from || {})) if (declared.has(pid) && typeof field === "string") mapping[pid] = field;
    // (the plan's id: Data Connection's sync, whose output dataset rid is `lease-plan-dataset:<plan id>` — syncDatasetRidOf)
    return { planId: projection, projection: s.ontology_projection_id || null, set: s, rid: `ri.ontology.main.datasource.${uuidOf(`lease-plan-datasource:${projection}`)}`, datasetRid: `ri.foundry.main.dataset.${uuidOf(`lease-plan-dataset:${projection}`)}`,
      mapping, count: s.objects.length, registeredAt: s.registered_at || null, setRef: s.ref || null, runRef: s.materializing_run_ref || null };
  });
  const byKey = new Map();
  for (const ds of datasources) for (const o of ds.set.objects) {
    const key = String(o?.object_key ?? "");
    if (!key) continue;
    const cur = byKey.get(key);
    if (!cur || String(ds.registeredAt || "") >= String(cur.registeredAt || "")) byKey.set(key, { key, title: String(o.title ?? key), props: o.properties && typeof o.properties === "object" ? o.properties : {}, datasource: ds.rid, setRef: ds.setRef, runRef: ds.runRef, registeredAt: ds.registeredAt });
  }
  const objects = [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key)).map((o) => ({ ...o, rid: objectRidOf(ot, o.key) }));
  // the key property: the declared property every object's key is the value of (its mapping's key); the title only if nothing else is
  const keyed = ot.properties.filter((p) => objects.every((o) => o.props[p.id] !== undefined && String(o.props[p.id]) === o.key));
  const keyProperty = (keyed.find((p) => p.id !== ot.title_property) || keyed[0] || null)?.id || null;
  return { datasources, objects, keyProperty };
}
// an object's rid: its type's and its key (reversible: a set that names an object by rid finds it again)
export const objectRidOf = (ot, key) => `ri.phonograph2-objects.main.object.v4.${String(ot.rid).split(".").pop()}.${Buffer.from(String(key)).toString("base64url")}`;
// The version the app loads an ontology at. A draft's is its own revision (the reference's versions read
// "<ordinal>-<uuid tail>"); it is a version of the draft, never a published revision.
export const apiNameOfOntology = (model) => String(String(model?.family || "").split("/").pop() || model?.displayName || "ontology").toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-+|-+$/gu, "") || "ontology";
export const draftVersionOf = (draftId, revision) => `${Number(revision).toString(16).padStart(8, "0")}-${uuidOf(`draft:${draftId}`).slice(9)}`;
export const modelOf = (models, ontologyRid) => (models || []).find((m) => m.rid === ontologyRid) || null;

// GET /ontology-metadata/api/ontology/featureConfigurations — none of these platform features exist in the Hypervisor.
export const FEATURE_CONFIGURATIONS = {
  allowSharedPropertyTypeUsage: false, allowGothamTypeMappingUsage: false, allowTypeRegistryUsage: false,
  allowNonRoleEntitiesInProposals: false, ontologyProposalsInDefaultOntologyWillBeOrgMarked: false,
};
// POST /ontology-metadata/api/organization/getSettings/user — usage metrics are not kept; proposals are not enabled.
export const userSettingsOf = (organizationRid) => ({ organization: organizationRid, usage: { usageEnabled: false }, proposals: { enabledStatus: { type: "disabled", disabled: {} } } });
// GET /ontology-metadata/api/permissions/ontology/<rid> — nothing is offered to a caller who may not change the ontology.
export const ONTOLOGY_PERMISSIONS = {
  canCreateObjectTypes: false, canCreateLinkTypes: false, canCreateActionTypes: false, canUseNotificationsWithActionType: false,
  canCreateRuleSets: false, canCreateWorkflows: false, canCreateSharedPropertyTypes: false, canCreateInterfaceTypes: false,
  canCreateTypeGroups: false, canUpdateOntology: false, canDeleteOntology: false,
};
// …and to one who may (its owner, or an administrator of its organization: the daemon's `caller_may_change`), adding an
// object, link or action type — each is a change to the ODK model, which the daemon lets exactly them make. Nothing else is
// offered: the model keeps no shared properties, groups, interfaces, rule sets or workflows, and the ontology's settings and
// its deletion are not changed from here. (The reference saves a new type only with a backing datasource, so its own save
// stays disabled — "Backing datasource is missing" — until a type's materialized set can back it.)
export const ontologyPermissionsOf = (model) => ({
  ...ONTOLOGY_PERMISSIONS,
  canCreateObjectTypes: model?.mayChange === true, canCreateLinkTypes: model?.mayChange === true, canCreateActionTypes: model?.mayChange === true,
});
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
  "ObjectTypeObjectsCountQuery", "ObjectTypeDependentsQuery", "ObjectTypeArchiveStatusQuery",
  "LinkTypeRedirectQuery", "LinkTypeStorageStatusQuery", "SelectedObjectTypeQuery", "ObjectTypeSearch", "ObjectTypeQuicksearch",
  "IndividualRoleGrantsEditorQuery", "GetAllMarkingPermissions", "IsResourceBranchProtectedByRidQuery",
  "ObjectTypesAndLinkTypesWithDatasourcesQuery", "ActionTypesRecommendationsQuery", "SharedPropertiesRecommendationsQuery", "InterfacesRecommendationsQuery",
]);
// An object type as the pickers select it: its title, icon and status (a draft's types are experimental), its primary
// key, and no datasource, group or storage; it is not editable here.
function objectTypeVersionOf(model, ot) {
  const pk = ot.properties.find((p) => p.id === ot.primaryKey) || null;
  return {
    __typename: "ObjectTypeVersion", _id: cid(`ObjectTypeVersion:${ot.rid}`), apiName: pascal(ot.name || ot.id), displayName: ot.name || ot.id, description: ot.description || null,
    iconV2: { __typename: "BlueprintIcon", locator: ICON.blueprint.locator, color: ICON.blueprint.color }, status: { __typename: "ObjectTypeStatus_Experimental" },
    objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${ot.rid}`), rid: ot.rid, id: ot.id, storage: null, ontology: ontologyNode(model) },
    primaryKeyProperties: pk ? [{ __typename: "ObjectTypeProperty", _id: cid(`ObjectTypeProperty:${pk.rid}`), displayName: pk.name || pk.id, type: { __typename: `ObjectTypePropertyType_${pascal(pk.base || "string")}` } }] : [],
    settings: { __typename: "ObjectTypeSettings", editable: false }, dataSources: [], groups: [],
  };
}
// the words a picker filters by (every string in its filter clauses); a type matches when its name holds one
const wordsOf = (v) => (typeof v === "string" ? [v] : v && typeof v === "object" ? Object.values(v).flatMap(wordsOf) : []).map((w) => w.trim().toLowerCase()).filter((w) => w && !/^(and|or|not)$/u.test(w));
const matches = (ot, words) => !words.length || words.some((w) => `${ot.name || ""} ${ot.id}`.toLowerCase().includes(w));
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
    // its API name is its family's name (ontology://<namespace>/<name>), in the reference's lowercase, hyphenated form
    ...base, displayName: model.displayName, description: model.description || "", apiName: apiNameOfOntology(model),
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
    // Discover's "recently modified": the draft's revisions, newest first, each with the object types it recorded
    // creating or updating (a revision recorded before ODK kept its changes lists none).
    case "RecentlyModifiedObjectTypesQueryOnDefault": {
      if (!model) return { ...root, ontology: null };
      const live = new Map(model.objectTypes.map((o) => [o.id, o]));
      const version = (o) => ({ __typename: "ObjectTypeVersion", _id: cid(`otv:${o.rid}`), objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${o.rid}`), rid: o.rid } });
      const pick = (h, change) => Object.entries(h.affected?.object_types || {}).filter(([id, c]) => c === change && live.has(id)).map(([id]) => version(live.get(id)));
      const values = [...model.history].sort((a, b) => Number(b.revision) - Number(a.revision)).slice(0, Math.max(1, Number(variables?.pageSize) || 20)).map((h) => ({
        __typename: "OntologyBranchHistoryItem", _id: cid(`history:${model.rid}:${h.revision}`),
        summary: { __typename: "OntologyModificationSummary", affectedObjectTypes: { __typename: "AffectedObjectTypes", createdObjectTypes: pick(h, "CREATED"), updatedObjectTypes: pick(h, "UPDATED") } },
      }));
      return { ...root, ontology: { ...ontologyNode(model), defaultBranch: { __typename: "OntologyBranch", _id: cid(`branch:${model.rid}`), history: { __typename: "OntologyBranchHistoryPage", values } } } };
    }
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
    // how many objects a type has: the caller's materialized objects of it (cut O8; none for a type no set materializes)
    case "ObjectTypeObjectsCountQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, defaultOrGlobalBranch: { __typename: "DefaultGlobalBranch", _id: cid("branch:default"), objectType: hit ? { __typename: "ObjectTypeBranch", _id: cid(`otb:${hit.ot.rid}`), objectCount: (hit.ot.backing?.objects || []).length } : null } };
    }
    // no resource depends on a type, and it has no storage to archive
    case "ObjectTypeDependentsQuery": case "ObjectTypeArchiveStatusQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, objectTypeV2: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, dependents: { __typename: "OntologyDependentPage", values: [] }, storage: null } : null };
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
    // a link type's page opens it by id, in the ontology that holds it
    case "LinkTypeRedirectQuery": {
      const mm = (ctx.models || []).find((x) => x.linkTypes.some((l) => l.id === variables?.id));
      const l = mm?.linkTypes.find((x) => x.id === variables?.id);
      return { ...root, linkTypeById: l && linkTypeOf(mm, l) ? { __typename: "LinkType", _id: cid(`LinkType:${l.rid}`), rid: l.rid, ontology: ontologyNode(mm) } : null };
    }
    // the link editor's object type pickers: the selected type, and the caller's types to choose from
    case "SelectedObjectTypeQuery": {
      const mm = (ctx.models || []).find((x) => x.objectTypes.some((o) => o.id === variables?.id));
      const ot = mm?.objectTypes.find((o) => o.id === variables?.id);
      return { ...root, objectTypeById: ot ? { __typename: "ObjectType", _id: cid(`ObjectType:${ot.rid}`), rid: ot.rid, id: ot.id, latest: objectTypeVersionOf(mm, ot) } : null };
    }
    case "ObjectTypeSearch": {
      const want = new Set(variables?.ontologyRids || []), excluded = new Set(variables?.excludeObjectTypeRids || []), words = wordsOf(variables?.filter?.clauses || []);
      const values = (ctx.models || []).filter((mm) => !want.size || want.has(mm.rid)).flatMap((mm) => mm.objectTypes.filter((o) => !excluded.has(o.rid) && matches(o, words)).map((o) => objectTypeVersionOf(mm, o)));
      return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", nextPageToken: null, totalNumberOfResults: values.length, values } };
    }
    case "ObjectTypeQuicksearch": {
      const words = wordsOf(variables?.title || "");
      const hits = (ctx.models || []).flatMap((mm) => mm.objectTypes.filter((o) => matches(o, words)).map((o) => ({ __typename: "ObjectType", _id: cid(`ObjectType:${o.rid}`), rid: o.rid, latest: objectTypeVersionOf(mm, o) })));
      return { ...root, search: hits.slice(0, Math.max(1, Number(variables?.limit) || 100)) };
    }
    // a type's role grants (the Security tab): the Hypervisor keeps no ontology roles — access is its principal and
    // tenant — so the role set has no roles and nobody holds one, on the type or on the ontology
    case "IndividualRoleGrantsEditorQuery": {
      const mm = modelOf(ctx.models, variables?.ontologyRid);
      const ours = mm && (mm.objectTypes.some((o) => o.rid === variables?.rid) || mm.linkTypes.some((l) => l.rid === variables?.rid) || mm.actionTypes.some((a) => a.rid === variables?.rid));
      return { ...root,
        roleSet: { __typename: "RoleSet", _id: cid(`RoleSet:${variables?.roleSetId}`), id: variables?.roleSetId || null, roles: [] },
        ontology: mm ? { ...ontologyNode(mm), metadata: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${mm.rid}`), parent: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${namespaceRidOf(ctx.owner)}`), roleGrants: [] } } } : null,
        resourceMetadata: ours ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${variables.rid}`), rid: variables.rid, roleGrants: [], everyoneRoles: [] } : null };
    }
    // a link type's storage: it is stored in none
    case "LinkTypeStorageStatusQuery": {
      const hit = linkTypeHitOf(ctx.models, variables?.rid);
      return { ...root, linkType: hit ? { __typename: "LinkType", _id: cid(`LinkType:${hit.l.rid}`), rid: hit.l.rid, storage: null } : null };
    }
    // Ontology configuration → Proceed to migration: the project-permission migration assistant reads the ontology's object,
    // action and link types with their datasources, projects and who may move them into project permissions. An ODK type
    // is filed in no project and backed by no datasource, and the Hypervisor keeps no project permissions for ontology
    // resources to move one into (an ontology is changed by its owner or an administrator of its organization), so no
    // resource may be migrated by anyone: canUpdatePermissions is false for every one, and nothing is recommended. The
    // model keeps no shared properties or interfaces (cut O7).
    case "ObjectTypesAndLinkTypesWithDatasourcesQuery": case "ActionTypesRecommendationsQuery": case "SharedPropertiesRecommendationsQuery": case "InterfacesRecommendationsQuery": {
      if (!model) return { ...root, ontology: null };
      const meta = (r) => ({ __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${r}`), rid: r, projectRid: null, project: null,
        parent: ctx.owner ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${namespaceRidOf(ctx.owner)}`), rid: namespaceRidOf(ctx.owner) } : null });
      const perms = (r) => ({ __typename: "EntityPermissions", _id: cid(`migration-perm:${r}`), canEdit: model.mayChange === true, canUpdatePermissions: false });
      const pageOf = (typename, values) => ({ __typename: typename, values, nextPageToken: null, totalNumberOfResults: values.length });
      const node = { ...ontologyNode(model) };
      if (name === "ObjectTypesAndLinkTypesWithDatasourcesQuery") node.objectTypesV2 = pageOf("ObjectTypeVersionPage", model.objectTypes.map((o) => ({ __typename: "ObjectTypeVersion", _id: cid(`migration-otv:${o.rid}`),
        objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${o.rid}`), rid: o.rid, metadata: meta(o.rid), permissions: { ...perms(o.rid), __typename: "ObjectTypePermissions" }, owningPackage: null,
          latest: { __typename: "ObjectTypeVersion", _id: cid(`ObjectTypeVersion:${o.rid}`), dataSources: [], linksIncludingLinksToObjectTypesWithoutSearchableDatasources: [] } } })));
      if (name === "ActionTypesRecommendationsQuery") node.actionTypes = pageOf("ActionTypeVersionPage", model.actionTypes.map((a) => ({ __typename: "ActionTypeVersion", _id: cid(`migration-atv:${a.rid}`),
        affectedObjectTypes: model.objectTypes.filter((o) => o.id === a.applies_to).map((o) => ({ __typename: "ObjectType", _id: cid(`ObjectType:${o.rid}`), rid: o.rid })), affectedLinkTypes: [],
        actionType: { __typename: "ActionType", _id: cid(`ActionType:${a.rid}`), rid: a.rid, metadata: meta(a.rid), permissions: { ...perms(a.rid), __typename: "ActionTypePermissions" }, owningPackage: null } })));
      if (name === "SharedPropertiesRecommendationsQuery") node.sharedProperties = pageOf("SharedObjectTypePropertyVersionPage", []);
      if (name === "InterfacesRecommendationsQuery") node.interfaces = pageOf("OntologyInterfaceVersionPage", []);
      return { ...root, ontology: node };
    }
    // Review changes validates an edit against the caller's markings: the Hypervisor keeps no marking categories, and its one
    // organization (the owner tenant) is the caller's, its marking theirs to use (cut O7)
    case "GetAllMarkingPermissions": return { ...root, markingCategories: [], organizations: ctx.owner ? [organizationNodeOf(ctx.owner)] : [] };
    // …and whether each edited entity sits in a protected project: none is filed in a project (its parent is the namespace),
    // and nothing is protected
    case "IsResourceBranchProtectedByRidQuery": {
      const r = String(variables?.rid || "");
      const ours = (ctx.models || []).some((mm) => mm.rid === r || mm.objectTypes.some((o) => o.rid === r) || mm.linkTypes.some((l) => l.rid === r) || mm.actionTypes.some((a) => a.rid === r));
      return { ...root, resourceMetadata: ours ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${r}`), rid: r, projectRid: null, project: null, isProtected: false,
        parent: ctx.owner ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${namespaceRidOf(ctx.owner)}`), rid: namespaceRidOf(ctx.owner) } : null } : null };
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
// (a draft is not a published revision). A type is backed by a datasource, and stored in an object store, exactly when its
// materialized sets back it (cut O8: datasourcesOfType, entityMetadataOf); otherwise its storage metadata says it is stored
// nowhere. (The GraphQL metadata panel's `dataSources` stays empty: its shape was never recorded.)
const DRAFT_STATUS = { type: "experimental", experimental: {} };
const ICON = { type: "blueprint", blueprint: { color: "#5F6B7C", locator: "cube" } };
export const branchRidOf = (model) => `ri.ontology.main.branch.${uuidOf(`branch:${model.family}`)}`;
export const renderHintsOf = (p) => (baseTypeOf(p.base).type === "string" ? [{ kind: "render_hint", name: "SELECTABLE" }] : []);
export function propertyTypeOf(p) {
  return {
    rid: p.rid, id: p.id, apiName: camel(p.name || p.id), sharedPropertyTypeApiName: null,
    displayMetadata: { description: p.description || null, displayName: p.name || p.id, visibility: "NORMAL" },
    // a string property's values are matched and bucketed exactly (Object Explorer's filters and histograms over materialized
    // objects, cut O8): the reference's own SELECTABLE render hint, which its editor sets on every exact-matching string
    indexedForSearch: true, ruleSetBinding: null, baseFormatter: null, type: baseTypeOf(p.base), typeClasses: renderHintsOf(p), status: DRAFT_STATUS,
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
    ontologyRid: model.rid, ontologyVersion: model.version, datasources: datasourcesOfType(ot),
    entityMetadata: entityMetadataOf(ot),
    resolvedBranch: { type: "default", default: { rid: branchRidOf(model) } },
    schemaMigrations: { schemaTransitions: [], schemaVersion: 1 },
  };
}
// A backed type's datasources (cut O8): one per projection that materializes it — a dataset datasource whose dataset is that
// projection's materialized sets (its newest the current contents) and whose property mapping is each property's source field.
// An unbacked type has none.
export function datasourcesOfType(ot) {
  return (ot?.backing?.datasources || []).map((ds) => ({
    rid: ds.rid,
    datasource: { type: "dataset", dataset: { branchId: "master", datasetRid: ds.datasetRid, writebackDatasetRid: null,
      propertyMapping: Object.fromEntries(ot.properties.filter((p) => ds.mapping[p.id]).map((p) => [p.rid, ds.mapping[p.id]])) } },
    editsConfiguration: { onlyAllowPrivilegedEdits: false }, redacted: null, dataSecurity: null,
  }));
}
// GET /foundry-metadata/api/schemas/datasets/<dataset rid>/branches/master — a backing dataset's schema: the source fields its
// properties are mapped from, typed by the property each backs, at its newest set (its current transaction). Null when the
// dataset is not one of the caller's backing datasets.
const FIELD_TYPE = { string: "STRING", integer: "INTEGER", long: "LONG", double: "DOUBLE", boolean: "BOOLEAN", date: "DATE", timestamp: "TIMESTAMP" };
export function datasetSchemaOf(models, datasetRid) {
  for (const m of models || []) for (const ot of m.objectTypes) for (const ds of ot.backing?.datasources || []) {
    if (ds.datasetRid !== datasetRid) continue;
    const fields = ot.properties.filter((p) => ds.mapping[p.id]).map((p) => ({ type: FIELD_TYPE[String(p.base || "string").toLowerCase()] || "STRING", name: ds.mapping[p.id], nullable: null,
      userDefinedTypeClass: null, customMetadata: {}, arraySubtype: null, precision: null, scale: null, mapKeyType: null, mapValueType: null, subSchemas: null }));
    return { branchId: "master", transactionRid: `ri.foundry.main.transaction.${uuidOf(`odk-set-transaction:${ds.setRef}`)}`, versionId: uuidOf(`odk-set-version:${ds.setRef}`),
      schema: { fieldSchemaList: fields, primaryKey: null, dataFrameReaderClass: null, customMetadata: {} }, attribution: null };
  }
  return null;
}
// the object store a backed type's objects are held and searched in: the daemon's materialized-set store, in the reference's
// vocabulary its object storage (V2) — the only store its reads know — so the type's data "is available"
export const OBJECT_STORE_DB = Object.freeze({ type: "highbury", cluster: "ri.highbury.main.cluster.1" });
export const objectIndexRidOf = (ot) => `ri.highbury.main.index.${uuidOf(`odk-object-index:${ot.rid}`)}`;
// An object type's storage metadata: an unbacked type is stored nowhere (no object database, no patches, no edits history); a
// backed one (cut O8) is held in the object store its materialized sets are (above).
export function entityMetadataOf(ot = null) {
  const backed = (ot?.backing?.datasources || []).length > 0;
  return {
    entityConfig: { objectDbTypeConfigs: backed ? { [OBJECT_STORE_DB.type]: { objectDbConfigs: { [OBJECT_STORE_DB.cluster]: { configValue: "{}" } } } } : {} }, arePatchesEnabled: false,
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
  return { objectTypes: (request?.objectTypes || []).filter((r) => ours.has(r.objectTypeRid)).map((r) => ({ objectTypeRid: r.objectTypeRid, objectTypeEntityMetadata: entityMetadataOf(objectTypeOf(models, { rid: r.objectTypeRid })?.ot) })) };
}
// PUT /ontology-metadata/api/permissions/objectTypes — the caller sees their types, and edits one exactly when the daemon
// reads them as one who may change its ontology (`caller_may_change`); anyone else reads the reference's own "You do not
// have edit permissions". Deleting a type, datasources and roles are not offered (none is bound here).
const mayChangeOf = (models, has) => (models || []).find(has)?.mayChange === true;
export function objectTypePermissionsOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.objectTypes.map((o) => o.rid)));
  return { objectTypePermissions: Object.fromEntries((request?.objectTypeRids || []).filter((r) => ours.has(r)).map((r) => [r, {
    canView: true, canEdit: mayChangeOf(models, (m) => m.objectTypes.some((o) => o.rid === r)), canDelete: false, canAddDatasources: false, canUpdateRoles: false, canApplyRestrictedSchemaMigrations: false,
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
// PUT /ontology-metadata/api/permissions/actionTypes — the caller sees their action types, and edits one as they may its
// ontology (the daemon's `caller_may_change`)
export function actionTypePermissionsOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.actionTypes.map((a) => a.rid)));
  return { actionTypePermissions: Object.fromEntries((request?.actionTypeRids || []).filter((r) => ours.has(r)).map((r) => [r, {
    canView: true, canEdit: mayChangeOf(models, (m) => m.actionTypes.some((a) => a.rid === r)), canUseNotifications: false, canUpdateRoles: false, hasRolesApplied: false,
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
    linkTypes: (request?.linkTypes || []).map((r) => linkTypeHitOf(models, r?.identifier?.linkTypeRid || r?.linkTypeRid, r?.identifier?.linkTypeId)).filter(Boolean).map(({ model, lt }) => ({
      linkType: lt, ontologyRid: model.rid, ontologyVersion: model.version, datasources: [],
      entityMetadata: { entityConfig: { objectDbTypeConfigs: {} }, arePatchesEnabled: false, targetStorageBackend: { type: "objectStorageV2", objectStorageV2: { migrationConfiguration: null, editsHistoryImportConfiguration: null, archiveState: null } }, provenance: null, redacted: null },
      resolvedBranch: { type: "default", default: { rid: branchRidOf(model) } },
    })),
    sharedPropertyTypes: [], interfaceTypes: [], typeGroups: [],
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

// ---- An ODK link type as the reference's. A one_to_one or one_to_many link is the reference's one-to-many (its `from`
// type the one side, its `to` type the many side, the cardinality its hint); a many_to_many link is many-to-many. An
// ODK link names its two endpoints, not the property that joins them, so the key-to-property mapping is empty. One
// whose endpoints do not resolve to the ontology's types is not offered.
const endpointOf = (l, side) => l[side] || l[side === "from" ? "source" : "target"] || l[side === "from" ? "object_type_a" : "object_type_b"] || null;
export function linkTypeOf(model, l) {
  const byId = new Map(model.objectTypes.map((o) => [o.id, o]));
  const a = byId.get(endpointOf(l, "from")), b = byId.get(endpointOf(l, "to"));
  if (!a || !b) return null;
  const side = (o, name) => ({ displayMetadata: { displayName: name || o.name, groupDisplayName: null, pluralDisplayName: name || o.name, visibility: "NORMAL" }, typeClasses: [], apiName: camel(name || o.name) });
  const definition = String(l.cardinality) === "many_to_many"
    ? { type: "manyToMany", manyToMany: { objectTypeAToBLinkMetadata: side(b, l.name), objectTypeBToALinkMetadata: side(a, l.inverse_name), objectTypeRidA: a.rid, objectTypeRidB: b.rid, objectTypeAPrimaryKeyPropertyMapping: {}, objectTypeBPrimaryKeyPropertyMapping: {}, peeringMetadata: null } }
    : { type: "oneToMany", oneToMany: { cardinalityHint: String(l.cardinality) === "one_to_one" ? "ONE_TO_ONE" : "ONE_TO_MANY", manyToOneLinkMetadata: side(a, l.inverse_name), objectTypeRidManySide: b.rid, objectTypeRidOneSide: a.rid, oneToManyLinkMetadata: side(b, l.name), oneSidePrimaryKeyToManySidePropertyMapping: {} } };
  return { description: l.description || null, definition, id: l.id, rid: l.rid, status: DRAFT_STATUS, redacted: null };
}
export function linkTypeHitOf(models, linkTypeRid, linkTypeId = null) {
  for (const m of models || []) {
    const l = m.linkTypes.find((x) => (linkTypeRid && x.rid === linkTypeRid) || (linkTypeId && x.id === linkTypeId));
    if (l) { const lt = linkTypeOf(m, l); if (lt) return { model: m, l, lt }; }
  }
  return null;
}
// POST /ontology-metadata/api/ontology/linkTypesForObjectTypes(V2) — each requested object type's link types. Object Explorer
// (`traversableOnly`, cut O8) follows a link to the linked objects through the property that joins the two types (the one
// side's primary key → the many side's property; exactly one entry, or its object layer throws "Property mapping has more
// than one entry" and the page crashes). An ODK link names its endpoints and never that property, so no ODK link can be
// followed there: each type is answered with none. The Ontology Manager still lists them (its link pages read the endpoints).
export function linkTypesForObjectTypesOf(request, models, { traversableOnly = false } = {}) {
  const out = {};
  for (const otRid of Object.keys(request?.objectTypeVersions || {})) {
    const hit = (models || []).map((mm) => ({ mm, ot: mm.objectTypes.find((o) => o.rid === otRid) })).find((x) => x.ot);
    if (!hit) continue;
    out[otRid] = traversableOnly ? [] : hit.mm.linkTypes.filter((l) => [endpointOf(l, "from"), endpointOf(l, "to")].includes(hit.ot.id)).map((l) => linkTypeOf(hit.mm, l)).filter(Boolean);
  }
  return { linkTypes: out };
}
// POST /ontology-metadata/api/ontology/ontology/load/<ontology rid>/<version>/loadAllObjectTypes — the ontology's object
// types (each in its load envelope, as bulkLoadEntities answers it), a page at a time (the page token is the offset)
export function allObjectTypesOf(model, request) {
  if (!model) return { objectTypes: [], nextPageToken: null };
  const from = Math.max(0, Number(request?.pageToken) || 0), size = Math.max(1, Number(request?.pageSizeLimit) || 500);
  const page = model.objectTypes.slice(from, from + size).map((ot) => objectTypeEntityOf(model, ot));
  return { objectTypes: page, nextPageToken: from + size < model.objectTypes.length ? String(from + size) : null };
}
// POST /ontology-metadata/api/actions/types/load/all/<ontology rid>[/<version>] — the ontology's action types (each the
// action type itself, not its load envelope), a page at a time
export function allActionTypesOf(model, request) {
  if (!model) return { actionTypes: [], nextPageToken: null };
  const from = Math.max(0, Number(request?.pageToken) || 0), size = Math.max(1, Number(request?.pageSizeLimit) || 500);
  return { actionTypes: model.actionTypes.slice(from, from + size).map((a) => actionTypeEntityOf(model, a).actionType), nextPageToken: from + size < model.actionTypes.length ? String(from + size) : null };
}
// ---- Object views (cut O7). An object view is a per-type view module the reference builds in its object view editor and
// previews over the type's indexed objects. The Hypervisor keeps no object views and has no object view editor; an ODK type's
// instances, once materialized, are read through the daemon's object-instance search, never through a view. The reference
// decides the tab from the platform's page environment — the applications it names — and disables it, with its own reason
// ("Object views are not enabled"), when no object view editor is named. That environment is the recorded tenant's; the
// Ontology Manager's page is served naming no object view editor, so the tab says so instead of spinning over reads of
// objects that no view can show. Nothing else in the environment is changed.
const OBJECT_VIEW_EDITOR_ROUTE = [/&quot;object-view-editor&quot;:&quot;[^&"]*&quot;,/gu, /,&quot;object-view-editor&quot;:&quot;[^&"]*&quot;/gu, /"object-view-editor":"[^"]*",/gu, /,"object-view-editor":"[^"]*"/gu];
export function ontologyPageOf(html) {
  if (typeof html !== "string") return html;
  return OBJECT_VIEW_EDITOR_ROUTE.reduce((out, re) => out.replace(re, ""), html);
}
// POST /objects-data-funnel/api/view/currentV4 — the object database views of the caller's types: none (an ODK type
// is indexed in no object database)
// … and (cut O8) a backed type's one view: its objects in the object store (its materialized sets), at the ontology's version, as a
// batch index whose base version is the newest registration among its datasources
export function objectViewsOf(request, models) {
  return { snapshotId: null, views: (request?.objectTypes || []).map((l) => ({ l, hit: objectTypeOf(models, { rid: l?.rid }) })).filter((x) => x.hit).map(({ l, hit }) => {
    const ds = hit.ot.backing?.datasources || [];
    const views = ds.length ? [{ rid: objectIndexRidOf(hit.ot), dbType: OBJECT_STORE_DB.type, dbRid: OBJECT_STORE_DB.cluster, ontologyVersion: hit.model.version,
      status: { type: "batch", batch: { baseVersion: `${uuidOf(`odk-object-index-version:${ds.map((d) => d.setRef).join(",")}`)}`, patchOffset: 0 } } }] : [];
    return { locator: { rid: l.rid, ref: l.ref ?? null }, resolved: { views, ref: null, forkView: null } };
  }) };
}
// POST /objects-data-funnel/api/status/object-type — a type's indexing status, and it is not archived. An unbacked ODK type is
// indexed by no pipeline. A backed one (cut O8) is indexed by its materializing runs: each datasource's last run registered its
// newest set (a run that registered a set succeeded — a failed run registers none), which the object store holds at the
// ontology's version, up to date; no patches or direct writes exist. Null for a type that is not the caller's.
const jobOfRun = (runRef) => `ri.foundry.main.job.${uuidOf(`materializing-run-job:${String(runRef || "").replace(/^materializing-run:\/\//u, "")}`)}`;
export function objectTypeFunnelStatusOf(request, models) {
  const hit = objectTypeOf(models, { rid: request?.objectType });
  if (!hit) return null;
  const ds = hit.ot.backing?.datasources || [];
  const base = { isMigratingFunnelStorageSystem: null, resolvedRef: null, activePipeline: null, replacementPipeline: null, invalidDefinition: null, archiveStatus: { type: "active", active: {} }, activePipelineHasPatches: false };
  if (!ds.length) return base;
  const jobHistory = (d) => { const run = { job: jobOfRun(d.runRef), startedAt: d.set?.source_contact?.at || d.registeredAt, finishedAt: d.registeredAt, error: null, failureReason: null, profile: { type: "small", small: {} } };
    return { last: run, lastSuccessful: run, firstFailed: null, lastFailed: null, status: { type: "upToDate", upToDate: {} }, retryCount: null, platformFailuresStreakLength: 0 }; };
  const newest = [...ds].sort((a, b) => String(b.registeredAt || "").localeCompare(String(a.registeredAt || "")))[0];
  const baseVersion = uuidOf(`odk-object-index-version:${ds.map((d) => d.setRef).join(",")}`);
  return { ...base, activePipeline: { type: "batch", batch: {
    pipelineId: { type: "batch", batch: uuidOf(`odk-object-pipeline:${hit.ot.rid}`) }, ontologyVersion: hit.model.version,
    current: { data: { baseVersion, provenance: Object.fromEntries(ds.map((d) => [d.rid, `ri.foundry.main.transaction.${uuidOf(`odk-set-transaction:${d.setRef}`)}`])) } }, upcoming: null,
    datasources: Object.fromEntries(ds.map((d) => [d.rid, jobHistory(d)])),
    datasourceReferences: Object.fromEntries(ds.map((d) => [d.rid, { type: "dataset", dataset: { rid: d.datasetRid, branch: "master" } }])),
    page: jobHistory(newest),
    objectDbs: [{ type: OBJECT_STORE_DB.type, rid: OBJECT_STORE_DB.cluster, bootstrapped: "COMPLETE", current: { jobHistory: jobHistory(newest), ontologyVersion: hit.model.version,
      activeBaseVersion: { type: "materialized", materialized: { baseVersion, locator: objectIndexRidOf(hit.ot), materializedAt: newest.registeredAt, repairing: null } }, upcomingBaseVersion: null }, replacement: null }],
    hasPatches: false, patchedPropertiesV2: [], patchedProperties: [], latestPatchCommittedAt: null, latestDirectWriteCommittedAt: null, schemaVersion: 1, failureDetails: [], storageSystem: "ALTA", directSourceTelemetry: null,
  } } };
}
// POST /objects-data-funnel/api/view/policiesV3 — the row and property policies of the caller's types: none (no granular
// policy restricts who sees a type's objects or properties; there are no objects)
export function objectTypePoliciesOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.objectTypes.map((o) => o.rid)));
  return { policies: (request?.objectTypes || []).filter((l) => ours.has(l?.rid)).map((l) => ({ locator: { rid: l.rid, ref: l.ref ?? null }, resolved: { policies: { row: [], property: {} }, ref: null } })) };
}
// POST /compass/api/roles — the role grants on the caller's types: none (no ontology roles are kept)
export function compassRolesOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => [m.rid, ...m.objectTypes.map((o) => o.rid), ...m.linkTypes.map((l) => l.rid), ...m.actionTypes.map((a) => a.rid)]));
  return { resourceRolesResultMap: Object.fromEntries((request?.rids || []).filter((r) => ours.has(r)).map((r) => [r, { grants: [], disableInheritedPermissionsForPrincipals: [], disableInheritedPermissions: false, disableInheritedPermissionsType: null }])) };
}
// PUT /ontology-metadata/api/permissions/linkTypes — the caller sees their link types, and edits one as they may its
// ontology (the daemon's `caller_may_change`)
export function linkTypePermissionsOf(request, models) {
  return { linkTypePermissions: Object.fromEntries((request?.linkTypeRids || []).filter((r) => linkTypeHitOf(models, r)).map((r) => [r, {
    canView: true, canEdit: linkTypeHitOf(models, r)?.model?.mayChange === true, canDelete: false, canAddDatasources: false, canUpdateRoles: false,
    datasourcePermissions: {}, isEditRestrictedByDatasources: false, packageRid: null, permissionModel: { type: "roles", roles: {} },
  }])) };
}
// POST /ontology-metadata/api/ontology/ontology/load/datasources — each of the caller's requested types with its datasources: a
// backed type's materialized sets (cut O8, datasourcesOfType), none for a type no set materializes. An ODK link keeps no join
// table, so a many-to-many link type has none.
export function datasourcesOf(request, models) {
  return {
    objectTypes: Object.fromEntries(Object.keys(request?.objectTypes || {}).map((r) => [r, objectTypeOf(models, { rid: r })]).filter(([, hit]) => hit).map(([r, hit]) => [r, datasourcesOfType(hit.ot)])),
    manyToManyLinkTypes: Object.fromEntries(Object.keys(request?.manyToManyLinkTypes || {}).filter((r) => linkTypeHitOf(models, r)).map((r) => [r, []])),
  };
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

// ---- Objects (cut O8): the object-set service's reads over the caller's materialized objects. The reference reads objects
// by OBJECT SET — an expression (a type's objects, filtered, unioned, intersected, subtracted, or named by rid) that the service
// evaluates for a page of objects, an aggregate (counts, histograms, min/max), or the types it spans. Each is evaluated here over
// the objects of the caller's backed types (backingOf: the daemon's materialized sets) and nothing else; a construct this layer
// does not evaluate is refused by name (Hypervisor:OntologyReadNotBound), never answered as an empty set.
export class ObjectSetNotBound extends Error {
  constructor(what) { super(`${what} is not evaluated over the Hypervisor's materialized objects yet: a named gap, and no object is invented in its place`); this.what = what; }
}
// a property value in the reference's typed form (by the property's base type); undefined when the object has none
export function typedValueOf(base, v) {
  if (v === null || v === undefined) return undefined;
  switch (String(base || "string").toLowerCase()) {
    case "integer": return { type: "integer", integer: Number(v) };
    case "long": return { type: "long", long: String(v) };
    case "double": return { type: "double", double: Number(v) };
    case "boolean": return { type: "boolean", boolean: v === true || v === "true" };
    case "timestamp": { const ms = typeof v === "number" ? v : Date.parse(v); return Number.isFinite(ms) ? { type: "timestamp", timestamp: ms } : { type: "string", string: String(v) }; }
    case "date": return { type: "date", date: String(v) };
    default: return { type: "string", string: typeof v === "string" ? v : JSON.stringify(v) };
  }
}
// every backed object of the caller's, with its type and ontology
export function objectUniverseOf(models) {
  return (models || []).flatMap((model) => model.objectTypes.flatMap((ot) => (ot.backing?.objects || []).map((o) => ({ model, ot, o }))));
}
const propOf = (ot, propertyId) => ot.properties.find((p) => p.id === propertyId || p.rid === propertyId || camel(p.name || p.id) === propertyId) || null;
const valueOf = (e, propertyId) => { const p = propOf(e.ot, propertyId); return p ? e.o.props[p.id] : undefined; };
const comparable = (e, propertyId) => {
  const p = propOf(e.ot, propertyId), v = p ? e.o.props[p.id] : undefined;
  if (v === null || v === undefined) return null;
  if (p && ["date", "timestamp"].includes(String(p.base))) { const ms = typeof v === "number" ? v : Date.parse(v); return Number.isFinite(ms) ? ms : null; }
  return typeof v === "number" ? v : typeof v === "boolean" ? (v ? 1 : 0) : Number.isFinite(Number(v)) && String(v).trim() !== "" && p && ["integer", "long", "double"].includes(String(p.base)) ? Number(v) : v;
};
const words = (s) => String(s ?? "").toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
// the properties a filter's property set names (every property when it names all of them)
const propertySetOf = (ot, set) => {
  const ids = set?.propertyWhitelist?.properties || set?.selected?.propertySelection?.propertyId?.propertyIds || null;
  return Array.isArray(ids) ? ot.properties.filter((p) => ids.includes(p.id) || ids.includes(p.rid)) : ot.properties;
};
export function objectMatches(filter, e) {
  const f = filter || {};
  switch (f.type) {
    case "and": return (f.and?.filters || []).every((x) => objectMatches(x, e));
    case "or": return (f.or?.filters || []).some((x) => objectMatches(x, e));
    case "not": return !objectMatches(f.not?.filter, e);
    case "hasProperty": { const v = valueOf(e, f.hasProperty?.propertyId); return v !== null && v !== undefined && v !== ""; }
    case "exactMatch": { const v = valueOf(e, f.exactMatch?.propertyId); return v !== null && v !== undefined && (f.exactMatch?.terms || []).some((t) => String(t) === String(v)); }
    // every word of the query begins a word of some property in the set (the reference's keyword match over the properties
    // it names); a fuzzy match is not evaluated
    case "multiMatch": {
      if (f.multiMatch?.fuzzy === true) throw new ObjectSetNotBound("a fuzzy keyword filter");
      const want = words(f.multiMatch?.query);
      const have = propertySetOf(e.ot, f.multiMatch?.propertySet).flatMap((p) => words(e.o.props[p.id]));
      return want.every((w) => have.some((h) => h.startsWith(w)));
    }
    case "range": {
      const r = f.range || {}, v = comparable(e, r.propertyId);
      if (v === null) return false;
      const cmp = (x) => { const n = typeof v === "number" ? (Number.isFinite(Number(x)) ? Number(x) : Date.parse(x)) : x; return v < n ? -1 : v > n ? 1 : 0; };
      return (r.lt === undefined || r.lt === null || cmp(r.lt) < 0) && (r.lte === undefined || r.lte === null || cmp(r.lte) <= 0)
        && (r.gt === undefined || r.gt === null || cmp(r.gt) > 0) && (r.gte === undefined || r.gte === null || cmp(r.gte) >= 0);
    }
    default: throw new ObjectSetNotBound(`an object filter of type ${JSON.stringify(f.type ?? null)}`);
  }
}
// temporary object sets (the reference registers one to page through a set): the caller's own expression, kept by rid for
// this serve's lifetime only — it is the caller's query, not truth, and evaluates over the daemon's sets on every read
export const temporaryObjectSetRidOf = (principalRef, expression) => `ri.object-set.main.temporary-object-set.${uuidOf(`temporary-object-set:${principalRef || "anonymous"}:${canon(expression)}`)}`;
// → the set's entries (each { model, ot, o }), deduplicated by object rid, in key order
export function evaluateObjectSet(os, ctx) {
  const universe = ctx.universe || objectUniverseOf(ctx.models);
  const byRid = new Map(universe.map((e) => [e.o.rid, e]));
  const uniq = (list) => { const seen = new Set(); return list.filter((e) => (seen.has(e.o.rid) ? false : (seen.add(e.o.rid), true))); };
  const walk = (x, depth = 0) => {
    if (depth > 32) throw new ObjectSetNotBound("an object set nested this deeply");
    switch (x?.type) {
      case "base": { const id = x.base?.objectTypeId, r = x.base?.objectTypeRid; return universe.filter((e) => (id && e.ot.id === id) || (r && e.ot.rid === r)); }
      case "filtered": return walk(x.filtered?.objectSet, depth + 1).filter((e) => objectMatches(x.filtered?.filter, e));
      case "unioned": return uniq((x.unioned?.objectSets || []).flatMap((s) => walk(s, depth + 1)));
      case "intersected": { const parts = (x.intersected?.objectSets || []).map((s) => new Set(walk(s, depth + 1).map((e) => e.o.rid))); return parts.length ? universe.filter((e) => parts.every((p) => p.has(e.o.rid))) : []; }
      case "subtracted": { const [head, ...rest] = x.subtracted?.objectSets || []; const gone = new Set(rest.flatMap((s) => walk(s, depth + 1)).map((e) => e.o.rid)); return head ? walk(head, depth + 1).filter((e) => !gone.has(e.o.rid)) : []; }
      case "static": return uniq((x.static?.objectRids || []).map((r) => byRid.get(r)).filter(Boolean));
      case "staticV2": return uniq((x.staticV2?.objectIdentifiers || []).map((i) => (i?.objectRid ? byRid.get(i.objectRid) : null)).filter(Boolean));
      case "referenced": case "reference": {
        const r = x.referenced?.objectSetRid || x.reference?.objectSetRid || x[x.type]?.rid;
        const kept = ctx.temporary?.get(r);
        if (!kept) throw new ObjectSetNotBound("a saved or expired object set");
        return walk(kept, depth + 1);
      }
      default: throw new ObjectSetNotBound(`an object set of type ${JSON.stringify(x?.type ?? null)}`);
    }
  };
  return walk(os).sort((a, b) => a.ot.rid.localeCompare(b.ot.rid) || a.o.key.localeCompare(b.o.key));
}
// the types an object set spans (whether or not it holds objects): the types its bases name, among the caller's
export function objectSetTypesOf(os, models) {
  const ids = new Set(), rids = new Set();
  const visit = (x) => { if (!x || typeof x !== "object") return; if (x.type === "base") { if (x.base?.objectTypeId) ids.add(x.base.objectTypeId); if (x.base?.objectTypeRid) rids.add(x.base.objectTypeRid); } for (const v of Object.values(x)) if (v && typeof v === "object") visit(v); };
  visit(os);
  for (const r of JSON.stringify(os || {}).match(/ri\.phonograph2-objects\.main\.object\.v4\.[0-9a-f-]{36}/gu) || []) rids.add(`ri.ontology.main.object-type.${r.split(".").pop()}`);
  return (models || []).flatMap((m) => m.objectTypes.filter((ot) => ids.has(ot.id) || rids.has(ot.rid)).map((ot) => ({ model: m, ot })));
}
const objectSetEntitiesOf = (types) => ({ linkTypeRids: [], objectTypeRids: types.map((t) => t.ot.rid), interfaceTypeRids: [],
  objectTypeMetadata: Object.fromEntries(types.map((t) => [t.ot.rid, { objectTypeId: t.ot.id, properties: Object.fromEntries(t.ot.properties.map((p) => [p.rid, { propertyId: p.id }])) }])) });
// an object on the wire: its rid, type, primary key, title and the asked properties (typed)
export function objectWireOf(e, propertySet) {
  const selectedIds = propertySet?.propertyWhitelist?.properties || propertySet?.selected?.propertySelection?.propertyId?.propertyIds || null;
  const props = {};
  for (const p of e.ot.properties) {
    if (Array.isArray(selectedIds) && !selectedIds.includes(p.id) && !selectedIds.includes(p.rid)) continue;
    const tv = typedValueOf(p.base, e.o.props[p.id]);
    if (tv) props[p.rid] = tv;
  }
  const pk = e.ot.properties.find((p) => p.id === e.ot.primaryKey);
  return { objectRid: e.o.rid, objectTypeRid: e.ot.rid, primaryKey: pk ? { [pk.rid]: typedValueOf(pk.base, e.o.props[pk.id] ?? e.o.key) } : {}, title: e.o.title, properties: props,
    runtimeDerivedProperties: {}, score: null, version: { type: "v1", v1: Buffer.from(`${e.o.setRef || ""}#${e.o.key}`).toString("base64").slice(-24) } };
}
// PUT /object-set-service/api/objectSets/objects/top/initial (and /top/next): a page of the set's objects, in the asked order
export function objectsPageOf(request, ctx) {
  const all = evaluateObjectSet(request?.objectSet, ctx);
  const ordering = request?.resultOrdering || {};
  if (ordering.type === "propertyValue") {
    const keys = ordering.propertyValue?.propertyOrdering || [];
    all.sort((a, b) => { for (const k of keys) { const x = comparable(a, k.propertyId), y = comparable(b, k.propertyId); if (x === y) continue; const s = x === null ? 1 : y === null ? -1 : x < y ? -1 : 1; return String(k.direction || "ASC").toUpperCase().startsWith("DESC") ? -s : s; } return 0; });
  } else if (!["relevancy", "unspecified", undefined].includes(ordering.type)) throw new ObjectSetNotBound(`an object ordering of type ${JSON.stringify(ordering.type)}`);
  const from = Math.max(0, Number(request?.pageToken) || 0), size = Math.max(1, Math.min(10000, Number(request?.pageSize) || 50));
  const page = all.slice(from, from + size);
  return { results: page.map((e) => objectWireOf(e, request?.propertySet)), interfaceViews: {}, interfaceViewsV2: {}, nextPageToken: from + size < all.length ? String(from + size) : null, totalResults: all.length,
    objectSetEntities: request?.responseOptions?.includeObjectSetEntities ? objectSetEntitiesOf(objectSetTypesOf(request?.objectSet, ctx.models)) : null, usageCost: null, securities: [], objectLoadingFailures: null };
}
// PUT /object-set-service/api/objectSets/objectTypes — the types an object set spans
export function objectSetObjectTypesOf(request, ctx) {
  const types = objectSetTypesOf(request?.objectSet, ctx.models);
  evaluateObjectSet(request?.objectSet, ctx); // (a construct not evaluated is refused, as for its objects)
  return { objectTypeIds: types.map((t) => t.ot.id), objectTypeRids: types.map((t) => t.ot.rid) };
}
// PUT /object-set-service/api/aggregate — the set's metrics (count, min, max, sum, average, distinct count) and buckets (by
// type, by a property's exact values, by fixed-width numeric ranges, by date intervals)
const bucketKeyOfNumber = (n) => (Number.isInteger(n) ? `${n}.0` : String(n));
function metricOf(spec, entries) {
  const kind = spec?.type, body = spec?.[kind] || {};
  const values = () => entries.map((e) => comparable(e, body.propertyId)).filter((v) => typeof v === "number");
  switch (kind) {
    case "count": return entries.length;
    case "max": { const v = values(); return v.length ? Math.max(...v) : null; }
    case "min": { const v = values(); return v.length ? Math.min(...v) : null; }
    case "sum": return values().reduce((s, v) => s + v, 0);
    case "avg": case "average": { const v = values(); return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null; }
    case "approximateCardinality": case "cardinality": case "exactCardinality": return new Set(entries.map((e) => valueOf(e, body.propertyId)).filter((v) => v !== null && v !== undefined).map(String)).size;
    default: throw new ObjectSetNotBound(`an aggregate metric of type ${JSON.stringify(kind ?? null)}`);
  }
}
const metricsOf = (metrics, entries) => Object.fromEntries(Object.entries(metrics || {}).map(([name, spec]) => [name, metricOf(spec, entries)]));
function bucketsOf(dimension, entries) {
  const out = new Map(), nulls = [];
  const put = (key, e) => { if (!out.has(key)) out.set(key, []); out.get(key).push(e); };
  if (dimension?.type === "objectType") { for (const e of entries) put(e.ot.id, e); return { out, nulls }; }
  if (dimension?.type !== "propertyValue") throw new ObjectSetNotBound(`an aggregate dimension of type ${JSON.stringify(dimension?.type ?? null)}`);
  const { propertyId, bucketing } = dimension.propertyValue || {};
  for (const e of entries) {
    const raw = valueOf(e, propertyId), v = comparable(e, propertyId);
    if (raw === null || raw === undefined || raw === "") { nulls.push(e); continue; }
    switch (bucketing?.type) {
      case "exactValue": put(String(raw), e); break;
      case "numeric": {
        const w = Number(bucketing.numeric?.fixedWidth?.bucketWidth);
        if (bucketing.numeric?.type !== "fixedWidth" || !(w > 0) || typeof v !== "number") throw new ObjectSetNotBound("a numeric bucketing that is not a fixed width over a number");
        put(bucketKeyOfNumber(Math.floor(v / w) * w), e); break;
      }
      case "date": {
        const unit = String(bucketing.date?.interval?.unit || "DAY").toUpperCase(), n = Math.max(1, Number(bucketing.date?.interval?.value) || 1), d = new Date(typeof v === "number" ? v : Date.parse(raw));
        if (Number.isNaN(d.getTime())) { nulls.push(e); break; }
        const y = d.getUTCFullYear(), m = d.getUTCMonth(), day = d.getUTCDate();
        const start = unit === "YEAR" ? Date.UTC(y - (y % n), 0, 1) : unit === "QUARTER" ? Date.UTC(y, m - (m % (3 * n)), 1) : unit === "MONTH" ? Date.UTC(y, m - (m % n), 1)
          : unit === "WEEK" ? Date.UTC(y, m, day - ((d.getUTCDay() + 6) % 7)) : unit === "DAY" ? Date.UTC(y, m, day) : null;
        if (start === null) throw new ObjectSetNotBound(`a date bucketing by ${unit}`);
        put(new Date(start).toISOString(), e); break;
      }
      default: throw new ObjectSetNotBound(`a property bucketing of type ${JSON.stringify(bucketing?.type ?? null)}`);
    }
  }
  return { out, nulls, bucketing };
}
function subAggregationOf(spec, entries) {
  if (spec?.type !== "metrics") throw new ObjectSetNotBound(`an aggregation of type ${JSON.stringify(spec?.type ?? null)}`);
  const m = spec.metrics || {};
  const { out, nulls, bucketing } = bucketsOf(m.dimension, entries);
  const exact = bucketing?.exactValue || {};
  const excluded = new Set((exact.valueFilter?.type === "excludeValues" ? exact.valueFilter.excludeValues?.values : []) || []);
  if (nulls.length && typeof exact.defaultValue === "string") { out.set(exact.defaultValue, nulls.splice(0)); }
  let buckets = [...out.entries()].filter(([k]) => !excluded.has(k)).map(([key, es]) => ({ key, metrics: metricsOf(m.metrics, es), subAggregations: Object.fromEntries(Object.entries(m.subAggregations || {}).map(([n, s]) => [n, subAggregationOf(s, es)])), _n: es.length }));
  const order = (m.ordering || []).find((o) => o?.type === "valueOrdering")?.valueOrdering;
  buckets.sort((a, b) => {
    if (order) { const x = a.metrics[order.metricName] ?? 0, y = b.metrics[order.metricName] ?? 0; if (x !== y) return String(order.direction).toUpperCase().startsWith("DESC") ? y - x : x - y; }
    const nx = Number(a.key), ny = Number(b.key);
    return Number.isFinite(nx) && Number.isFinite(ny) ? nx - ny : String(a.key).localeCompare(String(b.key));
  });
  const max = Number(exact.maxBuckets || m.dimension?.objectType?.bucketing?.maxBuckets) || Infinity;
  const kept = buckets.slice(0, max), other = buckets.slice(max).reduce((s, b) => s + b._n, 0);
  return { itemsInOtherBuckets: other, resultAccuracy: { type: "accurate", accurate: {} }, buckets: kept.map(({ _n, ...b }) => b),
    nullValueBucket: nulls.length ? { key: null, metrics: metricsOf(m.metrics, nulls), subAggregations: {} } : null };
}
export function aggregateOf(request, ctx) {
  const entries = evaluateObjectSet(request?.objectSet, ctx);
  const a = request?.aggregation || {};
  return { result: { metrics: metricsOf(a.metrics, entries), subAggregations: Object.fromEntries(Object.entries(a.subAggregations || {}).map(([n, s]) => [n, subAggregationOf(s, entries)])) },
    objectSetEntities: request?.responseOptions?.includeObjectSetEntities ? objectSetEntitiesOf(objectSetTypesOf(request?.objectSet, ctx.models)) : null, usageCost: null };
}
// POST /hubble-server/api/explorations/configurations/get/<type rid> — an exploration's saved layouts: none is kept for any type
// (no exploration or layout is saved here), so the reference lays the exploration out by its own defaults
export const EXPLORATION_CONFIG_NONE = Object.freeze({ explorationConfig: { layoutToUse: null, userLayout: null, globalLayout: null, contextSpecificLayout: null, layoutsPerWorkspace: {} } });
// GET /hubble-server/api/user-preferences/v2 (and /global) — the caller's table preferences: none is kept
export const TABLE_PREFERENCES_NONE = Object.freeze({ version: "1.2.0", tablePreferences: [], versionMetadata: null });
// POST /hubble-server/api/object-views/v8/configuration/has-permissions — who may edit or publish a type's object view: no one
// (no object view is kept and there is no object view editor), for the caller's types
export function objectViewPermissionsOf(request, models) {
  const ours = new Set((models || []).flatMap((m) => m.objectTypes.map((o) => o.id)));
  const of = (ids) => Object.fromEntries((Array.isArray(ids) ? ids : []).filter((id) => ours.has(id)).map((id) => [id, false]));
  return { hasEditPermission: of(request?.hasEditPermission), hasPublishPermission: of(request?.hasPublishPermission) };
}
export const defaultObjectViewRidOf = (ot) => `ri.hubble-server.main.object-view.${uuidOf(`odk-default-object-view:${ot.rid}`)}`;
// GET /opus-server/api/graph/v2/pointer/object/<object rid> — the graphs an object is in: none is kept
export const GRAPH_POINTERS_NONE = Object.freeze({ graphPointers: [], nextPageToken: null });
// GET /carbon-server/api/configuration/config-for-carbon-sessionV2 — the Workshop workspaces objects may be opened in: none
export const CARBON_SESSION_NONE = Object.freeze({ defaultWorkspace: null, allAvailableWorkspaces: [], displayMetadata: null });
// POST /ontology-metadata/api/ontology/search/v0/searchObjectTypes — the caller's types a clause names (status, visibility, and
// their and/or/not), each in its load envelope. A draft's types are EXPERIMENTAL, of NORMAL visibility.
function typeClauseMatches(c, mm, ot) {
  switch (c?.type) {
    case "and": return (c.and || []).every((x) => typeClauseMatches(x, mm, ot));
    case "or": return (c.or || []).some((x) => typeClauseMatches(x, mm, ot));
    case "not": return !typeClauseMatches(c.not, mm, ot);
    case "status": return String(c.status || "").toUpperCase() === "EXPERIMENTAL";
    case "visibility": return String(c.visibility || "").toUpperCase() === "NORMAL";
    case undefined: return true;
    default: throw new ObjectSetNotBound(`an object type search clause of type ${JSON.stringify(c.type)}`);
  }
}
export function searchObjectTypesOf(request, models) {
  const want = new Set(request?.ontologyRids || []), excluded = new Set(request?.excludedObjectTypeRids || []), only = new Set(request?.includedObjectTypeRids || []);
  const hits = (models || []).filter((mm) => !want.size || want.has(mm.rid)).flatMap((mm) => mm.objectTypes.filter((ot) => !excluded.has(ot.rid) && (!only.size || only.has(ot.rid)) && typeClauseMatches(request?.clause, mm, ot)).map((ot) => objectTypeEntityOf(mm, ot)));
  const size = Math.max(1, Number(request?.pageSizeLimit) || 250), from = Math.max(0, Number(request?.pageToken) || 0);
  return { objectTypes: hits.slice(from, from + size), totalResults: hits.length, nextPageToken: from + size < hits.length ? String(from + size) : null };
}
// POST /foundry-search/api/compass/v2/search for the caller's saved explorations and lists (object-set service, versioned object
// sets — dynamic explorations and static lists): none is kept, in the reference's own empty answer (recorded by the O8 harvest). Any
// other Compass search is not answered here (it stays a named gap).
export function savedObjectSetSearchOf(request) {
  const clauses = request?.query?.filter?.and;
  const service = (Array.isArray(clauses) ? clauses : []).find((c) => c?.type === "service")?.service?.equals;
  const type = (Array.isArray(clauses) ? clauses : []).find((c) => c?.type === "resourceType")?.resourceType?.equals;
  if (service !== "object-set" || type !== "versioned-object-set" || request?.fetchFields !== "RIDS") return null;
  return { results: { type: "resourceRidSearchResult", resourceRidSearchResult: [] }, nextPageToken: null };
}
// the answer for a refused object-set read (the fence's named-gap shape)
export const objectSetRefusalBodyOf = (e, method, pathname) => ({ errorCode: "INTERNAL", errorName: "Hypervisor:OntologyReadNotBound", errorInstanceId: "",
  parameters: { message: `${method} ${pathname}: ${e?.message || "an object set construct is not evaluated here"}` } });

// ---- Object Explorer (/workspace/hubble, cut O4): the same ontology truth, as the explorer's catalog, search, recents
// and shortcuts read it. A type's object count is its materialized objects (cut O8; none when no set materializes it); no
// usage is kept, so its users are unknown (null); no favorites, saved explorations or type groups are kept, so each lists none.
export const EXPLORER_GRAPHQL_OPERATIONS = new Set([
  "AllObjectTypesQuery", "ObjectTypesQuery", "ObjectTypeResultsQuery", "OntologiesQuery", "CurrentUserQuery",
  "RecentObjectTypesQuery", "RecentsQuery", "FavoritesQuery", "FavoriteSavedExplorationsQuery", "FavoriteTypeGroupsQuery",
  "SavedExplorationsListQuery", "TypeGroupResultsQuery", "TypeGroupsQuery", "ObjectTypeSemanticSearchUnavailableReasonQuery",
  "YourExplorationsQuery", "GetObjectTypeDependents",
  // an exploration over a type and its objects (cut O8)
  "ObjectsQuery", "PreviewObjectQuery", "ObjectTypePreviewQuery", "SelectedObjectQuery", "ObjectPropertyRendererQuery",
  // …and its keyword search (cut O8)
  "ObjectTypeCountQuery", "ObjectTypeUsageMetricsQuery", "FavoritedObjectsQuery", "SemanticObjectTypeResultsQuery", "ObjectTypesWithGroupsQuery",
  // …and an object's full view (cut O8)
  "ObjectViewFullVersionQuery", "ResolveObjectViewRidQuery", "ProminentPropertiesQuery", "ObjectViewCorePropertiesTableQuery", "ObjectLinkTypesQuery",
]);
// ---- an object as the GraphQL object layer reads it (cut O8): an ObjectBranch with its title, type, primary key and properties
function objectPropertyNodeOf(ot, p, v) {
  const base = pascal(p.base || "string");
  return { __typename: `ObjectProperty_${base}`, __implements: ["ObjectProperty", "ObjectPrimaryKey"],
    propertyV2: { __typename: "ObjectTypeProperty", _id: cid(`ObjectTypeProperty:${p.rid}`), rid: p.rid,
      latest: { __typename: "ObjectTypePropertyVersion", _id: cid(`ObjectTypePropertyVersion:${p.rid}`), displayName: p.name || p.id, apiName: camel(p.name || p.id), typeClasses: [],
        objectTypeProperty: { __typename: "ObjectTypeProperty", _id: cid(`ObjectTypeProperty:${p.rid}`), rid: p.rid } } },
    value: objectPropertyValueNodeOf(p.base, v) };
}
// a property value as the object layer types it (no formatting or style is kept for a property: the reference's defaults apply)
function objectPropertyValueNodeOf(baseType, v) {
  if (v === null || v === undefined) return { __typename: "ObjectPropertyValue_Null", __implements: ["ObjectPropertyValue"], style: null };
  const base = pascal(baseType || "string");
  const node = { __typename: `ObjectPropertyValue_${base}`, __implements: ["ObjectPropertyValue", "ObjectArrayPropertyValue", "ObjectStructPropertyValue"], style: null, formatting: null };
  switch (String(baseType || "string").toLowerCase()) {
    case "long": return { ...node, value: String(v), valueV2: String(v) };
    case "integer": case "double": return { ...node, value: Number(v) };
    case "boolean": return { ...node, value: v === true || v === "true", formattedValue: String(v === true || v === "true") };
    case "timestamp": { const ms = typeof v === "number" ? v : Date.parse(v); return { ...node, value: Number.isFinite(ms) ? new Date(ms).toISOString() : String(v) }; }
    default: return { ...node, value: typeof v === "object" ? JSON.stringify(v) : v };
  }
}
export function objectBranchNodeOf(mm, ot, o) {
  const pk = ot.properties.find((p) => p.id === ot.primaryKey) || null;
  return { __typename: "ObjectBranch", _id: cid(`ObjectBranch:${o.rid}`), rid: o.rid, title: o.title,
    type: { __typename: "ObjectType", _id: cid(`ObjectType:${ot.rid}`), rid: ot.rid,
      latest: { ...explorerShallowVersionOf(ot), objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${ot.rid}`), rid: ot.rid, id: ot.id } } },
    primaryKey: pk ? objectPropertyNodeOf(ot, pk, o.props[pk.id] ?? o.key) : null,
    properties: ot.properties.filter((p) => o.props[p.id] !== undefined && o.props[p.id] !== null).map((p) => objectPropertyNodeOf(ot, p, o.props[p.id])),
    iconProperties: [] };
}
// a type's preview (the exploration's header and its About panel): its properties, object count, where it is filed (its
// ontology's namespace; no project, no package), what depends on it (nothing) and no object storage the reference keeps
function explorerTypePreviewOf(mm, ot, owner) {
  const version = explorerVersionOf(mm, ot);
  const nsRid = owner ? namespaceRidOf(owner) : null, nsName = owner ? namespaceNameOf(owner) : null;
  version.objectType = { ...explorerObjectTypeOf(mm, ot, explorerShallowVersionOf(ot)), storage: null, owningPackage: null,
    dependents: { __typename: "OntologyDependentPage", values: [] },
    ontology: { ...ontologyNode(mm), displayName: mm.displayName, description: mm.description || null },
    metadata: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${ot.rid}`), rid: ot.rid, project: null,
      parent: nsRid ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${nsRid}`), rid: nsRid, alias: nsName, name: nsName, openUrl: null, collections: [], status: null, trashedStatus: "NOT_TRASHED",
        type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-namespace" }, permissions: { __typename: "ResourceMetadataPermissions", _id: cid(`perm:${nsRid}`), canOpenLink: false } } : null } };
  return version;
}
const explorerShallowVersionOf = (ot) => ({
  __typename: "ObjectTypeVersion", _id: cid(`ObjectTypeVersion:${ot.rid}`), displayName: ot.name || ot.id, apiName: pascal(ot.name || ot.id),
  // (a string, never null: the explorer's type preview trims it)
  description: ot.description || "", visibility: "NORMAL", status: { __typename: "ObjectTypeStatus_Experimental" },
  iconV2: { __typename: "BlueprintIcon", color: ICON.blueprint.color, locator: ICON.blueprint.locator },
});
function explorerObjectTypeOf(mm, ot, latest) {
  return {
    // an object type is a Favorite (the interface the explorer's shortcuts spread their fragments on)
    // its object count: the caller's materialized objects of it (cut O8; none for a type no set materializes)
    __typename: "ObjectType", __implements: ["Favorite"], _id: cid(`ObjectType:${ot.rid}`), rid: ot.rid, id: ot.id, favorited: false, objectCount: (ot.backing?.objects || []).length,
    permissions: { __typename: "ObjectTypePermissions", canViewData: true }, usage: { __typename: "ObjectTypeUsage", uniqueUsersCount: null },
    ontology: { ...ontologyNode(mm), displayName: mm.displayName }, latest: latest || explorerShallowVersionOf(ot),
  };
}
// a type as the catalog and search rows read it: its properties (primary key and title marked), its links, no groups
export function explorerVersionOf(mm, ot) {
  const byId = new Map(mm.objectTypes.map((o) => [o.id, o]));
  const titleOf = (o) => ({ ...explorerShallowVersionOf(o), objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${o.rid}`), id: o.id, rid: o.rid } });
  const side = (o, name) => ({ __typename: "LinkTypeSideMetadata", displayName: name || o.name, apiName: camel(name || o.name) });
  const links = mm.linkTypes.filter((l) => [endpointOf(l, "from"), endpointOf(l, "to")].includes(ot.id)).map((l) => {
    const a = byId.get(endpointOf(l, "from")), b = byId.get(endpointOf(l, "to"));
    if (!a || !b) return null;
    const other = a.id === ot.id ? b : a;
    const definition = String(l.cardinality) === "many_to_many"
      ? { __typename: "LinkTypeDefinition_ManyToMany", aSide: { __typename: "LinkTypeSide", metadata: side(b, l.name), objectTypeV2: titleOf(a) }, bSide: { __typename: "LinkTypeSide", metadata: side(a, l.inverse_name), objectTypeV2: titleOf(b) } }
      : { __typename: "LinkTypeDefinition_OneToMany", oneSide: { __typename: "LinkTypeOneSide", metadata: side(a, l.inverse_name), objectTypeV2: titleOf(a) },
        manySide: { __typename: "LinkTypeManySide", cardinality: String(l.cardinality) === "one_to_one" ? "ONE" : "MANY", metadata: side(b, l.name), objectTypeV2: titleOf(b) } };
    return {
      __typename: "ObjectTypeLinkVersion", _id: cid(`ObjectTypeLinkVersion:${ot.rid}:${l.rid}`),
      metadata: { __typename: "LinkMetadata", displayName: other === b ? (l.name || b.name) : (l.inverse_name || a.name) },
      linkType: { __typename: "LinkTypeVersion", _id: cid(`LinkTypeVersion:${l.rid}`), linkType: { __typename: "LinkType", _id: cid(`LinkType:${l.rid}`), id: l.id, rid: l.rid }, definition, status: { __typename: "LinkTypeStatus_Experimental" } },
      otherSide: { __typename: "LinkOtherSide", objectTypeRid: other.rid },
    };
  }).filter(Boolean);
  const version = {
    ...explorerShallowVersionOf(ot), groups: [], linksIncludingLinksToObjectTypesWithoutSearchableDatasources: links,
    propertiesV2: ot.properties.map((p) => ({
      __typename: "ObjectTypePropertyVersion", _id: cid(`ObjectTypePropertyVersion:${p.rid}`), objectTypeProperty: { __typename: "ObjectTypeProperty", _id: cid(`ObjectTypeProperty:${p.rid}`), rid: p.rid },
      displayName: p.name || p.id, apiName: camel(p.name || p.id), status: { __typename: "ObjectTypePropertyStatus_Experimental" }, sharedProperty: null,
      isPrimary: p.id === ot.primaryKey, isTitle: p.rid === ot.titleRid, type: { __typename: `ObjectTypePropertyType_${pascal(p.base || "string")}` },
    })),
  };
  version.objectType = explorerObjectTypeOf(mm, ot, explorerShallowVersionOf(ot));
  return version;
}
// the caller's types in the asked ontologies (none named: every one), whose names hold the asked text
function explorerTypesOf(models, variables) {
  const want = new Set(variables?.ontologyRids || variables?.ontologyRIDs || []);
  const text = [variables?.queryString, ...(variables?.filter?.clauses || []).map((c) => c?.objectTypeDisplayNameContains)].find((t) => typeof t === "string" && t.trim()) || "";
  return (models || []).filter((mm) => !want.size || want.has(mm.rid))
    .flatMap((mm) => mm.objectTypes.filter((o) => !text || `${o.name || ""} ${o.id}`.toLowerCase().includes(text.trim().toLowerCase())).map((ot) => ({ mm, ot })));
}
// ctx: { models, userId, recents: [{ rid, viewed_at }] } — recents are the caller's Recently viewed (the same store the
// Ontology Manager records an opened type in)
export function explorerGraphqlFacts(name, variables, ctx) {
  const root = { __typename: "Query" };
  const types = explorerTypesOf(ctx.models, variables);
  const page = (size) => {
    const from = Math.max(0, Number(variables?.pageToken) || 0);
    return { values: types.slice(from, from + size).map(({ mm, ot }) => explorerVersionOf(mm, ot)), totalNumberOfResults: types.length, nextPageToken: from + size < types.length ? String(from + size) : null };
  };
  const viewed = (ctx.recents || []).map((r) => (ctx.models || []).map((mm) => ({ mm, ot: mm.objectTypes.find((o) => o.rid === r.rid) })).find((x) => x.ot)).filter(Boolean)
    .slice(0, Math.max(1, Number(variables?.limit) || 50))
    .map(({ mm, ot }) => ({ __typename: "RecentItem", _id: cid(`recent:${ot.rid}`), recent: explorerObjectTypeOf(mm, ot, explorerVersionOf(mm, ot)) }));
  switch (name) {
    case "AllObjectTypesQuery": return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", totalNumberOfResults: types.length } };
    case "ObjectTypesQuery": return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", ...page(20) } };
    case "ObjectTypeResultsQuery": return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", ...page(10) } };
    case "OntologiesQuery": return { ...root, allOntologies: (ctx.models || []).map((mm) => ({ ...ontologyNode(mm), displayName: mm.displayName, description: mm.description || null })) };
    case "CurrentUserQuery": return { ...root, me: ctx.userId ? { __typename: "User", _id: cid(`User:${ctx.userId}`), id: ctx.userId } : null };
    case "RecentObjectTypesQuery": case "RecentsQuery": return { ...root, recents: viewed };
    case "FavoritesQuery": case "FavoriteSavedExplorationsQuery": case "FavoriteTypeGroupsQuery": return { ...root, favorites: [] };
    case "SavedExplorationsListQuery": case "YourExplorationsQuery": return { ...root, searchResources: { __typename: "SearchResourcesPage", results: [], nextPageToken: null } };
    // what uses a type (the catalog's apps count): nothing, as the Ontology Manager's dependents answer
    case "GetObjectTypeDependents": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.rid });
      return { ...root, objectTypeV2: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, dependents: { __typename: "ResourceMetadataPage", values: [] } } : null };
    }
    case "TypeGroupResultsQuery": case "TypeGroupsQuery": return { ...root, objectTypeGroups: { __typename: "ObjectTypeGroupPage", values: [], nextPageToken: null } };
    // no semantic index is kept over the caller's types (the reference treats any reason as "unavailable" and searches by name)
    case "ObjectTypeSemanticSearchUnavailableReasonQuery": return { ...root, objectTypeSemanticSearchUnavailableReason: "NOT_AVAILABLE" };
    case "SemanticObjectTypeResultsQuery": return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", values: [] } };
    // how many of the caller's types a keyword names (the search's Object types tab), and a type's object count (its
    // materialized objects) beside no usage (none is kept)
    case "ObjectTypeCountQuery": return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", totalNumberOfResults: types.length } };
    // the groups of the types a keyword names (the Object types tab's group filter): no type groups are kept
    case "ObjectTypesWithGroupsQuery": return { ...root, objectTypesV2: { __typename: "ObjectTypeVersionPage", nextPageToken: null, values: types.map(({ ot }) => ({ __typename: "ObjectTypeVersion", _id: cid(`ObjectTypeVersion:${ot.rid}`), groups: [] })) } };
    case "ObjectTypeUsageMetricsQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.rid });
      return { ...root, objectType: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, objectCount: (hit.ot.backing?.objects || []).length, usage: { __typename: "ObjectTypeUsage", uniqueUsersCount: null } } : null };
    }
    // no favorite objects are kept
    case "FavoritedObjectsQuery": return { ...root, favorites: [] };
    // an object's full view: no object view is kept for any type (the Hypervisor has no object view editor), published or saved
    case "ObjectViewFullVersionQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, defaultOrGlobalBranch: { __typename: "DefaultGlobalBranch", _id: cid("branch:default"), objectType: hit ? { __typename: "ObjectTypeBranch", _id: cid(`otb:${hit.ot.rid}`), objectViewConfiguration: null } : null } };
    }
    // the view an object opens in: the reference's default (core) view of a type — its object's properties — under the type's one
    // default view id; nothing is saved or published for it (above), so the reference lays it out by its own defaults
    case "ResolveObjectViewRidQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, globalBranch: null, objectType: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid,
        objectViewConfiguration: { __typename: "ObjectViewConfiguration", _id: cid(`ObjectViewConfiguration:${hit.ot.rid}`), rid: defaultObjectViewRidOf(hit.ot) } } : null };
    }
    // a type's objects, a page at a time, whose title or primary key holds the search term (cut O8): the caller's materialized
    // objects of it
    case "ObjectsQuery": {
      const hit = objectTypeOf(ctx.models, variables?.objectTypeIdentifier || {});
      const term = String(variables?.searchTerm || "").trim().toLowerCase();
      const all = hit ? (hit.ot.backing?.objects || []).filter((o) => !term || o.title.toLowerCase().includes(term) || o.key.toLowerCase().includes(term)) : [];
      const from = Math.max(0, Number(variables?.pageToken) || 0), size = Math.max(1, Number(variables?.pageSize) || 30);
      return { ...root, defaultOrGlobalBranch: { __typename: "DefaultGlobalBranch", _id: cid("branch:default"), objectType: hit ? { __typename: "ObjectTypeBranch", _id: cid(`otb:${hit.ot.rid}`),
        objectsV3: { __typename: "ObjectBranchPage", nextPageToken: from + size < all.length ? String(from + size) : null, values: all.slice(from, from + size).map((o) => objectBranchNodeOf(hit.model, hit.ot, o)) } } : null } };
    }
    // the object an exploration previews first: none is pinned (no object view is kept), so its first object
    case "PreviewObjectQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, objectTypeV2: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, objectViewConfiguration: null,
        objects: { __typename: "ObjectPage", values: (hit.ot.backing?.objects || []).slice(0, 1).map((o) => ({ __typename: "Object", _id: cid(`Object:${o.rid}`), rid: o.rid })) } } : null };
    }
    // one object (the exploration's selected object and its property panel; the object view's properties and links): the caller's
    // materialized object with this rid. No property is marked prominent (the view's header lists none), none is hidden, and an
    // ODK link cannot be followed to linked objects (it names no join property), so the view lists no link types.
    case "SelectedObjectQuery": case "ObjectPropertyRendererQuery": case "ProminentPropertiesQuery": case "ObjectViewCorePropertiesTableQuery": case "ObjectLinkTypesQuery": {
      const e = objectUniverseOf(ctx.models).find((x) => x.o.rid === variables?.objectRid);
      let object = e ? objectBranchNodeOf(e.model, e.ot, e.o) : null;
      if (object && name === "ProminentPropertiesQuery") object = { ...object, properties: [] };
      if (object && name === "ObjectViewCorePropertiesTableQuery") object = { ...object, type: { ...object.type, latest: { ...explorerVersionOf(e.model, e.ot), propertiesV2: explorerVersionOf(e.model, e.ot).propertiesV2.map((p) => ({ ...p, visibility: "NORMAL" })) } } };
      if (object && name === "ObjectLinkTypesQuery") object = { ...object, type: { ...object.type, latest: { ...explorerShallowVersionOf(e.ot), objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${e.ot.rid}`), rid: e.ot.rid, id: e.ot.id }, linksIncludingLinksToObjectTypesWithoutSearchableDatasources: [] } } };
      return { ...root, defaultOrGlobalBranch: { __typename: "DefaultGlobalBranch", _id: cid("branch:default"), object } };
    }
    case "ObjectTypePreviewQuery": {
      const hit = objectTypeOf(ctx.models, { rid: variables?.objectTypeRid });
      return { ...root, objectType: hit ? { __typename: "ObjectType", _id: cid(`ObjectType:${hit.ot.rid}`), rid: hit.ot.rid, latest: explorerTypePreviewOf(hit.model, hit.ot, ctx.owner) } : null };
    }
    default: return null;
  }
}

// ---- Proposals (cut O6): the caller's ODK ontology proposals (`/v1/hypervisor/odk/ontology-proposals`) as the reference's
// ontology proposals. An ODK proposal is a declared, validated change against one ontology at one revision (its title,
// rationale, proposer and change set); applying it writes through the ontology plane's one writer, and withdrawing it
// closes it. It is not a branch: the reference's proposal is an approval request over an ontology branch, so each ODK
// proposal is answered as a request (task type ontology-metadata:approvals-v2) over a branch that holds exactly its change
// set and names no Foundry branch. Only proposals on the caller's ontologies are listed (the plane's list is not scoped).
// Statuses: open → In review (PENDING_APPROVAL), applied → Merged (APPROVED_AND_COMPLETED), withdrawn → Closed (CLOSED).
import { principalUserId } from "./adopted-automate.mjs";
export const PROPOSAL_TASK_TYPES = Object.freeze(["ontology-metadata:approvals-v2", "ontology-metadata:approvals"]);
export const proposalRidOf = (id) => `ri.approvals.main.task-request.${uuidOf(`ontology-proposal:${id}`)}`;
export const proposalBranchRidOf = (id) => `ri.ontology.main.branch.${uuidOf(`ontology-proposal-branch:${id}`)}`;
// a proposal's review tasks: the rids of the object, link and action types its change set touches (none: the ontology itself)
export function proposalTaskIdsOf(r) {
  const fam = r.model.family, a = r.affected || {};
  const ids = [...Object.keys(a.object_types || {}).map((id) => rid("object-type", `${fam}/${id}`)), ...Object.keys(a.link_types || {}).map((id) => rid("relation", `${fam}/link/${id}`)),
    ...Object.keys(a.action_types || {}).map((id) => `ri.actions.main.action-type.${uuidOf(`${fam}/action/${id}`)}`)];
  return ids.length ? ids : [r.ontologyRid];
}
export const PROPOSAL_STATUS = Object.freeze({ open: "PENDING_APPROVAL", applied: "APPROVED_AND_COMPLETED", withdrawn: "CLOSED" });
const puser = (ref) => (ref ? principalUserId(ref) : null);
// canonical JSON (key order ignored), so "changed" means what the daemon's model_changes means
const canon = (v) => (Array.isArray(v) ? `[${v.map(canon).join(",")}]` : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}` : JSON.stringify(v ?? null));
// what a change set does to a model, per kind and entry id (CREATED / UPDATED / DELETED) — the daemon's model_changes
export function modelChangesOf(prev, next) {
  const out = {};
  for (const kind of ["object_types", "link_types", "action_types", "value_types"]) {
    const index = (m) => new Map((Array.isArray(m?.[kind]) ? m[kind] : []).filter((e) => e && typeof e.id === "string").map((e) => [e.id, e]));
    const before = index(prev), after = index(next), changes = {};
    for (const [id, e] of after) { if (!before.has(id)) changes[id] = "CREATED"; else if (canon(before.get(id)) !== canon(e)) changes[id] = "UPDATED"; }
    for (const id of before.keys()) if (!after.has(id)) changes[id] = "DELETED";
    if (Object.keys(changes).length) out[kind] = changes;
  }
  return out;
}
// drafts: the ODK domain ontologies (raw records); models: ontologyModelsOf(drafts). A proposal's changes are read against
// the revision it was made on while that is the ontology's current revision; once applied, the ontology's own history entry
// for the revision it produced records them; otherwise (withdrawn, or the ontology moved on) against the current revision.
export function proposalsOf(proposals, drafts, models) {
  const byDraft = new Map((models || []).map((m) => [m.draftId, m]));
  const rawById = new Map((drafts || []).map((d) => [d.id, d]));
  return (proposals || []).filter((p) => p && p.id && byDraft.has(p.ontology_id)).map((p) => {
    const model = byDraft.get(p.ontology_id), raw = rawById.get(p.ontology_id) || {};
    const current = Number(raw.revision) || 1, basedOn = Number(p.based_on_revision) || 0;
    const odkStatus = String(p.status || "");
    const changes = p.changes && typeof p.changes === "object" ? p.changes : {};
    const resulting = Number(p.applied?.resulting_revision) || null;
    const recorded = resulting ? (Array.isArray(raw.history) ? raw.history : []).find((h) => Number(h?.revision) === resulting) : null;
    const affected = recorded?.affected && typeof recorded.affected === "object" ? recorded.affected
      : "canonical_object_model" in changes ? modelChangesOf(raw.canonical_object_model || {}, changes.canonical_object_model || {}) : {};
    const fields = ["domain", "version", "description"].filter((k) => typeof changes[k] === "string");
    // the ontology as the proposal would leave it: its change set over the revision it was made on (the entity rids are the
    // same — they derive from the family and the ids), at the proposal's own version
    const proposedRaw = { ...raw, ...Object.fromEntries(fields.map((k) => [k, changes[k]])), canonical_object_model: "canonical_object_model" in changes ? changes.canonical_object_model : raw.canonical_object_model };
    const proposedModel = ontologyModelsOf([proposedRaw], null, () => ({ family: model.family }))[0] || null;
    return {
      id: p.id, rid: proposalRidOf(p.id), branchRid: proposalBranchRidOf(p.id), ontologyRid: model.rid, model, raw,
      title: String(p.title || p.id), description: String(p.rationale || ""), odkStatus, status: PROPOSAL_STATUS[odkStatus] || "CLOSED",
      creatorRef: p.proposed_by || null, created_at: p.created_at || null,
      decidedBy: p.applied?.applied_by || p.withdrawn?.withdrawn_by || null, decidedAt: p.applied?.applied_at || p.withdrawn?.withdrawn_at || null,
      withdrawReason: p.withdrawn?.reason || "", resultingRevision: resulting, receiptRef: p.applied?.ontology_receipt_ref || null,
      basedOn, currentRevision: current, stale: odkStatus === "open" && basedOn !== current, changes, fields, affected, record: p,
      // what the caller may decide, as the daemon reads it for them (the rule its apply and withdraw routes enforce)
      mayApply: p.caller_may_apply === true, mayWithdraw: p.caller_may_withdraw === true,
      proposed: proposedModel ? { ...proposedModel, version: proposalVersionOf({ id: p.id, basedOn }) } : null,
      baseVersion: draftVersionOf(p.ontology_id, basedOn || 1),
    };
  });
}
// POST …/bulkLoadEntities for a proposal's page: an entity asked at a proposal's version is read from the ontology as that
// proposal would leave it; asked at the revision a proposal was made on after the ontology has moved on (applied, or stale),
// it is not kept (the daemon keeps no revision snapshots) and is left out; every other ask is answered as before.
export function bulkLoadEntitiesAt(request, models, rows) {
  const byVersion = new Map((rows || []).filter((r) => r.proposed).map((r) => [r.proposed.version, r]));
  const lostBase = new Set((rows || []).filter((r) => r.basedOn !== r.currentRevision).map((r) => r.baseVersion));
  const versionOf = (e) => e?.versionReference?.ontologyVersion || null;
  const out = { objectTypes: [], linkTypes: [], sharedPropertyTypes: [], interfaceTypes: [], typeGroups: [], actionTypes: [] };
  const answer = (kind, entries) => {
    for (const e of entries || []) {
      const v = versionOf(e), hit = v ? byVersion.get(v) : null;
      if (v && lostBase.has(v) && !hit) continue;
      const one = bulkLoadEntitiesOf({ [kind]: [e] }, hit ? [hit.proposed] : models);
      out[kind].push(...(one[kind] || []));
    }
  };
  answer("objectTypes", request?.objectTypes); answer("linkTypes", request?.linkTypes); answer("actionTypes", request?.actionTypes);
  return out;
}
export const asksProposalVersion = (request, rows) => {
  const versions = new Set((rows || []).flatMap((r) => [r.proposed?.version, r.basedOn !== r.currentRevision ? r.baseVersion : null]).filter(Boolean));
  return ["objectTypes", "linkTypes", "actionTypes"].some((k) => (request?.[k] || []).some((e) => versions.has(e?.versionReference?.ontologyVersion)));
};
// POST …/modification/history for a proposal's branch: its one change set, by its proposer, from the revision it was made on
// to the proposal's version (and, once applied, the revision it produced is the ontology's own history)
export function proposalBranchHistoryOf(r) {
  const affected = proposalAffectedOf(r);
  return { modificationPageItems: [{
    previousOntologyVersion: r.baseVersion, ontologyVersion: r.proposed?.version || r.baseVersion,
    attribution: { date: r.created_at, author: puser(r.creatorRef) },
    summary: { ...EMPTY_AFFECTED, ...Object.fromEntries(Object.entries(affected).map(([k, v]) => [k, Object.fromEntries(Object.entries(v).map(([rid, m]) => [rid, m.modificationType]))])) },
    description: r.title, sourceOntologyBranchRid: r.branchRid,
  }], nextPageToken: null };
}
export const proposalByRid = (rows, rid) => (rows || []).find((r) => r.rid === rid || r.branchRid === rid) || null;
// PUT /approvals/api/search/task-requests (and /counts) from the Proposals section: every filter it sends is honored as a
// real server would; one this layer does not know matches nothing (never silently ignored). No reviewer is named on an ODK
// proposal (the plane has no review step: its ontology's owner, or an administrator of its organization, applies it), so a
// reviewer filter matches none.
export function proposalMatches(row, f) {
  if (!f || !f.type) return true;
  switch (f.type) {
    case "taskType": return (f.taskType?.taskTypes || []).some((t) => PROPOSAL_TASK_TYPES.includes(t));
    case "customIndexedData": return f.customIndexedData?.key === "ONTOLOGY_RID" ? (f.customIndexedData.values || []).includes(row.ontologyRid) : !(f.customIndexedData?.values || []).length;
    case "status": return (f.status?.statuses || []).includes(row.status);
    case "createdBy": return !!row.creatorRef && (f.createdBy?.userIds || []).includes(puser(row.creatorRef));
    case "reviewers": return false;
    case "notReviewedBy": return true;
    case "title": return row.title.toLowerCase().includes(String(f.title?.contains || "").toLowerCase());
    case "notTitle": return !row.title.includes(String(f.notTitle?.contains || "\u0000"));
    default: return false;
  }
}
const proposalsMatching = (rows, filters) => (rows || []).filter((r) => (filters || []).every((f) => proposalMatches(r, f)));
const proposalSubStatusOf = (status) => (status === "PENDING_APPROVAL" ? "PENDING" : status === "CLOSED" ? "CLOSED" : "APPROVED");
function proposalSearchRowOf(r) {
  return { taskType: PROPOSAL_TASK_TYPES[0], taskRid: r.rid, title: r.title, creator: puser(r.creatorRef), creationTime: r.created_at, status: r.status,
    customIndexedData: { ONTOLOGY_RID: [r.ontologyRid] }, subtasks: proposalTaskIdsOf(r).map((id) => ({ type: "ontology-metadata:ontology-entity-review", id, version: String(r.basedOn || 1), approvalStatus: proposalSubStatusOf(r.status) })) };
}
export function proposalSearchOf(request, rows) {
  const asc = request?.sort?.order === "ASC";
  const found = proposalsMatching(rows, request?.filters).sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")) * (asc ? 1 : -1));
  const size = Math.max(1, Number(request?.pageSizeLimit) || 100), from = Math.max(0, Number(request?.pageToken) || 0);
  return { requests: found.slice(from, from + size).map(proposalSearchRowOf), totalCount: found.length, ...(from + size < found.length ? { nextPageToken: String(from + size) } : {}) };
}
export function proposalCountsOf(request, rows) {
  const global = request?.globalFilters || [];
  return { totalCount: proposalsMatching(rows, global).length, subCounts: Object.fromEntries(Object.entries(request?.subFilters || {}).map(([k, v]) => [k, proposalsMatching(rows, [...global, ...(v || [])]).length])) };
}
// GET /approvals/api/task-requests/<rid>(/minimal) — a proposal as its request: its title, rationale, proposer, and its
// history (created; applied or withdrawn, by whom and when)
export function proposalMinimalOf(r) {
  return { taskRid: r.rid, taskType: PROPOSAL_TASK_TYPES[0], latestVersion: 0, title: r.title, creationTime: r.created_at, invokeAsync: false, lastUpdatedAt: r.decidedAt || r.created_at, reviewers: [], status: r.status, customIndexedData: { ONTOLOGY_RID: [r.ontologyRid] } };
}
export function proposalTaskOf(r) {
  const creator = puser(r.creatorRef);
  const history = [{ type: "creationEntry", creationEntry: { time: r.created_at, creator } }];
  if (r.decidedAt) history.push(r.odkStatus === "applied" ? { type: "completedEntry", completedEntry: { time: r.decidedAt, user: puser(r.decidedBy) } } : { type: "closedEntry", closedEntry: { time: r.decidedAt, user: puser(r.decidedBy) } });
  return { ...proposalMinimalOf(r), taskRequestRid: r.rid, description: r.description, creator, contributors: creator ? [creator] : [], history,
    versionMetadata: [{ version: 0, createdBy: creator, createdAt: r.created_at }],
    subtasks: proposalTaskIdsOf(r).map((id) => ({ type: "ontology-metadata:ontology-entity-review", id, version: String(r.basedOn || 1), policies: [], reviews: [], approvalStatus: proposalSubStatusOf(r.status) })) };
}
// Writes on a proposal the Hypervisor refuses, each by name (the reference's error shape).
export const PROPOSAL_REFUSALS = Object.freeze({
  approvalsWrite: { status: 409, code: "Hypervisor:OntologyProposalWriteRefused", message: "An ODK ontology proposal is decided through the daemon's proposal plane only: merging applies it and closing withdraws it. Nothing else on it (reviewers, comments, edits to the request) is kept, so nothing was changed." },
  createBranch: { status: 409, code: "Hypervisor:OntologyBranchNotKept", message: "The Hypervisor keeps no ontology branches. An ODK proposal is created with its change set in one step (the daemon refuses an empty proposal), and a materialized object type's edit saves straight to the ontology as an ODK patch, so there is nothing to stage on a branch. Nothing was created." },
  openOnBranch: { status: 409, code: "Hypervisor:OntologyBranchNotKept", message: "The Hypervisor keeps no ontology branches, so a proposal's edits cannot be opened for editing on one. Review the change set on the proposal's page, then approve it to apply it or close it to withdraw it." },
  review: { status: 409, code: "Hypervisor:OntologyProposalRejectionNotKept", message: "An ODK proposal is applied or withdrawn; the daemon keeps no rejection or change request on it. Close the proposal to withdraw it. Nothing was changed." },
  reviewers: { status: 409, code: "Hypervisor:OntologyProposalReviewersNotKept", message: "An ODK proposal names no reviewers: its ontology's owner, or an administrator of its organization, applies it. Nothing was changed." },
  editRequest: { status: 409, code: "Hypervisor:OntologyProposalNotEditable", message: "An ODK proposal's title and rationale are fixed when it is proposed; the daemon has no route to change them. Nothing was changed." },
  decided: { status: 409, code: "Hypervisor:OntologyProposalDecided", message: "This proposal is already applied or withdrawn. Nothing was changed." },
  signedOut: { status: 403, code: "Hypervisor:OntologyProposalSignInRequired", message: "Sign in to decide a proposal. Nothing was changed." },
  notFound: { status: 404, code: "Hypervisor:OntologyProposalNotFound", message: "No proposal on your ontologies has this id. Nothing was changed." },
});
// ---- Saving an edit (cut O7, O8). Whoever may change an ontology (the daemon's `caller_may_change`) edits its types here, and the
// reference's Review changes validates the edit; its save (Save to ontology…, and a branch's save) writes one modification
// batch. Save to ontology (v2/modify) is answered below (cut O8): a materialized object type's edit becomes the daemon's ODK patch
// at the expected revision, and everything else in it is refused by name. A branch save and the legacy modify stay refused here
// (no ontology branch is kept). An unmaterialized object or link type's own save stays disabled before this: the reference's
// review lists "Backing datasource is missing".
export const ONTOLOGY_SAVE_PATHS = [/^\/ontology-metadata\/api\/ontology\/ontology\/modify$/u, /^\/ontology-metadata\/api\/ontology\/v2\/modify$/u,
  /^\/ontology-metadata\/api\/ontology\/approvals\/experimental\/ontology\/ri\.ontology\.main\.ontology\.[0-9a-f-]{36}\/modifyBranch$/u];
export const ONTOLOGY_SAVE_REFUSAL = Object.freeze({ status: 409, code: "Hypervisor:OntologyEditNotBound",
  message: "This save is not bound: an ODK ontology changes only by an ODK patch at its current revision (Save to ontology on a materialized object type, by its owner or an administrator of its organization) or by applying a proposal, and a branch save or the legacy modify is neither. Nothing was changed." });
// GET /language-model-service/api/config/v1/enabled — an editable page offers language-model assists (generated descriptions
// and the like) when this reads true; none is bound on this surface, so it reads false (passed through, it answered the
// recorded tenant's true)
export const LANGUAGE_MODEL_ENABLED_PATH = "/language-model-service/api/config/v1/enabled";
export const LANGUAGE_MODEL_ENABLED = false;
export const ontologySaveRefusalOf = (method, pathname) => (method === "POST" && ONTOLOGY_SAVE_PATHS.some((re) => re.test(pathname)) && pathname !== ONTOLOGY_MODIFY_V2 ? ONTOLOGY_SAVE_REFUSAL : null);
// ---- Saving an object type's edit as an ODK patch (cut O8). Once a type is backed (its materialized sets are its datasource and
// object store), the reference's own validation lets Review changes save it: one POST …/ontology/v2/modify?ontologyRid=<rid> naming
// the ontology version it was made on (expectedOntologyVersion). It is answered by the daemon's PATCH of that ODK ontology at the
// matching revision (expected_revision), under the caller's session — the daemon checks who may change it (its owner, or an
// administrator of its organization) and refuses a stale revision; nothing is signed or written here. Only what an ODK model keeps
// is carried: a type's name, plural name, description and title property, and its properties' names, descriptions and (for a
// property no mapping reads) base types, added properties, and removed properties no mapping reads. Anything else in the batch —
// a new or deleted type, a changed primary key, API name, icon, status, render hint or visibility, the backing datasource or object
// store, links, actions, shared properties, interfaces, groups, workflows or schema migrations — is refused by name, and nothing
// is written.
export const ONTOLOGY_MODIFY_V2 = "/ontology-metadata/api/ontology/v2/modify";
const saveRefusal = (message) => ({ refusal: { status: 409, code: "Hypervisor:OntologyEditNotBound", message: `${message} Nothing was changed.` } });
const sameJson = (a, b) => canon(a ?? null) === canon(b ?? null);
const EMPTY_OK = (v) => v === undefined || v === null || v === false || (Array.isArray(v) && !v.length) || (typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);
const SAVE_KEYS = new Set(["objectTypes", "objectTypeDatasources", "objectTypeEntityMetadata", "expectedOntologyVersion", "useRoles"]);
const BASE_OF_TYPE = { string: "string", integer: "integer", long: "long", double: "double", boolean: "boolean", date: "date", timestamp: "timestamp" };
export const revisionOfVersion = (model, version) => {
  const m = /^([0-9a-f]{8})-(.+)$/u.exec(String(version || ""));
  if (!m || m[2] !== uuidOf(`draft:${model.draftId}`).slice(9)) return null;
  return parseInt(m[1], 16) || null;
};
// → { refusal } | { draftId, body (the daemon PATCH), types (the ids it updates) }
export function ontologySaveStepOf(request, models, ontologyRid) {
  const model = modelOf(models, ontologyRid);
  if (!model) return saveRefusal("This ontology is not one of yours.");
  if (!model.mayChange) return saveRefusal("Only this ontology's owner, or an administrator of its organization, may change it (the daemon's rule).");
  const r = request && typeof request === "object" ? request : {};
  const extra = Object.keys(r).filter((k) => !SAVE_KEYS.has(k) && !EMPTY_OK(r[k]));
  if (extra.length) return saveRefusal(`Only a materialized object type's edits are saved from here: this save also changes ${extra.join(", ")}, and an ODK action or link type (or anything else) changes by an ODK patch or a proposal, not from the Ontology Manager yet.`);
  if (r.useRoles === true) return saveRefusal("The Hypervisor keeps no ontology roles.");
  const expected = revisionOfVersion(model, r.expectedOntologyVersion);
  if (!expected) return saveRefusal("This save names no version of this ontology.");
  const canonical = JSON.parse(JSON.stringify(model.canonical || {}));
  const objectTypes = Array.isArray(canonical.object_types) ? canonical.object_types : [];
  const edits = Object.entries(r.objectTypes || {});
  if (!edits.length) return saveRefusal("This save changes no object type.");
  for (const [id, op] of edits) {
    const typed = model.objectTypes.find((o) => o.id === id);
    const raw = objectTypes.find((o) => o.id === id);
    if (op?.type !== "update" || !typed || !raw) return saveRefusal(op?.type === "create" ? "A new object type must be backed by a datasource, and an ODK type is backed only once a materializing run registers its objects, so none is created from here." : `Object type ${id} is ${op?.type === "delete" ? "not deleted from here" : "not one of this ontology's"}.`);
    if (!(typed.backing?.datasources || []).length) return saveRefusal(`Object type ${typed.name || id} has no backing datasource: it is saved from here once materialized.`);
    // the backing and the object store are what they read now (checked first: the rest of the batch is diffed against them)
    const sources = r.objectTypeDatasources?.[id];
    if (sources !== undefined) {
      const ours = datasourcesOfType(typed);
      const same = Array.isArray(sources) && sources.length === ours.length && sources.every((x) => {
        const o = ours.find((d) => d.rid === x?.update?.rid), def = x?.update?.objectTypeDatasourceDefinition;
        const ds = def?.[def?.type];
        if (x?.type !== "update" || !o || !ds || ds.datasetRid !== o.datasource.dataset.datasetRid) return false;
        const cols = Object.fromEntries(Object.entries(ds.propertyMapping || {}).map(([pid, m]) => [pid, m?.column ?? m]));
        const want = Object.fromEntries(typed.properties.filter((p) => o.datasource.dataset.propertyMapping[p.rid]).map((p) => [p.id, o.datasource.dataset.propertyMapping[p.rid]]));
        return sameJson(cols, want);
      });
      if (!same) return saveRefusal("A backed type's datasource is its materialized sets, from its connector mapping; it changes by a new mapping and a materializing run, not here.");
    }
    const meta = r.objectTypeEntityMetadata?.[id];
    if (meta !== undefined && (!sameJson(Object.keys(meta?.entityConfig?.objectDbTypeConfigs || {}), [OBJECT_STORE_DB.type]) || meta?.arePatchesEnabled === true || (meta?.editsHistory && meta.editsHistory.type !== "none") || !EMPTY_OK(meta?.aliases)))
      return saveRefusal("A backed type's objects are held where its materialized sets are; object edits, patches, edit history and aliases are not kept.");
    const next = op.update?.objectType || {};
    const dm = next.displayMetadata || {};
    // what the model does not keep must be what the type already reads
    if (next.id !== id) return saveRefusal("An object type's id is not changed.");
    if (!sameJson(next.primaryKeys, [typed.primaryKey])) return saveRefusal("A backed type's primary key is the property its connector mapping keys objects by; it is not changed here.");
    if (!sameJson(dm.icon, ICON) || String(dm.visibility || "NORMAL") !== "NORMAL" || (dm.groupDisplayName ?? null) !== null) return saveRefusal("An ODK type keeps no icon, visibility or group name.");
    if (!sameJson(next.status, DRAFT_STATUS)) return saveRefusal("An ODK draft's types are experimental; a status is not set here.");
    if (!EMPTY_OK(next.implementsInterfaces) || !EMPTY_OK(next.implementsInterfaces2) || !EMPTY_OK(next.sharedPropertyTypes) || !EMPTY_OK(next.typeGroups)) return saveRefusal("An ODK model keeps no interfaces, shared properties or type groups.");
    if (Object.entries(next.traits || {}).some(([k, v]) => !(k === "workflowObjectTypeTraits" ? EMPTY_OK(v) : v === null || v === undefined))) return saveRefusal("An ODK type keeps no traits (events, time series, action logs).");
    const newName = String(dm.displayName ?? typed.name ?? id).trim();
    if (!newName) return saveRefusal("An object type needs a name.");
    if (next.apiName !== undefined && next.apiName !== pascal(typed.name || id) && next.apiName !== pascal(newName)) return saveRefusal("An ODK type's API name is its name's; it is not set separately.");
    for (const [rid, pid] of Object.entries(op.update?.propertyTypeIdMappings?.existingPropertyTypeRenames || {})) {
      const p = typed.properties.find((x) => x.rid === rid);
      if (p && p.id !== pid) return saveRefusal(`Property ${p.name || p.id}'s id is the key its values are stored by; it is not renamed.`);
    }
    const mapped = new Set((typed.backing?.datasources || []).flatMap((d) => Object.keys(d.mapping || {})));
    const props = next.propertyTypes && typeof next.propertyTypes === "object" ? next.propertyTypes : {};
    const rawProps = Array.isArray(raw.properties) ? raw.properties : [];
    const nextProps = [];
    for (const [pid, np] of Object.entries(props)) {
      const cur = typed.properties.find((x) => x.id === pid);
      const pdm = np?.displayMetadata || {};
      const base = BASE_OF_TYPE[String(np?.type?.type || "")];
      if (!base) return saveRefusal(`Property ${pid}'s type (${np?.type?.type}) is not an ODK base type.`);
      if (String(pdm.visibility || "NORMAL") !== "NORMAL" || np?.baseFormatter || np?.ruleSetBinding || np?.valueType || np?.sharedPropertyTypeRid || np?.dataConstraints || np?.inlineAction) return saveRefusal(`Property ${pid} sets what an ODK property does not keep (visibility, formatting, rules, value or shared types, constraints, inline actions).`);
      if (np?.status && !sameJson(np.status, DRAFT_STATUS)) return saveRefusal(`Property ${pid}'s status is not set here.`);
      if (!sameJson((np?.typeClasses || []).filter((c) => c), renderHintsOf({ base }))) return saveRefusal(`Property ${pid}'s render hints are not kept (a string property is always selectable here).`);
      const name = String(pdm.displayName ?? cur?.name ?? pid).trim();
      if (np?.apiName !== undefined && np.apiName !== camel(cur?.name || pid) && np.apiName !== camel(name)) return saveRefusal(`Property ${pid}'s API name is its name's; it is not set separately.`);
      const rawP = rawProps.find((x) => x.id === pid);
      if (cur) {
        if (base !== baseTypeOf(cur.base).type && mapped.has(pid)) return saveRefusal(`Property ${cur.name || pid} is read by the type's connector mapping; its type changes there, not here.`);
        const entry = { ...rawP, name, ...(base !== baseTypeOf(cur.base).type ? { value_type: base } : {}) };
        if (pdm.description) entry.description = String(pdm.description); else delete entry.description;
        nextProps.push(entry);
      } else {
        if (!/^[a-z][a-z0-9_]*$/u.test(pid)) return saveRefusal(`A new property's id (${pid}) must be lowercase letters, digits and underscores, starting with a letter.`);
        nextProps.push({ id: pid, name, value_type: base, ...(pdm.description ? { description: String(pdm.description) } : {}) });
      }
    }
    for (const p of typed.properties) if (!props[p.id] && mapped.has(p.id)) return saveRefusal(`Property ${p.name || p.id} is read by the type's connector mapping; it is not removed here.`);
    const title = next.titlePropertyTypeId ?? raw.title_property;
    if (title && !nextProps.some((x) => x.id === title)) return saveRefusal("The title property must be one of the type's properties.");
    const updated = { ...raw, name: newName, properties: nextProps, ...(title ? { title_property: title } : {}) };
    if (dm.description) updated.description = String(dm.description); else delete updated.description;
    if (dm.pluralDisplayName && dm.pluralDisplayName !== newName) updated.plural_name = String(dm.pluralDisplayName); else delete updated.plural_name;
    objectTypes.splice(objectTypes.indexOf(raw), 1, updated);
  }
  for (const k of Object.keys(r.objectTypeDatasources || {})) if (!r.objectTypes?.[k]) return saveRefusal("A datasource is saved only with its type's edit.");
  for (const k of Object.keys(r.objectTypeEntityMetadata || {})) if (!r.objectTypes?.[k]) return saveRefusal("Object storage is saved only with its type's edit.");
  return { draftId: model.draftId, types: edits.map(([id]) => id), body: { expected_revision: expected, canonical_object_model: { ...canonical, object_types: objectTypes } } };
}
// the save's answer: the ontology at the revision the patch produced, and the rids of the types it updated
export function ontologySaveAnswerOf(model, revision, types) {
  // (nothing is created by an update: the reference reads its created-entity maps, and reloads what the new version changed)
  void types;
  return { ontologyRid: model.rid, ontologyVersion: draftVersionOf(model.draftId, revision), createdObjectTypes: {}, createdLinkTypes: {}, createdActionTypes: [], createdTypeGroups: {},
    createdSharedPropertyTypes: {}, createdInterfaceTypes: {}, createdRuleSets: {}, createdWorkflows: {} };
}
// POST /ontology-metadata/api/ontology/v2/<ontology rid>/diff — what changed between two of the draft's versions: the types each
// revision after the base recorded (ODK keeps each revision's changes), keyed by the rids the app knows. A version that is not one
// of this draft's is refused by name.
export function ontologyDiffOf(model, request) {
  const base = revisionOfVersion(model, request?.baseOntologyVersion), next = revisionOfVersion(model, request?.newOntologyVersion);
  if (!model || !base || !next) return null;
  const merged = {};
  for (const h of [...model.history].filter((x) => Number(x.revision) > base && Number(x.revision) <= next).sort((a, b) => Number(a.revision) - Number(b.revision)))
    for (const [kind, changes] of Object.entries(h.affected || {})) merged[kind] = { ...(merged[kind] || {}), ...changes };
  return { diff: affectedOf(model, merged) };
}
export const proposalRefusalBodyOf = (refusal) => ({ errorCode: refusal.status === 404 ? "NOT_FOUND" : refusal.status === 403 ? "PERMISSION_DENIED" : "CONFLICT", errorName: refusal.code, errorInstanceId: "", parameters: { message: refusal.message }, message: refusal.message });
// ---- a proposal as the reference's OntologyChangeProposal (GraphQL: the Proposals section's rows, a proposal's page). Its
// branch is the proposal's own change set on its ontology; it names no Foundry (global) branch and no datasource branch. The
// review task is the plane's apply: the ontology's owner, or an administrator of its organization, applies an open proposal
// (the daemon checks the caller and the revision, not a reviewer), so the caller may fully approve it exactly when it is open
// and the daemon reads them as one who may apply it (caller_may_apply) — offered to no one the daemon would refuse.
export const PROPOSAL_GRAPHQL_OPERATIONS = new Set(["ApprovalRequestDetails", "ProposalDetailQuery", "GlobalBranchTitle", "OntologyBranchSuggestedReviewers", "ResourceProjectQuery", "TaskReviewSectionQuery",
  "CreateBranchDialogQuery", "SearchSpacesQuery", "GetSimilarBranches", "OrganizationSelectionQuery", "GetSpace", "InviteReviewersPrincipalSearchQuery"]);
export function proposalNodeOf(r, principalRef) {
  const canApply = !!principalRef && r.odkStatus === "open" && r.mayApply === true;
  return {
    __typename: "OntologyChangeProposal", __implements: ["ApprovalRequest"], _id: cid(`OntologyChangeProposal:${r.rid}`), rid: r.rid, status: r.status, title: r.title, description: r.description,
    // nothing about the request itself is edited here (its title and rationale are the proposal's); no reviewer is named
    // an ODK proposal is applied in one act — the review IS the merge — so it is set to merge when its one review approves it
    invocationBlockers: [], invokeWhenReady: true, reviewers: [], lastInvokedAt: r.odkStatus === "applied" ? r.decidedAt : null,
    permissions: { __typename: "ApprovalRequestPermissions", _id: cid(`ApprovalRequestPermissions:${r.rid}`), canEditMetadata: false, canUpdateCheckpointInteractions: false },
    permissionsForCreator: { __typename: "ApprovalRequestPermissions", _id: cid(`ApprovalRequestPermissionsForCreator:${r.rid}`), canView: true },
    created: { __typename: "Attribution", user: puser(r.creatorRef) ? { __typename: "User", _id: cid(`User:${puser(r.creatorRef)}`), id: puser(r.creatorRef) } : null, time: r.created_at },
    branch: { __typename: "OntologyBranch", _id: cid(`OntologyBranch:${r.branchRid}`), rid: r.branchRid, globalBranch: null, datasourceBranchName: null,
      latestOntologyVersion: { __typename: "OntologyVersion", _id: cid(`OntologyVersion:${r.branchRid}`), ontology: ontologyNode(r.model) } },
    // one review task per entity the change set touches (the reference's task id is the entity's rid), each decided by the
    // plane's apply: approved by whoever applied it; a withdrawn proposal was closed, not rejected, so it records no review
    latestVersion: { __typename: "ApprovalRequestVersion", _id: cid(`ApprovalRequestVersion:${r.rid}`), version: 0, subRequests: proposalTaskIdsOf(r).map((id) => ({
      __typename: "ApprovalSubRequest", _id: cid(`ApprovalSubRequest:${r.rid}:${id}`), id, status: proposalSubStatusOf(r.status), version: String(r.basedOn || 1),
      reviews: r.odkStatus === "applied" && r.decidedBy ? [{ __typename: "ApprovalSubRequestReview", _id: cid(`ApprovalSubRequestReview:${r.rid}:${id}`), active: true, reviewType: "APPROVE",
        created: { __typename: "Attribution", user: { __typename: "User", _id: cid(`User:${puser(r.decidedBy)}`), id: puser(r.decidedBy) }, time: r.decidedAt } }] : [],
      checkpointInteraction: null, passesCheckpointsValidation: true, hasCheckpointInteraction: false, isCurrentlyApplied: r.odkStatus === "applied",
      permissions: { __typename: "ApprovalSubRequestPermissions", _id: cid(`ApprovalSubRequestPermissions:${r.rid}:${id}`), canFullyApprove: canApply, canPartiallyApprove: canApply },
      applicablePolicies: [] })) },
  };
}
// the namespace (the owner tenant) and organization Create branch's dialog names; null signed out
function branchNamespaceNodeOf(ownerRef, models) {
  if (!ownerRef) return null;
  const nsRid = namespaceRidOf(ownerRef), name = namespaceNameOf(ownerRef);
  return { __typename: "Namespace", _id: cid(`namespace-node:${nsRid}`), rid: nsRid, ontologies: (models || []).map((m) => ({ __typename: "Ontology", _id: cid(`ontology:${m.rid}`), rid: m.rid })),
    metadata: { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${nsRid}`), rid: nsRid, alias: name, name, path: `/${name}`, type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-namespace" }, trashedStatus: "NOT_TRASHED", status: null } };
}
function organizationNodeOf(ownerRef) {
  if (!ownerRef) return null;
  const orgRid = `ri.multipass..organization.${uuidOf(ownerRef)}`;
  return { __typename: "Organization", _id: cid(`Organization:${orgRid}`), rid: orgRid, marking: { __typename: "OrganizationMarking", __implements: ["MandatoryControl"], _id: cid(`OrganizationMarking:${orgRid}`),
    id: uuidOf(`org-marking:${ownerRef}`), name: namespaceNameOf(ownerRef), description: null, deprecated: false, organizationRid: orgRid,
    permissions: { __typename: "MandatoryControlPermissions", _id: cid(`OrganizationMarkingPermissions:${orgRid}`), canUse: true, canDeclassify: false, isMember: true } } };
}
// ctx: { rows, principalRef, principal: { ref, name, email }, owner, models }
export function proposalGraphqlFacts(name, variables, ctx) {
  const root = { __typename: "Query" };
  switch (name) {
    case "ApprovalRequestDetails": case "ProposalDetailQuery": case "TaskReviewSectionQuery": {
      const r = proposalByRid(ctx.rows, variables?.rid || variables?.approvalTaskId);
      return { ...root, approvalRequest: r ? proposalNodeOf(r, ctx.principalRef) : null };
    }
    // the reviewers a branch suggests come from its changed types' owning packages and datasource projects: an ODK type has
    // neither, so the changed types are listed and nobody is suggested
    case "OntologyBranchSuggestedReviewers": {
      const r = proposalByRid(ctx.rows, variables?.branchRid);
      if (!r) return { ...root, ontologyBranch: null };
      const fam = r.model.family, a = r.affected || {};
      const ids = (kind, change) => Object.entries(a[kind] || {}).filter(([, c]) => c === change).map(([id]) => id);
      const ot = (id) => ({ __typename: "ObjectTypeVersion", _id: cid(`otv-branch:${r.branchRid}:${id}`), objectType: { __typename: "ObjectType", _id: cid(`ObjectType:${rid("object-type", `${fam}/${id}`)}`), owningPackage: null }, dataSources: [] });
      const at = (id) => ({ __typename: "ActionTypeVersion", _id: cid(`atv-branch:${r.branchRid}:${id}`), actionType: { __typename: "ActionType", _id: cid(`ActionType:${fam}/${id}`), owningPackage: null } });
      const branchOf = (typename, latest) => ({ __typename: typename, _id: cid(`${typename}:${latest._id}`), latest });
      return { ...root, ontologyBranch: { __typename: "OntologyBranch", _id: cid(`OntologyBranch:${r.branchRid}`),
        createdObjectTypes: ids("object_types", "CREATED").map((id) => branchOf("ObjectTypeBranch", ot(id))), updatedObjectTypes: ids("object_types", "UPDATED").map((id) => branchOf("ObjectTypeBranch", ot(id))), deletedObjectTypes: ids("object_types", "DELETED").map(ot),
        createdActionTypes: ids("action_types", "CREATED").map((id) => branchOf("ActionTypeBranch", at(id))), updatedActionTypes: ids("action_types", "UPDATED").map((id) => branchOf("ActionTypeBranch", at(id))), deletedActionTypes: ids("action_types", "DELETED").map(at) } };
    }
    // a proposal's review task is not filed in a project (Review changes groups a proposal's edits by project)
    case "ResourceProjectQuery": {
      const r = (ctx.rows || []).find((x) => proposalTaskIdsOf(x).includes(variables?.resourceRid));
      return { ...root, resourceMetadata: r ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${variables.resourceRid}`), rid: variables.resourceRid, project: null } : null };
    }
    // Create branch's dialog: the caller's ontologies, each in its namespace (the owner tenant) and organization. No branch is
    // kept, so none is similar; creating one is refused by name (CreateGlobalBranchMutation)
    case "CreateBranchDialogQuery": {
      const ns = branchNamespaceNodeOf(ctx.owner, ctx.models), org = organizationNodeOf(ctx.owner);
      const mm = modelOf(ctx.models, variables?.resourceRid);
      return { ...root, allOntologies: (ctx.models || []).map((m) => ({ ...ontologyNode(m), displayName: m.displayName, description: m.description || null, namespace: ns })),
        // the platform's default ontology holds none of the caller's types (as everywhere on this surface)
        defaultOntology: { ...ontologyNode({ rid: "ri.ontology.main.ontology.00000000-0000-0000-0000-000000000000" }), objectTypesV2: { __typename: "ObjectTypeVersionPage", values: [] }, actionTypes: { __typename: "ActionTypeVersionPage", values: [] } }, resourceMetadata: mm ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${mm.rid}`), name: mm.displayName, namespace: ns } : null,
        organizations: org ? [org] : [], me: org ? { __typename: "User", _id: cid(`me:${ctx.principalRef}`), organization: org } : null };
    }
    case "SearchSpacesQuery": {
      const ns = branchNamespaceNodeOf(ctx.owner, ctx.models);
      return { ...root, searchResources: { __typename: "ResourceSearchResultsPage", nextPageToken: null, results: ns ? [{ __typename: "ResourceSearchResult", resource: { __typename: "ResourceMetadata", _id: cid(`sr:${ns.rid}`), resource: ns } }] : [] } };
    }
    case "GetSimilarBranches": return { ...root, globalBranchesV2: { __typename: "GlobalBranchPage", values: [] } };
    // Invite reviewers' picker: the principal the adopted layer can name (the caller); inviting is refused by name
    case "InviteReviewersPrincipalSearchQuery": {
      const me = ctx.principal?.ref ? puser(ctx.principal.ref) : null, name = ctx.principal?.name || ctx.principal?.email || ctx.principal?.ref || "";
      const text = String(variables?.query || "").trim().toLowerCase();
      const hit = me && (!text || name.toLowerCase().includes(text));
      return { ...root, principalsV2: { __typename: "PrincipalPage", values: hit ? [{ __typename: "User", __implements: ["Principal"], _id: cid(`User:${me}`), id: me, displayName: name, fullName: name, username: ctx.principal?.email || name,
        initials: String(name).split(/\s+/u).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("") || "?", imageUrl: null, permissions: { __typename: "UserPermissions", isCurrentUser: true } }] : [] } };
    }
    // the namespace's organization (the owner tenant's), and the namespace as the space picker reads it
    case "OrganizationSelectionQuery": case "GetSpace": {
      const ns = branchNamespaceNodeOf(ctx.owner, ctx.models), org = organizationNodeOf(ctx.owner);
      if (!ns || ns.rid !== (variables?.namespaceRid || variables?.rid)) return { ...root, namespace: null };
      return { ...root, namespace: { ...ns, metadata: { ...ns.metadata, markings: org ? [{ __typename: "MarkingInfo", disjunctiveInheritedConjunctively: false, marking: { ...org.marking, organization: org } }] : [] } } };
    }
    // a proposal's branch names no Foundry branch
    case "GlobalBranchTitle": {
      const r = proposalByRid(ctx.rows, variables?.rid);
      return { ...root, ontologyBranch: r ? { __typename: "OntologyBranch", _id: cid(`OntologyBranch:${r.branchRid}`), globalBranch: null } : null };
    }
    default: return null;
  }
}
// ---- a proposal's branch (POST /ontology-metadata/api/ontology/approvals/experimental/ontology/<rid>/loadBranchWithProposal):
// the proposal's change set as the branch's modifications — each object, link and action type it creates, updates or deletes,
// keyed by the rids the app knows — made by its proposer on the revision it was proposed against. Its version is the
// proposal's own (never a published revision); the version it was based on is the draft's revision it was proposed on.
export const proposalVersionOf = (r) => `${Number((r.basedOn || 1) + 1).toString(16).padStart(8, "0")}-${uuidOf(`ontology-proposal-version:${r.id}`).slice(9)}`;
const keyedChanges = (map, ridOf) => Object.fromEntries(Object.entries(map || {}).map(([id, change]) => [ridOf(id), { modificationType: String(change) }]));
export function proposalAffectedOf(r) {
  const fam = r.model.family, a = r.affected || {};
  const objectTypes = keyedChanges(a.object_types, (id) => rid("object-type", `${fam}/${id}`));
  return {
    affectedObjectTypes: objectTypes, affectedObjectTypeEntityMetadatas: {}, affectedObjectTypeDatasources: {}, affectedObjectTypeSchemaMigrations: {},
    affectedLinkTypes: keyedChanges(a.link_types, (id) => rid("relation", `${fam}/link/${id}`)), affectedLinkTypeEntityMetadatas: {}, affectedManyToManyLinkTypeDatasources: {},
    affectedActionTypes: keyedChanges(a.action_types, (id) => `ri.actions.main.action-type.${uuidOf(`${fam}/action/${id}`)}`),
    affectedRuleSets: {}, affectedSharedPropertyTypes: {}, affectedInterfaceTypes: {}, affectedTypeGroups: {},
  };
}
export function branchWithProposalOf(r) {
  return {
    rid: r.branchRid, ontologyRid: r.ontologyRid, displayName: r.title, description: r.description,
    attribution: { author: puser(r.creatorRef), lastUpdatedAt: r.decidedAt || r.created_at },
    latestOntologyVersion: proposalVersionOf(r), latestRebasedOntologyVersion: draftVersionOf(r.model.draftId, r.basedOn || 1),
    ontologyBranchModificationData: { contributors: puser(r.creatorRef) ? [puser(r.creatorRef)] : [], ...proposalAffectedOf(r) },
    proposal: { approvalTaskRid: r.rid, status: r.status }, status: r.odkStatus === "open" ? { type: "open", open: {} } : r.odkStatus === "applied" ? { type: "merged", merged: {} } : { type: "closed", closed: {} },
  };
}
// ---- a proposal's writes (GraphQL mutations the reference sends). Approving its one review (Approve all edits, or the task's
// Approve) and merging it are the daemon's apply — an ODK proposal is set to merge when approved, and the daemon lets any
// signed-in principal apply an open proposal on the revision it was made against (a stale or decided one it refuses by name,
// and that refusal is shown). Closing it is the daemon's withdraw. Rejecting, requesting changes, reviewers and editing the
// request's title or description are refused by name: the plane keeps none of them. The UI server holds no key and signs
// nothing; each step runs under the caller's own session.
export const PROPOSAL_MUTATIONS = new Set(["ReviewApprovalSubRequests", "ReviewSubRequests", "InvokeApprovalRequest", "CloseProposal", "CloseTask", "UpdateProposalTitle", "UpdateProposalDescription", "UpdateReviewers", "UpdateReviewersMutation",
  "CreateFoundryBranchMutationV2WithRoleGrants", "CreateGlobalBranchMutation", "ResolveCombinedBranchRidBranchQuery"]);
export const proposalMutationRidOf = (variables) => variables?.taskRid || variables?.rid || null;
// → { refusal } | { daemon: { route, method, body } }
export function proposalMutationStepOf(name, row, variables, principalRef) {
  const R = PROPOSAL_REFUSALS;
  // no ontology branch is kept: creating one, or opening a proposal's edits on its branch, is refused by name
  if (name === "CreateFoundryBranchMutationV2WithRoleGrants" || name === "CreateGlobalBranchMutation") return { refusal: R.createBranch };
  if (name === "ResolveCombinedBranchRidBranchQuery") return { refusal: R.openOnBranch };
  if (!row) return { refusal: R.notFound };
  if (name === "UpdateProposalTitle" || name === "UpdateProposalDescription") return { refusal: R.editRequest };
  if (name === "UpdateReviewers" || name === "UpdateReviewersMutation") return { refusal: R.reviewers };
  if (!principalRef) return { refusal: R.signedOut };
  const apply = { daemon: { route: `/v1/hypervisor/odk/ontology-proposals/${encodeURIComponent(row.id)}/apply`, method: "POST", body: {} } };
  if (name === "ReviewApprovalSubRequests" || name === "ReviewSubRequests") {
    if (String(variables?.reviewType || "") !== "APPROVE") return { refusal: R.review };
    return row.odkStatus === "open" ? apply : { refusal: R.decided };
  }
  if (name === "InvokeApprovalRequest") return row.odkStatus === "open" ? apply : { refusal: R.decided };
  if (name === "CloseProposal" || name === "CloseTask") return row.odkStatus === "open" ? { daemon: { route: `/v1/hypervisor/odk/ontology-proposals/${encodeURIComponent(row.id)}/withdraw`, method: "POST", body: {} } } : { refusal: R.decided };
  return { refusal: R.approvalsWrite };
}
// the mutation's answer: its root field is the proposal as it now stands (walked by the mutation's own document)
export function proposalMutationFacts(name, row, principalRef) {
  const node = row ? proposalNodeOf(row, principalRef) : null;
  return { __typename: "Mutation", reviewApprovalSubRequests: node, invokeApprovalRequest: node, closeApprovalRequest: node, updateApprovalRequest: node };
}
