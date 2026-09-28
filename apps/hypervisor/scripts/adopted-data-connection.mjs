// The adopted Data Connection's answers over Hypervisor truth (R-241, Data Connection cut D1).
//
// The reference app (booted by the local mirror, routed at /workspace/data-ingestion-app) lists sources, syncs, agents and
// listeners. Here a source is one of the caller's declared data sources (the data-source plane); its connection type is
// the Hypervisor's kind, answered in the reference's catalog shape under the reference's type id where one names the same
// thing. A declared source syncs nothing yet (ingestion is declaration-only until an authority crossing), runs on no agent,
// and no listener, agent, export or external stack exists — each answers none. Nothing recorded is served: the recorded
// answers lend STRUCTURE only. Every other read on the surface is fenced by the serve as a named gap.
import crypto from "node:crypto";
import { uuidOf } from "./adopted-pipeline.mjs";

const cid = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");

// A data-source kind as a connection type: the reference's type id where it names the same connector, else the
// Hypervisor's own; its catalog entry in the reference's shape (name, description, capabilities, syncs, exports). No
// kind is explorable or syncs here: a declared source does not ingest.
const KINDS = {
  rest_api: { type: "webhooks-rest", name: "REST API", description: "An HTTP API the Hypervisor calls under a leased credential." },
  s3: { type: "s3-direct", name: "S3", description: "An S3 bucket, declared by its endpoint." },
  postgres: { type: "postgresql-42", name: "PostgreSQL", description: "A PostgreSQL database, declared by its endpoint." },
  kafka: { type: "streaming-kafka-source", name: "Kafka", description: "A Kafka cluster, declared by its endpoint." },
  mysql: { type: "hypervisor-mysql", name: "MySQL", description: "A MySQL database, declared by its endpoint." },
  graphql_api: { type: "hypervisor-graphql-api", name: "GraphQL API", description: "A GraphQL API, declared by its endpoint." },
  object_store: { type: "hypervisor-object-store", name: "Object store", description: "An object store, declared by its endpoint." },
  http_feed: { type: "hypervisor-http-feed", name: "HTTP feed", description: "An HTTP feed, declared by its endpoint." },
  file_drop: { type: "hypervisor-file-drop", name: "File drop", description: "Files dropped for the Hypervisor to pick up." },
  local_folder: { type: "hypervisor-local-folder", name: "Local folder", description: "A folder on the Hypervisor's host." },
};
export const sourceTypeOf = (kind) => KINDS[kind]?.type || `hypervisor-${String(kind || "source").replace(/[^a-z0-9]+/gu, "-")}`;
// GET /magritte-coordinator/api/managed-sources/sources — the connection types, one per Hypervisor kind
export const MANAGED_SOURCE_TYPES = Object.fromEntries(Object.values(KINDS).map((k) => [k.type, { name: k.name, description: k.description, capabilities: [], syncs: {}, exports: {} }]));
export const sourceRidOf = (sourceId) => `ri.magritte..source.${uuidOf(`data-source:${sourceId}`)}`;

// The caller's data sources: the ones they declared, and the ones filed in a project they can see. (The plane's list is
// not caller-scoped; the adopted layer never shows another principal's source.)
export function callerSourcesOf(sources, principalRef, projectRefs) {
  const projects = new Set(projectRefs || []);
  return (sources || []).filter((s) => s && s.source_id && ((principalRef && s.declared_by_principal_ref === principalRef) || (s.project_ref && projects.has(s.project_ref))));
}

function sourceNodeOf(src) {
  const rid = sourceRidOf(src.source_id);
  return {
    __typename: "MagritteSource", _id: cid(`MagritteSource:${rid}`), rid, type: sourceTypeOf(src.kind), name: src.name || src.source_id, description: "",
    // a declared source is reached by the Hypervisor itself, on no agent
    runtimePlatform: { __typename: "CloudRuntimePlatform" }, numberOfExtracts: 0,
    metadata: {
      __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${rid}`), rid, favorited: null, trashedStatus: "NOT_TRASHED", tags: [], markings: [], defaultBranch: null,
      classification: { __typename: "Classification", resourceClassificationBanner: null, containerClassificationBanner: null },
      project: { __typename: "Project", _id: cid(`Project:${src.project_ref || "none"}`), usageAccountEnrollment: { __typename: "Enrollment", _id: cid(`Enrollment:${src.project_ref || "none"}`), magritteDirectorySourceTypeConfigV2: { __typename: "MagritteDirectorySourceTypeConfig", enabled: false } } },
    },
  };
}

// REST: GET /magritte-coordinator/api/source-store/sources/types — each connection type's sources
export function sourceTypesOf(sources) {
  const out = {};
  for (const s of sources || []) (out[sourceTypeOf(s.kind)] ||= []).push(sourceRidOf(s.source_id));
  return out;
}
// REST: GET /magritte-coordinator/api/extract-store/extracts/source — each source's syncs (extracts): none
export const extractsBySourceOf = (sources) => Object.fromEntries((sources || []).map((s) => [sourceRidOf(s.source_id), []]));
// REST: the agent and external-stack reads — none exists, and none can be made here
export const EXTERNAL_STACK_PRELOAD = { enabledAsSource: false, enabledAsDestination: false, canCreateExternalStacks: false };
export const AGENTS = [];
export const AGENT_HEALTH = {};
export const BOOTVISOR_STATUS = {};

// REST: POST streaming/extracts/get-for-sources — the asked sources' streaming syncs: none
export function streamingExtractsOf(request, sources) {
  const ours = new Set((sources || []).map((s) => sourceRidOf(s.source_id)));
  return { streamingExtracts: Object.fromEntries((request?.sourceIds || request?.sourceRids || []).filter((r) => ours.has(r)).map((r) => [r, []])) };
}
// REST: POST source-store/sources/description/bulk — the asked sources' names and connection types
export function sourceDescriptionsOf(rids, sources) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => { const s = byRid.get(r); return [r, { type: sourceTypeOf(s.kind), name: s.name || s.source_id, description: "", apiName: null }]; }));
}
// REST: POST extract-store/extracts/bulk — the asked syncs: none exists
export const extractsBulkOf = () => ({});

export const DATA_CONNECTION_GRAPHQL_OPERATIONS = new Set([
  "SourcesListQuery", "CreateSourceButtonQuery", "SplashTableQuery", "TargetsListQuery", "GetRemoteStoreRid", "RecentInstallationsPopoverQuery",
  "CommunicationChannelsQuery",
]);
// ctx: { sources } (already the caller's)
export function dataConnectionGraphqlFacts(name, variables, ctx) {
  const root = { __typename: "Query" };
  switch (name) {
    case "SourcesListQuery": {
      const want = new Set(variables?.sourceTypes || []);
      const text = String(variables?.name || "").trim().toLowerCase();
      const rows = (ctx.sources || []).filter((s) => (!want.size || want.has(sourceTypeOf(s.kind))) && (!text || String(s.name || "").toLowerCase().includes(text)));
      const from = Math.max(0, Number(variables?.pageToken) || 0);
      return { ...root, sources: { __typename: "MagritteSourcePage", values: rows.slice(from, from + 50).map(sourceNodeOf), nextPageToken: from + 50 < rows.length ? String(from + 50) : null } };
    }
    // creating a source is not bound yet (cut D3): the app offers no create it would refuse
    case "CreateSourceButtonQuery": return { ...root, globalPermissions: { __typename: "GlobalPermissions", _id: cid("GlobalPermissions"), canCreateMagritteSourceV2: false } };
    // recently viewed and favorite Data Connection resources: none is kept
    case "SplashTableQuery": return { ...root, recents: [], favorites: [] };
    // listeners (inbound message targets): none exists
    case "TargetsListQuery": return { ...root, searchInboundMessageListenerTargets: { __typename: "InboundMessageListenerTargetPage", values: [], nextPageToken: null } };
    // the reference examples' marketplace store: the Hypervisor has no remote marketplace
    case "GetRemoteStoreRid": return { ...root, remoteStore: null };
    case "RecentInstallationsPopoverQuery": return { ...root, store: null };
    // administrator communication channels: none is configured
    case "CommunicationChannelsQuery": return { ...root, communicationChannelCategories: [],
      me: { __typename: "User", _id: cid("User:me"), organization: { __typename: "Organization", _id: cid("Organization:me"), enrollment: { __typename: "Enrollment", _id: cid("Enrollment:me"), administratorCommunicationControls: { __typename: "AdministratorCommunicationControls", disallowedCommunicationChannels: [] } } } } };
    default: return null;
  }
}
