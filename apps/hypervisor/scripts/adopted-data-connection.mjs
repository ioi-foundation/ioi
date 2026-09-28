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
import { namespaceRidOf, namespaceNameOf } from "./adopted-ontology.mjs";
import { principalUserId } from "./adopted-automate.mjs";

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

// ---- a source's own pages (cut D2): the source by its rid, from the caller's sources. A declared source's configuration
// is its endpoint (a REST API's domain, a bucket's URL); nothing can be exported, synced, explored, registered or
// webhooked from it here, so every such permission is false, and nothing depends on it.
const endpointUrl = (e) => { try { return new URL(String(e || "")); } catch { return null; } };
export function sourceConfigOf(src) {
  const type = sourceTypeOf(src.kind);
  if (type === "webhooks-rest") {
    const u = endpointUrl(src.endpoint);
    const id = uuidOf(`domain:${src.source_id}`);
    return { source: { type, config: { domains: [{ domainId: id, host: u?.host || "", scheme: u?.protocol === "http:" ? "HTTP" : "HTTPS" }] } },
      connections: { [id]: { id, config: { type: "http", http: { url: u ? `${u.protocol}//${u.host}` : "" } } } }, additionalSecrets: {}, resources: {} };
  }
  return { source: { type, config: { url: src.endpoint || null } }, connections: {}, additionalSecrets: {}, resources: {} };
}
// The enrollment a source runs under is the Hypervisor itself: no compute service, no egress CIDRs, no cloud identity, no
// private link, and no standing network egress policy (the daemon decides each crossing on its own lease), and nothing
// here may create one. Organization-wide, not per source.
export const ENROLLMENT_RID = `ri.multipass..enrollment.${uuidOf("enrollment")}`;
const enrollmentOf = (base) => ({
  ...base, __typename: "Enrollment", rid: ENROLLMENT_RID, name: "Hypervisor",
  computeEnvironmentDetails: { __typename: "ComputeEnvironmentDetails", cloudPlatformDetails: null, rubixEnvironmentDetails: { __typename: "RubixEnvironmentDetails", egressCidrs: [] } },
  cloudIdentities: [], isPrivateLinkEgressServiceAvailable: false, isSourceBasedNetworkingAvailable: false, networkEgressPolicies: [],
  networkEgressConfiguration: "SELF_SERVICE", isSelfApprovalEnabledForNetworkPolicyApprovalRequests: false, organizations: [],
  permissions: { __typename: "EnrollmentPermissions", _id: cid("EnrollmentPermissions"), canCreateNetworkPolicy: false, canCreateNetworkPolicyApprovalRequest: false, canCreateBcapEgress: false },
});
// A source bound to a wallet credential lease names that lease as its one secret (the secret itself never leaves the
// wallet); any other posture holds none here.
const secretsOf = (src) => src.credential_binding?.credential_lease_ref ? [{ __typename: "MagritteSecret", name: "Credential lease", vaultEntryRid: src.credential_binding.credential_lease_ref }] : [];
function sourceDetailOf(src) {
  const node = sourceNodeOf(src);
  const off = { canCreateExport: false, canCreateExtract: false, canExploreSource: false, canRegisterTable: false, canUpdateSourceConfig: false, canCreateWebhook: false, canUseSourceTerminal: false };
  return {
    ...node, apiName: null, sourceConfig: sourceConfigOf(src), permissions: { __typename: "MagritteSourcePermissions", ...off }, secrets: secretsOf(src),
    runtimePlatform: { __typename: "CloudRuntimePlatform", clientCertificatesV2: [], serverCertificateBundlesV2: [], migrationToCloudInfo: null },
    exportState: { __typename: "MagritteExportState", isEnabled: false },
    codeResourceImportUsageRestrictionsV2: { __typename: "CodeResourceImportUsageRestrictions", allowStemmaRepositoriesUsage: false, allowDeployedApplicationsUsage: false },
    streamingExtracts: [], exports: [], changeDataCaptureStreamingExtract: null, importingCodeResources: [], streamingMediaExtracts: [], mediaExtracts: [], hyperAutoIntegrations: [],
    tables: { __typename: "MagritteTablePage", values: [] }, magritteIcebergExtractsV2: { __typename: "MagritteIcebergExtractPage", totalNumberOfResults: 0 },
    webhooks: { __typename: "WebhooksPage", totalNumberOfResults: 0, values: [], nextPageToken: null }, lastKnownCdataOauthAuthenticationStatus: null, userUploadedJdbcDrivers: [],
    // a declared source syncs nothing, so no folder receives its datasets
    outputFolder: null,
    metadata: { ...node.metadata, name: src.name || src.source_id, description: "", permissions: { __typename: "ResourcePermissions", canEditMetadata: false },
      project: { ...node.metadata.project, usageAccountEnrollment: enrollmentOf(node.metadata.project.usageAccountEnrollment) } },
  };
}
// REST: POST source-store/sources/config/bulk — the asked sources' configurations
export function sourceConfigsOf(rids, sources) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => [r, sourceConfigOf(byRid.get(r))]));
}
// REST: POST source-store/sources/metadata — when each asked source was declared and last changed, and by whom
export function sourceMetadataOf(rids, sources) {
  const byRid = new Map((sources || []).map((s) => [sourceRidOf(s.source_id), s]));
  return Object.fromEntries((Array.isArray(rids) ? rids : []).filter((r) => byRid.has(r)).map((r) => { const s = byRid.get(r); const who = principalUserId(s.declared_by_principal_ref);
    return [r, { created: { time: s.created_at || null, userId: who }, lastModified: { time: s.updated_at || s.created_at || null, userId: who }, displayOptions: null }]; }));
}
// REST: GET compass/api/resources/<source rid>/parent — a source is filed in no project here, so its parent is the owner's
// organization folder (the namespace the adopted Ontology Manager answers too)
export function sourceParentOf(rid, sources, ownerRef) {
  const s = (sources || []).find((x) => sourceRidOf(x.source_id) === rid);
  if (!s || !ownerRef) return null;
  const at = { time: s.created_at || null, userId: principalUserId(s.declared_by_principal_ref) };
  return { rid: namespaceRidOf(ownerRef), name: namespaceNameOf(ownerRef), created: at, modified: at, lastModified: Date.parse(s.created_at || "") || 0,
    urlVariables: {}, directlyTrashed: false, isAutosave: false, isHidden: false, isPreviewResource: false, status: null };
}
// REST: POST compass/api/batch/resources — the caller's sources (and their parent, the owner's organization folder) as
// the resources the app names and places them by: its header, breadcrumbs and path. No operation is granted on them here.
export function compassSourceResources(rids, sources, ownerRef) {
  const out = {};
  const want = new Set(Array.isArray(rids) ? rids : []);
  const folder = ownerRef ? namespaceRidOf(ownerRef) : null;
  const base = (rid, name, at, extra) => ({ rid, name, created: at, modified: at, lastModified: Date.parse(at.time || "") || 0, description: null, operations: [], urlVariables: {},
    favorite: null, branches: [], defaultBranch: null, longDescription: null, directlyTrashed: false, inTrash: false, isAutosave: false, isHidden: false, isPreviewResource: false,
    deprecation: null, collections: [], namedCollections: [], tags: [], namedTags: [], alias: "", collaborators: [], markings: [], projectAccessMarkings: [],
    linkedItems: [], classification: null, portfolioRid: null, status: null, ...extra });
  for (const s of sources || []) {
    const rid = sourceRidOf(s.source_id);
    if (!want.has(rid)) continue;
    const at = { time: s.created_at || null, userId: principalUserId(s.declared_by_principal_ref) };
    out[rid] = base(rid, s.name || s.source_id, at, { path: `/${namespaceNameOf(ownerRef)}/${s.name || s.source_id}`, namedAncestors: folder ? [{ rid: folder, name: namespaceNameOf(ownerRef) }] : [] });
  }
  if (folder && want.has(folder)) out[folder] = base(folder, namespaceNameOf(ownerRef), { time: null, userId: null }, { path: `/${namespaceNameOf(ownerRef)}`, namedAncestors: [] });
  return out;
}
// REST: GET source-store/v2/source/<rid>/runtimePlatform — the Hypervisor reaches a source itself (the "cloud" runtime),
// holding no credential there (a credential stays in the wallet), no egress policy, cloud identity, OIDC runtime or
// certificate; and GET source-certificates/source/<rid>/redacted — no certificate
export function sourceRuntimePlatformOf(rid, sources) {
  if (!(sources || []).some((s) => sourceRidOf(s.source_id) === rid)) return null;
  return { type: "cloud", cloud: { credential: null, networkEgressPolicies: { networkEgressPolicies: [] }, cloudIdentity: null, oidcRuntime: null, clientCertificates: [], serverCertificateBundles: [] } };
}
export const SOURCE_CERTIFICATES = { client: {}, server: {} };
// a source as a resource the settings pages name and place (its name, its folder, its path); nothing is editable here
function sourceResourceMetadataOf(src, ownerRef) {
  const rid = sourceRidOf(src.source_id);
  const folderRid = ownerRef ? namespaceRidOf(ownerRef) : null;
  const seg = (r, name, path) => ({ __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${r}`), rid: r, name, alias: null, openUrl: null, path, collections: [], status: null,
    trashedStatus: "NOT_TRASHED", type: { __typename: "ResourceType", iconName: null }, permissions: { __typename: "ResourcePermissions", canEditMetadata: false, canOpenLink: false },
    autosaved: false, statusInfo: null, ancestors: [], parent: null });
  const folder = folderRid ? seg(folderRid, namespaceNameOf(ownerRef), `/${namespaceNameOf(ownerRef)}`) : null;
  return { ...seg(rid, src.name || src.source_id, `/${namespaceNameOf(ownerRef)}/${src.name || src.source_id}`), parent: folder, ancestors: folder ? [folder] : [] };
}
export const SOURCE_PAGE_OPERATIONS = new Set(["SourcePageQuery", "SourcePageHelperQuery", "SourceBadConfigurationCalloutQuery", "CdataSourceInformationQuery", "ActiveResourceQuery", "WalkthroughsForResourceQuery", "SourceOutputFolderCondensedQuery",
  "SourceSettingsPageQuery", "SourceEditorQuery", "SourceEgressSelectPanelQuery", "SourceWebhooksPageQuery", "SourceWebhooksSectionQuery", "CodeImportsStepQuery", "ResourceMetadataQuery"]);
// no service a source's settings name exists here: no compute service, no egress or on-prem proxy
const SERVICE_AVAILABILITY = { __typename: "MagritteServiceAvailability", computeService: { __typename: "MagritteServiceAvailabilityResult", isAvailable: false },
  egressProxy: { __typename: "MagritteServiceAvailabilityResult", isAvailable: false }, onPremProxy: { __typename: "MagritteServiceAvailabilityResult", isAvailable: false } };
const sourceOf = (sources, rid) => (sources || []).find((s) => sourceRidOf(s.source_id) === rid) || null;

export const DATA_CONNECTION_GRAPHQL_OPERATIONS = new Set([...SOURCE_PAGE_OPERATIONS, 
  "SourcesListQuery", "CreateSourceButtonQuery", "SplashTableQuery", "TargetsListQuery", "GetRemoteStoreRid", "RecentInstallationsPopoverQuery",
  "CommunicationChannelsQuery", "FoundryProvidedDriverQuery",
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
    // a source's page
    case "SourcePageQuery": case "SourcePageHelperQuery": case "SourceBadConfigurationCalloutQuery": case "CdataSourceInformationQuery": case "SourceOutputFolderCondensedQuery":
    case "SourceSettingsPageQuery": case "SourceEditorQuery": case "SourceWebhooksPageQuery": case "SourceWebhooksSectionQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid || variables?.rid);
      // no identity provider federates a source's outbound calls
      return { ...root, source: src ? sourceDetailOf(src) : null, magritteServiceAvailability: SERVICE_AVAILABILITY, oidcMetadata: null };
    }
    // the egress panel reads the enrollment through the source's resource metadata
    case "SourceEgressSelectPanelQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      return { ...root, resourceMetadata: src ? sourceDetailOf(src).metadata : null };
    }
    // code imports: no code repository, deployed application or pipeline imports a source here, and none may be allowed
    case "CodeImportsStepQuery": {
      const src = sourceOf(ctx.sources, variables?.sourceRid);
      if (!src) return { ...root, source: null };
      const d = sourceDetailOf(src);
      return { ...root, source: { ...d, codeResourceImportUsageRestrictionsV2: { ...d.codeResourceImportUsageRestrictionsV2, __typename: "MagritteSourceCodeResourceImportUsageRestrictions", allowEddiePipelinesUsage: false },
        permissions: { ...d.permissions, canManageImportUsageRestrictions: false, canManageImportingCodeResources: false } } };
    }
    case "ResourceMetadataQuery": {
      const src = sourceOf(ctx.sources, variables?.resourceRid || variables?.rid);
      return { ...root, resourceMetadata: src ? sourceResourceMetadataOf(src, ctx.ownerRef) : null };
    }
    // a JDBC driver: no connection type here uses one
    case "FoundryProvidedDriverQuery": return { ...root, magritteProvidedJdbcDriver: null };
    // a source as a resource: not promoted, and no walkthrough
    case "ActiveResourceQuery": case "WalkthroughsForResourceQuery": {
      const rid = variables?.rid || variables?.resourceRid;
      const src = sourceOf(ctx.sources, rid);
      return { ...root, resourceMetadata: src ? { __typename: "ResourceMetadata", _id: cid(`ResourceMetadata:${rid}`), rid, promotion: null, aipAssistWalkthroughs: [] } : null };
    }
    default: return null;
  }
}
