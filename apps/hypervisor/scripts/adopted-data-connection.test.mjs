// The adopted Data Connection's pure answers (R-241, Data Connection D1): the caller's data sources as the reference
// app's sources, and the bootstrap reads over them.
import test from "node:test";
import assert from "node:assert/strict";
import { answerDocument } from "./adopted-graphql.mjs";
import * as DC from "./adopted-data-connection.mjs";

const mine = { source_id: "ds_1", name: "Orders API", kind: "rest_api", declared_by_principal_ref: "user://me", project_ref: null };
const bucket = { source_id: "ds_2", name: "Plants bucket", kind: "s3", declared_by_principal_ref: "user://me", project_ref: null };
const teamProject = { source_id: "ds_3", name: "Team feed", kind: "http_feed", declared_by_principal_ref: "user://colleague", project_ref: "project://team" };
const stranger = { source_id: "ds_4", name: "Someone else's", kind: "postgres", declared_by_principal_ref: "user://stranger", project_ref: "project://theirs" };

test("the caller sees the sources they declared and those filed in a project they can see — never another principal's", () => {
  const seen = DC.callerSourcesOf([mine, bucket, teamProject, stranger], "user://me", ["project://team"]);
  assert.deepEqual(seen.map((s) => s.source_id), ["ds_1", "ds_2", "ds_3"]);
  assert.deepEqual(DC.callerSourcesOf([mine, stranger], null, []), [], "no principal: nothing");
});

test("a kind is a connection type: the reference's type id where it names the same connector, else the Hypervisor's own; none syncs", () => {
  assert.equal(DC.sourceTypeOf("rest_api"), "webhooks-rest");
  assert.equal(DC.sourceTypeOf("s3"), "s3-direct");
  assert.equal(DC.sourceTypeOf("http_feed"), "hypervisor-http-feed");
  assert.equal(DC.MANAGED_SOURCE_TYPES["webhooks-rest"].name, "REST API");
  assert.ok(Object.values(DC.MANAGED_SOURCE_TYPES).every((t) => Object.keys(t.syncs).length === 0 && t.capabilities.length === 0), "a declared source ingests nothing");
  assert.deepEqual(DC.sourceTypesOf([mine, bucket]), { "webhooks-rest": [DC.sourceRidOf("ds_1")], "s3-direct": [DC.sourceRidOf("ds_2")] });
  assert.deepEqual(DC.extractsBySourceOf([mine]), { [DC.sourceRidOf("ds_1")]: [] });
});

test("the Sources list answers the caller's sources in the list's own document, filtered by name and type", () => {
  const q = "query SourcesListQuery($name: String, $sourceTypes: [String!]) { sources(filter: {name: $name, types: $sourceTypes}) { values { rid type name numberOfExtracts runtimePlatform { __typename } __typename } nextPageToken __typename } __typename }";
  const all = answerDocument(q, DC.dataConnectionGraphqlFacts("SourcesListQuery", {}, { sources: [mine, bucket] }), null, "SourcesListQuery");
  assert.deepEqual(all.sources.values.map((v) => [v.name, v.type, v.numberOfExtracts]), [["Orders API", "webhooks-rest", 0], ["Plants bucket", "s3-direct", 0]]);
  const s3 = DC.dataConnectionGraphqlFacts("SourcesListQuery", { sourceTypes: ["s3-direct"] }, { sources: [mine, bucket] });
  assert.deepEqual(s3.sources.values.map((v) => v.name), ["Plants bucket"]);
  const named = DC.dataConnectionGraphqlFacts("SourcesListQuery", { name: "orders" }, { sources: [mine, bucket] });
  assert.deepEqual(named.sources.values.map((v) => v.name), ["Orders API"]);
  assert.equal(DC.dataConnectionGraphqlFacts("CreateSourceButtonQuery", {}, {}).globalPermissions.canCreateMagritteSourceV2, false, "no create offered until it is bound");
});

test("the list reads name only the caller's sources", () => {
  const rid = DC.sourceRidOf("ds_1");
  assert.deepEqual(DC.sourceDescriptionsOf([rid, "ri.magritte..source.other"], [mine]), { [rid]: { type: "webhooks-rest", name: "Orders API", description: "", apiName: null } });
  assert.deepEqual(DC.streamingExtractsOf({ sourceIds: [rid, "ri.magritte..source.other"] }, [mine]), { streamingExtracts: { [rid]: [] } });
});

test("a source's own page: its configuration is its declared endpoint, it can do nothing here, and it sits in the owner's folder", () => {
  const rest = { ...mine, endpoint: "https://api.example.test/orders", created_at: "2026-09-28T00:00:00Z" };
  const cfg = DC.sourceConfigOf(rest);
  assert.equal(cfg.source.type, "webhooks-rest");
  assert.equal(cfg.source.config.domains[0].host, "api.example.test");
  assert.equal(Object.values(cfg.connections)[0].config.http.url, "https://api.example.test");
  assert.equal(DC.sourceConfigOf({ ...bucket, endpoint: "s3://plants/" }).source.config.url, "s3://plants/");
  const rid = DC.sourceRidOf("ds_1");
  const page = DC.dataConnectionGraphqlFacts("SourcePageQuery", { sourceRid: rid }, { sources: [rest] });
  assert.ok(Object.values(page.source.permissions).filter((v) => typeof v === "boolean").every((v) => v === false), "no export, sync, explore, table or webhook is offered");
  assert.equal(page.source.outputFolder, null);
  assert.equal(page.magritteServiceAvailability.egressProxy.isAvailable, false);
  assert.equal(DC.dataConnectionGraphqlFacts("SourcePageQuery", { sourceRid: DC.sourceRidOf("ds_4") }, { sources: [rest] }).source, null, "another's source is not answered");
  assert.equal(DC.sourceMetadataOf([rid], [rest])[rid].created.time, "2026-09-28T00:00:00Z");
  assert.equal(DC.sourceParentOf(rid, [rest], "org://local").name, "local");
  const res = DC.compassSourceResources([rid], [rest], "org://local")[rid];
  assert.equal(res.name, "Orders API");
  assert.deepEqual([res.branches, res.tags, res.markings], [[], [], []], "the link component iterates these");
});

test("a source's settings: its runtime is the Hypervisor's own with nothing held there, its imports and webhooks are off, and a wallet lease is its one secret", () => {
  const rid = DC.sourceRidOf("ds_1");
  assert.deepEqual(DC.sourceRuntimePlatformOf(rid, [mine]).cloud, { credential: null, networkEgressPolicies: { networkEgressPolicies: [] }, cloudIdentity: null, oidcRuntime: null, clientCertificates: [], serverCertificateBundles: [] });
  assert.equal(DC.sourceRuntimePlatformOf(DC.sourceRidOf("ds_4"), [mine]), null, "another's source has no runtime answered");
  const editor = DC.dataConnectionGraphqlFacts("SourceEditorQuery", { sourceRid: rid }, { sources: [mine] });
  const enrollment = editor.source.metadata.project.usageAccountEnrollment;
  assert.deepEqual([enrollment.networkEgressPolicies, enrollment.cloudIdentities, enrollment.permissions.canCreateNetworkPolicy], [[], [], false]);
  assert.equal(editor.source.permissions.canUpdateSourceConfig, false, "a declared source cannot be changed (no update route)");
  assert.deepEqual(editor.source.secrets, [], "no lease bound: no secret");
  const leased = { ...mine, credential_binding: { kind: "lease_ref", credential_lease_ref: "lease://wallet/1" } };
  assert.deepEqual(DC.dataConnectionGraphqlFacts("SourceEditorQuery", { sourceRid: rid }, { sources: [leased] }).source.secrets.map((x) => x.vaultEntryRid), ["lease://wallet/1"]);
  const imports = DC.dataConnectionGraphqlFacts("CodeImportsStepQuery", { sourceRid: rid }, { sources: [mine] }).source;
  assert.ok(Object.values(imports.codeResourceImportUsageRestrictionsV2).filter((v) => typeof v === "boolean").every((v) => v === false));
  assert.deepEqual([imports.permissions.canManageImportUsageRestrictions, imports.permissions.canManageImportingCodeResources, imports.permissions.canCreateWebhook], [false, false, false]);
  const meta = DC.dataConnectionGraphqlFacts("ResourceMetadataQuery", { resourceRid: rid }, { sources: [mine], ownerRef: "org://local" }).resourceMetadata;
  assert.deepEqual([meta.name, meta.parent.name, meta.permissions.canEditMetadata], ["Orders API", "local", false]);
  assert.equal(DC.dataConnectionGraphqlFacts("ResourceMetadataQuery", { resourceRid: DC.sourceRidOf("ds_4") }, { sources: [mine], ownerRef: "org://local" }).resourceMetadata, null);
});
