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
