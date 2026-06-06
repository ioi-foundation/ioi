import assert from "node:assert/strict";
import { test } from "node:test";

import {
  redactRuntimeNodeForDoctor,
  runtimeAccount,
  runtimeNodes,
  runtimeToolRegistryGovernanceMetadata,
  runtimeTools,
} from "./runtime-tool-catalog.mjs";

test("runtime tool catalog applies governance metadata to read-only and effectful tools", () => {
  const read = runtimeToolRegistryGovernanceMetadata({
    stable_tool_id: "fs.read",
    effect_class: "local_read",
    evidence_requirements: ["file_read_receipt"],
  });
  assert.equal(read.approval_required, false);
  assert.equal(read.credential_ready, true);
  assert.equal(read.idempotency_behavior.strategy, "read_only");
  assert.equal(read.marketplace_exposure.eligible, true);
  assert.equal(Object.hasOwn(read, "stableToolId"), false);
  assert.equal(Object.hasOwn(read, "approvalRequired"), false);

  const effectful = runtimeToolRegistryGovernanceMetadata({
    stable_tool_id: "sys.exec",
    effect_class: "local_command",
    risk_domain: "host",
    authority_scope_requirements: ["scope:host.controlled_execution"],
  });
  assert.equal(effectful.approval_required, true);
  assert.equal(effectful.idempotency_behavior.required, true);
  assert.equal(effectful.marketplace_exposure.eligible, false);
});

test("runtime tool catalog filters by pack and includes coding contracts", () => {
  const tools = runtimeTools({ pack: "coding" }, {
    codingToolContracts() {
      return [
        {
          stable_tool_id: "coding.apply_patch",
          display_name: "Apply patch",
          pack: "coding",
          effect_class: "local_command",
        },
      ];
    },
  });

  assert.deepEqual(tools.map((tool) => tool.stable_tool_id), ["coding.apply_patch"]);
  assert.equal(tools[0].approval_required, true);
  assert.equal(Object.hasOwn(tools[0], "stableToolId"), false);
});

test("runtime account and nodes project env-backed local status", () => {
  const env = {
    IOI_OPERATOR_EMAIL: "operator@example.test",
    IOI_AGENT_SDK_HOSTED_ENDPOINT: "https://hosted.example.test",
  };

  assert.deepEqual(runtimeAccount(env), {
    id: "local-operator",
    email: "operator@example.test",
    authorityLevel: "local",
    privacyClass: "local_private",
    source: "ioi-daemon-agentgres",
  });
  const nodes = runtimeNodes(env);
  assert.equal(nodes.find((node) => node.id === "hosted-provider").status, "available");
  assert.equal(nodes.find((node) => node.id === "self-hosted-provider").status, "blocked");
});

test("runtime node doctor projection redacts endpoint values", () => {
  const redacted = redactRuntimeNodeForDoctor({
    id: "hosted-provider",
    kind: "hosted",
    status: "available",
    endpoint: "https://hosted.example.test",
    privacyClass: "hosted",
    evidence_refs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
  }, {
    doctorHash(value) {
      return `hash:${value}`;
    },
  });

  assert.deepEqual(redacted, {
    id: "hosted-provider",
    kind: "hosted",
    status: "available",
    privacyClass: "hosted",
    endpointConfigured: true,
    endpointHash: "hash:https://hosted.example.test",
    evidence_refs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
  });
  assert.equal(Object.hasOwn(redacted, "evidenceRefs"), false);
});
