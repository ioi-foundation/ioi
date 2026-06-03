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
    stableToolId: "fs.read",
    effectClass: "local_read",
    evidenceRequirements: ["file_read_receipt"],
  });
  assert.equal(read.approvalRequired, false);
  assert.equal(read.credentialReady, true);
  assert.equal(read.idempotencyBehavior.strategy, "read_only");
  assert.equal(read.marketplaceExposure.eligible, true);

  const effectful = runtimeToolRegistryGovernanceMetadata({
    stable_tool_id: "sys.exec",
    effect_class: "local_command",
    risk_domain: "host",
    authority_scope_requirements: ["scope:host.controlled_execution"],
  });
  assert.equal(effectful.approvalRequired, true);
  assert.equal(effectful.idempotencyBehavior.required, true);
  assert.equal(effectful.marketplaceExposure.eligible, false);
});

test("runtime tool catalog filters by pack and includes coding contracts", () => {
  const tools = runtimeTools({ pack: "coding" }, {
    codingToolContracts() {
      return [
        {
          stableToolId: "coding.apply_patch",
          displayName: "Apply patch",
          pack: "coding",
          effectClass: "local_command",
        },
      ];
    },
  });

  assert.deepEqual(tools.map((tool) => tool.stableToolId), ["coding.apply_patch"]);
  assert.equal(tools[0].approvalRequired, true);
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
    evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
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
    evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
  });
});
