import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeToolSurface } from "./runtime-tool-surface.mjs";

test("runtime tool surface returns Rust-owned account nodes and tools", () => {
  const calls = [];
  const toolCatalogRunner = {
    projectRuntimeToolCatalog(request) {
      calls.push(request);
      if (request.projection_kind === "account") {
        return {
          projection_kind: "account",
          operation_kind: request.operation_kind,
          account: {
            id: "local-operator",
            email: request.operator_email,
            authorityLevel: "local",
            privacyClass: "local_private",
            source: "rust-daemon-core-agentgres",
          },
        };
      }
      if (request.projection_kind === "runtime_nodes") {
        return {
          projection_kind: "runtime_nodes",
          operation_kind: request.operation_kind,
          runtime_nodes: [
            {
              id: "hosted-provider",
              status: request.hosted_endpoint_configured ? "available" : "blocked",
              privacyClass: "hosted",
              evidence_refs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
            },
          ],
        };
      }
      return {
        projection_kind: "tools",
        operation_kind: request.operation_kind,
        pack: request.pack,
        tools: [
          {
            stable_tool_id: "file.apply_patch",
            pack: "coding",
            approval_required: true,
          },
        ],
      };
    },
  };
  const surface = createRuntimeToolSurface({
    env: {
      IOI_OPERATOR_EMAIL: "operator@example.test",
      IOI_AGENT_SDK_HOSTED_ENDPOINT: "https://hosted.example.test",
    },
    toolCatalogRunner,
    workspaceRoot: "/workspace/project",
  });

  const account = surface.getAccount();
  const nodes = surface.listRuntimeNodes();
  const tools = surface.listTools({ pack: "Coding" });

  assert.equal(account.source, "rust-daemon-core-agentgres");
  assert.equal(nodes[0].status, "available");
  assert.deepEqual(tools.map((tool) => tool.stable_tool_id), ["file.apply_patch"]);
  assert.equal(Object.hasOwn(tools[0], "stableToolId"), false);
  assert.deepEqual(calls.map((call) => call.projection_kind), [
    "account",
    "runtime_nodes",
    "tools",
  ]);
  assert.equal(calls[0].operator_email, "operator@example.test");
  assert.equal(calls[1].hosted_endpoint_configured, true);
  assert.equal(calls[2].pack, "coding");
  assert.equal(calls[2].workspace_root, "/workspace/project");
  assert.equal(Object.hasOwn(calls[2], "workspaceRoot"), false);
});

test("runtime tool surface fails closed when Rust projection is missing", () => {
  const surface = createRuntimeToolSurface({ workspaceRoot: "/workspace/project" });

  assert.throws(
    () => surface.listTools({ pack: "coding" }),
    (error) =>
      error.code === "runtime_tool_catalog_rust_core_required" &&
      error.details.projection_kind === "tools" &&
      error.details.pack === "coding" &&
      error.details.workspace_root === "/workspace/project" &&
      !Object.hasOwn(error.details, "projectionKind"),
  );
});

test("runtime tool surface rejects Rust projection mismatches", () => {
  const surface = createRuntimeToolSurface({
    toolCatalogRunner: {
      projectRuntimeToolCatalog() {
        return {
          projection_kind: "account",
          operation_kind: "runtime.tool_catalog.projection.account",
          account: { id: "local-operator" },
        };
      },
    },
  });

  assert.throws(
    () => surface.listTools(),
    (error) =>
      error.code === "runtime_tool_catalog_rust_projection_invalid" &&
      error.details.expected_projection_kind === "tools" &&
      error.details.projection_kind === "account",
  );
});
