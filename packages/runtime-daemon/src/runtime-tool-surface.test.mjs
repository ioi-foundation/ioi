import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeToolSurface } from "./runtime-tool-surface.mjs";

test("runtime tool surface fails closed for retired JS public projections", () => {
  const calls = [];
  const toolCatalogRunner = {
    planRuntimeToolCatalogProjectionRequired(request) {
      calls.push(request);
      return {
        source: "rust_runtime_tool_catalog_projection_required_command",
        record: {
          status_code: 501,
          code: "runtime_tool_catalog_rust_core_required",
          message:
            "Runtime account, node, and tool catalog projections require direct Rust daemon-core projection over Agentgres-admitted runtime catalog truth.",
          details: {
            rust_core_boundary: "runtime.tool_catalog",
            operation: request.operation,
            operation_kind: request.operation_kind,
            projection_kind: request.projection_kind,
            pack: request.pack ?? null,
            workspace_root: request.workspace_root,
            evidence_refs: request.evidence_refs,
          },
        },
      };
    },
  };
  const surface = createRuntimeToolSurface({
    toolCatalogRunner,
    workspaceRoot: "/workspace/project",
  });

  assert.throws(
    () => surface.getAccount(),
    (error) =>
      error.code === "runtime_tool_catalog_rust_core_required" &&
      error.details.projection_kind === "account" &&
      error.details.workspace_root === "/workspace/project" &&
      !Object.hasOwn(error.details, "projectionKind"),
  );
  assert.throws(
    () => surface.listRuntimeNodes(),
    (error) =>
      error.code === "runtime_tool_catalog_rust_core_required" &&
      error.details.projection_kind === "runtime_nodes" &&
      !Object.hasOwn(error.details, "workspaceRoot"),
  );
  assert.throws(
    () => surface.listTools({ pack: "Coding" }),
    (error) =>
      error.code === "runtime_tool_catalog_rust_core_required" &&
      error.details.projection_kind === "tools" &&
      error.details.pack === "coding",
  );

  assert.deepEqual(calls.map((call) => call.projection_kind), [
    "account",
    "runtime_nodes",
    "tools",
  ]);
  assert.deepEqual(calls.map((call) => call.source), [
    "runtime.tool_surface",
    "runtime.tool_surface",
    "runtime.tool_surface",
  ]);
});
