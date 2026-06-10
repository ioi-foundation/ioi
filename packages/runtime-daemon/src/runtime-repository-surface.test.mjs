import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRepositorySurface } from "./runtime-repository-surface.mjs";

test("runtime repository surface fails closed before JS public projection builders", () => {
  const surface = createRuntimeRepositorySurface({
    repositoryContextProjection() {
      throw new Error("JS repository projection must not author public truth");
    },
  });
  const store = { defaultCwd: "/workspace/project" };

  assert.throws(
    () => surface.repositoryContext(store),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(
        error.code,
        "runtime_repository_workflow_projection_rust_core_required",
      );
      assert.equal(
        error.details.rust_core_boundary,
        "runtime.repository_workflow_projection",
      );
      assert.equal(
        error.details.operation,
        "repository_workflow_repository_context",
      );
      assert.equal(
        error.details.operation_kind,
        "repository_workflow.projection.repository_context",
      );
      assert.equal(error.details.projection_kind, "repository_context");
      assert.equal(error.details.workspace_root, "/workspace/project");
      assert.equal(Object.hasOwn(error.details, "projectionKind"), false);
      assert.equal(Object.hasOwn(error.details, "workspaceRoot"), false);
      return true;
    },
  );
});

test("runtime repository surface translates mounted Rust projection-required record", () => {
  let captured = null;
  const surface = createRuntimeRepositorySurface({
    repositoryRunner: {
      planRepositoryWorkflowProjectionRequired(request) {
        captured = request;
        return {
          record: {
            status_code: 501,
            code: "runtime_repository_workflow_projection_rust_core_required",
            message:
              "Repository workflow projection requires direct Rust daemon-core projection over Agentgres-admitted repository workflow truth.",
            details: {
              rust_core_boundary: "runtime.repository_workflow_projection",
              operation: request.operation,
              operation_kind: request.operation_kind,
              projection_kind: request.projection_kind,
              workspace_root: request.workspace_root,
              source: request.source,
              evidence_refs: request.evidence_refs,
            },
          },
        };
      },
    },
  });
  const store = { defaultCwd: "/workspace/project" };

  assert.throws(
    () => surface.prAttempts(store),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(
        error.code,
        "runtime_repository_workflow_projection_rust_core_required",
      );
      assert.equal(error.details.operation, "repository_workflow_pr_attempts");
      assert.equal(
        error.details.operation_kind,
        "repository_workflow.projection.pr_attempts",
      );
      assert.equal(error.details.projection_kind, "pr_attempts");
      assert.equal(error.details.workspace_root, "/workspace/project");
      assert.equal(error.details.source, "runtime.repository_surface");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_repository_workflow_js_projection_retired",
        "rust_daemon_core_repository_workflow_projection_required",
        "agentgres_repository_workflow_truth_required",
      ]);
      return true;
    },
  );

  assert.deepEqual(captured, {
    operation: "repository_workflow_pr_attempts",
    operation_kind: "repository_workflow.projection.pr_attempts",
    projection_kind: "pr_attempts",
    workspace_root: "/workspace/project",
    source: "runtime.repository_surface",
    evidence_refs: [
      "runtime_repository_workflow_js_projection_retired",
      "rust_daemon_core_repository_workflow_projection_required",
      "agentgres_repository_workflow_truth_required",
    ],
  });
});
