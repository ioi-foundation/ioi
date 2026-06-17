import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRepositoryApi } from "./runtime-repository-api.mjs";

test("runtime repository API returns Rust-owned repository workflow projections", () => {
  const calls = [];
  const surface = createRuntimeRepositoryApi({
    contextPolicyCore: {
      projectRepositoryWorkflow(request) {
        calls.push(request);
        if (request.projection_kind === "repository_context") {
          return {
            source: "rust_repository_workflow_projection_api",
            projection_kind: "repository_context",
            projection: {
              schemaVersion: "ioi.agent-runtime.repository-context.v1",
              object: "ioi.repository_context",
              contextId: "repoctx_one",
            },
          };
        }
        return {
          source: "rust_repository_workflow_projection_api",
          projection_kind: "pr_attempts",
          projection: [
            {
              schemaVersion: "ioi.agent-runtime.pr-attempt.v1",
              object: "ioi.pr_attempt",
              attemptId: "pr_attempt_one",
            },
          ],
        };
      },
    },
  });
  const store = { defaultCwd: "/workspace/project" };

  assert.equal(surface.repositoryContext(store).contextId, "repoctx_one");
  assert.equal(surface.prAttempts(store)[0].attemptId, "pr_attempt_one");
  assert.deepEqual(calls, [
    {
      operation: "repository_workflow_repository_context",
      operation_kind: "repository_workflow.projection.repository_context",
      projection_kind: "repository_context",
      workspace_root: "/workspace/project",
      source: "runtime.repository_api",
      evidence_refs: [
        "runtime_repository_workflow_rust_projection",
        "agentgres_repository_workflow_truth_required",
      ],
    },
    {
      operation: "repository_workflow_pr_attempts",
      operation_kind: "repository_workflow.projection.pr_attempts",
      projection_kind: "pr_attempts",
      workspace_root: "/workspace/project",
      source: "runtime.repository_api",
      evidence_refs: [
        "runtime_repository_workflow_rust_projection",
        "agentgres_repository_workflow_truth_required",
      ],
    },
  ]);
});

test("runtime repository API fails closed when Rust projection is missing", () => {
  const surface = createRuntimeRepositoryApi({});
  const store = { defaultCwd: "/workspace/project" };

  assert.throws(
    () => surface.repositoryContext(store),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_repository_workflow_rust_projection_missing");
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

test("runtime repository API rejects Rust projection mismatches", () => {
  const surface = createRuntimeRepositoryApi({
    contextPolicyCore: {
      projectRepositoryWorkflow() {
        return {
          source: "rust_repository_workflow_projection_api",
          projection_kind: "github_context",
          projection: {
            schemaVersion: "ioi.agent-runtime.github-context.v1",
          },
        };
      },
    },
  });
  const store = { defaultCwd: "/workspace/project" };

  assert.throws(
    () => surface.branchPolicy(store),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "runtime_repository_workflow_rust_projection_invalid");
      assert.equal(error.details.expected_projection_kind, "branch_policy");
      assert.equal(error.details.actual_projection_kind, "github_context");
      assert.equal(
        error.details.operation_kind,
        "repository_workflow.projection.branch_policy",
      );
      return true;
    },
  );
});
