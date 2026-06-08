import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_AGENTGRES_COMMAND_ARGS_ENV,
  RUNTIME_AGENTGRES_COMMAND_ENV,
  RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
  RUST_AGENTGRES_STORAGE_BACKEND,
  RuntimeAgentgresAdmissionRunnerError,
  RustRuntimeAgentgresAdmissionRunner,
  createRuntimeAgentgresAdmissionRunnerFromEnv,
} from "./runtime-agentgres-admission-runner.mjs";

function storageWriteRequest() {
  return {
    schema_version: "ioi.storage_backend_write_admission.v1",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    object_ref: "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
    content_hash: "sha256:run-state-json",
    artifact_refs: [],
    payload_refs: ["payload://runtime/runs/run_1/records/runs/run_1.json"],
    receipt_refs: ["receipt_policy"],
  };
}

function runtimeRun() {
  return {
    id: "run_1",
    agentId: "agent_1",
    status: "completed",
    mode: "send",
    objective: "Ship the runtime state slice",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [{ type: "started" }, { type: "completed" }],
    receipts: [{ id: "receipt_policy", kind: "policy_decision" }],
    artifacts: [{ id: "artifact_1", name: "result.txt", kind: "text" }],
    trace: {
      traceBundleId: "trace_bundle_1",
      taskState: { state: "done" },
      postconditions: [],
      semanticImpact: { impact: "local" },
      stopCondition: { reason: "done" },
      scorecard: { score: 1 },
      qualityLedger: { entries: [] },
    },
  };
}

function commitRequest() {
  return {
    schema_version: "ioi.runtime_run_state_commit.v1",
    run_id: "run_1",
    operation_kind: "run.create",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    run: runtimeRun(),
    agent: {
      id: "agent_1",
      status: "active",
      runtime: "local",
    },
    canonical_projection: { runId: "run_1", projection: "canonical" },
  };
}

function agentCommitRequest() {
  return {
    schema_version: "ioi.runtime_agent_state_commit.v1",
    agent_id: "agent_1",
    operation_kind: "agent.create",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    agent: {
      id: "agent_1",
      status: "active",
      runtime: "local",
      updated_at: "2026-06-06T00:00:00.000Z",
      receipt_refs: ["receipt_agent"],
    },
  };
}

function memoryCommitRequest() {
  return {
    schema_version: "ioi.runtime_memory_state_commit.v1",
    memory_state_kind: "record",
    state_id: "memory_1",
    operation_kind: "memory.write",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    payload: {
      schemaVersion: "ioi.agent-runtime.memory.v1",
      id: "memory_1",
      object: "ioi.agent_memory_record",
      fact: "Remember the launch checklist.",
      threadId: "thread_1",
      agentId: "agent_1",
      receipt_refs: ["receipt_memory"],
    },
  };
}

function subagentCommitRequest() {
  return {
    schema_version: "ioi.runtime_subagent_state_commit.v1",
    subagent_id: "subagent_1",
    operation_kind: "subagent.wait",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    subagent: {
      subagent_id: "subagent_1",
      parent_thread_id: "thread_1",
      agent_id: "agent_1",
      lifecycle_status: "completed",
      updated_at: "2026-06-06T00:00:00.000Z",
      receipt_refs: ["receipt_subagent"],
    },
  };
}

function artifactCommitRequest() {
  return {
    schema_version: "ioi.runtime_artifact_state_commit.v1",
    artifact_id: "artifact_1",
    operation_kind: "artifact.coding_tool_draft",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    artifact: {
      schema_version: "ioi.runtime.coding-tool-artifact.v1",
      id: "artifact_1",
      thread_id: "thread_1",
      tool_name: "file.read",
      tool_call_id: "tool_call_1",
      channel: "stdout",
      media_type: "text/plain",
      receipt_id: "receipt_artifact",
      content: "hello",
      content_bytes: 5,
      content_hash: "sha256:content",
    },
  };
}

function modelMountRecordCommitRequest() {
  return {
    schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
    record_dir: "provider-health",
    record_id: "health.provider_openai",
    operation_kind: "model_mount.provider_health.write",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    record: {
      id: "health.provider_openai",
      provider_id: "provider.openai",
      status: "available",
      checked_at: "2026-06-04T00:00:00.000Z",
      receipt_id: "receipt_provider_health",
      evidence_refs: ["provider_http_health"],
    },
  };
}

function modelMountReceiptCommitRequest() {
  return {
    schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
    receipt_id: "receipt_model_invocation",
    operation_kind: "model_mount.receipt.write",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    receipt: {
      id: "receipt_model_invocation",
      kind: "model_invocation",
      redaction: "redacted",
      evidenceRefs: ["rust_receipt_binder_core", "rust_agentgres_admission"],
      details: {
        model_mount_receipt_binding_ref: "sha256:binding",
        model_mount_accepted_receipt_append_hash: "sha256:append",
        model_mount_agentgres_operation_ref: "agentgres://model-mounting/accepted-receipts/op_1",
        model_mount_agentgres_admission_hash: "sha256:agentgres",
      },
    },
  };
}

test("runtime Agentgres runner sends runtime run-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_run_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_run_state_commit.v1",
              run_id: request.request.run_id,
              transition: {
                operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
                state_root_after: "sha256:after",
                resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
                transition_hash: "sha256:transition",
              },
              persistence: {
                materialization: {
                  materialization_hash: "sha256:materialization",
                },
                storage_write_set: {
                  write_set_hash: "sha256:write-set",
                  records: [{ record_path: "runs/run_1.json" }],
                },
                persistence_hash: "sha256:persistence",
              },
              commit_hash: "sha256:commit",
            },
            operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
            state_root_after: "sha256:after",
            resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
            transition_hash: "sha256:transition",
            materialization_hash: "sha256:materialization",
            write_set_hash: "sha256:write-set",
            persistence_hash: "sha256:persistence",
            commit_hash: "sha256:commit",
            written_records: [{ record_path: "runs/run_1.json" }],
            evidence_refs: ["rust_agentgres_runtime_run_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeRunState("/runtime-state", commitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_run_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.run_id, "run_1");
  assert.equal(calls[0].request.request.agent.id, "agent_1");
  assert.equal(Object.hasOwn(calls[0].request.request, "expected_heads"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "state_root_before"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "receipt_refs"), false);
  assert.equal(result.state_root_after, "sha256:after");
  assert.equal(result.resulting_head, "agentgres://runtime-state/runs/run_1/head/abcd");
  assert.equal(result.commit_hash, "sha256:commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_run_state_commit"]);
});

test("runtime Agentgres runner sends storage write admission bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_storage_write_admission_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              ...request.request,
              admission_hash: "sha256:storage-admission",
            },
            admission_hash: "sha256:storage-admission",
            evidence_refs: ["rust_agentgres_storage_write_admission"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitStorageBackendWrite(storageWriteRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_storage_backend_write");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.storage_backend_ref, "storage://runtime-agentgres/local-json");
  assert.equal(result.admission_hash, "sha256:storage-admission");
  assert.equal(result.object_ref, "agentgres://runtime-state/runs/run_1/records/runs/run_1.json");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_storage_write_admission"]);
});

test("runtime Agentgres runner sends runtime agent-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_agent_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_agent_state_commit.v1",
              agent_id: "agent_1",
              operation_kind: "agent.create",
              storage_backend_ref: "storage://runtime-agentgres/local-json",
              record: {
                record_path: "agents/agent_1.json",
                object_ref: "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json",
                content_hash: "sha256:agent-content",
                payload_refs: ["payload://runtime/agents/agent_1/records/agents/agent_1.json"],
                receipt_refs: ["receipt_agent"],
                admission: {
                  admission_hash: "sha256:agent-admission",
                },
              },
              commit_hash: "sha256:agent-commit",
            },
            agent_id: "agent_1",
            object_ref: "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json",
            content_hash: "sha256:agent-content",
            admission_hash: "sha256:agent-admission",
            commit_hash: "sha256:agent-commit",
            written_record: {
              record_path: "agents/agent_1.json",
            },
            evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeAgentState("/runtime-state", agentCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_agent_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.agent_id, "agent_1");
  assert.equal(result.agent_id, "agent_1");
  assert.equal(result.commit_hash, "sha256:agent-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_agent_state_commit"]);
});

test("runtime Agentgres runner sends runtime memory-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_memory_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_memory_state_commit.v1",
              memory_state_kind: "record",
              state_id: "memory_1",
              operation_kind: "memory.write",
              storage_backend_ref: "storage://runtime-agentgres/local-json",
              record: {
                record_path: "memory-records/memory_1.json",
                object_ref: "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json",
                content_hash: "sha256:memory-content",
                payload_refs: ["payload://runtime/memory/record/memory_1/records/memory-records/memory_1.json"],
                receipt_refs: ["receipt_memory"],
                admission: {
                  admission_hash: "sha256:memory-admission",
                },
              },
              commit_hash: "sha256:memory-commit",
            },
            memory_state_kind: "record",
            state_id: "memory_1",
            object_ref: "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json",
            content_hash: "sha256:memory-content",
            admission_hash: "sha256:memory-admission",
            commit_hash: "sha256:memory-commit",
            written_record: {
              record_path: "memory-records/memory_1.json",
            },
            evidence_refs: ["rust_agentgres_runtime_memory_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeMemoryState("/runtime-state", memoryCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_memory_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.memory_state_kind, "record");
  assert.equal(calls[0].request.request.state_id, "memory_1");
  assert.equal(result.state_id, "memory_1");
  assert.equal(result.commit_hash, "sha256:memory-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_memory_state_commit"]);
});

test("runtime Agentgres runner sends runtime subagent-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_subagent_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_subagent_state_commit.v1",
              subagent_id: "subagent_1",
              operation_kind: "subagent.wait",
              storage_backend_ref: "storage://runtime-agentgres/local-json",
              record: {
                record_path: "subagents/subagent_1.json",
                object_ref: "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json",
                content_hash: "sha256:subagent-content",
                payload_refs: ["payload://runtime/subagents/subagent_1/records/subagents/subagent_1.json"],
                receipt_refs: ["receipt_subagent"],
                admission: {
                  admission_hash: "sha256:subagent-admission",
                },
              },
              commit_hash: "sha256:subagent-commit",
            },
            subagent_id: "subagent_1",
            object_ref: "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json",
            content_hash: "sha256:subagent-content",
            admission_hash: "sha256:subagent-admission",
            commit_hash: "sha256:subagent-commit",
            written_record: {
              record_path: "subagents/subagent_1.json",
            },
            evidence_refs: ["rust_agentgres_runtime_subagent_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeSubagentState("/runtime-state", subagentCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_subagent_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.subagent_id, "subagent_1");
  assert.equal(result.subagent_id, "subagent_1");
  assert.equal(result.commit_hash, "sha256:subagent-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_subagent_state_commit"]);
});

test("runtime Agentgres runner sends runtime artifact-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_artifact_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_artifact_state_commit.v1",
              artifact_id: "artifact_1",
              operation_kind: "artifact.coding_tool_draft",
              storage_backend_ref: "storage://runtime-agentgres/local-json",
              record: {
                record_path: "artifacts/artifact_1.json",
                object_ref: "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json",
                content_hash: "sha256:artifact-content",
                payload_refs: ["payload://runtime/artifacts/artifact_1/records/artifacts/artifact_1.json"],
                receipt_refs: ["receipt_artifact"],
                admission: {
                  admission_hash: "sha256:artifact-admission",
                },
              },
              commit_hash: "sha256:artifact-commit",
            },
            artifact_id: "artifact_1",
            object_ref: "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json",
            content_hash: "sha256:artifact-content",
            admission_hash: "sha256:artifact-admission",
            commit_hash: "sha256:artifact-commit",
            written_record: {
              record_path: "artifacts/artifact_1.json",
            },
            evidence_refs: ["rust_agentgres_runtime_artifact_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeArtifactState("/runtime-state", artifactCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_artifact_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.artifact_id, "artifact_1");
  assert.equal(result.artifact_id, "artifact_1");
  assert.equal(result.commit_hash, "sha256:artifact-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_artifact_state_commit"]);
});

test("runtime Agentgres runner sends runtime model-mount record-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_model_mount_record_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
              record_dir: "provider-health",
              record_id: "health.provider_openai",
              operation_kind: "model_mount.provider_health.write",
              storage_backend_ref: "storage://runtime-agentgres/local-json",
              record: {
                record_path: "provider-health/health.provider_openai.json",
                object_ref: "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json",
                content_hash: "sha256:model-mount-record-content",
                payload_refs: ["payload://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"],
                receipt_refs: ["receipt_provider_health"],
                admission: {
                  admission_hash: "sha256:model-mount-record-admission",
                },
              },
              commit_hash: "sha256:model-mount-record-commit",
            },
            record_dir: "provider-health",
            record_id: "health.provider_openai",
            object_ref: "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json",
            content_hash: "sha256:model-mount-record-content",
            admission_hash: "sha256:model-mount-record-admission",
            commit_hash: "sha256:model-mount-record-commit",
            written_record: {
              record_path: "provider-health/health.provider_openai.json",
            },
            evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeModelMountRecordState("/runtime-state", modelMountRecordCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_model_mount_record_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.record_id, "health.provider_openai");
  assert.equal(result.record_dir, "provider-health");
  assert.equal(result.record_id, "health.provider_openai");
  assert.equal(result.commit_hash, "sha256:model-mount-record-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_model_mount_record_state_commit"]);
});

test("runtime Agentgres runner sends runtime model-mount receipt-state commit bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
              receipt_id: "receipt_model_invocation",
              operation_kind: "model_mount.receipt.write",
              storage_backend_ref: "storage://runtime-agentgres/local-json",
              record: {
                record_path: "receipts/receipt_model_invocation.json",
                object_ref:
                  "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json",
                content_hash: "sha256:receipt-content",
                payload_refs: [
                  "payload://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json",
                ],
                receipt_refs: ["receipt_model_invocation"],
                admission: {
                  admission_hash: "sha256:receipt-admission",
                },
              },
              commit_hash: "sha256:receipt-commit",
            },
            receipt_id: "receipt_model_invocation",
            object_ref:
              "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json",
            content_hash: "sha256:receipt-content",
            admission_hash: "sha256:receipt-admission",
            commit_hash: "sha256:receipt-commit",
            written_record: {
              record_path: "receipts/receipt_model_invocation.json",
            },
            evidence_refs: ["rust_agentgres_runtime_model_mount_receipt_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeModelMountReceiptState("/runtime-state", modelMountReceiptCommitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_model_mount_receipt_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.receipt_id, "receipt_model_invocation");
  assert.equal(result.receipt_id, "receipt_model_invocation");
  assert.equal(result.commit_hash, "sha256:receipt-commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_model_mount_receipt_state_commit"]);
});

test("runtime Agentgres runner env uses daemon-core command boundary", () => {
  const runner = createRuntimeAgentgresAdmissionRunnerFromEnv({
    [RUNTIME_AGENTGRES_COMMAND_ENV]: "ioi-runtime-daemon-core",
    [RUNTIME_AGENTGRES_COMMAND_ARGS_ENV]: "--json",
    IOI_RUNTIME_AGENTGRES_COMMAND: "retired-runtime-agentgres-bridge",
    IOI_RUNTIME_AGENTGRES_COMMAND_ARGS: "--retired-agentgres",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
  assert.deepEqual(runner.args, ["--json"]);
});

test("runtime Agentgres runner fails closed without command", () => {
  const runner = new RustRuntimeAgentgresAdmissionRunner();

  assert.throws(
    () => runner.commitRuntimeRunState("/runtime-state", commitRequest()),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_admission_bridge_unconfigured",
  );
});
