import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE,
  HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH,
  buildTerminalTranscriptReceiptEvidenceRecord,
  loadHypervisorReceiptEvidenceProjection,
  normalizeHypervisorReceiptEvidenceProjection,
} from "./hypervisorReceiptEvidenceModel.ts";

test("receipt evidence projection binds receipts to Agentgres, artifacts, traces, state roots, and replay", () => {
  const projection = HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.receipt_evidence_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.page_cursor, null);
  assert.equal(projection.next_page_cursor, null);
  assert.equal(projection.page_size, 25);
  assert.equal(projection.has_more, false);
  assert.match(projection.receipt_boundary_invariant, /Agentgres admits operational truth/);
  assert.match(projection.receipt_boundary_invariant, /Hypervisor client only renders/);
  assert.ok(projection.records.length >= 8);
  assert.ok(
    projection.records.every((record) =>
      record.agentgres_operation_refs.every((ref) =>
        ref.startsWith("agentgres://operation/"),
      ),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.artifact_refs.every((ref) => ref.startsWith("artifact://")),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.trace_refs.every(
        (ref) => ref.startsWith("trace://") || ref.startsWith("agentgres://trace/"),
      ),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.state_root_ref.startsWith("agentgres://state-root/"),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.replay_ref.startsWith("agentgres://replay/"),
    ),
  );
});

test("receipt evidence projection covers session, provider, harness, lease, and restore evidence", () => {
  const kinds = new Set(
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.map(
      (record) => record.kind,
    ),
  );
  assert.ok(kinds.has("session_lifecycle"));
  assert.ok(kinds.has("authority"));
  assert.ok(kinds.has("environment_lease"));
  assert.ok(kinds.has("provider_placement"));
  assert.ok(kinds.has("artifact_restore"));
  assert.ok(kinds.has("harness_comparison"));
  assert.ok(kinds.has("terminal_transcript"));
  assert.ok(
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.some(
      (record) => record.status === "draft",
    ),
  );
});

test("terminal transcript evidence is built only after admitted transcript closure", () => {
  const terminalAttach = {
    schema_version: "ioi.runtime.harness_session_terminal_attach.v1" as const,
    attach_id: "terminal-attach:test",
    decision: "admitted" as const,
    attach_state: "client_pty_attach_admitted" as const,
    attach_lane: "hypervisor_client_terminal_adapter" as const,
    spawn_id: "harness-session-spawn:test",
    readiness_id: "harness-session-readiness:test",
    launch_id: "harness-session-launch:test",
    session_binding_ref: "harness-session-binding:test",
    session_route_ref: "session-route:test",
    harness_selection_ref: "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id: "codex_cli" as const,
    model_configuration_ref: "model-config:qwen",
    model_route_ref: "model-route:local-qwen",
    model_name: "qwen",
    workspace_ref: "workspace:test",
    workspace_root: "/workspace",
    terminal_session_ref: "terminal-session:test",
    command_contract_ref: "harness-command:test",
    command_contract: {
      command_ref: "harness-command:test",
      binary_name: "codex",
      argv_template: [
        "codex",
        "--oss",
        "--model",
        "${HYPERVISOR_LOCAL_HARNESS_MODEL:-qwen}",
        "--cd",
        "${HYPERVISOR_SESSION_WORKSPACE}",
      ],
      resolved_argv: ["codex", "--oss", "--model", "qwen", "--cd", "/workspace"],
      resolved_command_line: "codex --oss --model qwen --cd /workspace",
      env_policy_ref: "env-policy:test",
      secret_release_policy: "none" as const,
      requires_pty: true as const,
      workspace_env: "HYPERVISOR_SESSION_WORKSPACE",
      model_env: "HYPERVISOR_LOCAL_HARNESS_MODEL",
      pty_transport: "hypervisor_client_terminal_adapter" as const,
      process_custody:
        "client_host_pty_after_daemon_spawn_admission" as const,
    },
    client_attach_contract: {
      root: ".",
      cols: 120,
      rows: 32,
      command_line: "codex --oss",
      requires_pty: true as const,
      launch_after_attach: true as const,
      initial_write: "codex --oss\n",
      transcript_stream_ref:
        "agentgres://trace/harness-terminal-transcript/test",
      pty_transport: "hypervisor_client_terminal_adapter" as const,
      process_custody:
        "client_host_pty_after_daemon_attach_admission" as const,
    },
    terminal_transcript_projection: {
      schema_version:
        "ioi.runtime.harness_terminal_transcript_projection.v1" as const,
      transcript_id: "harness-terminal-transcript:test",
      transcript_state: "streaming" as const,
      transcript_stream_ref:
        "agentgres://trace/harness-terminal-transcript/test",
      cursor: 7,
      lines: [
        {
          stream: "stdout" as const,
          text: "Codex ready\n",
          sequence: 1,
          terminal_session_ref: "terminal-session:test",
        },
      ],
      runtimeTruthSource: "daemon-runtime" as const,
    },
    workspace_mount_policy: "redacted_projection" as const,
    privacy_posture_ref: "privacy:redacted-projection",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_policy_ref: "receipt-policy:harness-adapter/default",
    receipt_refs: ["receipt://harness-session-terminal-attach/test"],
    agentgres_operation_refs: [
      "agentgres://operation/harness-session-terminal-attach/test",
    ],
    state_root:
      "agentgres://state-root/harness-session-terminal-attach/test",
    attached_at: "2026-06-19T00:00:00.000Z",
    requiresDaemonGate: true as const,
    runtimeTruthSource: "daemon-runtime" as const,
  };

  assert.equal(
    buildTerminalTranscriptReceiptEvidenceRecord({
      sessionRef: "session:test",
      terminalAttach,
    }),
    null,
  );

  const record = buildTerminalTranscriptReceiptEvidenceRecord({
    sessionRef: "session:test",
    terminalAttach: {
      ...terminalAttach,
      terminal_transcript_projection: {
        ...terminalAttach.terminal_transcript_projection,
        transcript_state: "closed" as const,
        cursor: 8,
      },
    },
  });

  assert.equal(record?.kind, "terminal_transcript");
  assert.match(
    record?.receipt_ref ?? "",
    /^receipt:\/\/hypervisor\/session-terminal-transcript\//,
  );
  assert.equal(
    record?.source_projection_ref,
    "agentgres://trace/harness-terminal-transcript/test",
  );
  assert.ok(
    record?.agentgres_operation_refs.includes(
      "agentgres://operation/harness-session-terminal-attach/test",
    ),
  );
  assert.match(record?.artifact_refs[0] ?? "", /^artifact:\/\//);
  assert.match(record?.state_root_ref ?? "", /^agentgres:\/\/state-root\//);
  assert.match(record?.replay_ref ?? "", /^agentgres:\/\/replay\//);
  assert.match(record?.summary ?? "", /cursor 8/);
});

test("receipt evidence normalization preserves daemon evidence boundaries", () => {
  const projection = normalizeHypervisorReceiptEvidenceProjection(
    {
      projection_id: "receipt-evidence:daemon/normalized",
      page_cursor: "cursor:receipt/current",
      next_page_cursor: "cursor:receipt/next",
      page_size: 10,
      has_more: true,
      receipt_boundary_invariant:
        "Agentgres admits receipt truth; clients render evidence.",
      records: [
        {
          receipt_ref: "receipt://daemon/session/normalized",
          kind: "session_lifecycle",
          summary: "Normalized session lifecycle receipt.",
          source_projection_ref: "session-operations:daemon/normalized",
          agentgres_operation_refs: [
            "agentgres://operation/session/normalized",
          ],
          artifact_refs: ["artifact://receipt-evidence/session/normalized"],
          trace_refs: ["trace://hypervisor/session/normalized"],
          state_root_ref: "agentgres://state-root/session/normalized",
          replay_ref: "agentgres://replay/session/normalized",
          status: "admitted",
        },
      ],
    },
    { source: "daemon-receipt-evidence-projection" },
  );

  assert.equal(projection.source, "daemon-receipt-evidence-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "receipt-evidence:daemon/normalized");
  assert.equal(projection.page_cursor, "cursor:receipt/current");
  assert.equal(projection.next_page_cursor, "cursor:receipt/next");
  assert.equal(projection.page_size, 10);
  assert.equal(projection.has_more, true);
  assert.equal(projection.records[0]?.receipt_ref, "receipt://daemon/session/normalized");
  assert.equal(projection.records[0]?.kind, "session_lifecycle");
  assert.deepEqual(projection.records[0]?.agentgres_operation_refs, [
    "agentgres://operation/session/normalized",
  ]);
});

test("receipt evidence normalization preserves empty daemon pages", () => {
  const projection = normalizeHypervisorReceiptEvidenceProjection(
    {
      projection_id: "receipt-evidence:daemon/empty-page",
      page_cursor: "cursor:receipt/page-2",
      next_page_cursor: null,
      page_size: 25,
      has_more: false,
      records: [],
    },
    { source: "daemon-receipt-evidence-projection" },
  );

  assert.equal(projection.projection_id, "receipt-evidence:daemon/empty-page");
  assert.equal(projection.records.length, 0);
  assert.equal(projection.page_cursor, "cursor:receipt/page-2");
  assert.equal(projection.next_page_cursor, null);
  assert.equal(projection.page_size, 25);
  assert.equal(projection.has_more, false);
});

test("receipt evidence loader calls the daemon projection route with project, session, and page refs", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorReceiptEvidenceProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    sessionRef: "session:ioi",
    pageCursor: "cursor:receipt/next",
    pageSize: 10,
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "receipt-evidence:daemon/loaded",
            page_cursor: "cursor:receipt/next",
            next_page_cursor: null,
            page_size: 10,
            has_more: false,
            records: [
              {
                receipt_ref: "receipt://loaded/session",
                kind: "session_lifecycle",
                summary: "Loaded receipt evidence.",
                source_projection_ref: "session-operations:daemon/loaded",
                agentgres_operation_refs: ["agentgres://operation/loaded/session"],
                artifact_refs: ["artifact://receipt-evidence/loaded/session"],
                trace_refs: ["trace://hypervisor/loaded/session"],
                state_root_ref: "agentgres://state-root/loaded/session",
                replay_ref: "agentgres://replay/loaded/session",
                status: "admitted",
              },
            ],
          });
        },
      };
    },
  });

  assert.deepEqual(calls, [
    {
      input:
        `http://daemon.test${HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH}?project_id=project%3Aioi&session_ref=session%3Aioi&page_cursor=cursor%3Areceipt%2Fnext&page_size=10`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-receipt-evidence-projection");
  assert.equal(projection.projection_id, "receipt-evidence:daemon/loaded");
  assert.equal(projection.page_cursor, "cursor:receipt/next");
  assert.equal(projection.page_size, 10);
  assert.equal(projection.records[0]?.receipt_ref, "receipt://loaded/session");
});
