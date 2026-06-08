export const WORKFLOW_AUTHORITY_BOUNDARY_VISUALIZER_SCHEMA_VERSION =
  "ioi.workflow.authority-boundary-visualizer.v1" as const;

export interface WorkflowAuthorityBoundaryVisualizerInput {
  sandboxProof: Record<string, unknown>;
}

export interface WorkflowAuthorityBoundaryZone {
  zoneKind: "workspace" | "outside_workspace" | "network" | "environment" | "computer_use";
  status: "allowed" | "denied" | "scrubbed" | "approval_required";
  label: string;
  path: string | null;
  authorityScope: string | null;
  evidence: string[];
}

export interface WorkflowAuthorityBoundaryVisualizer {
  schemaVersion: typeof WORKFLOW_AUTHORITY_BOUNDARY_VISUALIZER_SCHEMA_VERSION;
  status: "ready" | "blocked";
  workspaceRoot: string | null;
  outsideRoot: string | null;
  deniedZoneCount: number;
  approvalRequiredCount: number;
  scrubbedZoneCount: number;
  zones: WorkflowAuthorityBoundaryZone[];
}

export function buildWorkflowAuthorityBoundaryVisualizer(
  input: WorkflowAuthorityBoundaryVisualizerInput,
): WorkflowAuthorityBoundaryVisualizer {
  const proof = objectValue(input.sandboxProof) ?? {};
  const results = objectField(proof, "results");
  const checks = objectField(proof, "checks");
  const zones = [
    {
      zoneKind: "workspace",
      status: "allowed",
      label: "Workspace writes stay inside canonical workspace root",
      path: stringField(proof, "workspace_root"),
      authorityScope: "scope:workspace.write",
      evidence: ["resolveWorkspacePath", "workspace_canonical_root"],
    },
    {
      zoneKind: "outside_workspace",
      status: booleanField(checks, "absolute_path_escape_denied") ? "denied" : "allowed",
      label: "Absolute outside path",
      path: stringField(proof, "outside_root"),
      authorityScope: "scope:workspace.write.denied",
      evidence: [stringField(objectField(results, "absolute_escape"), "error_code")],
    },
    {
      zoneKind: "outside_workspace",
      status: booleanField(checks, "symlink_read_escape_denied") ? "denied" : "allowed",
      label: "Symlink read escape",
      path: stringField(objectField(results, "symlink_read_escape"), "resolved_path"),
      authorityScope: "scope:workspace.read.denied",
      evidence: [stringField(objectField(results, "symlink_read_escape"), "error_code")],
    },
    {
      zoneKind: "outside_workspace",
      status: booleanField(checks, "symlink_write_escape_denied") ? "denied" : "allowed",
      label: "Symlink write escape",
      path: stringField(proof, "outside_root"),
      authorityScope: "scope:workspace.write.denied",
      evidence: [
        stringField(objectField(results, "symlink_write_escape"), "error_code"),
        booleanField(objectField(results, "symlink_write_escape"), "outside_content_preserved")
          ? "outside_content_preserved"
          : null,
      ],
    },
    {
      zoneKind: "network",
      status: booleanField(checks, "disallowed_shell_network_command_denied") ? "denied" : "allowed",
      label: "Default shell network posture",
      path: null,
      authorityScope: "network.default.denied",
      evidence: [stringField(objectField(results, "disallowed_shell"), "error_code")],
    },
    {
      zoneKind: "environment",
      status: booleanField(checks, "secret_env_filtered_from_subprocess") ? "scrubbed" : "allowed",
      label: "Secret-shaped subprocess environment",
      path: null,
      authorityScope: "env.secret.redacted",
      evidence: ["secret_value_absent_from_test_run_result"],
    },
    {
      zoneKind: "computer_use",
      status: booleanField(checks, "computer_use_act_requires_approval_before_execution")
        ? "approval_required"
        : "allowed",
      label: "Computer-use action authority",
      path: null,
      authorityScope: stringField(objectField(results, "computer_use_act_lease"), "authority_scope"),
      evidence: [stringField(objectField(results, "computer_use_act_lease"), "request_ref")],
    },
  ] satisfies Array<Omit<WorkflowAuthorityBoundaryZone, "evidence"> & { evidence: unknown[] }>;
  const normalizedZones: WorkflowAuthorityBoundaryZone[] = zones.map((zone) => ({
    ...zone,
    evidence: uniqueStrings(zone.evidence),
  }));
  const deniedZoneCount = normalizedZones.filter((zone) => zone.status === "denied").length;
  const approvalRequiredCount = normalizedZones.filter((zone) => zone.status === "approval_required").length;
  const scrubbedZoneCount = normalizedZones.filter((zone) => zone.status === "scrubbed").length;
  return {
    schemaVersion: WORKFLOW_AUTHORITY_BOUNDARY_VISUALIZER_SCHEMA_VERSION,
    status:
      deniedZoneCount >= 3 && approvalRequiredCount >= 1 && scrubbedZoneCount >= 1
        ? "ready"
        : "blocked",
    workspaceRoot: stringField(proof, "workspace_root"),
    outsideRoot: stringField(proof, "outside_root"),
    deniedZoneCount,
    approvalRequiredCount,
    scrubbedZoneCount,
    zones: normalizedZones,
  };
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function objectField(record: unknown, key: string): Record<string, unknown> {
  const object = objectValue(record);
  return objectValue(object?.[key]) ?? {};
}

function stringField(record: unknown, key: string): string | null {
  const object = objectValue(record);
  const value = object?.[key];
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function booleanField(record: unknown, key: string): boolean {
  const object = objectValue(record);
  return object?.[key] === true;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (value === undefined || value === null ? null : String(value).trim()))
        .filter((value): value is string => Boolean(value)),
    ),
  );
}
