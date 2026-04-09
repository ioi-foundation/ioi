import type {
  SessionRemoteEnvBinding,
  SessionRemoteEnvSnapshot,
} from "../../../types";

export type RemoteEnvDiffTone = "ready" | "review" | "setup";

export interface RemoteEnvDiffEntry {
  key: string;
  sourceLabels: string[];
  valuePreviews: string[];
}

export interface RemoteEnvDiffOverview {
  tone: RemoteEnvDiffTone;
  statusLabel: string;
  statusDetail: string;
  meta: string[];
  overlappingBindings: RemoteEnvDiffEntry[];
}

function groupedOverlaps(
  bindings: SessionRemoteEnvBinding[],
): RemoteEnvDiffEntry[] {
  const groups = new Map<
    string,
    { sourceLabels: Set<string>; valuePreviews: Set<string> }
  >();

  bindings.forEach((binding) => {
    const existing = groups.get(binding.key) ?? {
      sourceLabels: new Set<string>(),
      valuePreviews: new Set<string>(),
    };
    existing.sourceLabels.add(binding.sourceLabel);
    existing.valuePreviews.add(binding.valuePreview);
    groups.set(binding.key, existing);
  });

  return [...groups.entries()]
    .filter(([, group]) => group.sourceLabels.size > 1)
    .map(([key, group]) => ({
      key,
      sourceLabels: [...group.sourceLabels].sort(),
      valuePreviews: [...group.valuePreviews],
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

export function buildRemoteEnvDiffOverview(
  snapshot: SessionRemoteEnvSnapshot | null,
): RemoteEnvDiffOverview {
  if (!snapshot || snapshot.bindings.length === 0) {
    return {
      tone: "setup",
      statusLabel: "No remote env bindings retained",
      statusDetail:
        "Open a retained session before reviewing source drift between the control plane and runtime process environment.",
      meta: ["0 control-plane", "0 process", "0 overlapping keys"],
      overlappingBindings: [],
    };
  }

  const overlappingBindings = groupedOverlaps(snapshot.bindings);
  const meta = [
    `${snapshot.controlPlaneBindingCount} control-plane`,
    `${snapshot.processBindingCount} process`,
    `${overlappingBindings.length} overlapping keys`,
  ];

  if (overlappingBindings.length > 0) {
    return {
      tone: "review",
      statusLabel: "Binding drift detected",
      statusDetail:
        "Some environment keys are present in both the local engine control plane and the runtime process. Review the paired values before relying on remote continuity or provider posture.",
      meta,
      overlappingBindings,
    };
  }

  if (snapshot.secretBindingCount > 0 || snapshot.redactedBindingCount > 0) {
    return {
      tone: "review",
      statusLabel: "Secrets redacted, no source drift",
      statusDetail:
        "The current environment posture still includes secret bindings, but no control-plane versus process drift is visible in the retained projection.",
      meta,
      overlappingBindings,
    };
  }

  return {
    tone: "ready",
    statusLabel: "Sources aligned",
    statusDetail:
      "The retained projection does not show any control-plane versus process binding drift for the current session scope.",
    meta,
    overlappingBindings,
  };
}
