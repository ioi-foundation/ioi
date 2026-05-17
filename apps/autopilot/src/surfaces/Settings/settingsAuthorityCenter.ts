import type {
  AuthorityCenterCapabilityRow,
  AuthorityCenterProjection,
} from "../Policy/authorityCenter";

export interface SettingsAuthorityCenterSummary {
  tone: "ready" | "warning" | "blocked" | "idle";
  label: string;
  detail: string;
  checklist: string[];
  topCapabilities: AuthorityCenterCapabilityRow[];
  failClosedReasons: string[];
}

export function summarizeSettingsAuthorityCenter(
  projection: AuthorityCenterProjection,
): SettingsAuthorityCenterSummary {
  const blocked = projection.summary.blockedCapabilities;
  const ready = projection.summary.readyCapabilities;
  const total = projection.capabilities.length;
  const tone =
    projection.status === "blocked"
      ? "blocked"
      : projection.status === "degraded"
        ? "warning"
        : projection.status === "ready"
          ? "ready"
          : "idle";
  const label =
    tone === "ready"
      ? "Runtime-ready"
      : tone === "blocked"
        ? "Fail-closed"
        : tone === "warning"
          ? "Needs review"
          : "Unavailable";
  const detail =
    tone === "ready"
      ? "Settings, Policy, Workflow Composer, and runtime runs are reading the same capability and authority projection."
      : (projection.blockers[0] ??
        "No canonical authority projection has been returned by the runtime yet.");
  const failClosedReasons = [
    ...projection.blockers,
    ...projection.capabilities
      .filter(
        (capability) =>
          capability.tone === "blocked" ||
          capability.grantStatus === "missing" ||
          capability.grantStatus === "partial" ||
          capability.policyStatus === "unbound" ||
          capability.receiptStatus === "missing",
      )
      .map(
        (capability) =>
          `${capability.label}: ${capability.readinessSummary}`,
      ),
  ];

  return {
    tone,
    label,
    detail,
    checklist: [
      `${ready}/${total} capabilities ready`,
      `${blocked} capability blocker${blocked === 1 ? "" : "s"}`,
      `${projection.summary.activeGrants} active grant${projection.summary.activeGrants === 1 ? "" : "s"}`,
      `${projection.summary.vaultRefs} vault ref${projection.summary.vaultRefs === 1 ? "" : "s"}`,
      `${projection.summary.policyOverrides} policy override${projection.summary.policyOverrides === 1 ? "" : "s"}`,
    ],
    topCapabilities: projection.capabilities.slice(0, 8),
    failClosedReasons,
  };
}
