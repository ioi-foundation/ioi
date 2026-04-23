export type TraceBundleExportVariant =
  | "trace_bundle"
  | "operator_share"
  | "redacted_share";

export interface TraceBundleExportPreset {
  variant: TraceBundleExportVariant;
  dialogTitle: string;
  filenamePrefix: string;
  includeArtifactPayloads: boolean;
  notificationTitle: string;
}

export function traceBundleExportVariantLabel(
  variant?: TraceBundleExportVariant | null,
): string | null {
  switch (variant) {
    case "operator_share":
      return "Operator evidence pack";
    case "redacted_share":
      return "Redacted review pack";
    case "trace_bundle":
      return "Canonical trace bundle";
    default:
      return null;
  }
}

function formatIsoForFilename(timestamp: string): string {
  return timestamp.replace(/[:]/g, "-").replace(/\.\d+Z$/, "Z");
}

export function buildTraceBundleDefaultFilename(
  threadId: string,
  filenamePrefix: string,
): string {
  const shortId = threadId.slice(0, 8) || "thread";
  const stamp = formatIsoForFilename(new Date().toISOString());
  return `${filenamePrefix}-${shortId}-${stamp}.zip`;
}

export function traceBundleExportPreset(
  variant: TraceBundleExportVariant = "trace_bundle",
): TraceBundleExportPreset {
  switch (variant) {
    case "operator_share":
      return {
        variant,
        dialogTitle: "Export Operator Evidence Pack",
        filenamePrefix: "autopilot-share",
        includeArtifactPayloads: true,
        notificationTitle: "Operator Evidence Pack Ready",
      };
    case "redacted_share":
      return {
        variant,
        dialogTitle: "Export Redacted Review Pack",
        filenamePrefix: "autopilot-share-redacted",
        includeArtifactPayloads: false,
        notificationTitle: "Redacted Review Pack Ready",
      };
    case "trace_bundle":
    default:
      return {
        variant: "trace_bundle",
        dialogTitle: "Export Canonical Trace Bundle",
        filenamePrefix: "autopilot-trace",
        includeArtifactPayloads: true,
        notificationTitle: "Trace Bundle Export Complete",
      };
  }
}
