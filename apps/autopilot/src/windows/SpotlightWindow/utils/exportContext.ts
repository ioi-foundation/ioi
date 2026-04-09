import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import {
  buildTraceBundleDefaultFilename,
  traceBundleExportPreset,
  type TraceBundleExportVariant,
} from "./traceBundleExportModel";

interface ExportContextOptions {
  threadId: string;
  includeArtifactPayloads?: boolean;
  variant?: TraceBundleExportVariant;
  dialogTitle?: string;
  filenamePrefix?: string;
}

async function notifySuccess(
  exportedPath: string,
  title: string,
): Promise<void> {
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    if (granted) {
      await sendNotification({
        title,
        body: exportedPath,
      });
    }
  } catch {
    // Notification is best-effort; export still succeeds.
  }
}

export async function exportThreadTraceBundle({
  threadId,
  includeArtifactPayloads,
  variant = "trace_bundle",
  dialogTitle,
  filenamePrefix,
}: ExportContextOptions): Promise<string | null> {
  const preset = traceBundleExportPreset(variant);
  const effectiveIncludeArtifactPayloads =
    includeArtifactPayloads ?? preset.includeArtifactPayloads;
  const outputPath = await save({
    title: dialogTitle ?? preset.dialogTitle,
    defaultPath: buildTraceBundleDefaultFilename(
      threadId,
      filenamePrefix ?? preset.filenamePrefix,
    ),
    filters: [{ name: "Zip Archive", extensions: ["zip"] }],
  });

  if (!outputPath) {
    return null;
  }

  const exportedPath = await invoke<string>("export_trace_bundle", {
    threadId,
    thread_id: threadId,
    outputPath,
    output_path: outputPath,
    includeArtifactPayloads: effectiveIncludeArtifactPayloads,
    include_artifact_payloads: effectiveIncludeArtifactPayloads,
  });

  await notifySuccess(exportedPath, preset.notificationTitle);
  return exportedPath;
}
