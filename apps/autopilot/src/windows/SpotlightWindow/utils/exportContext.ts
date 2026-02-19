import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

interface ExportContextOptions {
  threadId: string;
  includeArtifactPayloads?: boolean;
}

function formatIsoForFilename(timestamp: string): string {
  return timestamp.replace(/[:]/g, "-").replace(/\.\d+Z$/, "Z");
}

function buildDefaultFilename(threadId: string): string {
  const shortId = threadId.slice(0, 8) || "thread";
  const stamp = formatIsoForFilename(new Date().toISOString());
  return `autopilot-run-${shortId}-${stamp}.zip`;
}

async function notifySuccess(exportedPath: string): Promise<void> {
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    if (granted) {
      await sendNotification({
        title: "Context Export Complete",
        body: exportedPath,
      });
    }
  } catch {
    // Notification is best-effort; export still succeeds.
  }
}

export async function exportThreadContextBundle({
  threadId,
  includeArtifactPayloads = true,
}: ExportContextOptions): Promise<string | null> {
  const outputPath = await save({
    title: "Export Autopilot Run Context",
    defaultPath: buildDefaultFilename(threadId),
    filters: [{ name: "Zip Archive", extensions: ["zip"] }],
  });

  if (!outputPath) {
    return null;
  }

  const exportedPath = await invoke<string>("export_thread_bundle", {
    threadId,
    thread_id: threadId,
    outputPath,
    output_path: outputPath,
    includeArtifactPayloads,
    include_artifact_payloads: includeArtifactPayloads,
  });

  await notifySuccess(exportedPath);
  return exportedPath;
}
