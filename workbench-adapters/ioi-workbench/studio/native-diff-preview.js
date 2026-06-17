"use strict";

function createStudioNativeDiffPreview({
  appendStudioTimeline,
  crypto,
  getStudioRuntimeProjection,
  vscode,
}) {
  let studioDiffProviderDisposable = null;
  const studioDiffDocuments = new Map();

  function ensureStudioDiffProvider(context) {
    if (studioDiffProviderDisposable || !context) {
      return;
    }
    studioDiffProviderDisposable = vscode.workspace.registerTextDocumentContentProvider("ioi-studio-diff", {
      provideTextDocumentContent(uri) {
        return studioDiffDocuments.get(uri.toString()) || "";
      },
    });
    context.subscriptions.push(studioDiffProviderDisposable);
  }

  async function openStudioNativeDiffPreview(hunk, output) {
    try {
      const suffix = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}`;
      const fileName = String(hunk?.file || "agent-studio-preview.md").replace(/[^a-z0-9_.-]+/gi, "-");
      const beforeUri = vscode.Uri.parse(`ioi-studio-diff:/${fileName}.${suffix}.before.md`);
      const afterUri = vscode.Uri.parse(`ioi-studio-diff:/${fileName}.${suffix}.after.md`);
      const beforeText = String(hunk?.beforeContent || hunk?.before || "Studio runtime cockpit preview before\n");
      const afterText = String(hunk?.afterContent || hunk?.after || "Studio runtime cockpit preview after\n");
      studioDiffDocuments.set(beforeUri.toString(), beforeText);
      studioDiffDocuments.set(afterUri.toString(), afterText);
      await vscode.commands.executeCommand("vscode.diff", beforeUri, afterUri, `Autopilot Studio Patch Preview: ${fileName}`, {
        preview: true,
        preserveFocus: true,
      });
      getStudioRuntimeProjection().runtimeCockpit.inlineDiffOverlayObserved = true;
      appendStudioTimeline("Native diff overlay opened", fileName, "completed");
      return true;
    } catch (error) {
      appendStudioTimeline("Native diff overlay blocked", error?.message || String(error), "blocked");
      output?.appendLine?.(`[ioi-studio] native diff overlay unavailable: ${error?.message || String(error)}`);
      return false;
    }
  }

  return {
    ensureStudioDiffProvider,
    openStudioNativeDiffPreview,
  };
}

module.exports = {
  createStudioNativeDiffPreview,
};
