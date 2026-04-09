import assert from "node:assert/strict";
import {
  buildTraceBundleDefaultFilename,
  traceBundleExportPreset,
} from "./traceBundleExportModel.ts";

function presetDefaultsMatchExpectedSharePosture(): void {
  const tracePreset = traceBundleExportPreset("trace_bundle");
  const sharePreset = traceBundleExportPreset("operator_share");
  const redactedPreset = traceBundleExportPreset("redacted_share");

  assert.equal(tracePreset.includeArtifactPayloads, true);
  assert.equal(tracePreset.filenamePrefix, "autopilot-trace");

  assert.equal(sharePreset.includeArtifactPayloads, true);
  assert.equal(sharePreset.filenamePrefix, "autopilot-share");
  assert.equal(sharePreset.dialogTitle, "Export Operator Evidence Pack");

  assert.equal(redactedPreset.includeArtifactPayloads, false);
  assert.equal(redactedPreset.filenamePrefix, "autopilot-share-redacted");
  assert.equal(redactedPreset.notificationTitle, "Redacted Review Pack Ready");
}

function defaultFilenameUsesPresetPrefixAndThreadId(): void {
  const filename = buildTraceBundleDefaultFilename(
    "session-abcdef1234567890",
    "autopilot-share",
  );

  assert.match(
    filename,
    /^autopilot-share-session--\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.zip$/,
  );
}

presetDefaultsMatchExpectedSharePosture();
defaultFilenameUsesPresetPrefixAndThreadId();
