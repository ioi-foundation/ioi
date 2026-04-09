import assert from "node:assert/strict";
import type { SessionRemoteEnvSnapshot } from "../../../types.ts";
import { buildRemoteEnvDiffOverview } from "./artifactHubRemoteEnvModel.ts";

function snapshot(
  overrides: Partial<SessionRemoteEnvSnapshot> = {},
): SessionRemoteEnvSnapshot {
  return {
    generatedAtMs: 1,
    sessionId: "session-1",
    workspaceRoot: "/repo",
    focusedScopeLabel: "Remote runtime",
    governingSourceLabel: "Runtime",
    postureLabel: "Read-only environment projection",
    postureDetail: "Inspect remote bindings.",
    bindingCount: 2,
    controlPlaneBindingCount: 1,
    processBindingCount: 1,
    overlappingBindingCount: 0,
    secretBindingCount: 0,
    redactedBindingCount: 0,
    notes: [],
    bindings: [],
    ...overrides,
  };
}

{
  const overview = buildRemoteEnvDiffOverview(null);
  assert.equal(overview.tone, "setup");
  assert.equal(overview.statusLabel, "No remote env bindings retained");
}

{
  const overview = buildRemoteEnvDiffOverview(
    snapshot({
      bindingCount: 3,
      controlPlaneBindingCount: 1,
      processBindingCount: 2,
      overlappingBindingCount: 1,
      bindings: [
        {
          key: "OPENAI_API_KEY",
          valuePreview: "Present (redacted)",
          sourceLabel: "Local engine control plane",
          scopeLabel: "Provider auth",
          provenanceLabel: "Configured secret binding",
          secret: true,
          redacted: true,
        },
        {
          key: "OPENAI_API_KEY",
          valuePreview: "Present (redacted)",
          sourceLabel: "Runtime process",
          scopeLabel: "Provider auth",
          provenanceLabel: "Process secret",
          secret: true,
          redacted: true,
        },
        {
          key: "TZ",
          valuePreview: "UTC",
          sourceLabel: "Runtime process",
          scopeLabel: "Shell process",
          provenanceLabel: "Shell/runtime environment",
          secret: false,
          redacted: false,
        },
      ],
    }),
  );

  assert.equal(overview.tone, "review");
  assert.equal(overview.statusLabel, "Binding drift detected");
  assert.equal(overview.overlappingBindings.length, 1);
  assert.equal(overview.overlappingBindings[0]?.key, "OPENAI_API_KEY");
}

{
  const overview = buildRemoteEnvDiffOverview(
    snapshot({
      secretBindingCount: 1,
      redactedBindingCount: 1,
      bindings: [
        {
          key: "OPENAI_API_KEY",
          valuePreview: "Present (redacted)",
          sourceLabel: "Runtime process",
          scopeLabel: "Provider auth",
          provenanceLabel: "Process secret",
          secret: true,
          redacted: true,
        },
      ],
    }),
  );

  assert.equal(overview.tone, "review");
  assert.equal(overview.statusLabel, "Secrets redacted, no source drift");
}
