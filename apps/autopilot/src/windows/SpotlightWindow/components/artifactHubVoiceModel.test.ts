import assert from "node:assert/strict";
import { buildVoiceOverview } from "./artifactHubVoiceModel.ts";

{
  const overview = buildVoiceOverview({
    status: "idle",
    fileName: null,
    error: null,
    result: null,
  });

  assert.equal(overview.tone, "setup");
  assert.equal(overview.statusLabel, "Voice input ready");
}

{
  const overview = buildVoiceOverview({
    status: "transcribing",
    fileName: "meeting-note.wav",
    error: null,
    result: null,
  });

  assert.equal(overview.tone, "setup");
  assert.match(overview.statusDetail, /meeting-note\.wav/);
}

{
  const overview = buildVoiceOverview({
    status: "ready",
    fileName: "meeting-note.wav",
    error: null,
    result: {
      text: "Ship the patch after the smoke test passes.",
      mimeType: "audio/wav",
      fileName: "meeting-note.wav",
      language: "en",
      modelId: "voice-test-runtime",
    },
  });

  assert.equal(overview.tone, "ready");
  assert.equal(overview.statusLabel, "Transcript ready");
}

{
  const overview = buildVoiceOverview({
    status: "error",
    fileName: "meeting-note.wav",
    error: "runtime offline",
    result: null,
  });

  assert.equal(overview.tone, "attention");
  assert.equal(overview.statusLabel, "Voice transcription failed");
}
