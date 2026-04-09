import type { SpotlightVoiceInputStatus } from "../hooks/useSpotlightVoiceInput";
import type { VoiceInputTranscriptionResult } from "../../../types";

export type VoiceOverviewTone = "ready" | "setup" | "attention";

export interface VoiceOverview {
  tone: VoiceOverviewTone;
  statusLabel: string;
  statusDetail: string;
}

export function buildVoiceOverview(input: {
  status: SpotlightVoiceInputStatus;
  fileName: string | null;
  error: string | null;
  result: VoiceInputTranscriptionResult | null;
}): VoiceOverview {
  if (input.status === "error") {
    return {
      tone: "attention",
      statusLabel: "Voice transcription failed",
      statusDetail:
        input.error ||
        "The selected audio clip could not be transcribed by the shared runtime.",
    };
  }

  if (input.status === "ready" && input.result) {
    return {
      tone: "ready",
      statusLabel: "Transcript ready",
      statusDetail: input.fileName
        ? `${input.fileName} was transcribed through the shared runtime and is ready for the composer.`
        : "The latest audio clip was transcribed through the shared runtime and is ready for the composer.",
    };
  }

  if (input.status === "reading" || input.status === "transcribing") {
    return {
      tone: "setup",
      statusLabel: "Transcribing audio",
      statusDetail: input.fileName
        ? `Preparing ${input.fileName} for shared-runtime transcription.`
        : "Preparing the selected audio clip for shared-runtime transcription.",
    };
  }

  return {
    tone: "setup",
    statusLabel: "Voice input ready",
    statusDetail:
      "Choose an audio clip to transcribe it through the shared runtime and seed the transcript back into the composer.",
  };
}
