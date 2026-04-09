import { invoke } from "@tauri-apps/api/core";
import { useCallback, useState } from "react";
import type { VoiceInputTranscriptionResult } from "../../../types";

export type SpotlightVoiceInputStatus =
  | "idle"
  | "reading"
  | "transcribing"
  | "ready"
  | "error";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

export function useSpotlightVoiceInput() {
  const [status, setStatus] = useState<SpotlightVoiceInputStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VoiceInputTranscriptionResult | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);

  const reset = useCallback(() => {
    setStatus("idle");
    setError(null);
    setResult(null);
    setFileName(null);
  }, []);

  const transcribeFile = useCallback(async (file: File, language?: string | null) => {
    setStatus("reading");
    setError(null);
    setFileName(file.name);

    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const audioBase64 = bytesToBase64(bytes);
      setStatus("transcribing");
      const nextResult = await invoke<VoiceInputTranscriptionResult>(
        "transcribe_voice_input",
        {
          request: {
            audioBase64,
            mimeType: file.type || "audio/webm",
            fileName: file.name,
            language: language ?? null,
          },
        },
      );
      setResult(nextResult);
      setStatus("ready");
      return nextResult;
    } catch (nextError) {
      const message =
        nextError instanceof Error ? nextError.message : String(nextError ?? "");
      setResult(null);
      setStatus("error");
      setError(message);
      throw nextError;
    }
  }, []);

  return {
    status,
    error,
    result,
    fileName,
    reset,
    transcribeFile,
  };
}
