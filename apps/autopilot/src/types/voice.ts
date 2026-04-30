export interface VoiceInputTranscriptionResult {
  text: string;
  mimeType: string;
  fileName?: string | null;
  language?: string | null;
  modelId?: string | null;
}
