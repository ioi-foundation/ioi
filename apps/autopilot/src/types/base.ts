export type ExecutionMode = "local" | "session" | "settlement";

export type LiabilityLevel = "none" | "auditable" | "insured" | "proven";

export interface ChatMessage {
  role: string;
  text: string;
  timestamp: number;
}

export type JsonRecord = Record<string, unknown>;
