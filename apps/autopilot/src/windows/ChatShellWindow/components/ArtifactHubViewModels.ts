export interface KernelLogRow {
  eventId: string;
  timestamp: string;
  title: string;
  eventType: string;
  status: string;
  toolName: string;
  summary: string;
}

export interface SecurityPolicyRow {
  eventId: string;
  timestamp: string;
  decision: string;
  toolName: string;
  stage: string;
  resolution: string;
  summary: string;
  reportArtifactId: string | null;
}

export interface SubstrateReceiptRow {
  eventId: string;
  timestamp: string;
  stepIndex: number;
  toolName: string;
  queryHash: string;
  indexRoot: string;
  k: number;
  efSearch: number;
  candidateLimit: number;
  candidateTotal: number;
  candidateReranked: number;
  candidateTruncated: boolean;
  distanceMetric: string;
  embeddingNormalized: boolean;
  proofHash?: string;
  proofRef?: string;
  certificateMode?: string;
  success: boolean;
  errorClass?: string;
}
