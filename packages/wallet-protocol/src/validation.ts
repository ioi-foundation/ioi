import type {
  CandidateEvidence,
  ExchangeIntent,
  RiskCoverageState,
  TradeIntent,
} from "./types.js";

export const EXECUTABLE_COVERAGE_STATES: readonly RiskCoverageState[] = [
  "assessed",
] as const;

const INTENT_CANDIDATE_EVIDENCE_MISSING_CODES = {
  exchange: "exchange_intent_candidate_evidence_missing",
  trade: "trade_intent_candidate_evidence_missing",
} as const;

const INTENT_CANDIDATE_EVIDENCE_MISMATCH_CODES = {
  exchange: "exchange_intent_candidate_evidence_mismatch",
  trade: "trade_intent_candidate_evidence_mismatch",
} as const;

export interface WalletProtocolValidationIssue {
  readonly code: string;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export class WalletProtocolValidationError extends Error {
  readonly code: string;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(issue: WalletProtocolValidationIssue) {
    super(issue.message);
    this.name = "WalletProtocolValidationError";
    this.code = issue.code;
    this.details = issue.details;
  }
}

export interface CandidateEvidenceValidationOptions {
  readonly now?: string | Date;
  readonly require_assessed?: boolean;
  readonly require_not_expired?: boolean;
}

export function assertCandidateEvidenceExecutable(
  evidence: CandidateEvidence,
  options: CandidateEvidenceValidationOptions = {},
): CandidateEvidence {
  assertCandidateEvidenceShape(evidence);
  if (options.require_assessed ?? true) {
    if (!EXECUTABLE_COVERAGE_STATES.includes(evidence.coverage_state)) {
      throwValidationError({
        code: "candidate_evidence_not_executable",
        message:
          "Candidate evidence must be assessed before it can support executable exchange or trade intent approval.",
        details: {
          candidate_id: evidence.candidate_id,
          coverage_state: evidence.coverage_state,
        },
      });
    }
  }
  if (options.require_not_expired ?? true) {
    assertCandidateEvidenceNotExpired(evidence, options.now);
  }
  return evidence;
}

export function assertExchangeIntentCandidateEvidence(
  intent: ExchangeIntent,
  options: CandidateEvidenceValidationOptions = {},
): ExchangeIntent {
  assertIntentCandidateEvidence({
    domain: "exchange",
    expectedCandidateId: intent.route_candidate_id,
    evidence: intent.candidate_evidence,
    options,
  });
  return intent;
}

export function assertTradeIntentCandidateEvidence(
  intent: TradeIntent,
  options: CandidateEvidenceValidationOptions = {},
): TradeIntent {
  assertIntentCandidateEvidence({
    domain: "trade",
    expectedCandidateId: intent.venue_candidate_id,
    evidence: intent.candidate_evidence,
    options,
  });
  return intent;
}

function assertIntentCandidateEvidence({
  domain,
  expectedCandidateId,
  evidence,
  options,
}: {
  readonly domain: "exchange" | "trade";
  readonly expectedCandidateId: string;
  readonly evidence: readonly CandidateEvidence[];
  readonly options: CandidateEvidenceValidationOptions;
}) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    throwValidationError({
      code: INTENT_CANDIDATE_EVIDENCE_MISSING_CODES[domain],
      message:
        "Exchange and trade intents must bind the candidate evidence they approve.",
      details: { expected_candidate_id: expectedCandidateId },
    });
  }
  const matching = evidence.find(
    (candidate) => candidate.candidate_id === expectedCandidateId,
  );
  if (!matching) {
    throwValidationError({
      code: INTENT_CANDIDATE_EVIDENCE_MISMATCH_CODES[domain],
      message:
        "Intent candidate evidence must include the exact selected candidate id.",
      details: {
        expected_candidate_id: expectedCandidateId,
        candidate_ids: evidence.map((candidate) => candidate.candidate_id),
      },
    });
  }
  for (const candidate of evidence) {
    assertCandidateEvidenceExecutable(candidate, options);
  }
}

function assertCandidateEvidenceShape(evidence: CandidateEvidence) {
  const requiredStringFields = [
    "candidate_id",
    "source",
    "adapter_id",
    "observed_at",
    "expires_at",
    "coverage_state",
  ] as const;
  for (const field of requiredStringFields) {
    if (!nonEmptyString(evidence[field])) {
      throwValidationError({
        code: "candidate_evidence_field_missing",
        message: "Candidate evidence is missing a required string field.",
        details: { field },
      });
    }
  }
  if (!Array.isArray(evidence.evidence_refs) || evidence.evidence_refs.length === 0) {
    throwValidationError({
      code: "candidate_evidence_refs_missing",
      message: "Candidate evidence must include evidence refs.",
      details: { candidate_id: evidence.candidate_id },
    });
  }
  if (!Array.isArray(evidence.risk_labels)) {
    throwValidationError({
      code: "candidate_evidence_risk_labels_missing",
      message: "Candidate evidence must include risk labels.",
      details: { candidate_id: evidence.candidate_id },
    });
  }
  if (!evidence.claims || typeof evidence.claims !== "object") {
    throwValidationError({
      code: "candidate_evidence_claims_missing",
      message: "Candidate evidence must include source claims.",
      details: { candidate_id: evidence.candidate_id },
    });
  }
}

function assertCandidateEvidenceNotExpired(
  evidence: CandidateEvidence,
  now: string | Date | undefined,
) {
  const expiresAtMs = Date.parse(evidence.expires_at);
  if (!Number.isFinite(expiresAtMs)) {
    throwValidationError({
      code: "candidate_evidence_expiry_invalid",
      message: "Candidate evidence expires_at must be a valid timestamp.",
      details: {
        candidate_id: evidence.candidate_id,
        expires_at: evidence.expires_at,
      },
    });
  }
  const nowMs =
    now instanceof Date
      ? now.getTime()
      : typeof now === "string"
        ? Date.parse(now)
        : Date.now();
  if (Number.isFinite(nowMs) && expiresAtMs <= nowMs) {
    throwValidationError({
      code: "candidate_evidence_expired",
      message: "Candidate evidence is expired and cannot support execution.",
      details: {
        candidate_id: evidence.candidate_id,
        expires_at: evidence.expires_at,
      },
    });
  }
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function throwValidationError(issue: WalletProtocolValidationIssue): never {
  throw new WalletProtocolValidationError(issue);
}
