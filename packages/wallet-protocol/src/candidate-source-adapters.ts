import {
  assertCandidateEvidenceExecutable,
  type CandidateEvidenceValidationOptions,
} from "./validation.js";
import type {
  CandidateEvidence,
  RiskCoverageState,
  WalletCandidateSourceAdapter,
} from "./types.js";

export interface BuildCandidateEvidenceInput {
  readonly adapter: WalletCandidateSourceAdapter;
  readonly candidate_id: string;
  readonly observed_at: string;
  readonly expires_at: string;
  readonly coverage_state?: RiskCoverageState;
  readonly evidence_refs: readonly string[];
  readonly risk_labels?: readonly string[];
  readonly claims: Readonly<Record<string, string>>;
  readonly validation?: CandidateEvidenceValidationOptions;
}

export const EXCHANGE_ROUTE_SOURCE_ADAPTER_KIND = {
  domain: "exchange",
  candidate_kind: "route_candidate",
  trust_boundary: "candidate_source_only",
  evidence_policy: "claims_plus_refs_required",
} as const;

export const TRADE_VENUE_SOURCE_ADAPTER_KIND = {
  domain: "trade",
  candidate_kind: "venue_candidate",
  trust_boundary: "candidate_source_only",
  evidence_policy: "claims_plus_refs_required",
} as const;

export function exchangeRouteSourceAdapter(
  input: Pick<WalletCandidateSourceAdapter, "adapter_id" | "source">,
): WalletCandidateSourceAdapter {
  return {
    ...EXCHANGE_ROUTE_SOURCE_ADAPTER_KIND,
    adapter_id: input.adapter_id,
    source: input.source,
  };
}

export function tradeVenueSourceAdapter(
  input: Pick<WalletCandidateSourceAdapter, "adapter_id" | "source">,
): WalletCandidateSourceAdapter {
  return {
    ...TRADE_VENUE_SOURCE_ADAPTER_KIND,
    adapter_id: input.adapter_id,
    source: input.source,
  };
}

export function buildCandidateEvidenceFromSourceAdapter(
  input: BuildCandidateEvidenceInput,
): CandidateEvidence {
  assertCandidateSourceAdapter(input.adapter);

  const evidence: CandidateEvidence = {
    candidate_id: input.candidate_id,
    source: input.adapter.source,
    adapter_id: input.adapter.adapter_id,
    observed_at: input.observed_at,
    expires_at: input.expires_at,
    coverage_state: input.coverage_state ?? "assessed",
    evidence_refs: input.evidence_refs,
    risk_labels: input.risk_labels ?? [],
    claims: input.claims,
  };

  return assertCandidateEvidenceExecutable(evidence, input.validation);
}

export function assertCandidateSourceAdapter(
  adapter: WalletCandidateSourceAdapter,
): WalletCandidateSourceAdapter {
  if (adapter.trust_boundary !== "candidate_source_only") {
    throw new Error(
      "wallet candidate source adapters must remain candidate sources, not trust roots",
    );
  }
  if (adapter.evidence_policy !== "claims_plus_refs_required") {
    throw new Error(
      "wallet candidate source adapters must produce claims plus evidence refs",
    );
  }
  return adapter;
}
