#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function read(relativePath) {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function requireText(file, text) {
  const source = read(file);
  if (!source.includes(text)) {
    throw new Error(`${file} must include ${text}`);
  }
  return source;
}

function requireAll(file, values) {
  const source = read(file);
  for (const value of values) {
    if (!source.includes(value)) {
      throw new Error(`${file} must include ${value}`);
    }
  }
  return source;
}

const evidenceFields = [
  "CandidateEvidence",
  "candidate_id",
  "source",
  "adapter_id",
  "observed_at",
  "expires_at",
  "coverage_state",
  "evidence_refs",
  "risk_labels",
  "eligibility_labels",
  "claims",
];

const failureTerms = [
  "missing CandidateEvidence",
  "expired",
  "unknown",
  "unassessed",
  "stale",
  "conflicting_sources",
  "cannot execute silently",
];

requireAll("docs/architecture/domains/decentralized/exchange.md", [
  ...evidenceFields,
  ...failureTerms,
  "RouteCandidate",
  "route candidate without",
]);

requireAll("docs/architecture/domains/decentralized/trade.md", [
  ...evidenceFields,
  ...failureTerms,
  "TradeCandidate",
  "PredictionCandidate",
  "paper mode",
]);

requireAll("docs/architecture/components/wallet-network/product-exchange-risk.md", [
  ...evidenceFields,
  "ExchangeIntent",
  "TradeIntent",
  "PredictionIntent",
  "evidence-missing candidates",
]);

requireAll("packages/wallet-protocol/src/types.ts", [
  "export interface CandidateEvidence",
  "readonly candidate_id: string",
  "readonly adapter_id: string",
  "readonly observed_at: string",
  "readonly expires_at: string",
  "readonly coverage_state: RiskCoverageState",
  "readonly evidence_refs: readonly string[]",
  "readonly risk_labels: readonly string[]",
  "readonly claims: Readonly<Record<string, string>>",
  "readonly candidate_evidence: readonly CandidateEvidence[]",
]);

requireAll("packages/wallet-protocol/src/validation.ts", [
  "WalletProtocolValidationError",
  "assertCandidateEvidenceExecutable",
  "assertExchangeIntentCandidateEvidence",
  "assertTradeIntentCandidateEvidence",
  "candidate_evidence_not_executable",
  "candidate_evidence_expired",
  "exchange_intent_candidate_evidence_mismatch",
  "trade_intent_candidate_evidence_mismatch",
]);

requireAll("packages/wallet-protocol/schemas/authority-review.schema.json", [
  "\"CandidateEvidence\"",
  "\"adapter_id\"",
  "\"observed_at\"",
  "\"expires_at\"",
  "\"coverage_state\"",
  "\"evidence_refs\"",
  "\"claims\"",
]);

requireAll("packages/wallet-protocol/schemas/exchange-intent.schema.json", [
  "\"candidate_evidence\"",
  "\"CandidateEvidence\"",
  "\"minItems\": 1",
]);

requireAll("packages/wallet-protocol/schemas/trade-intent.schema.json", [
  "\"candidate_evidence\"",
  "\"CandidateEvidence\"",
  "\"minItems\": 1",
]);

requireAll("docs/architecture/_meta/implementation-matrix.md", [
  "`CandidateEvidence`",
  "`npm run check:candidate-evidence`",
  "stale/unknown/unassessed/conflicting candidates cannot execute silently",
]);

requireText("docs/architecture/_meta/vocabulary.md", "`CandidateEvidence`");

console.log("candidate evidence conformance passed");
