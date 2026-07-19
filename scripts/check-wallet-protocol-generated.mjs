#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function read(relativePath) {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function assertIncludes(file, source, needle) {
  if (!source.includes(needle)) {
    throw new Error(`${file} must include ${needle}`);
  }
}

function assertFile(relativePath, needles = []) {
  const source = read(relativePath);
  for (const needle of needles) {
    assertIncludes(relativePath, source, needle);
  }
  return source;
}

const rustSession = assertFile("crates/types/src/app/wallet_network/session.rs", [
  "pub struct SessionGrant",
  "pub struct SessionLease",
  "pub struct SessionReceiptCommit",
]);

const rustPolicy = assertFile("crates/types/src/app/wallet_network/policy.rs", [
  "pub struct WalletInterceptionContext",
  "pub struct WalletApprovalDecision",
  "pub struct VaultAuditEvent",
]);

const rustSecretInjection = assertFile(
  "crates/types/src/app/wallet_network/secret_injection.rs",
  ["pub struct SecretInjectionRequest", "pub struct SecretInjectionGrant"],
);

const rustService = assertFile("crates/services/src/wallet_network/mod.rs", [
  "wallet_network",
  "issue_session_lease@v1",
  "record_approval@v1",
  "grant_secret_injection@v1",
  "commit_receipt_root@v1",
]);

const protocolTypes = assertFile("packages/wallet-protocol/src/types.ts", [
  "AuthorityReview",
  "CapabilityLease",
  "CapabilityLeaseRevocation",
  "WalletReceipt",
  "ExchangeIntent",
  "TradeIntent",
  "CandidateEvidence",
  "WalletPresentationProfile",
  "allowed_approval_modes",
  "recommended_presentation_profile",
  "scope:",
]);

const protocolValidation = assertFile("packages/wallet-protocol/src/validation.ts", [
  "assertCandidateEvidenceExecutable",
  "assertExchangeIntentCandidateEvidence",
  "assertTradeIntentCandidateEvidence",
  "WalletProtocolValidationError",
]);

const protocolMethods = assertFile("packages/wallet-protocol/src/methods.ts", [
  "WALLET_NETWORK_KERNEL_METHODS",
  "issue_session_lease@v1",
  "record_approval@v1",
  "grant_secret_injection@v1",
  "wallet.capability.lease.issue",
  "wallet.capability.lease.revoke",
]);

for (const kernelMethod of [
  "issue_session_grant@v1",
  "issue_session_lease@v1",
  "record_interception@v1",
  "record_approval@v1",
  "commit_receipt_root@v1",
]) {
  assertIncludes("crates/services/src/wallet_network/mod.rs", rustService, kernelMethod);
  assertIncludes("packages/wallet-protocol/src/methods.ts", protocolMethods, kernelMethod);
}

for (const objectName of [
  "SessionLease",
  "WalletApprovalDecision",
  "SecretInjectionGrant",
]) {
  const rustSources = `${rustSession}\n${rustPolicy}\n${rustSecretInjection}`;
  assertIncludes("wallet Rust type anchors", rustSources, objectName);
}

for (const protocolObject of [
  "AuthorityReview",
  "CapabilityLease",
  "CapabilityLeaseRevocation",
  "WalletReceipt",
  "CandidateEvidence",
  "WalletPresentationProfile",
]) {
  assertIncludes("packages/wallet-protocol/src/types.ts", protocolTypes, protocolObject);
}

for (const validationExport of [
  "candidate_evidence_not_executable",
  "candidate_evidence_expired",
  "exchange_intent_candidate_evidence_mismatch",
  "trade_intent_candidate_evidence_mismatch",
]) {
  assertIncludes("packages/wallet-protocol/src/validation.ts", protocolValidation, validationExport);
}

const schemaFiles = [
  "packages/wallet-protocol/schemas/authority-review.schema.json",
  "packages/wallet-protocol/schemas/capability-lease.schema.json",
  "packages/wallet-protocol/schemas/capability-lease-revocation.schema.json",
  "packages/wallet-protocol/schemas/wallet-receipt.schema.json",
  "packages/wallet-protocol/schemas/exchange-intent.schema.json",
  "packages/wallet-protocol/schemas/trade-intent.schema.json",
];

for (const schemaFile of schemaFiles) {
  const schema = readJson(schemaFile);
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    throw new Error(`${schemaFile} must use JSON Schema draft 2020-12`);
  }

  if (!schema.$id?.startsWith("https://schemas.ioi.network/wallet/")) {
    throw new Error(`${schemaFile} must use the wallet schema id namespace`);
  }
}

const openapi = readJson("packages/wallet-protocol/openapi/wallet-network.openapi.json");
for (const path of [
  "/v1/authority/reviews",
  "/v1/capability/leases",
  "/v1/capability/leases/{lease_id}/revoke",
  "/v1/exchange/intents",
  "/v1/trade/intents",
  "/v1/receipts",
]) {
  if (!openapi.paths[path]) {
    throw new Error(`OpenAPI contract must include ${path}`);
  }
}

const fixtures = readJson("packages/wallet-protocol/fixtures/wallet-protocol-fixtures.json");
if (fixtures.schema_version !== "ioi.wallet.protocol.v1") {
  throw new Error("wallet protocol fixtures must declare the canonical schema version");
}

if (!fixtures.authority_review.requested_scopes.every((scope) => scope.startsWith("scope:"))) {
  throw new Error("wallet protocol fixtures must preserve scope:* authority scopes");
}

if (!Array.isArray(fixtures.authority_review.allowed_approval_modes)) {
  throw new Error("authority review fixtures must include allowed_approval_modes");
}

if (!fixtures.authority_review.recommended_presentation_profile) {
  throw new Error("authority review fixtures must include recommended_presentation_profile");
}

if (!fixtures.capability_lease?.capability_scope?.startsWith("scope:")) {
  throw new Error("wallet protocol fixtures must include a scoped capability lease");
}

if (
  fixtures.capability_lease_revocation?.lease_id !==
  fixtures.capability_lease.lease_id
) {
  throw new Error("wallet protocol fixtures must include capability lease revocation");
}

const sdkPackage = readJson("packages/wallet-sdk/package.json");
if (sdkPackage.dependencies["@ioi/wallet-protocol"] !== "0.1.0") {
  throw new Error("@ioi/wallet-sdk must depend on @ioi/wallet-protocol");
}

for (const sdkFile of [
  "packages/wallet-sdk/src/authority-review.ts",
  "packages/wallet-sdk/src/capabilities.ts",
  "packages/wallet-sdk/src/client.ts",
  "packages/wallet-sdk/src/receipts.ts",
  "packages/wallet-sdk/src/route-sources.ts",
  "packages/wallet-sdk/src/index.ts",
]) {
  assertIncludes(sdkFile, read(sdkFile), "@ioi/wallet-protocol");
}

const walletSdkRouteSources = read("packages/wallet-sdk/src/route-sources.ts");
for (const text of [
  "createHttpCandidateSourceClient",
  "createDecentralizedExchangeCandidateSourceClient",
  "createDecentralizedTradeCandidateSourceClient",
  "assertCandidateEvidenceExecutable",
  "candidate_source_only",
  "wallet candidate source evidence must match the declared adapter and source",
]) {
  assertIncludes("packages/wallet-sdk/src/route-sources.ts", walletSdkRouteSources, text);
}

const walletSdkCapabilities = read("packages/wallet-sdk/src/capabilities.ts");
for (const text of [
  "buildCapabilityLease",
  "buildCapabilityLeaseRevocation",
  "WALLET_PROTOCOL_SCHEMA_VERSION",
]) {
  assertIncludes("packages/wallet-sdk/src/capabilities.ts", walletSdkCapabilities, text);
}

const walletSdkClient = read("packages/wallet-sdk/src/client.ts");
for (const text of [
  "issueCapabilityLease",
  "revokeCapabilityLease",
  "WALLET_NETWORK_PROTOCOL_METHODS.revokeCapabilityLease",
]) {
  assertIncludes("packages/wallet-sdk/src/client.ts", walletSdkClient, text);
}

const hypervisorPackage = readJson("apps/hypervisor/package.json");
if (hypervisorPackage.dependencies["@ioi/wallet-sdk"] !== "*") {
  throw new Error("@ioi/hypervisor-app must package wallet product semantics through @ioi/wallet-sdk");
}

for (const scriptName of ["predev", "prebuild"]) {
  assertIncludes(
    "apps/hypervisor/package.json",
    hypervisorPackage.scripts?.[scriptName] ?? "",
    "npm run build --workspace=@ioi/wallet-sdk --if-present",
  );
}

const hypervisorApiAdapter = assertFile("apps/hypervisor/scripts/ioi-api-adapter.mjs", [
  "daemon EXECUTES · wallet AUTHORIZES (crossings only) · agentgres",
  '"authority/posture": "/v1/hypervisor/authority/posture"',
]);
if (hypervisorApiAdapter.includes("autopilot-authority-center")) {
  throw new Error("Hypervisor API adapter must not emit retired Autopilot authority audience names");
}

console.log("wallet protocol packaging conformance passed");
