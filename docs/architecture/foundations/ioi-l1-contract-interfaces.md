# IOI L1 Smart Contract Interfaces

Status: canonical low-level reference.
Canonical owner: this file for IOI L1 contract interfaces and sparse root commitments.
Supersedes: overlapping smart-contract interface examples in plans/specs when contract responsibility conflicts.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: canonical
Implementation status: speculative (interface sketches for a future chain)
Last implementation audit: 2026-07-05

## Purpose

IOI L1 is an optional IOI Network registry, rights, assurance,
shared-security, autonomous-system settlement, sparse-commitment, and
governance layer for explicitly connected or secured systems. It does not run the L0/kernel
substrate, Agentgres, or rich application state. aiagent.xyz, sas.xyz,
Hypervisor Nodes, and third-party autonomous systems interact with IOI L1
through smart contracts for economically meaningful commitments.

## Contract Set

```text
AiNamespaceRegistry
PublisherRegistry
DomainRegistry
ManifestRootRegistry
AutonomousSystemRegistry
NetworkEnrollmentRegistry
StandardDASProfileRegistry
SharedSecurityServiceRegistry
ServiceBondRegistry
SharedSecurityAgreementRegistry
AIIPChannelRegistry
AIIPSchemaRegistry
SettlementAccountRegistry
WorkerRegistry
ServiceRegistry
LicenseRightRegistry
ServiceOrderEscrow
SLABondRegistry
DisputeRegistry
ReputationRootRegistry
ContributionRootRegistry
AuthorityLeaseCommitmentRegistry
ReceiptRootRegistry
SettlementIntentRegistry
HandoffFinalityRegistry
WorkerEligibilityRootRegistry
SparseWorkerCategoryRegistry
BenchmarkProfileRegistry
TrainingLineageRootRegistry
RoutingDecisionRootRegistry
RuntimeProviderRegistry
AttestationProfileRegistry
ProtocolGovernance
```

## AiNamespaceRegistry

```solidity
function registerNamespace(string aiName, address owner, bytes32 manifestRoot) external payable;
function updateResolver(string aiName, bytes32 resolverRoot, string resolverURI) external;
function transferNamespace(string aiName, address newOwner) external;
function revokeNamespace(string aiName, string reason) external;
function resolve(string aiName) external view returns (NamespaceRecord);
```

Events:

```solidity
event NamespaceRegistered(string aiName, address owner, bytes32 manifestRoot);
event NamespaceResolverUpdated(string aiName, bytes32 resolverRoot, string resolverURI);
event NamespaceRevoked(string aiName, string reason);
```

## PublisherRegistry

```solidity
function registerPublisher(bytes32 publisherId, bytes32 identityRoot, string metadataURI) external payable;
function updatePublisher(bytes32 publisherId, bytes32 identityRoot, string metadataURI) external;
function suspendPublisher(bytes32 publisherId, string reason) external;
```

## DomainRegistry

`DomainRegistry` is the canonical name used by the L1 owner; the older
`AppDomainRegistry` label is retired.

```solidity
function registerDomain(bytes32 domainId, bytes32 operatorRoot, bytes32 resolverRoot, string resolverURI) external payable;
function updateDomain(bytes32 domainId, bytes32 operatorRoot, bytes32 resolverRoot, string resolverURI) external;
function suspendDomain(bytes32 domainId, bytes32 reasonRoot) external;
```

## ManifestRootRegistry

```solidity
function commitManifest(bytes32 manifestId, bytes32 manifestRoot, string uri, uint256 version) external;
function deprecateManifest(bytes32 manifestId, uint256 version, string reason) external;
function getManifest(bytes32 manifestId) external view returns (ManifestCommitment);
```

## AutonomousSystemRegistry

```solidity
struct SystemMutationProof {
  bytes32 enrollmentId;
  bytes32 expectedPriorCommitmentRoot;
  uint256 expectedPriorVersion;
  bytes32 governingDecisionRoot;
  bytes32 authorityProofRoot;
}
function registerSystem(bytes32 systemId, bytes32 genesisRoot, bytes32 constitutionRoot, bytes32 manifestRoot, bytes32 enrollmentId, bytes32 decisionRoot, bytes32 authorityProofRoot, string resolverURI) external payable;
function commitConstitution(bytes32 systemId, bytes32 constitutionRoot, uint256 version, SystemMutationProof calldata proof) external;
function recognizeSystemRelease(bytes32 systemId, bytes32 manifestRoot, bytes32 conformanceRoot, uint256 version, SystemMutationProof calldata proof) external;
function updateSystemRoots(bytes32 systemId, bytes32 policyRoot, bytes32 moduleRegistryRoot, bytes32 membershipRoot, bytes32 receiptRoot, uint256 version, SystemMutationProof calldata proof) external;
function commitLifecycleRoot(bytes32 systemId, bytes32 lifecycleRoot, bytes32 dispositionRoot, uint256 version, SystemMutationProof calldata proof) external;
function updateSystemStatus(bytes32 systemId, SystemStatus status, bytes32 reasonRoot, uint256 version, SystemMutationProof calldata proof) external;
```

Registration is an opt-in network service. It does not create the system,
grant permission to use L0, own its operational state, or prove its purpose,
membership, or outputs correct.

Every mutation must compare-and-swap the expected predecessor commitment and
version, verify an active connected/secured enrollment selecting the registry
service, validate the current constitution commitment and caller authority,
verify the governing decision/authority proof, and emit a resulting commitment
event plus `NetworkServiceInvocationReceipt`. Missing, stale, suspended, or
mismatched inputs fail closed. These interfaces commit sparse public roots; they
never directly mutate the system's operational state.

## NetworkEnrollmentRegistry

```solidity
enum NetworkEnrollmentProfile { IOI_CONNECTED, IOI_SECURED }
struct EnrollmentMutationProof {
  bytes32 expectedPriorEnrollmentRoot;
  uint256 expectedPriorVersion;
  bytes32 governingDecisionRoot;
  bytes32 systemAuthorityProofRoot;
}
function proposeEnrollment(bytes32 enrollmentId, bytes32 systemId, NetworkEnrollmentProfile profile, bytes32 enrollmentRoot, uint256 effectiveAt, uint256 expiresAt, EnrollmentMutationProof calldata proof) external payable;
function activateEnrollment(bytes32 enrollmentId, bytes32 conformanceRoot, bytes32 serviceSelectionRoot, uint256 version, EnrollmentMutationProof calldata proof) external;
function suspendEnrollment(bytes32 enrollmentId, bytes32 reasonRoot, uint256 version, EnrollmentMutationProof calldata proof) external;
function requestExit(bytes32 enrollmentId, bytes32 obligationRoot, uint256 version, EnrollmentMutationProof calldata proof) external;
function finalizeExit(bytes32 enrollmentId, bytes32 finalCommitmentRoot, uint256 version, EnrollmentMutationProof calldata proof) external;
```

The envelope vocabulary is `ioi_compatible | ioi_connected | ioi_secured`, but
the on-chain registry accepts only connected or secured enrollment. An
`ioi_compatible` system remains local-only and therefore has no enrollment
transaction or placeholder registry record.

Every enrollment mutation compare-and-swaps the predecessor root/version and
validates the system's governing decision and authority proof. Activation also
validates conformance and exact service selection; suspension and exit preserve
outstanding obligations/disputes. A stale or unauthorized enrollment mutation
fails closed and cannot be used to authorize a later registry or settlement
operation.

## StandardDASProfileRegistry

```solidity
function registerStandardDASProfile(bytes32 profileId, bytes32 requirementRoot, string profileURI, uint256 version) external;
function recognizeConformance(bytes32 systemId, bytes32 profileId, bytes32 conformanceRoot, bytes32 evidenceRoot, uint256 expiresAt) external;
function suspendConformance(bytes32 systemId, bytes32 profileId, bytes32 reasonRoot) external;
```

Conformance is versioned evidence against a declared profile, not a blanket
safe/correct/legal/available claim.

## SharedSecurityServiceRegistry

```solidity
function registerSecurityService(bytes32 serviceId, SecurityServiceKind kind, bytes32 providerRoot, bytes32 termsRoot, bytes32 assuranceRoot) external payable;
function updateSecurityService(bytes32 serviceId, bytes32 termsRoot, bytes32 assuranceRoot) external;
function suspendSecurityService(bytes32 serviceId, bytes32 reasonRoot) external;
```

Eligible kinds include validator, verifier, guardian, availability witness,
relayer, arbitrator, ordering, and finality services.

## ServiceBondRegistry

```solidity
function postServiceBond(bytes32 serviceId, bytes32 providerId, uint256 amount, address asset, bytes32 claimPolicyRoot) external payable;
function openBondClaim(bytes32 claimId, bytes32 serviceId, bytes32 evidenceRoot, uint256 amount) external payable;
function resolveBondClaim(bytes32 claimId, BondClaimDecision decision, uint256 amount, bytes32 adjudicationRoot) external;
function releaseServiceBond(bytes32 serviceId, bytes32 providerId, uint256 amount) external;
```

## SharedSecurityAgreementRegistry

```solidity
function activateAgreement(bytes32 agreementId, bytes32 systemId, bytes32 serviceId, bytes32 scopeRoot, bytes32 termsRoot, bytes32 obligationRoot) external payable;
function updateAgreement(bytes32 agreementId, bytes32 termsRoot, bytes32 obligationRoot) external;
function requestAgreementExit(bytes32 agreementId, bytes32 outstandingObligationRoot) external;
function finalizeAgreementExit(bytes32 agreementId, bytes32 finalRoot) external;
```

## AIIPChannelRegistry

```solidity
function registerChannel(bytes32 channelId, bytes32 fromSystemId, bytes32 toSystemId, bytes32 profileRoot, bytes32 schemaRoot) external payable;
function updateChannelRoot(bytes32 channelId, bytes32 sequenceRoot, bytes32 receiptRoot) external;
function closeChannel(bytes32 channelId, bytes32 finalityRoot, string reason) external;
```

## AIIPSchemaRegistry

```solidity
function registerAIIPSchema(bytes32 schemaId, bytes32 schemaRoot, string uri, uint256 version) external;
function deprecateAIIPSchema(bytes32 schemaId, uint256 version, string reason) external;
```

## SettlementAccountRegistry

```solidity
function registerSettlementAccount(bytes32 accountId, address controller, bytes32 policyRoot) external payable;
function updateSettlementPolicy(bytes32 accountId, bytes32 policyRoot) external;
```

## WorkerRegistry

```solidity
function publishWorker(bytes32 workerId, bytes32 publisherId, bytes32 manifestRoot, uint256 version) external payable;
function updateWorkerVersion(bytes32 workerId, bytes32 manifestRoot, uint256 version) external;
function deprecateWorker(bytes32 workerId, string reason) external;
function setWorkerBond(bytes32 workerId, uint256 amount) external payable;
```

## ServiceRegistry

```solidity
function publishService(bytes32 serviceId, bytes32 publisherId, bytes32 manifestRoot, uint256 version) external payable;
function updateServiceVersion(bytes32 serviceId, bytes32 manifestRoot, uint256 version) external;
function deprecateService(bytes32 serviceId, string reason) external;
```

## LicenseRightRegistry

```solidity
function mintInstallRight(bytes32 workerId, address buyer, bytes32 termsRoot) external payable returns (uint256 licenseId);
function revokeInstallRight(uint256 licenseId, string reason) external;
function verifyInstallRight(uint256 licenseId, address holder) external view returns (bool);
```

## ServiceOrderEscrow

```solidity
function createOrder(bytes32 serviceId, address customer, address provider, bytes32 orderRoot, uint256 amount, address token) external payable returns (uint256 orderId);
function lockEscrow(uint256 orderId, bytes32 expectedPriorOrderStateRoot, bytes32 settlementIntentRoot, bytes32 authorityProofRoot) external payable;
function submitDeliveryRoot(uint256 orderId, bytes32 expectedPriorOrderStateRoot, bytes32 deliveryRoot, bytes32 deliveryReceiptRoot, bytes32 authorityProofRoot) external;
function releasePayout(uint256 orderId, bytes32 expectedPriorOrderStateRoot, bytes32 acceptanceDecisionRoot, bytes32 settlementIntentRoot, bytes32 authorityProofRoot) external;
function applyAdjudicatedRemedy(uint256 orderId, bytes32 expectedPriorOrderStateRoot, bytes32 disputeId, bytes32 adjudicationRoot, bytes32 remedySettlementIntentRoot, bytes32 authorityProofRoot) external;
```

The escrow consumes admitted delivery, acceptance, adjudication, and settlement-
intent roots; it does not author those assurance stages. Disputes are opened and
resolved through `DisputeRegistry`. Payout, refund, partial remedy, or slashing
must bind the expected prior order state, applicable decision, intent, and
authority proof and emit a resulting settlement receipt/state root.

## SLABondRegistry

```solidity
function postBond(bytes32 providerId, bytes32 serviceId, uint256 amount, address token) external payable;
function slashBond(bytes32 providerId, bytes32 serviceId, uint256 amount, string reason) external;
function releaseBond(bytes32 providerId, bytes32 serviceId) external;
```

## DisputeRegistry

```solidity
function openDispute(bytes32 disputeId, bytes32 subjectId, bytes32 claimRoot, bytes32 evidenceRoot, bytes32 policyRoot) external payable;
function submitDisputeEvidence(bytes32 disputeId, bytes32 evidenceRoot, bytes32 disclosurePolicyRoot) external;
function recordDisputeDecision(bytes32 disputeId, DisputeDecision decision, bytes32 adjudicationRoot, bytes32 remedyRoot) external;
function appealDispute(bytes32 disputeId, bytes32 appealRoot) external payable;
function finalizeDispute(bytes32 disputeId, bytes32 finalityRoot) external;
```

The registry records staged dispute commitments and remedies. It does not make
a raw receipt, verifier vote, or evaluator response final by itself.

## ReputationRootRegistry

```solidity
function commitReputationRoot(bytes32 domainId, bytes32 reputationRoot, uint256 epoch) external;
function challengeReputationRoot(bytes32 domainId, uint256 epoch, bytes32 evidenceRoot) external;
```

## ContributionRootRegistry

```solidity
function commitContributionRoot(bytes32 domainId, bytes32 contributionRoot, uint256 epoch) external;
function submitContributionSettlementClaim(bytes32 contributionId, bytes32 proofRoot, bytes32 termsRoot) external;
```

The settlement claim stays asset- and reward-mechanism neutral until accepted
economic terms and token/native-asset doctrine exist.

## AuthorityLeaseCommitmentRegistry

```solidity
function commitAuthorityLease(bytes32 leaseId, bytes32 subjectId, bytes32 authorityRoot, bytes32 policyRoot, uint256 expiresAt) external;
function revokeAuthorityLease(bytes32 leaseId, bytes32 revocationRoot) external;
```

## ReceiptRootRegistry

```solidity
function commitReceiptRoot(bytes32 domainId, bytes32 receiptRoot, uint256 epoch, bytes32 disclosurePolicyRoot) external;
function challengeReceiptRoot(bytes32 domainId, uint256 epoch, bytes32 evidenceRoot) external;
```

## SettlementIntentRegistry

```solidity
function submitSettlementIntent(bytes32 intentId, bytes32 claimantId, bytes32 receiptConditionRoot, bytes32 paymentTermsRoot) external payable;
function acceptSettlementIntent(bytes32 intentId) external;
function challengeSettlementIntent(bytes32 intentId, bytes32 disputeRoot) external;
```

## HandoffFinalityRegistry

```solidity
function commitHandoffFinality(bytes32 handoffId, bytes32 fromSystemId, bytes32 toSystemId, bytes32 receiptRoot, bytes32 settlementRoot) external;
function challengeHandoff(bytes32 handoffId, bytes32 evidenceRoot) external;
```

## WorkerEligibilityRootRegistry

```solidity
function commitWorkerEligibilityRoot(bytes32 domainId, bytes32 eligibilityRoot, uint256 epoch) external;
function challengeWorkerEligibility(bytes32 domainId, uint256 epoch, bytes32 evidenceRoot) external;
```

## SparseWorkerCategoryRegistry

```solidity
function registerCategory(bytes32 categoryId, bytes32 profileRoot, string metadataURI) external payable;
function updateCategory(bytes32 categoryId, bytes32 profileRoot, string metadataURI) external;
function suspendCategory(bytes32 categoryId, string reason) external;
```

## BenchmarkProfileRegistry

```solidity
function commitBenchmarkProfile(bytes32 profileId, bytes32 profileRoot, string uri, uint256 version) external;
function commitBenchmarkResultRoot(bytes32 profileId, bytes32 resultRoot, uint256 epoch) external;
```

## TrainingLineageRootRegistry

```solidity
function commitTrainingLineageRoot(bytes32 workerId, bytes32 lineageRoot, uint256 version) external;
```

## RoutingDecisionRootRegistry

```solidity
function commitRoutingDecisionRoot(bytes32 domainId, bytes32 routingRoot, uint256 epoch) external;
```

## RuntimeProviderRegistry

```solidity
function registerRuntimeProvider(bytes32 providerId, bytes32 manifestRoot, string endpointURI) external payable;
function postRuntimeBond(bytes32 providerId, uint256 amount) external payable;
function updateProviderStatus(bytes32 providerId, ProviderStatus status) external;
```

## AttestationProfileRegistry

```solidity
function registerAttestationProfile(bytes32 profileId, bytes32 verifierRoot, string profileURI) external;
function updateAttestationProfile(bytes32 profileId, bytes32 verifierRoot, string profileURI) external;
```

## ProtocolGovernance

Protocol governance records public commitments for IOI Network conformance
profiles, contracts, recognized reference implementations, and recognized
L0/kernel release roots. It does not govern all compatible L0 use, external
AIIP peers, ordinary commits, pull requests, private deployments, or
application-domain state.

```solidity
function proposeProtocolUpgrade(bytes32 proposalRoot, string metadataURI) external payable;
function recordReferenceImplementationRelease(bytes32 releaseRoot, string uri, uint256 version) external;
function deprecateReferenceImplementationRelease(bytes32 releaseRoot, string reason) external;
function recordEmergencySecurityAction(bytes32 actionRoot, string reason) external;
```

## Gas Boundary

IOI gas is consumed for:

```text
namespace registration
publisher/app/worker/service publication
manifest commitments
license/install rights
escrow lock/release
SLA bonds
payouts/refunds
disputes
reputation/contribution root commitments
autonomous-system registration
connected/secured enrollment and exit
Standard DAS conformance commitments
shared-security service registration, agreements, bonds, claims, and exit
AIIP channel/schema/profile registration
authority lease commitments
receipt root anchoring
settlement intents
cross-system handoff finality
runtime provider registration/bonding
reference implementation release commitments
```

IOI gas is not consumed for:

```text
every Agentgres write
every workflow event
every tool call
every model call
every receipt detail
every local projection update
ioi-compatible system creation, deployment, node membership, or lifecycle
```

## Non-Negotiables

1. Contracts hold rights, release roots, and economic commitments, not rich operational state.
2. Every contract root must be resolvable to Agentgres refs and storage-backend evidence when required.
3. Contracts should accept roots and commitments, not bulky payloads.
4. L2/rollup is optional scaling, not base architecture.
5. AIIP and compatible L0 use do not require any contract call. Every L1
   interaction follows explicit connected or secured enrollment.
6. Shared-security and conformance contracts state exact scope and assurance;
   they never emit a generic `verified` or blanket safety claim.
7. Contract sketches remain asset-neutral until real service demand and native-
   asset governance are separately approved.
