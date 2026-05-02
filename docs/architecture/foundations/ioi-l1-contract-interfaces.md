# IOI L1 Smart Contract Interfaces

Status: canonical low-level reference.
Canonical owner: this file for IOI L1 contract interfaces and sparse root commitments.
Supersedes: overlapping smart-contract interface examples in plans/specs when contract responsibility conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

IOI L1 is the canonical Web4 registry, rights, settlement, and governance layer. It does not run Agentgres and does not store rich application state. aiagent.xyz and sas.xyz interact with IOI L1 through smart contracts for economically meaningful commitments.

## Contract Set

```text
AiNamespaceRegistry
PublisherRegistry
AppDomainRegistry
ManifestRootRegistry
WorkerRegistry
ServiceRegistry
LicenseRightRegistry
ServiceOrderEscrow
SLABondRegistry
DisputeRegistry
ReputationRootRegistry
ContributionRootRegistry
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

## ManifestRootRegistry

```solidity
function commitManifest(bytes32 manifestId, bytes32 manifestRoot, string uri, uint256 version) external;
function deprecateManifest(bytes32 manifestId, uint256 version, string reason) external;
function getManifest(bytes32 manifestId) external view returns (ManifestCommitment);
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
function lockEscrow(uint256 orderId) external payable;
function submitDeliveryRoot(uint256 orderId, bytes32 deliveryRoot) external;
function acceptDelivery(uint256 orderId) external;
function releasePayout(uint256 orderId) external;
function openDispute(uint256 orderId, bytes32 disputeRoot) external;
function refund(uint256 orderId) external;
```

## SLABondRegistry

```solidity
function postBond(bytes32 providerId, bytes32 serviceId, uint256 amount, address token) external payable;
function slashBond(bytes32 providerId, bytes32 serviceId, uint256 amount, string reason) external;
function releaseBond(bytes32 providerId, bytes32 serviceId) external;
```

## ReputationRootRegistry

```solidity
function commitReputationRoot(bytes32 domainId, bytes32 reputationRoot, uint256 epoch) external;
function challengeReputationRoot(bytes32 domainId, uint256 epoch, bytes32 evidenceRoot) external;
```

## ContributionRootRegistry

```solidity
function commitContributionRoot(bytes32 domainId, bytes32 contributionRoot, uint256 epoch) external;
function claimReward(bytes32 contributionId, bytes32 proofRoot) external;
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
runtime provider registration/bonding
```

IOI gas is not consumed for:

```text
every Agentgres write
every workflow event
every tool call
every model call
every receipt detail
every local projection update
```

## Non-Negotiables

1. Contracts hold rights and economic commitments, not rich operational state.
2. Every contract root must be resolvable to Agentgres/Filecoin/CAS evidence when required.
3. Contracts should accept roots and commitments, not bulky payloads.
4. L2/rollup is optional scaling, not base architecture.
