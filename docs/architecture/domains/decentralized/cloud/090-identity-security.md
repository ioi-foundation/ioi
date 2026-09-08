# 090 — Identity and security: principals, authorization, workload identity, secrets, supply chain, confidential execution; trust and threat model

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for identity, authorization, workload identity, secrets, supply chain, confidential execution and the threat model.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec sections:** 16, 26. **Depends on:** 010, 210. **Defines:** principals,
authorization, workload identity, secret release, and key custody; IAM APIs,
credential claims, policy decisions, KMS boundary; adversaries, attack surfaces,
tenant/provider controls. **Required diagrams:** authentication, authorization,
credential issuance; trust boundaries, credential exposure paths.

> **Estate note (ADR 0001, open decisions A and B):** wallet.network is one authority
> backend behind spend grants; agents are first-class principals with lease-bound
> execution grants. Both are to be written into this document by their ADRs.

## 16. IAM and security

### 16.1 Principal model

```text
Human user
Team
Service account
Workload identity
Provider agent
Platform controller
External CI identity
```

Use enterprise identity federation and short-lived credentials. Long-lived API keys are an exception with explicit scope, expiry, rotation, and last-used visibility.

### 16.2 Authorization

Combine role bindings with policy conditions.

Example:

```yaml
binding:
  principal: team:platform
  role: project-operator
  scope: projects/commerce-prod
  conditions:
    requireMFA: true
    denyDataDeletion: true

organizationPolicy:
  deny:
    - publicDatabaseEndpoints
    - placementOutsideApprovedJurisdictions
  requireApproval:
    - productionDataDeletion
    - secretExport
    - trustPolicyReduction
```

Roles:

| Role               | Typical permissions                                           |
| ------------------ | ------------------------------------------------------------- |
| Reader             | Read permitted resources and operational metadata             |
| Developer          | Create plans and deploy within project limits                 |
| Operator           | Scale, restart, roll out, and repair approved resources       |
| Project Admin      | Manage project-level access and configuration                 |
| Security Admin     | Manage identity and security policy                           |
| Billing Admin      | Manage payment, budgets, invoices, and commitments            |
| Organization Owner | Organization administration and delegated emergency authority |

Deployment permission does not imply permission to reveal secret values.

### 16.3 Workload identity

Use SPIFFE-compatible workload identities and SPIRE-style node/workload attestation where the infrastructure permits it. SPIRE explicitly separates node attestation from workload attestation, which is important when providers have different trust capabilities. ([Spiffe][12])

A credential binds to:

```text
organization
project
service
attempt
allocation
runtime profile
approved grants
expiry
assurance mode
```

Distinguish **provider-bound identity** from **hardware-attested identity**. A signed assertion from an untrusted host does not become hardware assurance merely because it uses a standard identity format.

### 16.4 Secrets and keys

Platform root keys live in HSM/KMS-controlled boundaries.

Workloads receive short-lived, narrowly scoped credentials after admission and identity verification. Providers never receive organization-wide credentials or treasury keys.

Secret rotation updates consumers through versioned grants. Revocation closes affected sessions where supported and prevents new credentials. It cannot make already-exfiltrated plaintext disappear.

### 16.5 Supply-chain controls

Require immutable image digests for production. Support verified signatures, provenance, SBOMs, and approved registries.

Sigstore's verification interfaces are suitable building blocks for artifact-signature checks; a valid signature establishes the asserted signing identity and artifact relationship, not that the software is safe or correct. ([Sigstore][13])

### 16.6 Confidential execution

A confidential profile requires the complete supported path:

```text
approved CPU confidential environment
supported GPU confidential mode, when applicable
fresh attestation
approved measurements and firmware
verified credential-release policy
protected network and storage interfaces
```

NVIDIA's documentation describes GPU confidential computing in conjunction with supported CPU confidential environments and attestation components. Therefore, a GPU model label alone is insufficient admission evidence. ([NVIDIA Developer][14])

### 16.7 Abuse and isolation

Separate platform, provider, and tenant management channels.

Apply quotas, payment-risk limits, workload admission controls, outbound abuse restrictions, DDoS controls, and incident suspension procedures.

Provider and tenant reports are untrusted inputs. Do not execute commands embedded in logs, support attachments, model outputs, or provider error messages.

## 26. Trust and threat model

| Trust boundary      | What remains trusted                                                              | What reduces trust                                                                 | Important limitation                                                   |
| ------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Cloud operator      | API correctness, scheduling, billing, IAM, service operation                      | Audit exports, customer-managed policies, portable manifests, independent evidence | The initial platform is not operator-trustless                         |
| Compute provider    | Physical availability and, for ordinary workloads, host confidentiality/integrity | Qualification, isolation, replication, confidential profiles                       | Root access on a normal host can expose workload plaintext             |
| Storage provider    | Availability and retention                                                        | Encryption, independent copies, integrity hashes, retrieval tests                  | Encryption does not force continued service                            |
| Protocol            | Resource and payment rules                                                        | Native verification and independent RPC observations                               | A valid lease does not prove healthy application execution             |
| Validators          | Protocol consensus assumptions                                                    | Diverse access and finality-aware adapters                                         | Protocol failure remains a correlated dependency                       |
| Smart contracts     | Implemented settlement behavior                                                   | Version pinning, review, bounded exposure                                          | Contract correctness is not application correctness                    |
| Hardware vendor     | Attestation roots and hardware security assumptions                               | Measurement verification and revocation checks                                     | Attestation does not eliminate every side channel or availability risk |
| Attestation service | Evidence validation and freshness                                                 | Multiple evidence sources where available                                          | Location and beneficial ownership need separate evidence               |
| Customer            | Application behavior and credential hygiene                                       | Least privilege, budgets, isolation, policy                                        | The cloud cannot make arbitrary application side effects reversible    |
| Payment provider    | Payment processing and settlement                                                 | Reconciliation, limited exposure, alternative rails                                | Chargebacks, delays, and service outages remain                        |
| AI assistant        | No independent authority                                                          | Structured APIs, plan review, scoped execution                                     | Model explanations may be wrong and require evidence                   |

### Principal threats

**Malicious provider:** falsified capacity, stale attestations, data withholding, misleading meters, unexpected termination.

**Malicious tenant:** resource abuse, attempted cross-tenant access, abusive traffic, payment fraud.

**Compromised controller:** unauthorized placement, secret release, or infrastructure purchase.

**Compromised adapter:** forged native state, credential misuse, repeated purchases.

**Correlated supplier failure:** multiple nominal providers share one operator, facility, transit dependency, or protocol.

**Confused deputy:** a service uses its own privileges to act outside the requesting tenant's scope.

Mitigations combine admission constraints, credential boundaries, independent observation, bounded financial authority, and recovery. No single cryptographic proof substitutes for this threat model.

[12]: https://spiffe.io/docs/latest/spire-about/spire-concepts/
[13]: https://docs.sigstore.dev/cosign/verifying/verify/
[14]: https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/
