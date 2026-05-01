# Runtime Nodes, DePIN, TEE, and Execution Privacy Specification

Status: canonical architecture authority.
Canonical owner: this file for runtime-node and execution-privacy doctrine; low-level task capsule protocol lives in [`runtime-node-and-task-capsule-protocol.md`](./runtime-node-and-task-capsule-protocol.md).
Supersedes: overlapping hosted/DePIN/TEE prose when execution-venue boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**Runtime nodes are execution venues that run IOI daemon profiles.**

They may be local, hosted, provider-operated, DePIN, TEE-verified, or customer-controlled. They are not Web4 applications by default.

## Taxonomy

```text
Web4 App:
  product/application domain that owns UX, state, contracts, and outcome semantics

Web4 Worker:
  executable agent/workflow/service unit that performs work

Runtime Node:
  machine or environment running IOI daemon to execute workers

Resource Provider:
  DePIN/cloud/enterprise/local provider offering compute/storage/model resources
```

DePIN nodes are Web4 worker infrastructure, not the apps themselves.

## Execution Venues

1. **Local Autopilot** — user machine/private runtime.
2. **Hosted IOI Runtime** — first-party managed runtime.
3. **Provider Runtime** — worker/service seller runtime.
4. **DePIN Runtime** — Akash-like decentralized compute node.
5. **TEE Runtime** — attested confidential compute node.
6. **Customer VPC Runtime** — enterprise-owned environment.

## Privacy Modes

### Mutual Blind Mode

No TEE required.

Properties:

- encrypted packages/capsules;
- minimized task context;
- redacted inputs;
- no raw secrets;
- no final settlement authority;
- no direct external effects;
- verification before settlement;
- watermarked capsules;
- contribution receipts.

Claim:

> The node never receives enough context or authority to matter.

Non-claim:

> The node cannot inspect RAM.

### Enterprise Secure Mode

TEE-verified nodes required.

Properties:

- remote attestation;
- measured runtime/container;
- sealed secret release;
- encrypted inputs/outputs;
- attested execution receipt;
- stricter enterprise privacy claims.

Use for:

- private enterprise code;
- regulated data;
- proprietary strategy;
- confidential model execution;
- sensitive customer workflows.

## Blind Capsule Execution

A remote node may execute a task-scoped capsule:

```yaml
TaskCapsule:
  task_id: task_123
  capsule_id: cap_07
  visible_context:
    - redacted_input
    - schema
    - bounded_objective
  hidden_context:
    - raw_secrets
    - full_memory
    - payment_info
  allowed_actions:
    - compute
    - transform
    - propose_patch
  forbidden_actions:
    - spend
    - send
    - publish
    - sign
    - settle_state
  output_contract:
    - artifact_hash
    - proposed_patch
    - execution_receipt
  ttl_seconds: 900
```

## Execution Flow

```text
marketplace/app creates RunRequest
→ domain kernel/router selects venue
→ runtime node fetches package/capsule from Filecoin/CAS
→ wallet.network grants scoped authority if allowed
→ node executes
→ artifacts stored to Filecoin/CAS
→ receipts/results returned to Agentgres
→ trusted verifier/settlement path accepts or rejects
→ IOI L1 contract updates only if economic boundary requires it
```

## TEE Flow

```text
runtime node produces attestation
→ wallet.network verifies measurement and policy
→ secrets/keys released only to enclave
→ worker executes inside TEE
→ outputs encrypted to destination key
→ attestation/execution receipt recorded
```

## Invariants

1. Untrusted nodes do not get raw long-lived secrets.
2. Mutual Blind nodes cannot directly execute final effects.
3. Enterprise-private plaintext requires local/customer/TEE execution.
4. Runtime nodes emit receipts and artifact hashes.
5. Marketplace payouts depend on delivery/settlement, not node claims alone.
6. TEE attestation is a policy requirement for enterprise secure placement.

## One-Line Doctrine

> **Mutual Blind Mode protects by minimizing what the node can know or do. Enterprise Secure Mode protects by verifying where plaintext is allowed to exist.**
