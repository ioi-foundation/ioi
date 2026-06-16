# Runtime Nodes, DePIN, TEE, and Execution Privacy Specification

Status: canonical architecture authority.
Canonical owner: this file for runtime-node and execution-privacy doctrine; low-level task capsule protocol lives in [`runtime-node-and-task-capsule-protocol.md`](./task-capsule-protocol.md).
Supersedes: overlapping hosted/DePIN/TEE prose when execution-venue boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-06-03.

## Canonical Definition

**Runtime nodes are execution venues that run Hypervisor Daemon profiles.**

They may be local, hosted, provider-operated, DePIN, HypervisorOS bare-metal,
Private Workspace cTEE, TEE-verified, or customer-controlled. They are not Web4
applications by default.

A runtime node may contain a lower-level runtime service bridge or worker SDK
helpers, but the node's architectural boot target is the Hypervisor Daemon runtime-node
profile. SDKs submit and control work as clients; they do not own node
execution.

## Taxonomy

```text
Web4 App:
  product/application domain that owns UX, state, contracts, and outcome semantics

Web4 Worker:
  executable agent/workflow/service unit that performs work

Runtime Node:
  machine or environment running a Hypervisor Daemon runtime-node profile to execute workers

Managed Worker Instance:
  user-, org-, or project-bound worker initialization that may expose chat,
  API, scheduler, form, or workflow-node surfaces over the runtime node

Resource Provider:
  DePIN/cloud/enterprise/local provider offering compute/storage/model resources

Compute Session:
  bounded allocation on a runtime node for one run, task capsule, service order,
  workflow execution, managed worker instance, training job, evaluation job,
  benchmark job, or routing job
```

DePIN nodes are Web4 worker infrastructure, not the apps themselves. Training,
evaluation, benchmark, and MoW routing jobs use the same daemon/runtime-node
profile boundary as worker execution.

## Execution Venues

1. **Local Hypervisor Daemon under Hypervisor App, Workbench, or
   CLI/headless** — user machine/private runtime; TUI is an optional
   presentation over CLI/headless.
2. **Hosted IOI Runtime** — first-party managed runtime.
3. **Provider Runtime** — worker/service seller runtime.
4. **DePIN Runtime** — Akash-like decentralized compute node.
5. **HypervisorOS Bare-Metal Runtime** — measured node image where the
   Hypervisor Daemon is the node root and autonomous workloads cannot bypass
   daemon policy.
6. **Private Workspace cTEE Runtime** — rented or hosted node profile where
   users open a private workspace while protected plaintext is forbidden from
   provider-rooted memory by default.
7. **TEE Runtime** — attested confidential compute node.
8. **Customer VPC Runtime** — enterprise-owned environment.

## Placement Privacy Profiles

### Mutual Blind Profile

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

### Private Workspace cTEE Profile

No hardware TEE required for the baseline claim.

Properties:

- persistent rented/provider/DePIN GPU node may run the Hypervisor Daemon, Hypervisor
  node shell, and Private Workspace public/redacted projections;
- public or redacted model inference can run at normal node speed;
- Plaintext-Free Runtime Mounting limits tool/model context to public/redacted
  projections, encrypted refs, private handles, declassification requests, and
  capability exits; `PlaintextFreeModelMount` is the model-facing specialization;
- Candidate-Lattice Private Decoding is the default protected-agency strategy:
  the node expands candidates, while AlphaSeal/guardian/wallet policy selects,
  filters, declassifies, or signs outside node plaintext custody;
- protected state classes are declared before routing;
- PII, strategy source, broker keys, private memory, live portfolio, and final
  action logic are forbidden from remote plaintext by default;
- persistent state is stored as encrypted Agentgres refs and sealed archives;
- sensitive scoring uses `AlphaSeal`, masked/secret-shared/ciphertext
  operators, local/client evaluation, or a cTEE guardian;
- external actions exit through wallet.network capability gates;
- declassification emits receipts.

Claim:

> The node can provide persistence and useful GPU compute without receiving
> protected plaintext by default. Private agency is handled by candidate
> generation on the node plus sealed/private selection outside node custody.

Non-claim:

> A consumer GPU or boot-measured image becomes a hardware confidential-compute
> boundary.

### Enterprise Secure Profile

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
→ RuntimeAssignment binds daemon profile, compute session, package refs, policy, and payment quote
→ runtime node fetches package/capsule from selected storage backend
→ wallet.network grants scoped authority if allowed
→ node executes
→ artifacts stored to selected storage backend behind Agentgres refs
→ receipts/results returned to Agentgres
→ trusted verifier/settlement path accepts or rejects
→ IOI L1 contract updates only if economic boundary requires it
```

Managed instances use the same boundary, but the assignment may be durable:

```text
aiagent.xyz creates install + WorkerInstance
→ runtime router selects hosted/provider/DePIN/TEE/customer/local daemon
→ subscription or zero-to-idle policy is attached
→ browser/API/workflow clients control the instance through daemon APIs
→ idle state checkpoints to Agentgres refs and sealed archive bytes in storage backends
→ runtime resumes or rehydrates when the user returns or a schedule fires
```

Persistent does not always mean always-on. A worker instance may be:

- **ephemeral** — one run, no durable instance;
- **session** — conversational/session continuity while active;
- **zero-to-idle** — archived when idle, rehydrated by policy;
- **persistent** — warm runtime maintained by subscription or provider contract.

Private Workspace cTEE instances additionally require:

- a sensitive-data policy;
- wallet.network authority and declassification rules;
- a cTEE guardian, trusted client, threshold service, or approved confidential
  environment for protected operations;
- `AutonomyLease` for work while the user is away;
- `ModelMountReceipt`, `PrivateInferenceReceipt`, `DeclassificationReceipt`,
  and deterrence/detection receipts when protected outputs are mounted,
  produced, revealed, watermarked, canary-checked, or disputed.

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
3. Private Workspace cTEE nodes do not get protected plaintext by default.
4. Enterprise-private plaintext requires local/customer/TEE execution.
5. Runtime nodes emit receipts and artifact hashes.
6. Marketplace payouts depend on delivery/settlement, not node claims alone.
7. TEE attestation is a policy requirement for enterprise secure placement.
8. HypervisorOS nodes treat the Hypervisor Daemon as the node root; measured
   boot is an integrity receipt, not a consumer-GPU plaintext privacy guarantee.
9. Runtime nodes run daemon-compatible profiles; SDK presence inside a worker or
   client does not make the SDK the runtime substrate.

## One-Line Doctrine

> **Mutual Blind minimizes what the node can know or do. HypervisorOS roots
> serious nodes under daemon policy and measurement. Private Workspace cTEE keeps
> protected plaintext off rented nodes by default. Enterprise Secure verifies
> where plaintext is allowed to exist.**

## Related Canon

- [`private-workspace-ctee.md`](./private-workspace-ctee.md): Private Workspace
  backed by cTEE, persistent rented GPU Hypervisor Nodes, private strategy
  execution, autonomy leases, and declassification gates.
- [`hypervisoros.md`](./hypervisoros.md): bare-metal Hypervisor node profile,
  measured boot, daemon-rooted workload launch, and node integrity receipts.
- [`default-harness-profile.md`](./default-harness-profile.md): daemon-executed
  orchestration profile.
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md):
  authority, decryption, key leases, and action power.
