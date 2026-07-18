# Runtime Nodes, DePIN, TEE, and Execution Privacy Specification

Status: canonical architecture authority.
Canonical owner: this file for runtime-node and execution-privacy doctrine; low-level task capsule protocol lives in [`runtime-node-and-task-capsule-protocol.md`](./task-capsule-protocol.md).
Supersedes: overlapping hosted/DePIN/TEE prose when execution-venue boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: canonical
Implementation status: mixed (the local venue is real; structured RATS-role attestation evaluation, startup assurance narrowing, live quote drivers, attestation-bound leases/re-attestation, and TEE/DePIN/cTEE/embodied venue deployments remain target contracts)
Last implementation audit: 2026-07-16

## Canonical Definition

**Runtime nodes are execution venues that run Hypervisor Daemon profiles.**

They may be local, hosted, provider-operated, DePIN, HypervisorOS bare-metal,
Private Workspace cTEE, TEE-verified, or customer-controlled. They are not Web4
applications by default.

A runtime node may contain a lower-level runtime service bridge or worker SDK
helpers, but the node's architectural boot target is the Hypervisor Daemon runtime-node
profile. SDKs submit and control work as clients; they do not own node
execution.

Runtime-node eligibility and autonomous-system membership are distinct. A
machine becomes a member of one logical bounded DAS only through an
`AutonomousSystemNodeMembershipEnvelope` that scopes its roles, authority,
failure-domain evidence, epoch, lease, catch-up/root state, and readiness. The
same runtime node may execute unowned jobs, participate in several systems
under separate memberships, or participate in none. Provisioning, attestation,
or daemon health alone never creates system membership or writer authority.

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

1. **Local Hypervisor Daemon under Hypervisor App, Developer Workspace, or
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
9. **Embodied Runtime** — local or edge runtime profile for robot fleets,
   facility systems, drones, vehicles or vehicle-adjacent systems, and IoT
   actuator domains. It binds controller bridges, heartbeat/failsafe posture,
   sensor and actuator registries, world state, physical command queues,
   telemetry, replay, and operator handoff to the Hypervisor Daemon boundary.
   Physical actuator execution still requires Physical Action Safety,
   wallet.network authority, Agentgres receipts, and local emergency stop.

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
  task_id: task://123
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
→ optional IOI L1 contract update only if explicit enrollment and the selected
  settlement profile require it
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

## Attestation Assurance And TEE Flow

Runtime-node attestation follows the RATS role boundary. The **Attester**
produces evidence for one workload. A distinct **Verifier/Appraiser** verifies
evidence and endorsements against named reference values and an appraisal
policy. The **Relying Party** consumes only the signed appraisal result and
decides admission. An Attester self-report, boot log, provider badge, or
Relying-Party recomputation is not an appraisal result.

Every admitted attestation assurance evaluation binds:

```yaml
attestation_assurance:
  policy_ref: policy://...
  required_posture:
    trusted_operator | software_only | measured_boot | secure_element |
    cpu_tee | gpu_confidential_compute |
    cpu_tee_and_gpu_confidential_compute
  roles:
    attester_ref: runtime://...
    verifier_ref: verifier://...
    appraiser_ref: appraiser://...
    relying_party_ref: runtime://... | authority://...
  challenge:
    nonce: string
    single_use_status:
      consumed_for_this_appraisal | already_consumed | unverified
    consumption_receipt_ref: receipt://...
  workload_identity: workload://...
  daemon_build_hash: sha256:...
  policy_build_hash: sha256:...
  endorsement_refs:
    - endorsement://...
  reference_value_refs:
    - reference://...
  appraisal:
    policy_ref: policy://...
    result_ref: appraisal://...
    status: pass | fail | indeterminate
    appraised_at: timestamp
    expires_at: timestamp
  authority_state:
    lease_ref: lease://...
    lease_expires_at: timestamp
    revocation_epoch: integer
    revocation_status: current | revoked | unverified
    revocation_check_receipt_ref: receipt://...
  reattest_by: timestamp
```

The same workload, daemon build, policy build, lease, and revocation epoch must
be present in CPU/TEE, GPU confidential-compute, secure-element, measured-boot,
software-only, and trusted-operator evidence. Hardware or measured postures
additionally require trusted vendor/platform endorsements. Every posture
requires an admitted reference value appropriate to that posture; a
software-only reference value does not become a hardware endorsement.

An implementation evaluates eligible evidence in this deterministic projection
order:

```text
cpu_tee_and_gpu_confidential_compute
> gpu_confidential_compute
> cpu_tee
> secure_element
> measured_boot
> software_only
> trusted_operator
> unverified
```

This order selects one display/admission projection; it does not assert that
incomparable hardware technologies are substitutes. A deployment requirement
for `cpu_tee`, `gpu_confidential_compute`, `secure_element`, or `measured_boot`
is satisfied only by that exact evidence kind (the composite satisfies both CPU
and GPU requirements). Loss or rejection of stronger evidence recomputes the
strongest still-proven projection. Valid `software_only` or `trusted_operator`
evidence may therefore keep an explicitly compatible workload running, but the
result must set `hardware_or_measured_attested: false`.

Replay/already-consumed nonce, wrong workload identity, wrong daemon or policy
build, stale or rejected appraisal, untrusted endorsement/reference value,
missing or expired lease, revoked or stale revocation state, and overdue
re-attestation make the affected stronger evidence ineligible. The Relying
Party fails closed when no remaining eligible evidence satisfies its required
posture.

```text
Attester produces nonce-bound evidence
→ Verifier/Appraiser checks identity, builds, endorsements/reference values,
  lease/revocation state, freshness, and appraisal policy
→ Relying Party applies the deployment's exact minimum posture
→ wallet.network releases scoped keys only when its own authority gate also passes
→ worker executes inside the admitted posture
→ outputs and attestation/execution receipts bind the same workload and lease
```

Attestation proves only the named evidence, appraisal policy, and time window.
It does not itself grant authority, create runtime-node membership, prove
workload correctness, make consumer GPUs confidential, or determine legal
conformity.

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
10. Runtime placement, system membership, authority distribution, and
    ordering/finality are independent claims. Adding compute capacity never
    silently changes the latter three.

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
