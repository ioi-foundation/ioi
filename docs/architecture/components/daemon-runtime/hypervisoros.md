# HypervisorOS Profile

Status: canonical architecture authority.
Canonical owner: this file for bare-metal Hypervisor nodes, Type 1 substrate
mode for autonomous systems, measured node boot, daemon-rooted runtime control,
node integrity receipts, and HypervisorOS deployment profiles.
Supersedes: wording that treats Hypervisor only as a hosted IDE, local daemon,
Type-2 runtime, or cloud agent harness.
Superseded by: none.
Last alignment pass: 2026-07-21.
Doctrine status: canonical
Implementation status: speculative (bare-metal node profile design; no HypervisorOS build)
Last implementation audit: 2026-07-19

## Canonical Definition

Placement note: this file lives under `components/daemon-runtime/`
because HypervisorOS is a daemon-rooted node profile, but much of its
content is deployment/product posture. Read the runtime contract as
daemon-runtime canon and the product framing as estate context; it was
deliberately not moved to avoid churn on cross-references.

**HypervisorOS is the bare-metal execution profile for Hypervisor.**

It turns the Hypervisor Daemon into the root control plane of a physical or
virtual node, so agents, tools, model runtimes, workspaces, containers,
microVMs, WASM workers, and capability exits run under Hypervisor policy rather
than beside it.

Product language:

```text
HypervisorOS
Bare-metal nodes for governed private agent compute and autonomous
infrastructure management.
```

Canonical framing:

```text
Hypervisor App / Web / Developer Workspace
  hosted/private workspace clients and application surface

Hypervisor CLI/headless
  operator, developer, scripting, CI, and node-ops interface

Optional TUI
  interactive presentation over the CLI/headless client

Hypervisor Daemon
  process-level alignment runtime

HypervisorOS
  bare-metal node profile where the daemon is the node root

Hypervisor SDK
  agents, tools, workers, cTEE profiles, capability exits

IOI
  routing, receipts, settlement, disputes, app chains
```

HypervisorOS is Hypervisor's Type 1 substrate mode for autonomous systems and a
natural foundation for broader VM/container/microVM/WASM estate management. A
traditional Type 1 hypervisor runs directly on hardware and supervises guest
operating systems. HypervisorOS generalizes that posture to autonomous work: it
gets beneath machine, VM, container, sandbox, model-runtime, tool, workspace,
authority, and receipt execution while keeping ordinary machine workloads under
the same daemon-rooted control doctrine.

## Owns

HypervisorOS owns:

```text
bare-metal Hypervisor node profile
measured node boot posture
minimal node image doctrine
daemon-rooted workload launch
VM/container/microVM/WASM workload launch posture
node integrity receipts
boot profile manifests
runtime substrate selection under the daemon
node egress/control policy
HypervisorOS conformance checks
```

## Does Not Own

HypervisorOS does not own:

```text
canonical runtime semantics, which belong to Hypervisor Daemon
loop-native orchestration, which belongs to the Default Harness Profile
privacy/no-plaintext-custody, which belongs to Private Workspace backed by cTEE
authority, secrets, and decryption, which belong to wallet.network
admitted operational truth, which belongs to Agentgres
payload bytes, which belong to storage backends
external public/economic/cross-domain settlement, which belongs to the
system's explicitly selected service; IOI L1 is optional
```

## Core Doctrine

```text
Type 1 substrate mode:
  HypervisorOS / appliance / cluster profile where the daemon is node root

Type 2 substrate mode:
  Hypervisor Desktop / Workstation hosted on an existing OS for local
  VMs, sandboxes, models, tools, agents, connectors, and environments

Type 3 autonomy mode:
  autonomy virtualization across sessions, WorkRuns, workers, model routes,
  tools, authority, receipts, replay, outcomes, and promotion

Firmware Hypervisor:
  optional future profile using UEFI / TPM / pre-OS hooks
```

HypervisorOS does not begin by cloning VMware or ESXi feature-for-feature. The
first implementation may use a minimal Linux/KVM/microVM base. The canonical
property is that **all autonomous workloads are subordinate to the Hypervisor
Daemon**, and ordinary machine, VM, container, microVM, WASM, sandbox, model
server, and device workloads can become governed provider and environment
primitives under the same node-root doctrine.

The long-term infrastructure path is therefore natural:

```text
HypervisorOS
  daemon-rooted node profile
  -> VMs / containers / microVMs / WASM workloads / model servers
  -> Hypervisor Environments management
  -> private workspaces, authority scopes, receipts, replay, and service outcomes
```

HypervisorOS should also make conventional hypervisor substrate control legible.
An operator evaluating HypervisorOS should be able to find:

```text
node / host inventory
provider and placement domains
runtime classes: VM, microVM, container, WASM, model server
CPU / GPU / memory / storage / network capacity
image, recipe, boot profile, and runtime package versions
network, egress, firewall, connector, and device posture
storage classes, artifact stores, checkpoint and restore targets
tasks, events, logs, health, alerts, and lifecycle status
permissions, policy, audit, and node integrity receipts
```

These controls feed Environments, Operations, Governance, Provenance, and
HypervisorOS node detail views. They should not become a separate clone of a
legacy virtualization product, but they must be visible enough that
infrastructure users recognize HypervisorOS as a real substrate-control surface.

## Non-Claims

HypervisorOS does not claim:

```text
consumer GPUs become confidential hardware
boot measurement makes plaintext private from root
a bare-metal image replaces cTEE no-plaintext-custody
a node owner cannot physically tamper with hardware
arbitrary private LLM inference becomes safe merely because HypervisorOS booted
all metadata, timing, resource, or scheduling leakage disappears
```

HypervisorOS improves **control, integrity, containment, measurement,
reproducibility, and policy enforcement**.

cTEE remains the privacy doctrine:

```text
protected workspace state must not become provider-readable plaintext
unless explicitly declassified or routed through an approved confidential profile
```

## Threat Model

HypervisorOS assumes a node may be operated by a user, provider, marketplace
worker, DePIN participant, enterprise, or customer environment.

Adversaries may attempt to:

```text
tamper with boot image
modify daemon binaries
bypass workspace routing
mount protected files as plaintext
exfiltrate logs, traces, caches, prompts, and artifacts
execute unreceipted work
replay old leases
forge node measurements
return fake work for payment
run unauthorized models or tools
self-grant capabilities
avoid slashing or dispute evidence
```

HypervisorOS primarily defends by:

```text
measured boot
minimal base image
daemon-rooted workload launch
policy-typed model/tool mounts
mandatory cTEE routing for protected classes
capability exits
receipt sinks
network egress control
revocation epochs
node measurements
workspace conformance checks
settlement-grade logs
```

## Required Stack

```text
Hardware / VM host
  CPU, GPU, storage, networking

Measured boot layer
  firmware, secure boot, TPM or equivalent measurement path where available

Minimal HypervisorOS base
  small OS image, locked package set, reproducible runtime manifest

Hypervisor Daemon
  PID 1 or root control service
  owns node policy, scheduling, receipts, mounts, workers, exits

Worker substrate
  microVMs, containers, WASM, model servers, tool runners

cTEE runtime profile
  Open Private Workspace, Plaintext-Free Runtime Mounting,
  Plaintext-Free Model Mounting, AlphaSeal, leakage profiles,
  declassification gates

Agentgres
  state roots, operation log, receipts, restore truth

wallet.network / Guardian
  keys, authority leases, declassification, capability signing

IOI L1 / app chains
  sparse commitments, routing, staking, disputes, settlement
```

## Execution Model

HypervisorOS boots into a node state where the daemon controls all autonomous
workloads.

```text
Hardware
  -> measured boot
  -> minimal HypervisorOS
  -> Hypervisor Daemon
  -> worker substrate
  -> agents / models / tools / private workspaces
  -> receipts / capability exits / settlement
```

No agent, model runtime, shell, tool, or workspace mount should bypass the
daemon.

## Deployment Profiles

### Hosted Profile

```text
Existing OS
  -> Hypervisor Daemon
    -> agents, tools, model runtimes
```

Use for:

```text
developer machines
cloud VMs
ordinary local installs
early DePIN nodes
IDE/CLI adoption
```

This is the Type-2 autonomous-systems profile.

### Bare-Metal Profile

```text
Hardware
  -> minimal HypervisorOS
    -> Hypervisor Daemon as root control plane
      -> microVMs / containers / WASM / model servers
```

Use for:

```text
serious runtime nodes
persistent rented GPU nodes
marketplace workers
enterprise private runners
high-integrity agent nodes
```

This is the Type 1 substrate mode for autonomous-systems infrastructure.

### Firmware Profile

```text
UEFI / TPM / pre-OS hook
  -> HypervisorOS loader
    -> daemon-rooted node
```

Use for future higher-integrity node attestation, early control, and
appliance-grade deployments.

Firmware Profile is optional. HypervisorOS should not require firmware work to
ship its first useful bare-metal form.

### Cluster And Bounded-DAS Membership

`HypervisorOS / appliance / cluster` describes the substrate-control form, not
an implicit autonomous-system cluster. A measured, daemon-rooted node is only a
candidate until the target logical system completes:

```text
identify and attest -> propose membership -> govern role assignment
-> verify constitution/package/profile -> restore checkpoint -> catch up log
-> verify root -> establish lease/epoch/fence -> ready
```

Drain and removal similarly revoke role leases, reconcile work, persist required
state/evidence, update membership roots, and fence any former writer before the
node leaves. A HypervisorOS node may participate in multiple systems under
separate memberships. Boot integrity never grants system authority, proves
failure independence, or changes ordering/finality. Cluster auto-scaling may
provision candidates and scale non-authority roles, but authority-bearing role
changes remain governed (`INV-22` through `INV-24`).

## Required Runtime Controls

HypervisorOS must enforce:

```text
all workspace mounts go through Hypervisor policy
all model mounts use Plaintext-Free Model Mounting when protected classes exist
all private files remain encrypted, redacted, sealed, guardian-mediated, or explicitly declassified
all tools run under declared capability scope
all network egress is policy-bound and receipted
all external actions go through capability exits
all state mutations commit to Agentgres
all long-running autonomy uses AutonomyLease
all node measurements produce NodeMeasurementReceipt
all protected runs emit required cTEE receipts
```

## Node Enforcement Profile

HypervisorOS should expose a `NodeEnforcementProfile` for below-harness control
and detection. This profile constrains ordinary workloads, model servers,
tools, shells, browser automation, and adapters before they become durable
effects.

The profile may include:

```text
daemon gates
sandbox profiles
seccomp / syscall filters
LSM / eBPF detection hooks where available
network proxy and egress policy
executable allow/deny policy
hash/signature/path policy
datawall / leakage detectors
log and support-bundle redaction
cTEE / Private Workspace custody checks
hardware TEE attestation checks where available
```

A conformant profile does not require a custom OS kernel module. Daemon gates,
brokers, proxies, sandboxing, and platform-native user-space controls are the
portable baseline. `seccomp`, eBPF, LSM, custom privileged hooks, or equivalent
platform mechanisms are optional, platform-qualified defenses for managed or
high-assurance nodes. A profile may claim only the mechanism and coverage its
deployment can verify; the presence of one privileged hook must not be
generalized into universal interception, prevention, attribution, or receipt
coverage.

Every profile declares the exact action-class/surface scopes and coverage
posture its deployment requires. The admitted deployment evidence set must then
carry one registered [`EnforcementCoverageDeclaration`](../../_meta/schemas/enforcement-coverage-declaration.v1.schema.json)
for every advertised or required scope, including an explicitly uncovered
scope. The declaration binds the exact profile or adapter revision and content
hash, implementation, deployment profile, platform, mechanism versions,
privilege, bypass assumptions, availability/failure posture, decision source,
final invoker, receipt scope, verification method, evidence, freshness, gaps,
and limitations. It is a typed evidence snapshot, not a policy, authority,
execution, admission, or truth owner.

The six capability claims -- `discovered`, `observable`, `attributable`,
`mediated`, `preventable`, and `receipted` -- are assessed independently rather
than treated as one cumulative assurance rank. `discovered` does not imply
`observable`; `observable` does not imply `attributable` or `mediated`;
`attributable` does not imply `mediated`; and `mediated` does not imply
`preventable`. `receipted` means only that the receipt proves its bound
observation, decision, or effect under the applicable receipt contract. It does
not by itself prove the assertion correct or establish mediation or prevention.
Every positive capability claim names a mechanism with the corresponding role
and cites verification evidence.

`uncovered: true` is the mutually exclusive terminal state for one exact scope:
none of the six capability claims may be positive in that declaration. A
partially covered scope instead keeps the unsupported claims false or `unknown`
and records its `known_gaps` and limitations. Mixed paths must be split into
narrower declarations rather than summarized as fully controlled. `unknown`
never inherits `true` from a neighboring declaration or a higher-assurance
deployment, and `uncovered` never becomes a global label for the node.

The consuming deployment evidence or operability index must bind the exact
declaration artifact ref and content hash. A status, freshness, evidence, or
claim change produces a newly content-bound snapshot; it must not mutate a
previously retained declaration in place. Schema validity alone does not prove
that a runtime evaluator emitted, verified, admitted, or currently relies on
the declaration.

This is not a privacy substitute for cTEE. It is the node-control and evidence
layer that blocks, detects, records, and receipts unsafe behavior such as
unmanaged executable launches, unscoped egress, private-data leakage attempts,
or daemon-bypass attempts.

## Minimal Implementation Objects

```yaml
HypervisorOSNode:
  node_id: runtime://...
  profile: hypervisoros_bare_metal
  owner_ref: wallet://... | provider://...
  daemon_ref: runtime://...
  boot_profile_ref: boot_profile://...
  measurement_policy_ref: measurement_policy://...
  ctee_policy_ref: policy://...
  node_enforcement_profile_ref: node_enforcement://... | null
  agentgres_domain_ref: agentgres://domain/...
  supported_worker_substrates:
    - vm
    - microvm
    - container
    - wasm
    - model_server
  supported_mount_profiles:
    - public_mount
    - redacted_mount
    - plaintext_free_model_mount
    - ctee_private_workspace
  forbidden_bypasses:
    - direct_plaintext_private_mount
    - unreceipted_tool_execution
    - raw_secret_env_injection
    - daemonless_model_server
    - unscoped_network_egress
  receipts_required:
    - HypervisorOSBootReceipt
    - NodeMeasurementReceipt
    - ModelMountReceipt
    - PrivateInferenceReceipt
    - CapabilityExitReceipt
    - ExecutableDeniedReceipt
    - EgressDetectionReceipt
```

```yaml
HypervisorOSBootProfile:
  boot_profile_id: boot_profile://...
  image_hash: sha256:...
  kernel_hash: sha256:...
  initrd_hash: sha256:...
  daemon_binary_hash: sha256:...
  package_manifest_hash: sha256:...
  driver_manifest_hash: sha256:...
  gpu_profile:
    class: consumer | datacenter | confidential_capable
    model_hint: rtx_3090 | rtx_4090 | h100 | other
  secure_boot:
    enabled: true | false | policy_declared
  tpm_measurement:
    enabled: true | false | unavailable
  attestation_assurance:
    appraisal_policy_ref: policy://...
    required_posture:
      trusted_operator | software_only | measured_boot | secure_element |
      cpu_tee | gpu_confidential_compute |
      cpu_tee_and_gpu_confidential_compute
    trusted_endorsement_refs:
      - endorsement://...
    trusted_reference_value_refs:
      - reference://...
    maximum_appraisal_age_ms: integer
    maximum_reattestation_interval_ms: integer
  update_policy:
    signed_updates_required: true
    rollback_protection_profile_ref: policy://...
    rollback_domain_ref: failure-domain://...
    protected_namespace_floor_kind: signed_update_version_and_image_head
    reanchor_after_boot_restore_or_replacement: required | policy_bounded
```

```yaml
HypervisorOSBootReceipt:
  receipt_id: receipt://...
  node_id: runtime://...
  boot_epoch: integer
  boot_profile_ref: boot_profile://...
  workload_identity: workload://...
  image_hash: sha256:...
  daemon_binary_hash: sha256:...
  policy_build_hash: sha256:...
  package_manifest_hash: sha256:...
  driver_manifest_hash: sha256:...
  measurement_method:
    secure_boot | tpm_quote | reproducible_image |
    provider_attestation | policy_declared
  privacy_claim:
    none | no_plaintext_custody | tee_attested
  attestation_assurance:
    attester_ref: runtime://...
    verifier_ref: verifier://...
    appraiser_ref: appraiser://...
    relying_party_ref: runtime://... | authority://...
    nonce: string
    nonce_single_use_status:
      consumed_for_this_appraisal | already_consumed | unverified
    nonce_consumption_receipt_ref: receipt://... | null
    endorsement_refs:
      - endorsement://...
    reference_value_refs:
      - reference://...
    appraisal_policy_ref: policy://...
    appraisal_result_ref: appraisal://... | null
    appraisal_status: pass | fail | indeterminate
    appraised_at: timestamp
    appraisal_expires_at: timestamp
    effective_posture:
      unverified | trusted_operator | software_only | measured_boot |
      secure_element | cpu_tee | gpu_confidential_compute |
      cpu_tee_and_gpu_confidential_compute
    hardware_or_measured_attested: boolean
    lease_ref: lease://... | null
    lease_expires_at: timestamp | null
    revocation_epoch: integer | null
    revocation_status: current | revoked | unverified
    revocation_check_receipt_ref: receipt://... | null
    reattest_by: timestamp
  temporal_state:
    temporal_verification_profile_ref: policy://...
    temporal_verification_profile_hash: sha256:...
    temporal_validity_evaluation_ref: evidence://... | receipt://...
    temporal_validity_evaluation_hash: sha256:...
    rollback_domain_ref: failure-domain://...
    continuity_floor_evidence_refs:
      - evidence://... | receipt://...
  note: "Boot measurement is an integrity receipt, not a consumer-GPU plaintext privacy guarantee."
  signature: ...
```

The nested assurance block extends the existing boot receipt; it is not a
parallel node-attestation registry. The runtime-node owner defines role
separation, freshness, appraisal, exact evidence-kind requirements, and
deterministic narrowing. `privacy_claim: tee_attested` is permitted only when
the effective posture contains the required CPU/TEE or GPU confidential-compute
evidence and the deployment's separate privacy policy permits that claim.
Measured boot, TPM presence, secure element, software measurement, and trusted
operator posture never imply plaintext confidentiality on their own.
They also do not establish rollback-resistant freshness by themselves.
`boot_epoch`, appraisal/lease timestamps, and `revocation_epoch` remain
owner-scoped evidence. A claimed non-regressing update, key, revocation,
appraisal, or boot posture requires the exact
`TemporalVerificationProfile` and `TemporalValidityEvaluation`, plus a
namespace floor outside the declared rollback domain or fresh independent
re-anchoring. A boot receipt restored with its verifier state can retain
historical integrity without proving currentness.

```yaml
NodeEnforcementProfile:
  profile_id: node_enforcement://...
  revision_ref: node_enforcement://.../revision/...
  version: 1.0.0
  content_hash: sha256:...
  node_id: runtime://...
  enforcement_layers:
    - daemon_gate
    - sandbox
    - seccomp
    - ebpf
    - lsm
    - network_proxy
    - datawall
    - ctee_policy
    - tee_attestation
  enforcement_coverage_contract_ref: schema://ioi/components/daemon-runtime/enforcement-coverage-declaration/v1
  enforcement_scope_refs:
    - enforcement-scope://.../shell/process-spawn
  enforcement_coverage_requirement_policy_ref: policy://...
  enforcement_coverage_freshness_policy_ref: policy://...
  executable_policy:
    mode:
      allowlist | denylist | signed_only | policy_declared
    allowed_hashes:
      - sha256:...
    denied_hashes:
      - sha256:...
    rename_resistant: true
  egress_policy:
    default: deny | policy_declared | allow
    allowed_destinations:
      - destination://...
    private_subnet_block: true
    dns_rebinding_guard: true
    receipt_required: true
  datawall_policy:
    protected_classes:
      - pii
      - strategy_source
      - broker_credentials
      - private_memory
    detection_only: true | false
    block_on_match: true | false
  receipt_refs:
    - receipt://...
```

## Daemon Execution-Root Rule

HypervisorOS is conformant only if the Hypervisor Daemon is the root admission,
enforcement, and execution boundary for autonomous work. Policy and the
applicable authority provider authorize; the daemon does not originate that
authority.

```text
Conformant:
  boot -> daemon -> worker -> model/tool/agent

Non-conformant:
  boot -> unmanaged shell/model/tool bypassing daemon
```

The daemon must be able to deny, terminate, quarantine, or mark unsafe any
workload that bypasses:

```text
workspace classification
model mount policy
capability exits
receipt generation
network policy
leakage profile
AutonomyLease
```

## cTEE Compatibility

HypervisorOS must natively support cTEE.

Required cTEE integrations:

```text
Open Private Workspace
Plaintext-Free Runtime Mounting
Plaintext-Free Model Mounting
PrivateWorkspaceCapsule
AlphaSeal
AutonomyLease
DeclassificationGate
CapabilityExit
PrivateInferenceReceipt
LeakageReceipt
NodeMeasurementReceipt
DeterrenceDetectionReceipt
```

Plaintext-Free Model Mounting is especially important. It exposes private
workspaces to model runtimes through public/redacted content, encrypted refs,
private handles, declassification requests, and capability exits rather than
provider-readable plaintext.

## Node Measurement Doctrine

Node measurement is useful for:

```text
integrity
compatibility
accounting
reproducibility
dispute handling
provider reputation
settlement qualification
```

Node measurement is not sufficient for:

```text
plaintext privacy on consumer GPUs
trusting a provider with raw strategy source
trusting a node with broker credentials
bypassing cTEE
bypassing wallet.network
claiming arbitrary private LLM inference
```

Correct doctrine:

```text
Measurement proves what was supposed to run.
cTEE limits what the node is allowed to see.
wallet.network limits what the node is allowed to do.
Agentgres proves what the node claimed happened.
The system settles locally or invokes its selected external settlement and
dispute services from receipts; IOI L1 is one optional service set.
```

## Network and Action Policy

HypervisorOS must default to denied egress for autonomous workloads.

Permitted egress requires:

```text
declared destination
declared tool schema
capability scope
receipt requirement
leakage classification
AutonomyLease check if unattended
revocation epoch check
```

External effects include:

```text
broker orders
wallet transactions
API writes
email sends
deployments
file exports
secret reveals
database mutations
model/tool marketplace calls
```

Every external effect must cross a `CapabilityExit`.

## Persistent Node Behavior

HypervisorOS supports persistent autonomy without granting raw secrets to the
node.

```yaml
PersistentHypervisorOSNode:
  node_id: runtime://...
  autonomy_mode: bounded
  lease_ref: autonomy_lease://...
  allowed_while_user_offline:
    - refresh_public_data
    - run_public_model_inference
    - update_encrypted_state
    - request_or_run_alpha_seal_through_approved_private_operator
    - propose_action_intent
    - draft_redacted_report
  forbidden_without_step_up:
    - reveal_pii
    - reveal_strategy_source
    - export_private_memory
    - widen_authority_scope
    - execute_unbounded_action
  freshness:
    revocation_epoch_required: true
    temporal_verification_profile_ref: policy://...
    temporal_validity_evaluation_required: true
    continuity_floor_or_fresh_reanchor_required_after:
      - reboot
      - restore
      - rollback_suspected
      - node_replacement
    lease_check_required_before:
      - model_mount
      - private_head_eval
      - declassification
      - capability_exit
```

Persistent autonomy inherits the bounded-offline contract of the selected
temporal profile: exact allowed operations, elapsed/boot continuity, maximum
holdover and revocation exposure, effect/call budgets, and reconnect
revalidation. A local lease, revocation epoch, wall clock, or signed boot
receipt alone cannot extend that envelope. Lost continuity narrows the node to
the profile's safe local inspection/proposal behavior until re-anchored; it
cannot mint authority or pass a `CapabilityExit`.

## Admission / Settlement Boundary

HypervisorOS measurements, workload receipts, cTEE receipts, and capability-exit
receipts are admitted into Agentgres when they affect restore, replay,
provider reputation, delivery, dispute, payout, or marketplace settlement.

The declared external settlement profile receives only selected roots, receipt
commitments, dispute commitments, registry state, staking claims, slashing
evidence, or economic settlement state. IOI L1 requires an active enrollment
that selected the service; no external rail may receive private workspace
payloads.

Non-IOI adopters may bind the same concept to an equivalent StateLog, but the
IOI canon uses Agentgres for admitted operational truth.

## Events and Receipts

HypervisorOS may emit:

```text
hypervisoros.boot.started
hypervisoros.boot.measured
hypervisoros.boot.failed
hypervisoros.node.ready
hypervisoros.node.quarantined
hypervisoros.workload.blocked
hypervisoros.egress.blocked
hypervisoros.egress.detected
hypervisoros.executable.denied
hypervisoros.datawall.detected
```

Required receipt families:

```text
HypervisorOSBootReceipt
NodeMeasurementReceipt
ModelMountReceipt
PrivateInferenceReceipt
CapabilityExitReceipt
AutonomyLeaseReceipt
DeterrenceDetectionReceipt
ExecutableDeniedReceipt
EgressDetectionReceipt
DataLeakageIncidentReceipt
```

## Conformance Checks

A HypervisorOS implementation conforms when:

```text
1. The daemon is the root control plane for agents, models, tools, workspaces, and exits.
2. No autonomous workload can bypass daemon policy.
3. Protected workspace classes cannot be mounted as provider-readable plaintext by default.
4. Plaintext-Free Model Mounting is required for protected model work.
5. All external effects require CapabilityExit.
6. All persistent autonomy requires AutonomyLease.
7. Node boot/runtime state emits measurement receipts.
8. Worker execution emits receipts bound to policy, inputs, outputs, and state roots.
9. Network egress is scoped, logged, and receipted.
10. Unsafe plaintext paths are blocked or visibly marked Unsafe.
11. cTEE privacy claims are not made from boot measurement alone.
12. A declared external settlement service receives only sparse selected
    commitments and receipts, never private payloads; IOI L1 requires explicit
    enrollment.
13. Node enforcement profiles are declared for executable launch, egress,
    datawall, log/export, and daemon-bypass detection on managed nodes.
14. Startup admission binds workload, daemon/policy builds, nonce single use,
    endorsements/reference values, appraisal policy/result, lease/revocation
    state, and re-attestation cadence to the required posture.
15. Rejected stronger evidence deterministically narrows to eligible evidence;
    software-only/trusted-operator continuity is never rendered as a hardware
    or measured attestation claim.
```

## Anti-Patterns

Do not:

```text
market HypervisorOS as making a rented 3090 confidential compute
treat measured boot as a substitute for no-plaintext-custody
allow unmanaged model servers beside the daemon
allow raw secrets in environment variables
mount private repos as plaintext on provider nodes
let nodes self-grant authority
let providers disable receipt sinks
settle work with no input/output commitments
let renamed binaries bypass executable policy
treat unscoped outbound network access as ordinary shell behavior
treat datawall detections as optional debug logs
treat a self-reported quote or provider badge as an appraisal result
reuse a nonce, appraisal result, or lease across workloads or daemon/policy builds
retain a stronger posture after appraisal expiry, revocation, or missed re-attestation
treat HypervisorOS as requiring a custom hardware hypervisor from day one
treat HypervisorOS as permanently unrelated to VM/container/microVM/WASM estate management
collapse guardian, wallet authority, and untrusted GPU node into one root-controlled provider box
```

## Product UX

For users:

```text
HypervisorOS
Bare-metal nodes for governed private agent compute.
```

For node operators:

```text
Boot a measured HypervisorOS image.
Attach GPU.
Run public trunks.
Never custody protected plaintext by default.
Earn from receipted work.
```

For developers:

```text
Build once against the Hypervisor SDK.
Run hosted through Hypervisor App, Hypervisor Web, Developer Workspace, or CLI/headless.
Promote to HypervisorOS for bare-metal nodes.
Settle locally by default; connect selected shared-trust services through the
IOI Network only when valuable.
```

For quant users:

```text
Rent the node. Keep the alpha.
```

## Related Canon

- [`doctrine.md`](./doctrine.md): Hypervisor Daemon and IOI CLI runtime
  ownership.
- [`runtime-nodes-tee-depin.md`](./runtime-nodes-tee-depin.md): runtime-node,
  hosted, DePIN, TEE, and execution privacy doctrine.
- [`private-workspace-ctee.md`](./private-workspace-ctee.md): Private
  Workspace backed by cTEE, no-plaintext-custody, private strategy execution,
  and capability exits.
- [`default-harness-profile.md`](./default-harness-profile.md):
  HarnessProfile semantics and Default Harness Profile reference
  scaffold/fallback behavior.
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md):
  wallet.network authority, decryption, approvals, and leases.
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md): canonical operational
  truth and receipts.

## Final Canonical Line

> **HypervisorOS is the bare-metal profile for Hypervisor: a measured,
> daemon-rooted node image where agents, models, tools, private workspaces, and
> external actions run beneath Hypervisor policy, cTEE no-plaintext-custody,
> Agentgres receipts, wallet.network authority, local settlement by default,
> and only explicitly selected external settlement services.**
