# HypervisorOS Profile

Status: canonical architecture authority.
Canonical owner: this file for bare-metal Hypervisor nodes, Type 1 substrate
mode for autonomous systems, measured node boot, daemon-rooted runtime control,
node integrity receipts, and HypervisorOS deployment profiles.
Supersedes: wording that treats Hypervisor only as a hosted IDE, local daemon,
Type-2 runtime, or cloud agent harness.
Superseded by: none.
Last alignment pass: 2026-06-07.
Doctrine status: canonical
Implementation status: speculative (bare-metal node profile design; no HypervisorOS build)
Last implementation audit: 2026-07-05

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
Hypervisor App / Web / Workbench
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
public/economic/cross-domain settlement, which belongs to IOI L1 by trigger
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

These controls feed Environments, Operations, Governance, Work Ledger, and
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
  update_policy:
    signed_updates_required: true
    rollback_protection: true
```

```yaml
HypervisorOSBootReceipt:
  receipt_id: receipt://...
  node_id: runtime://...
  boot_epoch: integer
  boot_profile_ref: boot_profile://...
  image_hash: sha256:...
  daemon_binary_hash: sha256:...
  package_manifest_hash: sha256:...
  driver_manifest_hash: sha256:...
  measurement_method:
    secure_boot | tpm_quote | reproducible_image |
    provider_attestation | policy_declared
  privacy_claim:
    none | no_plaintext_custody | tee_attested
  note: "Boot measurement is an integrity receipt, not a consumer-GPU plaintext privacy guarantee."
  signature: ...
```

```yaml
NodeEnforcementProfile:
  profile_id: node_enforcement://...
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

## Daemon Root Rule

HypervisorOS is conformant only if the Hypervisor Daemon is the root authority
for autonomous execution.

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
IOI settles or disputes from receipts.
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
    lease_check_required_before:
      - model_mount
      - private_head_eval
      - declassification
      - capability_exit
```

## Admission / Settlement Boundary

HypervisorOS measurements, workload receipts, cTEE receipts, and capability-exit
receipts are admitted into Agentgres when they affect restore, replay,
provider reputation, delivery, dispute, payout, or marketplace settlement.

IOI L1 or compatible app-chain settlement receives only selected roots,
receipt commitments, dispute commitments, registry state, staking claims,
slashing evidence, or economic settlement state. It must not receive private
workspace payloads.

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
12. IOI settlement receives sparse commitments and receipts, not private payloads.
13. Node enforcement profiles are declared for executable launch, egress,
    datawall, log/export, and daemon-bypass detection on managed nodes.
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
Run hosted through Hypervisor App, Hypervisor Web, Workbench, or CLI/headless.
Promote to HypervisorOS for bare-metal nodes.
Settle through IOI.
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
> Agentgres receipts, wallet.network authority, and IOI settlement.**
