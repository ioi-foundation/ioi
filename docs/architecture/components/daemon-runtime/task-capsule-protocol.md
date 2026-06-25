# Runtime Node and Task Capsule Protocol

Status: canonical low-level reference.
Canonical owner: this file for runtime assignment, task capsule, privacy-mode, TEE attestation, and remote result envelopes.
Supersedes: overlapping hosted/self-hosted worker protocol prose when capsule fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-13.

## Purpose

Runtime nodes are execution venues. They may be a local Hypervisor Daemon
managed by Hypervisor App, Hypervisor Web, CLI/headless clients, optional TUI
views, Workbench surfaces, or Environments views; hosted Hypervisor Daemon; provider node;
DePIN node; TEE-verified node; or customer VPC node. They execute task
capsules and return events, artifacts, and receipts.

Runtime nodes run Hypervisor Daemon-compatible profiles. A worker package may import
SDK helpers, and an operator may use the SDK to control the run, but the SDK is
not the compute-node execution substrate.

Training, evaluation, benchmark, and MoW routing jobs are task-capsule
compatible work. They use the same runtime assignment, authority, privacy, and
receipt boundaries as ordinary worker execution.

## Execution Privacy Modes

```text
local
hosted
customer_vpc
depin_mutual_blind
hypervisoros_bare_metal
tee_enterprise
```

## Mutual Blind Mode

No TEE required. The node receives minimum visible context and no final authority.

Security claim:

> The node never receives enough plaintext, durable context, or authority to matter.

Not claimed:

> The host cannot inspect RAM.

## HypervisorOS Bare-Metal Mode

Measured daemon-rooted node profile. The node must boot a HypervisorOS image,
emit boot/measurement receipts, and route all autonomous workloads through the
Hypervisor Daemon.

Security claim:

> The node ran under declared daemon-rooted control, measurement, egress policy,
> and receipt obligations.

Not claimed:

> Boot measurement alone makes consumer GPU plaintext private.

## Enterprise Secure Mode

TEE required. The node must provide attestation before wallet.network releases sealed secrets or private input keys.

Security claim:

> Sensitive data and worker IP may exist remotely only inside verified confidential compute.

## Runtime Assignment

```json
{
  "assignment_id": "assign_123",
  "run_id": "run_123",
  "compute_session_id": "compute_session_123",
  "daemon_profile": "hosted_ioi | provider | depin | hypervisoros | tee | customer_vpc | local",
  "runtime_bridge_profile": "fixture | runtime_service",
  "node_requirements": {
    "privacy_mode": "depin_mutual_blind | hypervisoros_bare_metal | tee_enterprise",
    "resources": {"cpu": 8, "memory_gb": 32, "gpu": false},
    "max_latency_ms": 2000
  },
  "package_refs": ["cid://worker_bundle"],
  "task_capsule_ref": "agentgres://task_capsules/cap_123",
  "worker_package_refs": ["cid://worker_bundle"],
  "verification_requirements": ["execution_receipt", "artifact_hash", "policy_hash"],
  "training_refs": {
    "training_spec_ref": "optional",
    "benchmark_profile_ref": "optional",
    "evaluation_rubric_ref": "optional"
  },
  "payment": {
    "quote": "5 IOI",
    "escrow_ref": "0x..."
  }
}
```

## ComputeSession

```json
{
  "compute_session_id": "compute_session_123",
  "assignment_id": "assign_123",
  "venue": "local | hosted | provider | depin | hypervisoros | tee | customer_vpc",
  "substrate": "process | container | vm | microvm | wasm | browser_sandbox | gpu_job | tee_enclave",
  "daemon_profile": "hosted_ioi",
  "runtime_node_id": "runtime://node_abc",
  "lifecycle": "cold | warming | ready | running | draining | idle | suspended | destroyed",
  "authority_grants": ["grant://..."],
  "state_checkpoint_policy": "none | periodic | terminal | zero_to_idle",
  "created_at": "2026-05-01T00:00:00Z",
  "expires_at": "2026-05-01T00:15:00Z"
}
```

The substrate may be a VM, container, browser sandbox, GPU job, TEE enclave, or
local process. The architectural unit is the compute session plus daemon
profile, not the VM by itself.

## TaskCapsule

```json
{
  "capsule_id": "cap_123",
  "run_id": "run_123",
  "task_id": "task_123",
  "work_item_ref": "hypervisor_work_item:optional",
  "work_run_ref": "hypervisor_work_run:optional",
  "work_queue_ref": "hypervisor_work_queue:optional",
  "worker_id": "ai://workers.runtime-auditor.ioi",
  "code_context": {
    "project_ref": "project:optional",
    "repository_refs": ["repo://optional"],
    "environment_ref": "hypervisor_environment_lifecycle:optional",
    "pull_request_ref": "scm_pr://optional"
  },
  "visible_context": [
    {"type": "text", "value": "redacted objective"},
    {"type": "artifact_ref", "ref": "artifact://redacted_input"}
  ],
  "hidden_context_classes": ["raw_secret", "payment_profile", "full_private_memory"],
  "allowed_actions": ["compute", "transform", "propose_patch", "render"],
  "forbidden_actions": ["send", "spend", "publish", "sign", "settle_state", "secret_export"],
  "output_contract": {
    "type": "artifact_plus_receipt",
    "schema_ref": "cid://schema",
    "required_receipts": ["execution"]
  },
  "review_contract_ref": "review_contract://optional",
  "conversation_projection_ref": "hypervisor_work_run_conversation:optional",
  "transcript_ref": "artifact://optional",
  "integration_status_refs": ["hypervisor_work_run_integration_status:optional"],
  "ttl_seconds": 900,
  "watermark": {
    "execution_id": "exec_123",
    "node_id": "node_abc"
  }
}
```

Work refs are optional because not every low-level runtime task is delegated
agent work. When present, they bind the capsule to Hypervisor's durable product
objects without giving the runtime node extra authority. The runtime node may
emit outputs, proposed patches, delivery refs, observations, and receipts; the
daemon, wallet.network, verifier path, and Agentgres decide what becomes
admitted truth.

## TEE Attestation Envelope

```json
{
  "attestation_id": "attest_123",
  "runtime_id": "runtime://node_abc",
  "provider": "eigen | sgx | sev | nitro | other",
  "measurement": "sha256:...",
  "runtime_manifest_hash": "sha256:...",
  "worker_manifest_hash": "sha256:...",
  "quote": "base64...",
  "verifier_profile": "attestation_profile_1",
  "valid_until": "2026-05-01T00:00:00Z"
}
```

## Secret Release Rule

```text
Mutual Blind:
  wallet.network may release non-secret handles only.

Enterprise Secure:
  wallet.network may release sealed task key only after attestation verifies:
    runtime measurement
    worker hash
    policy hash
    expiry
    node identity
```

## Result Envelope

```json
{
  "run_id": "run_123",
  "capsule_id": "cap_123",
  "node_id": "node_abc",
  "status": "completed | failed",
  "output_artifacts": ["artifact://..."],
  "proposed_patches": ["patch://..."],
  "delivery_refs": ["pull_request://optional"],
  "review_state_ref": "hypervisor_work_run_review_state:optional",
  "conversation_projection_ref": "hypervisor_work_run_conversation:optional",
  "transcript_ref": "artifact://optional",
  "receipts": ["receipt://execution_123"],
  "logs_ref": "artifact://redacted_logs",
  "attestation_ref": "optional"
}
```

## Non-Negotiables

1. Remote nodes produce proposed outputs; trusted verifier/Agentgres settle.
2. Mutual Blind nodes cannot receive raw secrets or final-effect authority.
3. Enterprise Secure nodes require attestation before sensitive key release.
4. Every remote run must emit execution receipts and artifact commitments.
5. Stolen capsules should be non-transferable: expiring, watermarked, authority-grant-bound, primitive-capability-constrained, and useless outside settlement path.
6. Runtime assignment must name a daemon/runtime-node profile and verification
   path; it must not imply that the SDK is the runtime owner.
