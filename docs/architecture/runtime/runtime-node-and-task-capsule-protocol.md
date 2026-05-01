# Runtime Node and Task Capsule Protocol

Status: canonical low-level reference.
Canonical owner: this file for runtime assignment, task capsule, privacy-mode, TEE attestation, and remote result envelopes.
Supersedes: overlapping hosted/self-hosted worker protocol prose when capsule fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

Runtime nodes are execution venues. They may be local Autopilot, hosted IOI daemon, provider node, DePIN node, TEE-verified node, or customer VPC node. They execute task capsules and return events, artifacts, and receipts.

## Execution Privacy Modes

```text
local
hosted
customer_vpc
depin_mutual_blind
tee_enterprise
```

## Mutual Blind Mode

No TEE required. The node receives minimum visible context and no final authority.

Security claim:

> The node never receives enough plaintext, durable context, or authority to matter.

Not claimed:

> The host cannot inspect RAM.

## Enterprise Secure Mode

TEE required. The node must provide attestation before wallet.network releases sealed secrets or private input keys.

Security claim:

> Sensitive data and worker IP may exist remotely only inside verified confidential compute.

## Runtime Assignment

```json
{
  "assignment_id": "assign_123",
  "run_id": "run_123",
  "node_requirements": {
    "privacy_mode": "depin_mutual_blind | tee_enterprise",
    "resources": {"cpu": 8, "memory_gb": 32, "gpu": false},
    "max_latency_ms": 2000
  },
  "package_refs": ["cid://worker_bundle"],
  "task_capsule_ref": "agentgres://task_capsules/cap_123",
  "payment": {
    "quote": "5 IOI",
    "escrow_ref": "0x..."
  }
}
```

## TaskCapsule

```json
{
  "capsule_id": "cap_123",
  "run_id": "run_123",
  "task_id": "task_123",
  "worker_id": "ai://workers.runtime-auditor.ioi",
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
  "ttl_seconds": 900,
  "watermark": {
    "execution_id": "exec_123",
    "node_id": "node_abc"
  }
}
```

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
