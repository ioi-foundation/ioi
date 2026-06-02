# Private Workspace Backed by cTEE

Status: canonical architecture authority.
Canonical owner: this file for Private Workspace backed by cTEE, persistent private Autopilot workspaces on rented GPU nodes, untrusted-node workspace privacy, private strategy execution, private workspace capsules, autonomy leases, and sensitive-compute routing under the IOI daemon.
Supersedes: `shielded-compute-profile.md` as the primary name, plus hosted/DePIN privacy wording that implies a rented GPU node can safely receive plaintext secrets merely because it runs a daemon, container, VM, benchmarked image, or boot-measured image.
Superseded by: none.
Last alignment pass: 2026-06-01.

## Canonical Definition

**Private Workspace backed by cTEE is the IOI daemon workspace and execution
profile for persistent rented GPU Autopilot nodes that must remain useful while
the user is away without exposing private files, folders, context, PII,
strategy source, broker keys, live portfolio state, or final action authority
to a root-level node provider.**

The user-facing phrase is:

```text
Open Private Workspace
```

The backing architecture is:

```text
cTEE = Cryptographic Trusted Execution Envelope
```

Product language:

```text
Open Private Workspace.
Run on rented GPU compute.
Private files, alpha, PII, credentials, and action authority stay out of
provider-readable plaintext by default.
```

Default execution strategy:

```text
Candidate-Lattice Private Decoding by default for protected agency:
  the rented GPU generates, simulates, drafts, searches, and expands candidates;
  the sealed private head / guardian / wallet policy selects, filters,
  declassifies, or signs without giving the node private plaintext custody.
```

Private Workspace does not turn a consumer GPU into trusted hardware, and it is
not just VM disk encryption. It changes the workspace and execution contract so
protected files and sensitive material are not mounted, logged, prompted, or
processed as normal plaintext on the rented node by default.

The daemon primitive family that makes this usable is:

```text
Plaintext-Free Runtime Mounting
```

It is not "encrypted prompt goes into a normal plaintext LLM." It is a runtime
mount contract where the untrusted node receives only public trunks, redacted
projections, encrypted refs, commitments, candidate sets, private-head handles,
declassification requests, and capability handles. Tools, shells, filesystems,
model servers, and models can work against the workspace, but protected
workspace objects are never mounted into provider-readable runtime context by
default. `PlaintextFreeModelMount` is the model-facing specialization.

Core invariant:

```text
The rented GPU node may be persistent.
The rented GPU node may have root controlled by the provider.
The rented GPU node may run the IOI daemon and Autopilot node shell.
The rented GPU node may run normal-speed public/generic model inference.
The user may see and edit a normal private workspace view.

The rented GPU node MUST NOT receive protected workspace state in plaintext
unless the user explicitly declassifies that state or an approved confidential
profile with an explicit trust claim applies.
```

Compatibility note:

```text
Deprecated wording:
  Shielded Compute Profile
  Shielded Workspace
  Protected Workspace

Canonical wording:
  Private Workspace backed by cTEE
```

## Generic cTEE and IOI Binding

`cTEE` is the portable systems pattern: a Cryptographic Trusted Execution
Envelope for private agency on untrusted compute. Other private agent
harnesses, enterprise runners, DePIN networks, worker runtimes, or
open-source autonomous-code agents can bind the same pattern to their own
authority, state, storage, and settlement components.

This document owns the IOI binding:

| Generic cTEE role | IOI binding |
| --- | --- |
| Guardian / authority view | authenticated browser, local Autopilot, CLI signer, wallet.network-backed authority |
| Authority plane | wallet.network |
| Execution boundary | IOI daemon |
| Plaintext-Free Runtime Mount | Default Harness Profile cTEE mount inside the daemon |
| StateLog | Agentgres |
| Artifact / blob store | Agentgres Artifact Plane plus storage backends |
| Settlement layer | IOI L1 / app chains only by trigger |
| Worker marketplace | aiagent.xyz advertises worker capabilities; it does not grant capabilities |
| Outcome marketplace | sas.xyz contracts service outcomes; authority exits still route through daemon + wallet.network |

Rule:

```text
cTEE is generic.
Private Workspace backed by cTEE is the IOI product/runtime binding.
```

## Threat Model

The default adversary is the node provider or host operator with:

- root on the host;
- process inspection;
- filesystem inspection;
- network observation at the node boundary;
- container/VM control;
- ability to snapshot RAM, logs, disks, and normal GPU-visible buffers;
- ability to delay, abort, replay, or return invalid work;
- economic incentive to steal user alpha, PII, code, prompts, or strategy.

Private Workspace does not assume the host OS, container boundary, rented 3090,
CUDA driver, VRAM, mounted filesystem, or boot image can keep plaintext secret
from root.

It separates three claims:

```text
privacy
  root cannot read protected state because it is not plaintext on the node

correctness
  root cannot get paid for fake work without receipts, verification,
  redundancy, challenge, or dispute paths

authority
  root cannot exceed delegated capability because effects leave through
  wallet.network and daemon gates
```

## Non-Claims

Do not claim:

- a 3090 or similar consumer GPU is a hardware TEE;
- boot measurement alone protects plaintext from root;
- a Docker container, VM, process sandbox, kernel module, or GPU namespace makes
  plaintext private from the node provider;
- full private LLM generation over raw secrets runs at normal token speed on an
  untrusted single GPU by default;
- cTEE proves private model cognition is aligned or truthful;
- cTEE hides all metadata such as timing, job size, public data source, model
  family, output length, or resource usage.

## Owns

Private Workspace backed by cTEE owns:

- `PrivateWorkspace`;
- `PrivateWorkspaceNode`;
- `PrivateWorkspaceCapsule`;
- `PlaintextFreeModelMount`;
- `ModelMountView`;
- `PrivateStrategyExecutionProfile`;
- `AlphaSeal`;
- `SensitiveDataClass`;
- `AutonomyLease`;
- `CapabilityExit`;
- `DeclassificationGate`;
- `DeclassificationReceipt`;
- `PrivateInferenceReceipt`;
- `NodeMeasurementReceipt`;
- `DeterrenceDetectionProfile`;
- `DeterrenceDetectionReceipt`;
- protected remote-node routing rules;
- sensitive-compute conformance checks.

Compatibility aliases:

```text
PersistentShieldedAutopilotNode -> PrivateWorkspaceNode
ShieldedTaskCapsule             -> PrivateWorkspaceCapsule
shielded_persistent             -> private_workspace_ctee
```

It does not own wallet keys, Agentgres state, artifact payload bytes, IOI L1
settlement, marketplace listings, or storage backend durability.

## Required Stack

```text
Private Workspace UI
  normal files/folders/project view for the user
  decrypted only in browser/device/guardian-approved views

wallet.network
  keys, key shares, authority leases, declassification policy,
  trade/action signing, revoke/panic controls

Persistent rented GPU node
  IOI daemon profile
  Autopilot node shell
  public/generic LLM inference
  public market-data transforms
  public training/backtest/simulation kernels
  public trunk files
  redacted workspace projections
  encrypted state/cache/artifact persistence
  no plaintext private files, alpha, PII, or secrets by default

cTEE authority view / guardian
  authenticated browser, wallet.network path, local Autopilot, CLI signer,
  mobile approval, enterprise key service, HSM, or threshold service
  participates in key release, private-head selection, masked/secret-shared
  strategy evaluation, declassification, and capability exits

Agentgres
  accepted operations, object heads, state commitments, artifact refs,
  receipt refs, archive refs, restore/import metadata, replay truth

Storage backends
  encrypted archives, checkpoints, traces, public datasets, payload bytes

IOI L1
  optional sparse commitments, disputes, staking, slashing, public settlement
```

The cTEE guardian is not a second runtime and should not feel like an extra
node for the user to operate. It is the **authority view** already needed to
decrypt, display, approve, or sign private work. A browser session, local
Autopilot desktop, CLI signer, passkey-backed wallet agent, customer VPC
service, enterprise HSM, mobile approval flow, or threshold committee may
implement it.

## Why A Guardian Is Required

For a persistent rented node with provider root, there is no software-only way
for that same node to both:

1. hold a secret in plaintext for arbitrary computation; and
2. guarantee the provider cannot inspect that plaintext.

If the user has no always-on local laptop or desktop, the architecture needs a
small trusted or threshold authority path outside the rented GPU node. In
product terms this is usually wallet.network, an authenticated browser/device
session, a mobile approval path, local Autopilot/CLI while online, or a cheap
policy/key service. It does not need to run the model. It needs to guard keys,
policy, declassification, private-head selection, leakage budgets, and small
sensitive computations.

Correct doctrine:

```text
GPU node = persistence and heavy compute
cTEE guardian = secret/authority membrane
Agentgres = proof and replay substrate
wallet.network = keys and power
```

## Workspace Semantics

A normal plaintext remote workspace is unsafe under this threat model.

Unsafe:

```text
/workspace/strategy.py
/workspace/signals.py
/workspace/risk.py
/workspace/config.yaml
```

If those files exist as ordinary plaintext on a provider-rooted rented node,
the provider can likely copy them, snapshot them, inspect logs, watch process
memory, and observe model prompts or tool inputs.

Private Workspace is different:

```text
user-visible workspace view
  -> decrypts in browser/device/guardian-approved context
  -> edits become encrypted patches or sealed workspace objects
  -> Agentgres records refs, commits, receipts, state roots, and policy
  -> storage backends hold encrypted blobs
  -> rented node receives public trunk files, redacted projections,
     encrypted refs, sealed AlphaSeal payloads, or bounded commitments
```

The node can compute against the workspace. It should not custody workspace
secrets.

High-security workspaces must also treat filenames, folder names, branch names,
trace labels, prompts, and report titles as possible leakage. Use neutral names
or encrypted refs for sensitive paths.

## Default Execution Contract

There should not be multiple user-facing privacy modes for the rented-node
experience. The product contract is simply:

```text
Open Private Workspace.
Private files and folders are encrypted blobs behind Agentgres refs.
The rented node can compute, but it cannot custody protected agency state.
```

Inside that single contract, the daemon uses **Candidate-Lattice Private
Decoding (CLPD)** as the default strategy for protected agency:

```text
1. The rented GPU runs public/generic model inference, simulation, search,
   backtests, feature generation, report drafting, and candidate expansion.

2. The candidate set or lattice is committed by hash, receipt, and policy.

3. AlphaSeal, the guardian, local/client policy, MPC/FHE/garbled operators, or
   wallet.network evaluates private utility, risk, PII, portfolio state,
   credentials, and authority constraints.

4. The node receives only a bounded selection, masked score, redacted critique,
   encrypted output, order-intent proposal, or declassification denial.

5. External actions exit through wallet.network capability gates.
```

The default rented 3090 view is:

```text
remote node sees:
  public model weights
  public or redacted prompts
  public datasets
  public feature tensors
  encrypted archives
  encrypted checkpoints
  artifact refs
  receipts

remote node does not see:
  PII plaintext
  strategy source plaintext
  broker credentials
  private coefficients
  private thresholds
  live portfolio plaintext
  final order logic
```

This preserves normal GPU performance for public/generic work while making the
agency side private by construction. The node may generate and propose; it does
not receive the private state needed to know why the protected head selected,
rejected, or authorized a branch.

Cryptographic private operators are implementation tactics, not product modes.
When the node must participate in sensitive scoring without seeing the secret,
the compiler may use secret shares, one-time masks, garbled circuits,
homomorphic scoring for low-degree formulas, private set membership, committed
private witnesses, or encrypted retrieval handles. The guardian or client
completes reconstruction, declassification, or signing.

## Plaintext-Free Runtime Mounting

Plaintext-Free Runtime Mounting is the daemon boundary between runtime
execution and private workspace custody. It covers tool, shell, filesystem,
model-server, and model-call views. `PlaintextFreeModelMount` is the
model-facing specialization.

Canonical definition:

```text
A Plaintext-Free Runtime Mount presents a private workspace to an untrusted
runtime as a typed mount of public content, redacted projections, encrypted
refs, commitments, candidate lattices, private-function handles, and capability
handles. It must not present protected workspace objects as provider-readable
plaintext on an untrusted node.
```

It is the cTEE answer to "can ciphering help?" Ciphering helps only when the
node never receives the deciphering key and never materializes protected
plaintext or plaintext-equivalent private activations. Plaintext-Free Model
Mounting combines ciphered storage with routing, custody control, private-head
evaluation, declassification gates, and receipts.

Allowed mount entries:

```text
public_file
public_dataset
public_model_weight
redacted_projection
encrypted_artifact_ref
encrypted_workspace_object_ref
candidate_lattice_ref
private_head_handle
masked_score_handle
capability_exit_handle
declassification_request_handle
receipt_ref
```

Forbidden mount entries on provider-rooted nodes:

```text
plaintext_private_file
plaintext_private_prompt
plaintext_strategy_source
plaintext_private_memory
plaintext_live_portfolio
plaintext_broker_secret
plaintext_action_authority
decryption_key
unrestricted_secret_handle
```

Minimal object:

```yaml
PlaintextFreeModelMount:
  mount_id: model_mount://...
  workspace_id: workspace://...
  node_ref: runtime_node:...
  model_route_ref: model_route://...
  policy_hash: sha256:...
  authority_ref: grant://...
  visible_entries:
    - kind: public_file | public_dataset | redacted_projection
      ref: artifact://... | projection://...
  protected_entries:
    - kind: encrypted_workspace_object_ref | private_head_handle |
            capability_exit_handle | declassification_request_handle
      ref: artifact://... | alpha_seal://... | capability_exit://...
      plaintext_on_node: false
  forbidden_plaintext_classes:
    - pii
    - strategy_source
    - broker_credentials
    - live_portfolio
    - private_memory
  leakage_profile_ref: leakage://...
  deterrence_detection_profile_ref: deterrence://...
  receipts_required:
    - ModelMountReceipt
    - PrivateInferenceReceipt
    - LeakageReceipt
```

Per-inference view:

```yaml
ModelMountView:
  view_id: model_mount_view://...
  mount_id: model_mount://...
  task_id: task:...
  visible_context_hash: sha256:...
  redaction_receipt_refs:
    - receipt://...
  encrypted_ref_commitments:
    - commitment://...
  private_handle_refs:
    - alpha_seal://...
    - capability_exit://...
  candidate_lattice_commitment: commitment://... | null
  plaintext_sensitive_classes_on_node:
    - none
  resulting_receipt_ref: receipt://...
```

What this gives:

```text
normal-speed remote inference over public/generic context
normal file/folder UX in the user's authority view
private workspace persistence through encrypted refs
private agency through CLPD, AlphaSeal, guardian, wallet policy, or private ops
receipts proving the node received no protected plaintext classes
```

What it does not give:

```text
arbitrary full-speed private LLM inference over fully private tokens
privacy if the user mounts private files as ordinary plaintext on the node
zero metadata leakage
protection from bad public candidates or denial of service
```

### Model Mount Lifecycle

```text
1. Classify workspace objects by sensitivity.
2. Build public trunk and redacted projections.
3. Replace protected objects with encrypted refs or private handles.
4. Bind forbidden plaintext classes, leakage profile, and authority policy.
5. Emit ModelMountReceipt before model invocation.
6. Run model on the rented node only over the mounted public/redacted view.
7. Route private selections, declassification, or actions through guardian and
   wallet.network.
8. Emit PrivateInferenceReceipt, LeakageReceipt, DeclassificationReceipt, or
   CapabilityExitReceipt as applicable.
9. Commit refs and receipts through Agentgres.
```

### ModelMountReceipt

```yaml
ModelMountReceipt:
  receipt_id: receipt://...
  mount_id: model_mount://...
  view_id: model_mount_view://...
  node_ref: runtime_node:...
  model_route_ref: model_route://...
  policy_hash: sha256:...
  visible_context_hash: sha256:...
  redacted_projection_refs:
    - projection://...
  encrypted_ref_commitments:
    - commitment://...
  private_handle_refs:
    - alpha_seal://...
    - capability_exit://...
  forbidden_plaintext_classes:
    - pii
    - strategy_source
    - broker_credentials
  plaintext_sensitive_classes_on_node:
    - none
  deterrence_detection_profile_ref: deterrence://...
  signature: ...
```

## Deterrence and Detection Layer

Detection does not make plaintext safe. It makes theft, leakage, replay, and
provider abuse more attributable when something escapes the no-plaintext
custody boundary or when public/redacted outputs are copied downstream.

Private Workspace cTEE should support a deterrence/detection profile for
high-value workspaces:

```yaml
DeterrenceDetectionProfile:
  profile_id: deterrence://...
  workspace_id: workspace://...
  provider_ref: provider://...
  node_ref: runtime_node:...
  capsule_fingerprint:
    provider_bound_nonce: sha256:...
    node_bound_watermark: sha256:...
    run_epoch: integer
  canaries:
    enabled: true
    classes:
      - decoy_strategy
      - decoy_credential
      - synthetic_pii
      - watermark_phrase
      - honeytoken_endpoint
    storage:
      never_mix_with_real_secret: true
      encrypted_canary_ref: artifact://...
  watermarking:
    candidate_lattice_watermark: true
    report_text_watermark: true
    code_patch_watermark: true
    provider_specific_output_marks: true
  monitoring:
    scan_public_leaks: true
    broker_honeytoken_alerts: true
    suspicious_replay_detection: true
    anomalous_access_pattern_detection: true
  receipts_required:
    - DeterrenceDetectionReceipt
    - CanaryTripReceipt
```

Required rules:

```text
Canaries must be synthetic or decoy data, never real secrets.
Canaries must be labeled in Agentgres policy/receipts so they do not poison
training, memory, settlement, or real user decisions.
Watermarks must not reveal private strategy content.
Detection receipts must not become a reason to put plaintext on the node.
```

### DeterrenceDetectionReceipt

```yaml
DeterrenceDetectionReceipt:
  receipt_id: receipt://...
  workspace_id: workspace://...
  node_ref: runtime_node:...
  profile_ref: deterrence://...
  event_type:
    canary_planted | watermark_bound | honeytoken_bound |
    canary_checked | canary_tripped | suspicious_replay_detected |
    leak_scan_completed
  bound_refs:
    - model_mount://...
    - private_workspace_capsule://...
    - artifact://...
  public_evidence_refs:
    - artifact://... # screenshot, web capture, broker alert, or scan result
  private_evidence_commitments:
    - commitment://...
  action:
    none | warn_user | revoke_node | rotate_keys | open_dispute |
    slash_provider | quarantine_workspace
  policy_hash: sha256:...
  timestamp: ...
```

This layer is especially relevant for `sas.xyz` and `aiagent.xyz` because
marketplace or service outcomes may need post-run dispute evidence without
revealing the user's private workspace contents.

### Confidential Hardware Overlay

TEE or confidential GPU support may upgrade where plaintext is allowed to
exist, but it is not required for the base cTEE privacy claim and it should not
be silently assumed for consumer DePIN nodes.

## Private Strategy Execution

Quantitative trading is the reference workload because it cleanly separates
heavy compute from high-value secrets.

Sensitive material:

```text
strategy source
signal formula
feature recipe when proprietary
private coefficients
private thresholds
hyperparameters when they reveal alpha
position/risk rules
broker keys
live portfolio state
order generation logic
```

Heavy work suitable for the rented GPU:

```text
public market data ingestion
public feature tensor generation
public model inference
public or redacted LLM research
simulation/backtest kernels over declassified inputs
training public trunks
candidate-lattice generation and expansion
batch scoring over masked, encrypted, or guardian-selected candidates
encrypted checkpoint storage
report drafting over redacted observations
```

## Winning Shape For A Rented 3090

The practical default product should be:

```text
Open Private Workspace
  persistent rented GPU node
  normal-speed public/generic inference
  Candidate-Lattice Private Decoding by default
  encrypted Agentgres-backed persistence
  AlphaSeal private strategy head
  wallet.network capability exits
  guardian/client declassification
```

Implementation shape:

```text
1. The rented node boots a measured daemon image, model server, artifact policy,
   and encrypted local Agentgres/storage profile.

2. The user creates or imports the private strategy locally, in a client, or
   through a wallet-controlled guardian path.

3. The strategy is compiled into an AlphaSeal:
     public trunk = feature schemas, public data transforms, model routes,
                    backtest kernels, redacted research prompts
     private head = coefficients, thresholds, rule gates, risk gates,
                    broker/action policy, live portfolio constraints

4. The rented GPU runs the public trunk at normal speed:
     market data ingest, tensor generation, LLM research, simulations,
     candidate-lattice expansion, report drafting, and public model inference.

5. Candidate lattices are committed with receipts. The private head selects,
   filters, reranks, denies, or declassifies through local/client/guardian,
   masked, secret-shared, garbled, or homomorphic operators depending on risk
   and cost.

6. The node receives only protected commitments, masked scores, selected branch
   commitments, redacted summaries, encrypted outputs, or bounded order-intent
   proposals.

7. wallet.network signs or denies broker/API actions under AutonomyLease,
   risk limits, declassification policy, and revocation epoch.

8. Agentgres records the run, refs, commitments, receipts, archive refs, and
   capability exits; storage backends hold encrypted payload bytes.
```

This keeps the 3090 useful:

```text
Fast path:
  public model inference
  feature/tensor compute
  public backtests
  redacted research
  report drafting
  encrypted persistence

Protected path:
  strategy source
  final alpha head
  broker credentials
  live portfolio
  order signing
  PII-bearing context
```

The guarantee is narrow but valuable: the provider can inspect the rented node,
steal public trunks, observe metadata, or deny service, but it should not find
the private strategy head, PII, broker credentials, live portfolio plaintext, or
signing authority because those never live as normal plaintext on the node.

If a user writes the full strategy as plaintext Python on the rented node, the
profile is broken. The product should make the safe path the easy path: create
an `AlphaSeal`, let the GPU generate candidate lattices and public simulations,
keep the alpha head sealed, and require wallet receipts for every reveal or
action.

## AlphaSeal

`AlphaSeal` is the sealed private strategy capsule.

```yaml
AlphaSeal:
  alpha_seal_id: alpha_seal://...
  owner_ref: wallet://...
  strategy_commitment: sha256:...
  public_trunk_ref: model://... | workflow://... | null
  private_head:
    representation:
      local_only | masked_linear | fhe_score | garbled_rules |
      mpc_share | committed_witness
    encrypted_payload_ref: artifact://...
    leakage_profile_ref: leakage://...
  inputs:
    public_feature_schema_ref: schema://...
    private_state_classes:
      - strategy_source
      - coefficients
      - thresholds
      - live_portfolio
  outputs:
    output_class:
      encrypted_score | masked_rank | order_intent | risk_gate_result
    declassification_required: true
  policy:
    policy_hash: sha256:...
    max_notional: ...
    max_daily_loss: ...
    allowed_markets: []
    allowed_brokers: []
    human_step_up_required_for: []
  authority:
    wallet_authority_ref: grant://...
    guardian_ref: guardian://...
  receipts:
    creation_receipt_ref: receipt://...
    verification_receipt_refs:
      - receipt://...
```

The remote node may hold an encrypted `AlphaSeal` payload. It may not hold the
unsealed strategy by default.

## PrivateStrategyExecutionProfile

```yaml
PrivateStrategyExecutionProfile:
  profile_id: private-strategy-execution
  default_remote_policy: no_plaintext_alpha
  remote_plaintext_forbidden:
    - strategy_source
    - broker_credentials
    - live_portfolio
    - final_order_logic
    - private_signal_weights
    - undeclassified_user_pii
  remote_allowed_work:
    - public_data_ingestion
    - public_feature_generation
    - public_model_inference
    - redacted_llm_analysis
    - masked_alpha_head_eval
    - fhe_score_eval
    - garbled_rule_eval
    - encrypted_checkpoint_storage
    - delivery_report_draft_redacted
  remote_sensitive_work_requires:
    - alpha_seal
    - leakage_profile
    - guardian_or_client_participation
    - Agentgres_receipts
    - wallet_authority_policy
  action_exits:
    trade_order:
      requires: capability_exit
      signer: wallet.network
      receipt: DeclassificationReceipt
```

## PersistentShieldedAutopilotNode

Deprecated name. Prefer `PrivateWorkspaceNode`.

```yaml
PrivateWorkspaceNode:
  node_id: runtime_node:...
  workspace_profile: private_workspace_ctee
  compatibility_mode_alias: shielded_persistent
  execution_venue:
    hosted | depin | provider | customer_vpc
  gpu_profile:
    class: consumer | datacenter | confidential_capable
    model_hint: rtx_3090 | rtx_4090 | h100 | other
    hardware_tee_claim:
      none | attested | policy_required
  daemon_profile_ref: default-harness-profile
  agentgres_domain_ref: agentgres://domain/...
  wallet_authority_ref: wallet://...
  guardian_ref: guardian://...
  sensitive_data_policy_ref: policy://...
  default_execution_strategy: candidate_lattice_private_decoding
  private_operator_tactics:
    - guardian_selection
    - masked_score
    - secret_share
    - garbled_rule
    - homomorphic_score
    - committed_witness
  forbidden_plaintext_classes:
    - pii
    - strategy_source
    - broker_credentials
    - live_portfolio
    - private_memory
  persistent_state:
    state_mode: encrypted_agentgres_refs
    archive_refs:
      - archive://...
  receipts_required:
    - NodeMeasurementReceipt
    - PrivateInferenceReceipt
    - DeclassificationReceipt
    - CapabilityExitReceipt
```

## ShieldedTaskCapsule

Deprecated name. Prefer `PrivateWorkspaceCapsule`.

```yaml
PrivateWorkspaceCapsule:
  capsule_id: shielded_capsule://...
  task_id: task:...
  node_id: runtime_node:...
  visible_context:
    - public_dataset_ref
    - redacted_summary
    - public_schema
    - bounded_objective
  protected_context:
    - encrypted_payload_ref: artifact://...
    - alpha_seal_ref: alpha_seal://...
    - private_memory_ref: memory://...
  allowed_remote_ops:
    - public_model_inference
    - tensor_compute
    - masked_score_eval
    - encrypted_checkpoint_write
  forbidden_remote_ops:
    - plaintext_secret_read
    - broker_key_read
    - live_portfolio_plaintext_read
    - unbounded_external_action
  leakage_profile:
    visible:
      - task_type
      - public_dataset_window
      - tensor_dimensions
      - runtime_cost
    padded:
      - output_size
      - schedule_window
  receipts:
    required:
      - private_inference
      - artifact_recorded
      - capability_exit_if_action
```

## AutonomyLease

An `AutonomyLease` lets a Private Workspace node work while the user is away.

```yaml
AutonomyLease:
  lease_id: autonomy_lease://...
  owner_ref: wallet://...
  node_ref: runtime_node:...
  valid_until: timestamp
  allowed_without_user_online:
    - refresh_public_data
    - run_public_model_inference
    - update_encrypted_state
    - evaluate_alpha_seal
    - propose_order_intent
    - draft_redacted_report
  forbidden_without_step_up:
    - reveal_strategy_source
    - reveal_pii
    - widen_broker_scope
    - exceed_risk_limits
    - export_private_memory
  action_limits:
    max_notional: ...
    max_daily_loss: ...
    market_hours_only: true
    allowed_symbols: []
  guardian_policy:
    required: true
    quorum: 1-of-1 | 2-of-3 | policy_defined
  receipts_required: true
  revocation_epoch: integer
```

The lease grants bounded autonomy, not plaintext access.

## Declassification Gate

All protected outputs are born encrypted, masked, redacted, or policy-bound.
They become visible or actionable only through a declassification gate.

```text
protected output produced
  -> Agentgres records commitment and receipt
  -> wallet.network checks authority and AutonomyLease
  -> guardian/client decrypts or reconstructs if allowed
  -> policy scanner checks disclosure/action limits
  -> CapabilityExit or visible result is approved, denied, or escalated
  -> DeclassificationReceipt recorded
```

External actions such as broker orders, emails, API writes, deployments, or
funds movements must exit through capability scopes. The rented node cannot
hold durable raw credentials.

## Inference Routing

The daemon should route inference by sensitivity. For protected agency, the
default is CLPD: let the rented GPU expand public/redacted candidates, then let
AlphaSeal, the guardian, local/client policy, or a private operator select,
deny, or declassify.

```text
public or declassified prompt
  -> rented GPU plaintext inference allowed

redacted prompt
  -> rented GPU plaintext inference allowed with redaction receipt

PII-bearing prompt
  -> candidate lattice over redacted/public context, then guardian/private
     selection; raw PII stays off the node

secret strategy decision
  -> AlphaSeal private head selects/reranks/denies candidate branches

trade/action decision
  -> CapabilityExit through wallet.network
```

The goal is not to make every token cryptographic. The goal is to preserve
normal token speed for non-sensitive context while preventing sensitive state
from entering rented-node plaintext.

## Node Measurement

Boot or runtime measurement is useful for integrity, accounting, compatibility,
and dispute handling.

It may record:

- daemon image hash;
- model/runtime package hash;
- GPU class and benchmark;
- allowed operator ABI;
- network policy;
- logging policy;
- receipt sink;
- storage refs.

Measurement is not a privacy root for consumer GPUs. It cannot by itself justify
sending plaintext alpha or PII to a root-controlled provider node.

## Receipts

```yaml
PrivateInferenceReceipt:
  receipt_id: receipt://...
  node_id: runtime_node:...
  capsule_id: shielded_capsule://...
  alpha_seal_ref: alpha_seal://... | null
  input_commitment: sha256:...
  output_commitment: sha256:...
  leakage_profile_ref: leakage://...
  operator_hash: sha256:...
  execution_strategy:
    candidate_lattice_private_decoding | public_trunk_plaintext |
    guardian_selected | masked_score | secret_shared | homomorphic |
    garbled_rule | committed_witness | confidential_hardware
  candidate_lattice_commitment: commitment://... | null
  plaintext_sensitive_classes_on_node:
    - none
  result:
    success | failure | blocked | invalid
```

```yaml
DeclassificationReceipt:
  receipt_id: receipt://...
  protected_output_ref: artifact://... | commitment://...
  authority_ref: grant://...
  guardian_ref: guardian://... | null
  policy_hash: sha256:...
  decision:
    reveal_to_user | reveal_to_third_party | execute_capability |
    deny | escalate
  disclosed_classes:
    - none | redacted | pii | strategy_summary | order_intent
  timestamp: ...
```

```yaml
NodeMeasurementReceipt:
  receipt_id: receipt://...
  node_id: runtime_node:...
  daemon_image_hash: sha256:...
  runtime_package_hash: sha256:...
  gpu_profile: string
  privacy_claim:
    none | blind_only | tee_attested | ctee_profile
  measurement_scope:
    integrity | compatibility | accounting | privacy
  note: "Measurement is not a consumer-GPU plaintext privacy guarantee."
```

## Guarantees

```text
The node provider can run high-performance public/generic inference while
protected agency state remains local, encrypted, masked, secret-shared,
garbled, homomorphically evaluated, committed, guardian-gated, or
capability-gated.

The default strategy is Candidate-Lattice Private Decoding:
  node expands candidates at speed;
  private head selects or denies;
  Agentgres records commitments and receipts;
  wallet.network gates declassification and external actions.
```

## Leakage

Allowed or bounded leakage must be explicit:

- task class;
- model family;
- public data source;
- market universe or time window if not padded;
- tensor dimensions;
- job duration;
- GPU utilization;
- output size;
- schedule pattern;
- failure/abort timing.

Mitigations:

- generic job names;
- batching;
- schedule jitter;
- padding;
- decoy jobs for high-value strategies;
- encrypted logs;
- no alpha-revealing filenames, symbols, prompts, or trace summaries.

Candidate-Lattice Private Decoding must account for selection leakage. Baseline
budget rules:

```text
selected one of K candidates:
  <= log2(K) bits before side information

revealed unordered top-m:
  <= log2(choose(K, m)) bits before side information

revealed total ranking:
  <= log2(K!) bits before side information

observable bucket with b possible buckets:
  <= log2(b) bits
```

Private Workspace runs should record leakage budget fields in
`PrivateInferenceReceipt` or a linked `LeakageReceipt`:

```yaml
LeakageReceipt:
  receipt_id: receipt://...
  candidate_lattice_commitment: commitment://...
  leakage_profile_ref: leakage://...
  selection_policy:
    selected_one | top_m | denial_only | masked_score
  selection_bits_bound: number
  timing_bucket_bits_bound: number
  size_bucket_bits_bound: number
  cumulative_budget_before: number
  cumulative_budget_after: number
  mitigation_refs:
    - padding_policy://...
    - schedule_jitter_policy://...
    - decoy_policy://...
```

## Conformance Checks

An implementation conforms when:

1. A rented root-controlled GPU node is treated as plaintext-capable unless a
   profile explicitly proves otherwise.
2. Protected classes are declared before routing.
3. Sensitive data classes are forbidden from remote plaintext by default.
4. Persistent remote state is encrypted and recorded through Agentgres refs.
5. A non-node authority path exists for decryption, declassification, key
   release, and capability exits.
6. Offline autonomy uses `AutonomyLease`, not durable raw secrets on the node.
7. All external actions cross wallet.network and daemon capability gates.
8. Private inference or private strategy evaluation emits receipts.
9. Boot measurement is not used as the sole privacy proof for consumer GPUs.
10. CLPD selections record candidate commitments and leakage budget fields.
11. Model invocations over private workspaces emit `ModelMountReceipt` before
    execution.
12. Plaintext-Free Runtime Mounting exposes only public/redacted entries,
    encrypted refs, commitments, private handles, declassification requests,
    or capability handles to provider-rooted nodes.
13. Deterrence/detection canaries are synthetic, policy-labeled, and excluded
    from real decisions, memory admission, training, and settlement truth.
14. The UI exposes whether a run is `Public`, `Redacted`,
    `Private Workspace`, `TEE`, or `Unsafe`.

## Anti-Patterns

Do not:

- market a rented 3090 as confidential compute by default;
- send raw alpha, PII, broker keys, or live portfolio state to an untrusted
  provider node;
- store strategy source in provider-visible logs or traces;
- call boot measurement a privacy guarantee;
- let a persistent node self-grant trading authority;
- make `sas.xyz` or `aiagent.xyz` the owner of cTEE execution semantics;
- require full private LLM inference for ordinary protected workflows;
- hide the leakage profile from users;
- call Plaintext-Free Runtime Mounting or Plaintext-Free Model Mounting
  "arbitrary encrypted LLM inference";
- put canaries or honeytokens in the same class as real user secrets;
- use canary/detection support as justification for mounting plaintext;
- say "the VM/workspace is encrypted" when protected files are still mounted as
  ordinary plaintext on the rented node.

## Product UX

The default user experience should be simple:

```text
Connect rented GPU node.
Open Private Workspace.
See a badge:
  Public compute fast
  Private files cTEE-backed
  Alpha sealed
  Broker keys local/wallet-only
  Offline autonomy bounded by lease
```

For quant users:

```text
Rent the node. Keep the alpha.
```

For sensitive productivity users:

```text
Cloud persistence without handing the provider your private context.
```

## Related Canon

- [`runtime-nodes-tee-depin.md`](./runtime-nodes-tee-depin.md): runtime node,
  DePIN, TEE, and execution privacy taxonomy.
- [`default-harness-profile.md`](./default-harness-profile.md): daemon-executed
  loop-native orchestration profile.
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md):
  authority, keys, declassification, and action power.
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md):
  artifact refs, archive refs, restore/import metadata, and payload meaning.
- [`../../domains/aiagent/worker-marketplace.md`](../../domains/aiagent/worker-marketplace.md):
  managed worker instances that may use Private Workspace placement.
- [`../../domains/sas/service-marketplace.md`](../../domains/sas/service-marketplace.md):
  service packages and outcomes that may declare Private Workspace privacy
  classes.
