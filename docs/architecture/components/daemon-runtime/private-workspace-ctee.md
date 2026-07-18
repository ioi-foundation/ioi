# Private Workspace Backed by cTEE

Status: canonical architecture authority.
Canonical owner: this file for Private Workspace backed by cTEE, persistent private Hypervisor workspaces on rented GPU nodes, untrusted-node workspace privacy, private strategy execution, private workspace capsules, autonomy leases, and sensitive-compute routing under the Hypervisor Daemon.
Supersedes: hosted/DePIN privacy wording that implies a rented GPU node can
safely receive plaintext secrets merely because it runs a daemon, container,
VM, benchmarked image, or boot-measured image.
Superseded by: none.
Last alignment pass: 2026-07-13.
Doctrine status: canonical
Implementation status: speculative (cTEE/CLPD design; no cTEE implementation)
Last implementation audit: 2026-07-05

## Canonical Definition

**Private Workspace backed by cTEE is the Hypervisor Daemon workspace and execution
profile for persistent rented GPU Hypervisor Nodes that must remain useful while
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

Managed execution modes:

```text
User-facing modes:
  Standard
  Private

Standard = private-native operating substrate by default:
  cTEE / Plaintext-Free Runtime Mounting for IOI-managed execution
  scoped authority
  connector vaulting
  receipts
  provider-trust model routes allowed with disclosure

Private = Standard plus no-provider-trust model routing:
  open-weight or user-controlled model route
  Private Workspace backed by cTEE
  hardware TEE
  local-only execution
  customer-boundary / customer-cloud execution
  BYO private node
  another approved custody-proven route
```

Private ioi.ai, Hypervisor private sessions, and marketplace/private worker
placements may require a paid plan, Work Credits, enterprise entitlement, or BYO
node when IOI provisions managed confidential compute, protected connector
processing, persistent private workspace custody, encrypted storage, or
attestation/custody proof. The paid entitlement is for the managed private
runtime, stricter no-provider-trust model route, and proof obligations; it is
not a fee on privacy as a concept.

No surface may claim `Private`, `Private Workspace`, `cTEE`, `private_native`,
or `no-provider-trust` merely because the user selected a private toggle.
`Standard` may be cTEE/private-native at the runtime layer while still allowing
provider-trust model routes. `Private` must bind the corresponding privacy
posture, custody proof, model/API boundary, no-provider-trust route, and receipt
obligations before the label is shown as satisfied.

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
The rented GPU node may run the Hypervisor Daemon and Hypervisor Node shell.
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
| Guardian / authority view | authenticated browser, local Hypervisor, CLI signer, wallet.network-backed authority |
| Authority plane | wallet.network |
| Execution boundary | Hypervisor Daemon |
| Plaintext-Free Runtime Mount | daemon-owned cTEE/private-workspace mount exposed to selected HarnessProfiles, model mounts, tools, and service modules |
| StateLog | Agentgres |
| Artifact / blob store | Agentgres Artifact Plane plus storage backends |
| Settlement layer | system-local by default; declared external/app-chain service by profile; IOI L1 only for explicitly enrolled, selected services |
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
- that raw private plaintext sent to a third-party model API remains inside
  cTEE no-plaintext-custody privacy;
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
- `CustodyType`;
- `CustodyProof`;
- `PrivateAgencyTransform`;
- `CandidateCoverageProfile`;
- `CounterfactualLatticeExecution`;
- `ExecutionPrivacyPosture`;
- `ExternalModelApiBoundary`;
- `CryptographicOperatorPlane`;
- `CryptographicOperatorPolicy`;
- `PrivateStrategyExecutionProfile`;
- `AlphaSeal`;
- `SensitiveDataClass`;
- `AutonomyLease`;
- `CapabilityExit`;
- `DeclassificationGate`;
- `DeclassificationReceipt`;
- `PrivateInferenceReceipt`;
- `CounterfactualLatticeReceipt`;
- `PrivateOperatorReceipt`;
- `NodeMeasurementReceipt`;
- `DeterrenceDetectionProfile`;
- `DeterrenceDetectionReceipt`;
- protected remote-node routing rules;
- sensitive-compute conformance checks.

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
  Hypervisor Daemon profile
  Hypervisor Node shell
  public/generic LLM inference
  public market-data transforms
  public training/backtest/simulation kernels
  public trunk files
  redacted workspace projections
  encrypted state/cache/artifact persistence
  no plaintext private files, alpha, PII, or secrets by default

cTEE authority view / guardian
  authenticated browser, wallet.network path, local Hypervisor, CLI signer,
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
Hypervisor desktop, CLI signer, passkey-backed wallet agent, customer VPC
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
session, a mobile approval path, local Hypervisor App/Web/CLI while online, or
a cheap policy/key service. It does not need to run the model. It needs to
guard keys, policy, declassification, private-head selection, leakage budgets,
and small sensitive computations.

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

Internal performance/privacy ladder:

```text
online CLPD
  normal public/generic GPU kernels
  near-normal token volume when candidate width is small
  bounded branch-selection leakage

Counterfactual Lattice Execution
  normal public/generic GPU kernels
  extra public token volume to expand unused futures
  lower online private-choice leakage

full private transformer inference
  requires trusted/private compute, hardware confidential computing,
  or heavier FHE/MPC-style cryptographic evaluation
```

Rule:

```text
cTEE preserves ordinary GPU token kernels for public work. It does not promise
same-token-budget arbitrary private inference on a root-owned consumer GPU.
```

## External Model API Boundary

cTEE is strongest when the user, service, or enterprise controls the compute
substrate: local GPU, rented GPU, customer VPC node, DePIN node, or another
execution venue where protected state can stay outside provider-readable
plaintext custody.

When the user rents a GPU node rather than buying model API tokens, extra
candidate or counterfactual generation mainly consumes:

```text
node wall-clock time
leased GPU occupancy
possibly a larger or longer rental
```

It does not create the same per-token third-party API cost or plaintext custody
surface.

Rule:

```text
If protected plaintext is sent to a third-party model API, the run leaves the
cTEE no-plaintext-custody model for that data and enters a provider-trust model.
```

Third-party APIs remain compatible with cTEE only when they receive:

```text
public inputs
redacted projections
synthetic/counterfactual candidates
explicitly declassified payloads
or a separately verifiable private-compute interface
```

Enterprise "no training" promises, retention controls, privacy policies, and
contracts can be valuable. They are still provider trust unless the provider
receives no sensitive plaintext or supplies a verifiable confidential/private
compute guarantee accepted by policy.

Institutional learning policy does not collapse this distinction. Before
protected material crosses to an external model API or processor, the daemon
intersects the active `InstitutionalLearningBoundaryProfile`, source policy and
consent, `TrainingEvidenceEligibility` when learning use is proposed, the
complete `ModelRouteRightsContract`, and `ExecutionPrivacyPosture`. Missing or
ambiguous rights fail closed. An admitted crossing emits the registered
`LearningEgressReceipt`; a denied attempt may claim
`blocked_before_egress` only with gateway or network evidence that no write
occurred.

A custody-proven local, customer-boundary, or accepted confidential-compute
route can keep protected material inside the institution and therefore avoid a
provider-readable learning egress. It still emits the ordinary invocation,
training, custody, and policy receipts required by the work. Conversely, a
provider-trust route with strong contractual no-training or retention terms is
compatible with disclosed `Standard` execution when policy permits, but those
terms do not become a cryptographic no-egress or no-learning proof. Private
Workspace protects custody; the learning boundary governs institutional use and
egress; neither one manufactures output reuse, distillation, competing-model
training, publication, or resale rights.

### ExecutionPrivacyPosture

Private workers, service packages, outcome engines, and agent harnesses should
declare their privacy posture:

```yaml
ExecutionPrivacyPosture:
  posture_id: privacy_posture://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: sha256:... | null
  posture:
    private_native | redacted_api | provider_trust | unsafe
  model_path:
    local_open_weight | rented_gpu | customer_vpc |
    third_party_api | managed_provider | hybrid
  sensitive_plaintext_to_third_party_api: true | false
  third_party_api_receives:
    - public
    - redacted
    - synthetic_candidate
    - declassified
    - sensitive_plaintext
  provider_trust_basis:
    - no_training_contract
    - retention_policy
    - enterprise_terms
    - subpoena_surface_acknowledged
    - confidential_compute_attestation
    - cryptographic_private_compute_proof
  ctee_claim:
    no_plaintext_custody | redacted_only | provider_trust | unsafe
  required_user_disclosure: string
```

`ExecutionPrivacyPosture` answers what happens to protected workspace data.
`ModelWeightCustodyProfile` answers what happens to the model weights. They are
separate decisions. `InstitutionalLearningBoundaryProfile` answers which
institutional prompts, outputs, traces, corrections, evals, memory, datasets,
and learned artifacts may be used, retained, derived, or allowed to cross the
institution boundary. For protected institutional material, its profile ref and
hash are required before an external mount, model route, processor, support
path, cross-organization handoff, or export is admitted.

### PrivateWorkspaceMountAdmission

Before a session, adapter, model route, provider target, or runtime mount
receives workspace material, the daemon admits the mount posture through
`POST /v1/hypervisor/private-workspace-mount-admissions`.

The admission boundary is the concrete enforcement point for Plaintext-Free
Runtime Mounting:

```text
public trunk
  may be provider-readable because it is not protected workspace plaintext

redacted projection
  requires redaction evidence before provider-readable mounting

encrypted blob ref
  remains sealed; the provider receives refs/bytes, not decrypted state

private head
  routes local/browser/user-owned, cTEE split, TEE, or customer-cloud custody
  handles depending on policy

capability exit
  lets the node request scoped action without receiving durable secrets

unsafe plaintext mount
  requires wallet approval, declassification receipts, provider-trust
  acceptance, explicit unsafe scope, and Agentgres-linked receipt refs
```

Clients may display the result and request admissions. They do not become
workspace custody truth.

```text
cTEE workspace state can remain sealed while public/open model weights run on a
rented GPU.

That does not imply proprietary model weights are safe to mount on the same
rented GPU as plaintext.
```

Model-weight custody lanes:

| Lane | cTEE meaning |
| --- | --- |
| `public_open_weight` | Safe for rented/DePIN GPU execution when workspace state remains sealed/redacted. |
| `user_local_private_weight` | Weights stay on user-owned or customer-controlled hardware. |
| `remote_api_private_weight` | Provider keeps its proprietary weights behind an API; input privacy is still a separate posture. |
| `provider_trust_remote_mount` | User/org weights are visible to the provider and require explicit provider-trust approval. |
| `tee_or_customer_cloud_mount` | User/org weights mount only inside accepted TEE/customer-cloud boundary. |
| `forbidden_plaintext_mount` | Untrusted remote provider would receive proprietary weights as plaintext; block by default. |

Admission rule:

```text
If proprietary weights would become provider-readable plaintext on a root-owned
remote node, the cTEE no-plaintext-custody claim does not apply to those
weights. The route must be forbidden, moved local/customer/TEE/API-side, or
approved as provider-trust with receipt-backed disclosure.
```

Execution postures:

```text
Private-native
  no sensitive plaintext leaves cTEE custody;
  local/open/self-hosted/rented compute handles private workspace work

Redacted-API
  third-party APIs see only public, redacted, synthetic, or declassified inputs

Provider-trust
  third-party API may receive sensitive plaintext under contract, policy,
  retention terms, or attestation; this is not base cTEE no-plaintext custody

Unsafe
  private data enters untrusted plaintext custody without explicit
  declassification or accepted provider-trust policy
```

Marketplace implication:

```text
sas.xyz outcomes, aiagent.xyz workers, enterprise packages, and third-party
agent harnesses should label whether they are private-native, redacted-API,
provider-trust, or unsafe for private workspace data.
```

These are not product modes. Product surfaces expose `Standard` and `Private`.
The posture labels above are receipt, audit, marketplace, and admission evidence
used to prove which mode a run actually satisfied.

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

## Custody Types And Proof-Carrying Workspace

cTEE should be implemented as a custody discipline, not a convention.

Core custody types:

```text
Public
  plaintext may enter the rented node

Redacted
  approved projection may enter the rented node

Sealed
  ciphertext, commitment, share, or opaque ref only

GuardianOnly
  plaintext only inside authenticated browser, client, local Hypervisor,
  mobile guardian, CLI signer, wallet.network path, or threshold path

CryptoOperator
  FHE, MPC, garbled circuit, ORAM, local guardian, or threshold operator only

CapabilityOnly
  authority value is not data; node may request an action but cannot read
  credentials, grants, or raw signing material

NeverRemotePlaintext
  no valid rented-node plaintext representation under current policy
```

Every tool, shell, model, file, connector, retrieval, and action edge into the
rented node should type-check against one of these custody kinds.

`CustodyProof` is the verifier-facing object that binds the run:

```yaml
CustodyProof:
  proof_id: custody_proof://...
  workspace_id: workspace://...
  policy_hash: sha256:...
  sensitivity_manifest_hash: sha256:...
  custody_type_derivation_hash: sha256:...
  mount_graph_hash: sha256:...
  remote_admissibility_derivation_hash: sha256:...
  candidate_lattice_commitments:
    - commitment://...
  counterfactual_lattice_receipts:
    - receipt://...
  private_operator_receipts:
    - receipt://...
  declassification_receipts:
    - receipt://...
  capability_exit_receipts:
    - receipt://...
  leakage_receipts:
    - receipt://...
  state_root_before: sha256:...
  state_root_after: sha256:...
  verifier_result:
    no_plaintext_custody | rejected | inconclusive
```

Conformance claim:

```text
If the custody proof verifies, the accepted run carries checkable evidence that
protected classes did not enter rented-node plaintext custody except through
explicit declassification.
```

## Private Agency Transform

The Private Agency Transform rewrites a protected agent step:

```text
private LLM over public context + secrets
```

into:

```text
public proposal generation on the rented GPU
  + private selection / verification / declassification / authorization
```

This applies when the task is candidate-selection-reducible: useful candidate
actions, reports, patches, trades, plans, or tool proposals can be generated
from public/redacted context, while private state is used to select, reject,
rerank, or authorize.

The transform is the main reason cTEE can keep the rented GPU useful:

```text
expensive transformer proposal path -> rented GPU at ordinary kernel speed
private agency path                 -> small selector / guardian / crypto op
```

It is not a claim that arbitrary private transformer inference has the same
token budget or latency as public inference.

## Candidate Coverage Frontier

The scheduler should estimate whether a task has enough proposal redundancy to
use CLPD or Counterfactual Lattice Execution.

Definitions:

```text
private-good set
  candidates that satisfy private utility, policy, and tolerance epsilon

redundancy mass r
  probability that one public candidate trace lands in the private-good set

coverage target rho
  probability that the generated candidate set contains at least one acceptable
  private-good trace
```

Frontier:

```text
coverage(m, r) >= 1 - (1 - r)^m

to reach coverage rho:
  m >= ceil( ln(1 - rho) / ln(1 - r) )
  m <= ceil( (1 / r) * ln(1 / (1 - rho)) )
```

Interpretation:

```text
high redundancy mass
  small bounded public overgeneration can hide private choice

low redundancy mass
  CLPD/CLE becomes expensive or unreliable; route to private generation,
  stronger cryptographic operators, trusted/private compute, or provider-trust
  after explicit disclosure
```

Redundancy phase transition:

```text
if r_D >= c > 0
  trace budget is O(log(1 / (1 - rho)))
  independent of task depth D and branch factor K

if r_D = exp(-alpha * D)
  trace budget is Theta(exp(alpha * D) * log(1 / (1 - rho)))
  CLPD/CLE should not be presented as the privacy answer
```

This is the non-obvious cTEE frontier:

```text
zero online branch-selection leakage can be bought with public overgeneration
proportional to inverse proposal redundancy, not by privately evaluating the
entire transformer path.
```

Path privacy result:

```text
naive hidden K-way branch path over D steps
  may look like K^D public continuations

counterfactual complete-trace sampling
  needs O((1 / r_D) * log(1 / (1 - rho))) traces
  when complete traces have redundancy mass r_D
```

### CandidateCoverageProfile

```yaml
CandidateCoverageProfile:
  profile_id: coverage://...
  task_class:
    quant_strategy | code_patch | legal_review |
    personal_assistant | research | service_delivery | ...
  epsilon_tolerance: number
  coverage_target_rho: number
  estimated_redundancy_mass_r: number
  redundancy_phase:
    constant_mass | inverse_polynomial | exponential_decay | unknown
  candidate_trace_budget_m: integer
  public_token_budget: integer
  schedule:
    online_clpd | counterfactual_lattice | private_generation |
    private_operator | provider_trust
  fallback_if_coverage_low:
    deny | ask_user | route_private | use_trusted_compute |
    use_provider_trust_with_disclosure
  evidence_refs:
    - benchmark://...
    - eval://...
    - receipt://...
```

## Counterfactual Lattice Execution

Counterfactual Lattice Execution is the high-assurance CLPD schedule.

Instead of telling the rented node which private branch won and asking it to
continue that branch, the node expands a committed lattice of plausible futures
before private selection feedback:

```text
node expands candidate lattice
node commits lattice
guardian/private operator selects hidden path
only policy-approved result is declassified
```

This reduces online private-choice leakage because the node does not learn which
branch mattered during generation.

The scheduler should choose the lattice width/depth from
`CandidateCoverageProfile`: desired coverage, estimated redundancy mass, leakage
budget, public token budget, and latency budget.

Tradeoff:

```text
better selection privacy
  costs more public token volume
  preserves ordinary GPU kernels
  does not preserve same token budget
```

`CounterfactualLatticeReceipt` binds the lattice:

```yaml
CounterfactualLatticeReceipt:
  receipt_id: receipt://...
  capsule_id: private_workspace_capsule://...
  lattice_commitment: commitment://...
  model_hash: sha256:...
  policy_hash: sha256:...
  width_budget_k: integer
  depth_budget_d: integer
  public_token_budget: integer
  generation_rule_hash: sha256:...
  dedupe_rule_hash: sha256:...
  padding_rule_hash: sha256:...
  node_ref: runtime_node:...
  state_root: sha256:...
```

## Cryptographic Operator Plane

Cryptographic private operators are internal implementation tactics, not user
privacy modes. The user-facing contract remains:

```text
Open Private Workspace.
Private Workspace On.
```

The operator plane is how the daemon handles protected subcomputations when the
rented node must participate without learning protected inputs, private policy,
or final authority.

Default routing:

```text
public/generic work      -> rented GPU node
private file view        -> authenticated browser / client / guardian
private head/scoring     -> FHE / MPC / local / threshold operator
private retrieval        -> ORAM / local / private index
external action          -> daemon + wallet.network capability exit
state truth              -> Agentgres
```

This preserves ordinary GPU kernels for public/generic LLM work. Overhead
appears only at protected boundaries: private scoring, private selection,
private retrieval, declassification, and action authorization. If the compiler
chooses Counterfactual Lattice Execution, the run may spend more public tokens
to reduce private-choice leakage.

Default topology:

```text
Party A:
  DePIN / rented GPU node

Party B:
  authenticated browser
  local Hypervisor when available
  mobile guardian
  CLI signer
  wallet.network-backed policy/key path
  enterprise key service when org-managed
```

Rule:

```text
The second logical party is the authenticated authority surface by default.
Managed non-colluding committees are optional escalation paths, not default
infrastructure users must rent or understand.
```

When the node must participate in sensitive scoring without seeing the secret,
the compiler may use FHE ciphertexts, MPC shares, one-time masks, garbled
circuits, homomorphic scoring for low-degree formulas, private set membership,
committed private witnesses, or encrypted retrieval handles. The authority
surface completes reconstruction, declassification, or signing.

### CryptographicOperatorPolicy

```yaml
CryptographicOperatorPolicy:
  policy_id: crypto_op_policy://...
  workspace_id: workspace://...
  protected_classes:
    - pii
    - strategy_source
    - private_memory
    - broker_secret
    - live_portfolio
  allowed_operator_families:
    - fhe_linear
    - fhe_approx
    - mpc_nonlinear
    - garbled_boolean
    - oram_lookup
    - local_guardian
    - threshold_guardian
  default_second_party: authority_surface
  second_party_refs:
    - browser_session://...
    - mobile_guardian://...
    - cli_signer://...
    - wallet.network://...
  fallback_order:
    - local_guardian
    - threshold_guardian
    - fhe_linear
    - mpc_nonlinear
    - deny_or_escalate
  max_latency_budget_ms: ...
  leakage_budget_ref: leakage://...
  receipts_required:
    - PrivateOperatorReceipt
    - LeakageReceipt
```

Confidential-compute replacement boundary:

```text
cTEE can replace hardware confidential computing for a workload when every
protected dependency is absent from the node view, represented by an approved
cryptographic carrier, evaluated by the authority surface / guardian /
threshold path, or exercised through a capability exit, and every transition is
receipt- and leakage-policy-bound.
```

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
receipts and custody attestations binding the claim that no protected plaintext
classes were admitted to the node
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
  Counterfactual Lattice Execution when leakage budget requires it
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

   For high-sensitivity rounds, the daemon may ask the node to expand
   counterfactual branches before private selection. This preserves normal GPU
   kernels but spends additional public tokens to reduce selection leakage.

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

third-party model API over sensitive plaintext
  -> provider-trust posture; cTEE no-plaintext-custody claim does not apply

third-party model API over public/redacted/synthetic/declassified context
  -> compatible with cTEE under Redacted-API posture
```

The goal is not to make every token cryptographic. The goal is to preserve
normal token speed for non-sensitive context while preventing sensitive state
from entering rented-node plaintext.

Performance interpretation:

```text
normal token speed
  means public/generic kernels run normally on the rented GPU

same token budget
  is not guaranteed when the daemon expands candidate lattices,
  counterfactual branches, padding, or decoy jobs
```

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
PrivateOperatorReceipt:
  receipt_id: receipt://...
  policy_ref: crypto_op_policy://...
  run_id: run:...
  capsule_id: shielded_capsule://...
  operator_family:
    fhe_linear | fhe_approx | mpc_nonlinear |
    garbled_boolean | oram_lookup |
    local_guardian | threshold_guardian
  node_ref: runtime_node:...
  second_party_ref:
    browser_session://... | mobile_guardian://... |
    cli_signer://... | wallet.network://... |
    threshold_guardian://...
  protected_input_commitments:
    - commitment://...
  public_input_refs:
    - artifact://...
  output_commitment: commitment://...
  leakage_profile_ref: leakage://...
  policy_hash: sha256:...
  plaintext_sensitive_classes_on_node:
    - none
  status:
    success | failure | denied | escalated
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

Counterfactual Lattice Execution changes the accounting:

```text
online CLPD
  selection may be visible each round
  selection leakage can accumulate across loop depth

counterfactual lattice round
  node commits candidate lattice before private selection feedback
  online branch-selection leakage before declassification is zero
  public token volume and lattice metadata still leak according to policy
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
11. CLPD/CLE scheduling that claims coverage, low leakage, or bounded overhead
    records `CandidateCoverageProfile` or equivalent benchmark/eval evidence.
12. Counterfactual lattice claims record `CounterfactualLatticeReceipt` before
    private selection feedback reaches the rented node.
13. Custody claims that affect acceptance, dispute, restore, or marketplace
    settlement carry `CustodyProof` or a receipt-equivalent verifier result.
14. Model invocations over private workspaces emit `ModelMountReceipt` before
    execution.
15. Plaintext-Free Runtime Mounting exposes only public/redacted entries,
    encrypted refs, commitments, private handles, declassification requests,
    or capability handles to provider-rooted nodes.
16. Protected private-operator results are not admitted without
    `PrivateOperatorReceipt`.
17. Private operators use the authenticated authority surface as the second
    logical party by default unless policy explicitly selects another threshold
    path.
18. Deterrence/detection canaries are synthetic, policy-labeled, and excluded
    from real decisions, memory admission, training, and settlement truth.
19. Product UI exposes the user-facing mode as `Standard` or `Private`; detailed
    proof views may expose `private_native`, `redacted_api`, `provider_trust`,
    `TEE`, `cTEE`, or `unsafe` as evidence.
20. Any third-party model API that may receive sensitive plaintext is labeled
    `provider_trust` and disclosed before execution.
21. `private_native` posture is not claimed when sensitive plaintext is sent to
    a third-party model API.

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
- require users to rent or understand a managed non-colluding committee for the
  default private-operator path;
- expose FHE/MPC/local/threshold choices as ordinary user-facing privacy modes
  instead of internal routing policy;
- claim cTEE is a universal drop-in hardware-confidential-compute replacement
  for workloads that still require plaintext on hostile hardware;
- confuse ordinary public GPU token speed with same-token-budget private
  inference when the compiler uses candidate width, counterfactual branches,
  padding, or decoy jobs;
- market a third-party model API call over private plaintext as cTEE
  no-plaintext-custody privacy;
- label a worker or service package as private-native when its default path
  sends sensitive plaintext to a provider API;
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
- [`default-harness-profile.md`](./default-harness-profile.md):
  HarnessProfile semantics and Default Harness Profile reference
  scaffold/fallback behavior.
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md):
  authority, keys, declassification, and action power.
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md):
  artifact refs, archive refs, restore/import metadata, and payload meaning.
- [`../../domains/aiagent/worker-marketplace.md`](../../domains/aiagent/worker-marketplace.md):
  managed worker instances that may use Private Workspace placement.
- [`../../domains/sas/service-marketplace.md`](../../domains/sas/service-marketplace.md):
  service packages and outcomes that may declare Private Workspace privacy
  classes.
