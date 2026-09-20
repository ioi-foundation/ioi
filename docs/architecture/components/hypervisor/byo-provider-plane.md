# BYO Provider Plane

Status: implemented contract (daemon `provider_routes.rs`, first cut)
Doctrine status: canonical
Implementation status: built (the plane plus eight adapter lanes — ssh, vast, runpod, lambda_cloud, akash, aws, gcp, azure — and k8s/KubeVirt namespace admission behind one operation vocabulary; live paths env-gated; the provider-neutral live transaction lane is an executable gate whose spend-free half runs in CI and whose fresh positive live branch is scheduled behind owner credentials — M09.6, 2026-09-20, register R-210)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs`
  - `apps/hypervisor/scripts/verify-hypervisor-byo-provider-plane.mjs`
  - `apps/hypervisor/scripts/assemble-c7-c8-evidence.mjs`
  - `apps/hypervisor/scripts/lib/c7-c8-certificate.mjs`
  - `apps/hypervisor/scripts/verify-akash-live-lifecycle.mjs`
  - `scripts/check-provider-neutral-live-transaction.mjs`
  - `apps/hypervisor/scripts/lib/c7-c8-evidence.mjs`
  - `scripts/check-c8-bounded-live-effect-certificate.mjs`
Last implementation audit: 2026-09-20
Canonical owner: this file for the ProviderAccount object plane, provider credential
binding, snapshot custody, and provider spend posture. Provider/environment doctrine
authority remains `providers-and-environments.md`; pricing boundaries remain
`../../foundations/economic-flywheel-and-pricing-boundaries.md`.

## Doctrine

Customers bring their own compute (bare-metal/homelab SSH nodes, AWS, GCP, K8s, Vast,
Akash). Hypervisor provisions, governs, snapshots, restores, and receipts work on those
nodes — it is not a compute reseller. Two rules bind every adapter:

- **Provider state is evidence. Daemon/Agentgres admitted state is truth.** Provider-native
  IDs are evidence refs; restore validity is a daemon-recorded `sha256:` state root, never
  blob existence on the provider.
- **BYO provider spend is customer-borne.** Hypervisor records, governs,
  estimates, and reconciles provider cost. It does not hide markup inside the
  provider bill. Direct local or self-managed BYO usage carries no
  percentage-of-provider-spend fee. BYO-through-Hypervisor may carry a visible
  adapter/orchestration fee when Hypervisor provisions, brokers credentials,
  manages leases, snapshots, restores, tracks cost, emits receipts, or tears
  down the provider resource. `RoutingDecisionReceipt` remains reserved for
  optimized placement or paid routing/procurement value, not ordinary provider
  account use.

The provider ontology is vendor-neutral. Vendor names belong in the priority adapter ladder,
not in the core object model. `ProviderAccount`, `RuntimeNode`, `PlacementDecision`,
`SnapshotRef`, `RestoreRef`, `SpendReceipt`, and `ProviderOperationReceipt` are the durable
contract; provider adapters are replaceable implementations under that contract.

## Product Placement Abstraction

Users should see four placement choices, not provider-mode plumbing:

```text
Run local
Use my infrastructure
Pick a cloud
Let Hypervisor choose
```

Those choices map to economics and risk:

```text
Run local
  this machine, local sandbox, local KVM, or HypervisorOS node
  Hypervisor may charge for the control plane, collaboration, governance,
  receipts, memory, Provenance, and support
  no percentage fee on provider spend because there is no external provider

Use my infrastructure
  user's provider account, user's provider bill
  direct self-managed provider usage has no percentage fee on provider spend
  BYO-through-Hypervisor may charge a visible adapter/orchestration fee when
  Hypervisor performs credential brokering, provisioning, IP/port leases,
  snapshot custody, restore, monitoring, receipts, teardown, or audit

Pick a cloud
  user pins a provider or venue such as AWS, GCP, Vast, Akash, K8s, SSH,
  Proxmox, RunPod-like runtime, Lambda-like GPU VM, or Filecoin/CAS storage
  Hypervisor should show provider-specific posture, price, region, GPU,
  persistence, custody, and support boundaries before the user commits
  if Hypervisor executes the provider lifecycle, a visible orchestration fee is
  legitimate even though the user selected the venue

Hypervisor managed infrastructure / managed option
  IOI or a partner is provider-of-record
  Work Credits, managed-runtime margin, reserved capacity, and support margin
  are legitimate

Let Hypervisor choose
  Hypervisor may call decentralized.cloud or other candidate sources, then
  compares, routes, procures, fails over, reconciles, or aggregates billing
  across providers
  a visible routing/procurement fee is legitimate only when a challengeable
  routing or placement receipt is emitted
```

Guided credential binding, provider preflight, templates, SSH fixture setup,
restore custody, and security posture checks are setup/service features inside
`Use my infrastructure` or `Pick a cloud`. They are not separate placement
modes.

The orthogonal axes are:

```text
placement_source:
  connected | managed | optimized

selection_mode:
  local | user_pinned | policy_pinned | auto | failover

runtime_class:
  VM | microVM | container | devcontainer | GPU runtime | browser |
  model server | HypervisorOS node

custody_posture:
  Standard | Private
```

The user-facing "Placement Receipt" is a projection, not necessarily one durable object:

```text
PlacementDecision
  why this substrate was selected

ProviderOperationReceipt
  what provider operation happened or failed

SpendReceipt
  who owns cost and how spend is recorded

Adapter orchestration fee line
  billing/receipt annotation when Hypervisor performed provider lifecycle work
  for a pinned or BYO venue

RoutingDecisionReceipt
  only when optimized placement, including decentralized.cloud-sourced
  candidate selection, creates paid routing/procurement value
```

Canonical economic line:

```text
Hypervisor never hides where work runs.
It lets users run local, bring infrastructure, pick a venue, or delegate
placement, and charges only where it provides control-plane, orchestration,
routing, custody, or managed-capacity value.
```

### Implemented contract (current state)

Implementation status: built for the placement picker, candidate-plane
advisory fill, spend reconciliation, and the adapter lanes below.
Daemon truth is live-composed from ProviderAccount records,
environment-class provider eligibility, and preflight posture:

- `GET /v1/hypervisor/placement/venues` — the four venue cards with
  declared fee posture (`fee_object_minted: false`, `cost_owner:
  customer`), capability hints, and connected-provider status. No fee
  objects, no invented quotes, no RoutingDecisionReceipt.
- `GET|PUT /v1/hypervisor/placement/venue-policy` — the durable chosen
  venue (`ioi.hypervisor.placement-venue-policy.v1`); `hypervisor_choose`
  is filled by the cloud-candidate plane (`/v1/hypervisor/cloud-candidates/*`,
  `cloud_candidate_routes.rs`) from local facts and connected provider adapters,
  with explicit `no_eligible_candidate` → `run_local` fallback. This file is that
  plane's canonical doctrine: the plane was renamed out of a product name on
  2026-09-17 when decentralized.cloud left the repository
  (moved out 2026-09-17, ADR 0054 — an archived forwarding record:
  [`../../domains/decentralized/README.md`](../../domains/decentralized/README.md)),
  and the source it declared was never live.
- `GET /v1/hypervisor/placement/preview` — the pre-launch placement
  projection with `receipts_expected` named before launch.
- `GET /v1/hypervisor/provider-spend/reconciliation` — quote-backed
  `provider-spend-exposure://pse_*` rows open on metered create, reserve
  first-hour estimates against `external_spend`, and close (or
  `closed_with_warning`) on teardown; budget `spent` reflects actual
  debits only.

Adapter lanes proven behind this contract. Every lane preserves its
provider's real semantics — never a flattened generic cloud; quotes are
verbatim source prices or skipped (never estimated); provider-native ids
are evidence only; daemon-admitted sha256 state roots are the only
restore truth; live proof is env-gated and otherwise blocks with a named
reason (never silently simulated):

| Lane | Kind / adapter | Semantics preserved | Gate codes | Live proof | Done-bar |
| --- | --- | --- | --- | --- | --- |
| BYO SSH | `baremetal_ssh` | reference custody lane, full lifecycle over genuine ssh | — | loopback sshd fixture | `verify-hypervisor-byo-provider-plane.mjs` |
| GPU marketplace | `vast` / `adapter:vast-quote` | offer/bid marketplace lease, quote-gated create | `vast_*` | `IOI_VAST_LIVE=1` | `verify-hypervisor-vast-lifecycle.mjs` |
| GPU runtime cloud | `runpod` / `adapter:runpod-quote` | direct-provider GPU runtime, secure/community rate cards | `runpod_*` | `IOI_RUNPOD_LIVE=1` | `verify-hypervisor-runpod-adapter.mjs` |
| GPU VM | `lambda_cloud` / `adapter:lambda-quote` | ordinary Linux GPU VM + ssh + instance-lifetime disk | `lambda_cloud_*` | `IOI_LAMBDA_LIVE=1` | `verify-hypervisor-lambda-gpu-vm-adapter.mjs` |
| DePIN compute | `akash` / `adapter:akash-bid` | SDL → bids → lease → endpoints → close → redeploy | `akash_*` | `IOI_AKASH_LIVE=1` | `verify-hypervisor-akash-depin-adapter.mjs` |
| Enterprise hyperscaler | `aws` / `adapter:aws-ec2-quote` | IAM/SigV4, VPC/security-group posture bound in the wallet challenge, real EC2 stop/start/restart billing | `aws_*` | `IOI_AWS_LIVE=1` | `verify-hypervisor-aws-enterprise-vm-adapter.mjs` |
| Enterprise hyperscaler | `gcp` / `adapter:gcp-compute-quote` | service-account IAM, project/zone/firewall posture bound in the wallet challenge, real Compute Engine billing | `gcp_*` | `IOI_GCP_LIVE=1` | `verify-hypervisor-gcp-enterprise-vm-adapter.mjs` |
| Enterprise hyperscaler | `azure` / `adapter:azure-vm-quote` | service-principal (`azure-service-principal`) over ARM, subscription/resource-group/location + VNet/NSG posture bound in the wallet challenge, stop DEALLOCATES and says so | `azure_*` | `IOI_AZURE_LIVE=1` | `verify-hypervisor-azure-enterprise-vm-adapter.mjs` |
| Cluster substrate | `k8s` / `adapter:k8s-cluster-facts` | clusters as CLUSTERS: namespace-scoped admission (RBAC/quota/PVC/GPU/service fail closed by name), Kubernetes exec (never fake single-VM SSH), KubeVirt VMIs when CRDs exist, unpriced customer clusters open NO exposure (metered posture must be declared AND priced) | `k8s_*` | `IOI_K8S_LIVE=1` | `verify-hypervisor-k8s-kubevirt-cluster-adapter.mjs` |

Billing semantics stay provider-real and honestly labeled: Lambda VMs
bill until terminate (`workspace_stopped_vm_running`); AWS stop halts
instance-hours while EBS keeps billing (the exposure stays open until
terminate); GCP stop reads TERMINATED with Persistent Disk still billing; Azure stop
DEALLOCATES (a merely-stopped VM keeps billing compute; managed disks bill
until delete);
Akash leases bill until CLOSED, and `redeploy` closes the
deployment-loss → restore-elsewhere loop over the storage plane;
private-only / no-ingress network postures fail CLOSED at boot
(`aws_ssh_ingress_unreachable` / `gcp_ssh_ingress_unreachable` /
`azure_ssh_ingress_unreachable`, naming the NSG).

Cross-provider FAILOVER is proven over these lanes: a failed environment
restores onto a different provider class from daemon custody (or the
storage-archive ladder), wallet-gated at every mutation, exposures
closing/opening honestly — done-bar
`verify-hypervisor-cross-provider-failover.mjs`; doctrine in
the archived forwarding record [`cloud.md`](../../domains/decentralized/cloud.md).

The cut-by-cut adapter build narration is archived verbatim at
[`../../_archive/implementation-logs/byo-provider-plane-adapter-build-log.md`](../../_archive/implementation-logs/byo-provider-plane-adapter-build-log.md).

## Priority Adapter Ladder

This ladder is roadmap priority, not a permanent provider ranking and not a routing policy.
It says which adapters should be proven first because they strengthen the lifecycle contract
for GPU SSH deployment, lease/IP posture, snapshot/archive/restore custody, spend evidence,
and provider-specific failure modes.

| Priority | Adapter class | Canonical role |
| --- | --- | --- |
| 1 | `baremetal_ssh` / homelab / Proxmox / KVM | Reference BYO adapter and conformance lane. Proves lifecycle, authority, workspace mutation, snapshot custody, restore, and receipts without a third-party cloud account. |
| 2 | Simple GPU VM providers such as Lambda Cloud | First paid GPU VM lane. Optimize for ordinary Linux VM + SSH + persistent disk + GPU inference loops before more exotic markets. |
| 3 | GPU runtime clouds such as RunPod | High-value dev-agent/model-serving lane with API-created GPU runtimes, SSH/web/editor access, network volumes, and zero-to-idle posture. |
| 4 | GPU marketplaces such as Vast.ai | Opportunistic capacity and price-discovery lane. Adapter must preserve offer/ask, availability, interruption, data-movement, and custody semantics rather than pretending every node is equivalent. |
| 5 | Enterprise hyperscalers, starting with AWS | Customer-cloud and enterprise lane for IAM, VPC/networking, EBS-style snapshots, audit, compliance, reserved capacity, and procurement expectations. |
| 6 | GCP and Azure | Customer-cloud coverage after AWS, especially for organizations already standardized on those clouds and their disk snapshot/identity/networking models. |
| 7 | Kubernetes, KubeVirt, CoreWeave, and customer clusters | Cluster substrate lane. Treat as cluster/provider posture with persistent volumes, namespaces, quotas, GPU scheduling, and admission, not as fake single-VM SSH. |
| 8 | Akash | DePIN compute/GPU lane. Preserve deployment, bid/provider selection, lease, IP lease, persistent storage, log/event, shell/exec, stop/close, and redeploy semantics. |
| 9 | Filecoin / CAS / IPFS storage | Archive and custody lane, not compute. Holds encrypted snapshot/archive/evidence bytes by content address while Agentgres/daemon state remains restore truth. |

The first production-quality external-compute trio should be Lambda-like GPU VMs,
RunPod-like GPU runtimes, and Vast-like GPU marketplaces. Akash and Filecoin remain
canonical, but they should enter after the generic lifecycle, custody, and spend receipts are
proven against SSH plus at least one straightforward GPU VM/runtimes provider.

Implementation rule:

```text
Build adapters in priority order.
Do not encode provider preference into placement truth.
Do not claim private/custody/restore guarantees from provider APIs alone.
Provider state is evidence; daemon/Agentgres admission is truth.
```

## ProviderAccount — `provider-account://pacc_*` (`ioi.hypervisor.provider-account.v1`)

Durable records under `/v1/hypervisor/provider-accounts` (CRUD + `/credential` +
`/preflight`). Account kinds admitted by the daemon:
`baremetal_ssh | aws | gcp | k8s | vast | runpod | lambda_cloud | akash`.
The priority ladder may name future adapter classes (clusters, Azure) before their account
kinds exist; they must not be presented as supported `ProviderAccount.kind` values until
the daemon admits them. Fields: display name,
kind, `status: unverified | verified | revoked`, `credential_binding_ref`, endpoint hints,
`provider_spend_borne_by: customer`, `budget_policy_ref`, per-kind capabilities (honest
per-provider semantics — never a flattened fake generic cloud; privacy posture never claims
"private" without custody proof). Endpoint changes invalidate a prior preflight verdict.
`GET /v1/hypervisor/providers` lists static adapters × durable accounts; placement reads
this catalog live, so a verified account becomes placeable with no extra wiring.

## Credential binding — one spine, no new gate

Provider secrets bind at `POST /provider-accounts/:id/credential`, sealed with the same
dcrypt ladder as every credential (`provider-credentials` vault), fingerprinted
(sha256), never returned, never exported. Kinds ride the existing CapabilityLease resolver:
`ssh-key` (new), `aws-sigv4`, `oidc-workload` (gcp), `bearer` (k8s/vast/akash). Binding
proves presence + preflight; agents and runs never receive provider secret material — the
daemon executes provider calls itself and materializes the ssh key only for the duration of
one operation.

## Authority + budget ordering (per operation)

Every mutation op on an account (`POST /provider-ops`, `provider_id: pacc_*`) runs, in
order: (1) **budget discovery BEFORE provider mutation** — `baremetal_ssh` is `local_free`
customer-borne; metered kinds require an `external_spend` resource budget to exist and have
headroom, else `budget_blocked` (409, receipted); (2) **a real wallet grant** via
`authorize_capability_lease` — 403 challenge echoing exact policy/request hashes, per-op
request facets (account, op, environment), lease descriptor persisted without secrets.
Presence-check `grant_ref` strings do not pass. Preflight/observe are read-only and
ungated.

**The challenge carries the bytes that will execute (2026-09-20, M03.9, register
R-212).** The 403 challenge echoes `lease_request_facets` — for a direct
marketplace deployment: stage, the SDL-derived ceiling amount and denomination,
the deposit, the provider selector, the SDL hash, the teardown policy, the
execution mode and auto-topup — and, under `approval`, the two preimages:
`request_preimage` and `policy_preimage`, the exact JSON strings the request
hash and the policy hash are the SHA-256 of, serialized by the same function
that hashes them. The hashed request adds the account, operation, environment,
kind and spend posture and omits the raw SDL; it is not the echoed superset. A
signing surface renders the signed facts FROM the request preimage, every
hashed member as the bytes the hash covers, with the full policy hash, request
hash and grant audience, and re-derives the request hash from those bytes
before it signs: what you sign is what executes. A paraphrased, truncated or
locally reconstructed facet set is a defect, and a challenge that carries no
preimage is not signable byte-derived. The gate that proves this is
`check:approval-card-facets`: the card grammar and its diff harness over a
tracked daemon-minted challenge fixture and, in full mode, over a fresh
challenge from an isolated daemon; the lane that parks a blocked provider
operation as a card in the App is the spend-approval lane's own unit.

## Receipts — success AND failure

Every dispatched op mints `ioi.hypervisor.provider-receipt.v1`
(`agentgres://provider-receipt/prc_*`, listed at `/v1/hypervisor/provider-receipts`)
enriched with `account_ref`, `grant_ref`, the full capability-lease descriptor,
`credential_source`, budget discovery, and cost estimate. Refused crossings (missing
authority, unresolved credential, budget block, refused restore) are receipted too.
Admitted ops persist as `ioi.hypervisor.provider-operation.v1` (`pop_*`).

## Snapshot / restore custody

`snapshot` streams the remote workspace back into daemon custody
(`ioi.hypervisor.provider-material.v1`, `provider-material://…`, bytes under the daemon's
`provider-materials/`); the daemon computes and admits `state_root: sha256:*`. `restore`
re-hashes the custody bytes against the ADMITTED state root and fails closed
(`restore_refused`) on unknown material or mismatch — before touching the node. `recover`
is restore-from-latest-admitted-material.

## Adapter ladder (current state)

`baremetal_ssh` is the reference BYO adapter — full `EnvironmentProvider` lifecycle
(preflight/create/start/workrun/stop/snapshot/restore/inject_outage/recover/delete/observe)
over genuine ssh, CI-proven against a loopback sshd fixture (`ensure-ssh-fixture.mjs`).
Metered kinds (`vast | runpod | lambda_cloud | akash | aws | gcp`) run guarded,
quote-gated lifecycles once a control-plane mode is set and are
`credential_preflight_only` before that — a mode-less metered account never fakes a
cloud. Kinds without a lifecycle adapter yet (`k8s`) are **credential + preflight
only**: accounts and sealed bindings are real, preflight proves credential
resolvability honestly (no cloud API call is claimed), and every lifecycle op fails
closed with `PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED` — never a fake cloud.

## EnvironmentClass honesty

Environment classes are durable records (`ioi.hypervisor.environment-class.v1`) with
`provider_eligibility` (provider kinds, required capabilities, credential kind, spend
posture). `enabled` is computed at read time and is true only when a real provider/account
path backs the class: local always; microvm only while the pinned, checksum-verified VM
toolchain resolves on the host; `byo-ssh-node` only while a verified `baremetal_ssh`
account exists.

Claim-truth note (emergency containment, 2026-07-29): the microvm arm previously returned an
unconditional `enabled: true, real: true` constant that probed nothing, so a host with no
monitor binary and no pinned toolchain still advertised an operational microVM lane — which
violated this section's own rule. The arm now resolves the same toolchain `build_vm_spec`
requires and reports `enabled: false` with a named `unavailable_reason` when it does not. The
done-bar assertion that pinned the old constant asserted a literal and is quarantined as
non-authoritative; it is retained, rewritten to check that the reported value matches the
probe. See [INV-38](../../foundations/invariants.md).

## Surfaces

Provider accounts live INSIDE the estate (no peer provider-management product):
Environments shows the account catalog with credential/preflight/spend posture; Operations
shows provider health and the recent receipt trail — both stating customer-borne spend
plainly.

Done-bar: `apps/hypervisor/scripts/verify-hypervisor-byo-provider-plane.mjs` (32 checks).

## Attached-estate claim journey

An Infrastructure claim is admitted for one selected adapter only after an
authenticated, host-identity-verified attachment produces current capability
evidence; read-only host, machine, storage, and network inventory; one
authority-mediated mutation; desired-versus-observed reconciliation including
out-of-band drift; scoped access; exact supported restore semantics; ambiguous-
effect recovery; and detach without deleting external resources or retained IOI
truth. Attachment begins read-only. Mutation is a separate graduation.

IOI manages the admitted estate through its existing provider and environment
owners. It does not thereby become the underlying VMM, acquire cluster
membership, or claim unsupported migration/HA semantics. Simulated evidence may
exercise projections but cannot close the live attached-estate claim.

## The Provider-Neutral Live Transaction Lane

One lane, provider-neutral in shape, proven on one provider: typed
admissible-provider selection, a verbatim-or-skipped quote, the committed
intent root, execution, the outcome root, reconciliation on ambiguity, teardown,
and provider-native billing readback, authorized leg by leg — a plan document
is never authorization to spend. The lane has two terminal branches and never
conflates them: no qualified bid → deployment close → provider-confirmed refund
or final debit, and qualified bid → selected lease → live provider readback →
endpoint evidence → teardown → provider-confirmed zero open exposure. Safe
refusal is not successful deployment; close acceptance is not refund
settlement. Changing the ceiling or the selector requires a fresh challenge and
explicit owner approval of the changed facets.

**The lane is executable (2026-09-20, M09.6, register R-210).** The runner is
`check:provider-neutral-live-transaction`. Its clauses are the legs above and
the two branches, each executed by the floored gates that already prove them —
the governed-effect assurance floor for the two-phase boundary, proposal
provenance for leg-by-leg authorization, the provider transport boundary,
provider-spend reconciliation for the readback, the retained capstone's
applicability to this tree, and the Akash lifecycle contract pins — or by the
runner's own legs: the no-qualified-bid branch as a typed terminal certificate
GENERATED at run time from the retained durable records of the nine live
closes (the deployment records with their provider-native settlement
readbacks, secrets stripped, kept in the tree), verified, and mutation-drilled
so that a lease smuggled into a no-bid certificate, a no-bid certificate
re-labelled success, a pending refund, a refund short of the deposit or an open
exposure each go red; and the provider-neutral shape read from the daemon's
own dispatch (one operation vocabulary over eight adapters behind one trait),
with the certificate's refusal to certify neutrality kept as the boundary it
is. The fresh positive live branch — bid, lease, live provider readback,
endpoint, teardown, provider-confirmed zero open exposure — is the unit's
scheduled check behind owner credentials and a funded deposit, authorized leg
by leg; a missing credential blocks that run, never the unit. The verdict is a
pass only with zero named failures and the live branch executed; today it is
the named failure, and no provider-neutral live pass is claimed.

## The C8 v2 Bounded Provider-Lifecycle Certificate

The immutable C8 v2 bounded provider-lifecycle certificate
(`ioi.hypervisor.c7-c8-certificate.v2`) is the machine-verifiable record of one
bounded live effect on one provider. It binds the source commit and daemon
binary of the run, the authenticated operator principal, the challenge policy
and request hashes and the exact reviewed facets (deposit, ceiling, selector,
SDL hash, teardown policy, retry count), the wallet grant and the consumed
one-shot capability lease with its expiry and revocation, the daemon-issued C4
proposal admission and consumption, the C2 intent and outcome roots with the
outcome a distinct successor of the intent, the provider-native deployment, bid,
provider and lease identifiers, the C6 state fetched live, the endpoint
evidence, teardown, the provider-native final billing or refund readback, the
final net cost, zero open and unknown exposure, and the negative refusal
receipts. Secret values, password paths, bearer sessions and credential
material are forbidden fields. The implementation program calls this object the
"bounded-live-effect certificate"; that is a gloss for the same v2 object, not a
second certificate. It is neither the kernel's C8 clause (deterministic replay
and recovery, in `../../foundations/web4-and-ioi-stack.md`) nor the
`C8CertificateV3` successor envelope of `providers-and-environments.md`, which
carries this v2 certificate as its exact predecessor.

Every incomplete or unsafe condition yields a typed non-success report, never a
success label: `ok:false`, inline caller-authored proposal provenance, a pending
refund, a missing provider readback, an absent or open lease, an unconsumed or
reusable one-shot lease, mismatched roots, unreconciled spend or a
secret-bearing artifact each refuse success by their own typed code, and the
report that carries those codes certifies nothing. The lane's other typed
non-success is the no-qualified-bid terminal certificate above: a terminal
outcome, not a refusal, and never a success either.

**The certificate is generated, not read (2026-09-20, M12.9, register R-211).**
The runner is `check:c8-bounded-live-effect-certificate`. It does not read a
pre-sealed certificate: it assembles the run evidence at run time from a
tracked, redacted, hash-committed record set of one retained owner-authorized
positive live run (the 2026-08-21 run that reached bid, lease, live provider
readback, endpoint evidence, teardown and a provider-confirmed final debit; it
is NOT the T7 integrated capstone, which stays re-qualified by its own
applicability gate as an attested hash), seals it, verifies it, and requires the
regenerated hash to equal the hash sealed on the day the records were written,
so the certificate bytes never need to be tracked. It then replays the
verifier's twenty-two structural and twenty-two durable mutation cases on the
generated certificate against the retained records, classifying each case as
fired, not applicable by a typed reason, or masked by the moved tree: the three
host-bound checks (the substrate log prefix, the certified daemon binary, the
equality of HEAD with the run's commit) are the named remainder that only the
run's own host can answer, and the gate asserts they are exactly three. Under
the kernel's C8 clause a certificate regenerated from retained records is
evidence about the retained crossing and never a new one; a fresh certificate
from a fresh live crossing is the unit's scheduled check behind owner
credentials and a funded deposit, authorized leg by leg. The verdict is a pass
only with zero named failures and the fresh crossing executed; today it is the
named failure, and no fresh bounded-live-effect pass is claimed.
