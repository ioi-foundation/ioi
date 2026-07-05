# BYO Provider Plane

Status: implemented contract (daemon `provider_routes.rs`, first cut)
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
  receipts, memory, Work Ledger, and support
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

### Implemented contract (placement picker cut)

Daemon truth, live-composed from ProviderAccount records, environment-class
provider eligibility, and preflight posture:

- `GET /v1/hypervisor/placement/venues` — the four venue cards (`run_local` ·
  `use_my_infrastructure` · `pick_provider` · `hypervisor_choose`) with
  per-venue fee posture (`fee_basis`, explanation, `fee_object_minted: false`,
  `cost_owner: customer`), kind-level capability hints (GPU / storage / IP /
  snapshot — labeled hints, never probed claims), connected/not-connected
  provider cards with verified/unverified + preflight reasons, and the declared
  `fee_bases` taxonomy (`none | subscription_control_plane |
  adapter_orchestration_fee | routing_fee | managed_margin`). No fee objects,
  no invented quotes (`quote: null` + quote policy), no RoutingDecisionReceipt.
- `GET|PUT /v1/hypervisor/placement/venue-policy` — the durable chosen venue
  (`ioi.hypervisor.placement-venue-policy.v1`, singleton `current`, history
  appended). Provider-pinned venues require a resolvable ProviderAccount of the
  right family; `hypervisor_choose` is accepted as an ADVISORY placeholder
  (`effective_venue: run_local`, explicit note) until the decentralized.cloud
  candidate plane exists — venue selection is never hidden behind auto.
- `GET /v1/hypervisor/placement/preview` — the pre-launch placement projection:
  venue card + pinned provider posture + fee copy + `receipts_expected` (the
  PlacementDecision / ProviderOperationReceipt / budget-discovery / lease
  receipt kinds a run at this venue mints — named before launch).
- Consumption: ioi-agent launch previews carry a `placement` block; launch
  phase A and environment create snapshot the venue policy in force
  (provenance — substrate stays local until session relocation lands). Provider
  receipts surface in the Work Ledger as `provider_crossing` proof entries.
- Surfaces: New Session modal venue picker (four explicit choices, fee copy,
  provider pinning); Environments shows the venue cards + provider cards;
  Operations links provider receipts into the ledger.

Done-bar: `apps/hypervisor/scripts/verify-hypervisor-placement-venue-picker.mjs`.

The `hypervisor_choose` venue is filled by the decentralized.cloud candidate
plane (`/v1/hypervisor/cloud-candidates/*` — canonical doctrine
`../../domains/decentralized/cloud.md`): evidence-bound, expiring candidates
derived from local facts, a deterministic reason-coded advisory, and explicit
`no_eligible_candidate` fallback to `run_local`. Candidates are never
authority; no fee objects or RoutingDecisionReceipt exist. The first live
external quote source is Vast (`adapter:vast-quote`, quote + preflight +
candidate enrichment only — verbatim offer prices, `advisory_only`
eligibility, done-bar `verify-hypervisor-vast-candidate-adapter.mjs`). The guarded Vast
LIFECYCLE is live behind it: quote-gated create (budget → quote freshness/
liveness → wallet lease binding quote/candidate/max-price/GPU/teardown), the
BYO SSH workspace/custody contract reused verbatim on the leased instance,
enriched receipts on every path, teardown always; simulator control plane for
CI (labelled, live_provisioning_not_run); done-bar
`verify-hypervisor-vast-lifecycle.mjs`.

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
`/preflight`). First-cut account kinds: `baremetal_ssh | aws | gcp | k8s | vast | akash`.
The priority ladder intentionally names future adapter classes such as Lambda-like GPU VMs
and RunPod-like GPU runtimes before their account kinds exist; they must not be presented as
supported `ProviderAccount.kind` values until the daemon admits them. Fields: display name,
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

## Adapter ladder (this cut)

`baremetal_ssh` is the first real BYO adapter — full `EnvironmentProvider` lifecycle
(preflight/create/start/workrun/stop/snapshot/restore/inject_outage/recover/delete/observe)
over genuine ssh, CI-proven against a loopback sshd fixture (`ensure-ssh-fixture.mjs`).
Cloud kinds are **credential + preflight only**: accounts and sealed bindings are real,
preflight proves credential resolvability honestly (no cloud API call is claimed), and
every lifecycle op fails closed with `PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED` — never a
fake cloud.

## EnvironmentClass honesty

Environment classes are durable records (`ioi.hypervisor.environment-class.v1`) with
`provider_eligibility` (provider kinds, required capabilities, credential kind, spend
posture). `enabled` is computed at read time and is true only when a real provider/account
path backs the class: local always; microvm while the VmMonitor lane is operational;
`byo-ssh-node` only while a verified `baremetal_ssh` account exists.

## Surfaces

Provider accounts live INSIDE the estate (no peer provider-management product):
Environments shows the account catalog with credential/preflight/spend posture; Operations
shows provider health and the recent receipt trail — both stating customer-borne spend
plainly.

Done-bar: `apps/hypervisor/scripts/verify-hypervisor-byo-provider-plane.mjs` (32 checks).
