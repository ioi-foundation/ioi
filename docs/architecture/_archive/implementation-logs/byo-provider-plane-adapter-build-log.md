# BYO Provider Plane — Per-Adapter Build Log (placement picker cut through GCP)

Status: archived implementation build log (verbatim extraction).
Doctrine status: archived
Implementation status: n/a (historical record)
Archived from: `docs/architecture/components/hypervisor/byo-provider-plane.md` on 2026-07-05.
Canonical owner: `docs/architecture/components/hypervisor/byo-provider-plane.md` (live doctrine); this file is history, not authority.
Superseded by: the canonical owner doc. Git history retains the original placement.

---

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

Provider SPEND RECONCILIATION rides those receipts
(`GET /v1/hypervisor/provider-spend/reconciliation`): a quote-backed metered
create opens a `provider-spend-exposure://pse_*` row citing account /
candidate / quote / grant / receipt refs (native ids evidence-only); open
exposures RESERVE first-hour estimates against the `external_spend` budget
(further creates refuse `vast_budget_reservation_exceeded` until teardown
releases them); ops accrete receipts and state roots without inventing price;
teardown closes the exposure — an unconfirmed native destroy leaves a standing
`closed_with_warning` incomplete-teardown warning. Budget `spent` reflects
actual debits only — estimates never fake it; no fees, no markup, no Work
Credit debit, no fake settlement: customer-borne provider spend throughout.
Done-bar: `verify-hypervisor-provider-spend-reconciliation.mjs`.

The LIVE Vast harness completes the lifecycle contract: live create seals an
ephemeral per-instance ssh key onto the instance record (dcrypt discipline —
never plaintext; materialized 0600 per op) and attaches the public key to the
lease; boot polling persists the runtime ssh block ONLY with readiness
evidence (polled status + proven_at), and every workspace op fails closed
with `vast_ssh_bootstrap_unknown` before that; bootstrap-on-start then reuses
the BYO SSH lane unchanged. `IOI_VAST_LIVE=1` proves the full live path or
BLOCKS with `vast_live_credentials_absent` — live execution is never claimed
without a real leased instance reaching ssh (simulator CI keeps reporting
live_provisioning_not_run).

RunPod is the SECOND GPU class (`adapter:runpod-quote` + guarded lifecycle),
proving the ladder is not Vast-specific while preserving RunPod semantics: a
`direct_provider` GPU runtime cloud quoted from per-GPU-type rate cards
(secure-cloud on-demand preferred; community-cloud pricing carries an explicit
interruption risk label; unpriced types are skipped, never estimated; region
is chosen at pod create). The same budget → quote → wallet ladder guards
create with per-kind reason codes (`runpod_quote_not_live`,
`runpod_price_above_max`, `runpod_budget_reservation_exceeded`, …); pods reuse
the BYO SSH custody lane; exposures open/close identically; custody is
`cloud_gpu_runtime_NOT_private`. `IOI_RUNPOD_LIVE=1` proves live or blocks
named. Done-bar: `verify-hypervisor-runpod-adapter.mjs`.

Lambda-class GPU VMs (`lambda_cloud`, `adapter:lambda-quote` + guarded
lifecycle) complete the first production external-compute trio: the BORING,
high-trust ordinary Linux GPU VM lane — VM + ssh (user ubuntu) +
instance-lifetime persistent local disk — never flattened into a generic
cloud. Quotes are per-instance-type rate cards priced in cents/hour
(converted verbatim; unpriced preview shapes skipped, never estimated) with
per-region capacity; region is chosen at create and the wallet challenge
binds it together with the instance type, disk, and teardown policy. ssh is
UNKNOWN until boot polling proves readiness (`lambda_ssh_bootstrap_unknown`
before that; resumable `lambda_boot_pending`); the VM reuses the BYO SSH
custody lane, so daemon-admitted sha256 state roots remain restore truth and
provider-native VM/disk/snapshot ids stay evidence-only. There is no native
stop — the VM accrues customer-borne spend until teardown, and the lifecycle
says so (`workspace_stopped_vm_running`) instead of faking it. Custody is
`cloud_vm_NOT_private`; exposures open/close (or close_with_warning)
identically; per-kind gate codes are `lambda_cloud_*`. `IOI_LAMBDA_LIVE=1`
proves live or blocks named. Done-bar:
`verify-hypervisor-lambda-gpu-vm-adapter.mjs`.

Akash is the DePIN compute/GPU lane (`adapter:akash-bid` + guarded
lifecycle), and deliberately NOT a generic VM adapter: semantics are
deployment intent → SDL manifest → provider BIDS → LEASE → lease-assigned
endpoints → logs/events → close → REDEPLOY. Bids are priced ONLY by a
source-quoted USD rate (the native uakt/block rate is carried as evidence,
never converted by the daemon; unquoted bids are skipped). The wallet
challenge binds the deployment spec (SDL hash) + bid/lease + persistence +
rate cap; endpoints are proven at start and recorded as evidence, not
authority; exec/custody ride the SDL-declared ssh service (provider-native
lease-shell lands with the live harness); provider-native dseq/bid/lease ids
stay evidence only, and deployment persistent storage is SDL posture — never
restore truth. Leases bill until CLOSED (stop says so); simulated
provider-side revocation exercises the bid_lease_revocation risk, and
`redeploy` mints an `AkashRedeployPlan` binding old → new deployment plus the
daemon-material and storage-archive refs — restore admits only after daemon
state_root + storage commitment validation, closing the deployment-loss →
restore-elsewhere loop over the storage plane. Per-kind gate codes are
`akash_*`; exposures open on create AND redeploy. `IOI_AKASH_LIVE=1` proves
live or blocks named (the on-chain tx flow lands with the live harness cut).
Done-bar: `verify-hypervisor-akash-depin-adapter.mjs`.

AWS is the first ENTERPRISE hyperscaler lane (`adapter:aws-ec2-quote` +
guarded lifecycle) — a customer-cloud posture, not a marketplace: IAM/SigV4
sealed credentials whose IAM scope bounds every action
(`iam_scope_dependent`), region/AZ-bound quotes from verbatim on-demand rate
cards (unpriced shapes skipped), and an ENTERPRISE NETWORK POSTURE bound into
the wallet challenge — explicit VPC/subnet/security-group config or the
labelled default-VPC simulator posture, with public-IP and SSH-ingress flags.
Private-only / no-ingress postures fail CLOSED at boot
(`aws_ssh_ingress_unreachable`) — never fake-ready. EC2 lifecycle semantics
are real: stop halts instance-hours while EBS storage keeps billing (the
exposure stays open until terminate, and stop says so), start-from-stopped
notes that a stop/start cycle can change the public IP, and restart is an
in-place reboot with the endpoint retained. EBS root volume posture is
recorded per instance and native EC2/EBS/snapshot ids (`i-*`, `vol-*`,
`snap-*`) are EVIDENCE only — daemon custody state roots remain restore
truth; archive/restore ride the storage plane. CloudTrail-style audit refs
land with the live harness (the audit trail is the customer's). Per-kind gate
codes are `aws_*`. `IOI_AWS_LIVE=1` proves live or blocks named (the SigV4
EC2 API flow lands with the live harness cut). Done-bar:
`verify-hypervisor-aws-enterprise-vm-adapter.mjs`.

GCP is the sibling enterprise lane (`adapter:gcp-compute-quote` + guarded
lifecycle), proving the customer-cloud pattern generalizes across IAM models
WITHOUT flattening semantics: service-account/workload-identity sealed
credentials (`iam_service_account_scope_dependent`), PROJECT/region/ZONE
scoping bound into the wallet challenge alongside machine type, Persistent
Disk posture, and the VPC network/subnetwork/FIREWALL posture
(`explicit_network_config` vs the labelled `default_network_simulator`).
Missing firewall ingress or private-only postures fail CLOSED at boot
(`gcp_ssh_ingress_unreachable`, naming the firewall) — instance state alone
is never readiness. Compute Engine billing semantics are real: stop reads
TERMINATED (vCPU/RAM billing halts, Persistent Disk keeps billing, the
exposure stays open until delete), start-from-TERMINATED notes the
ephemeral-external-IP change, restart is an in-place reset with the endpoint
retained. Native instance paths (`projects/{p}/zones/{z}/instances/{n}`),
disk names, and snapshot names are EVIDENCE only; Cloud Audit Log refs land
with the live harness. Per-kind gate codes are `gcp_*`. `IOI_GCP_LIVE=1`
proves live or blocks named. Done-bar:
`verify-hypervisor-gcp-enterprise-vm-adapter.mjs`.
