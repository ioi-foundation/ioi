# M15.3 — `CloudJobRequest` as the composition surface

Design only. No Rust was written for this document and none should be written
from it without an owner go: the unit needs daemon changes, a cargo build on a
shared box, and eventually real spend. Every anchor below was read out of the
worktree at `decentralized-cloud/m15`; anchors are `file:line` and are quoted
verbatim so a later implementer can check them rather than trust them.

Canon: [`cloud.md` § Minimal Implementation Objects](../../../docs/architecture/domains/decentralized/cloud.md)
and [ADR 0051](../../../docs/decisions/0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md).

Abbreviations used throughout:
`PR` = `crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs`,
`PF` = `.../placement_failover_routes.rs`,
`DCR` = `.../decentralized_cloud_routes.rs`,
`DAEMON` = `crates/node/src/bin/hypervisor-daemon.rs`.

---

## 1. What exists today, stated exactly

`grep -rn "CloudJobRequest\|cloud_job" crates/` returns **zero hits**. The
envelope does not exist at any layer. What does exist:

| Piece | Where | State |
|---|---|---|
| `CloudResourceIntent` | `DCR:101` builder, `DCR:797` handler | Exists. All eight canonical fields are accepted and stored. |
| Intent validation | `DCR:802-822` | Only two fields are validated: `resource_classes` against `RESOURCE_CLASSES` (`DCR:36-52`) and `custody_posture` against `CUSTODY_POSTURES` (`DCR:53`). |
| Inert intent fields | — | `user_placement_choice`, `selection_mode`, `privacy_requirements`, `region_preferences`, `budget_policy_ref`, `failover_policy_ref` are recorded and have **no read sites** in candidate derivation or ranking. `custody_posture` and `support_boundary` do (`DCR:198`, `PF:253`, `PF:260`). |
| Candidates | `DCR:218` generic builder; `VAST:220` per-provider | No Rust struct — `serde_json::Value` throughout. `evidence_mode` and the `quote` object exist ONLY on per-provider candidates (`VAST:358`, `VAST:338`); the generic builder emits `quote_ref: null` and a `quote_state` string (`DCR:257-258`). |
| Placement decision | `PF:307` handler, `PF:202` minter | Exists, mints a decision plus a decision receipt. |
| Fee | `PF:257`, `PF:283` | `"fee_object_minted": false` at both sites. No fee object exists anywhere. |
| The gate ladder | `PR:8958` | Exists and is complete: budget → quote freshness → wallet capability grant → effect → receipt on both paths. |

**The one-sentence finding:** the job primitive is not a new engine. Every
mechanism it needs already runs; what is missing is an envelope that binds them
and one resolver that turns `caller_kind` into an authority path.

---

## 2. The envelope

`CloudJobRequest` is a composition envelope over exactly one
`CloudResourceIntent` (canon, § Minimal Implementation Objects). It is not a
second intent type and it is not authority.

```
job_ref               CloudJobRef            server-minted, like intent_ref at DCR:105
intent                CloudResourceIntent    exactly one; the existing builder at DCR:101
caller_kind           human | agent          the ONLY field that changes the authority path
authority_ref         AuthorityRef           wallet grant (human) or CapabilityLease draw-down (agent)
budget_ref            BudgetRef              an existing external_spend budget, never an inline amount
deadline              JobDeadline            absolute deadline or max duration
receipt_requirements  ReceiptRequirements    placement | provider-operation | spend | failover | offline-verifiable
failover_policy_ref   Option<PolicyRef>
redundancy            RedundancyPosture      none | warm_standby | active_active
evidence_refs         Vec<EvidenceRef>
```

Rules that are not negotiable, because canon states them and the code already
enforces the hard half:

- **A human and an agent submit the same envelope and receive the same
  receipts.** `caller_kind` changes the authority path and nothing else — never
  the placement, never the price.
- **Budget is discovered before any mutation.** Already true:
  `discover_budget` (`PR:985`) is called at `PR:9046`, before anything else in
  the ladder, and refuses by name at `PR:1016`
  (`budget_undiscovered_before_mutation`) and `PR:1021`
  (`budget_exhausted_before_mutation`).
- **The venue is evidence in the receipt, not an input to the request.** A
  caller that must name a provider is using the `Pick a cloud` surface, not the
  job API.
- **Redundancy is declared or absent.** Never inferred, never defaulted, never
  applied by a fallback the caller did not authorize.
- **The request is complete only when its receipt chain is complete.** A job
  whose provider vanished mid-run is complete after failover or after a
  receipted refusal, and not before.

### What the envelope must NOT do

It must not add a second spine (ADR 0051 §1, §7). Specifically: no new
credential store, no new session plane, no new provider adapter, no second
placement scorer, and no new receipt format. Every one of those exists and is
owned elsewhere. The envelope's whole job is to compose.

---

## 3. `caller_kind` → authority, the one genuinely new resolver

This is the only piece with no current equivalent, and it is small.

Today `handle_provider_op` (`PR:8939`) reads authority from the request body:
`grant_value: body["wallet_approval_grant"]` (`PR:9574`), with a standing-draw
sub-lane at `PR:9578-9615`. There is also a broker path,
`invoke_workload_brokered_provider_operation` (`PR:8950`), taking a
`WorkloadBrokerProviderAuthority` — which is the shape an agent path should
follow rather than inventing one.

```
caller_kind: human  → resolve authority_ref to a wallet grant, exactly as
                      PR:9574 does today. Nothing new.
caller_kind: agent  → resolve authority_ref to a CapabilityLease draw-down,
                      following the broker authority shape at PR:8950, and
                      draw down against the lease rather than presenting a
                      grant value.
```

Both paths converge on the SAME `CapabilityLeaseRequest` literal at `PR:9498`
and the same `authorize_capability_lease` call at `PR:9641`. The caller never
holds a provider credential in either path — `credential_connector_id` and
`credential_store: CREDENTIAL_VAULT` (`PR:9567-9568`) stay daemon-side.

Refusal names already exist for the ambiguous cases and should be reused rather
than duplicated: `provider_authority_mode_ambiguous` (`PR:9587`),
`provider_standing_authority_incomplete` (`PR:9597`),
`provider_standing_authority_facets_refused` (`PR:9622`).

---

## 4. Tool schema

One primitive, two callable shapes, identical semantics and identical receipts.

### Native tool schema

```json
{
  "name": "cloud_job_submit",
  "description": "Submit one CloudJobRequest: this much capacity, under this budget, for this long, receipt back. The venue is chosen by the placement plane and reported in the receipt; it is not an input.",
  "input_schema": {
    "type": "object",
    "required": ["intent", "authority_ref", "budget_ref", "deadline"],
    "properties": {
      "intent": {
        "type": "object",
        "required": ["runtime_class", "resource_classes"],
        "properties": {
          "runtime_class": { "type": "string" },
          "resource_classes": { "type": "array", "items": { "type": "string" } },
          "compute": { "type": "object" },
          "gpu": { "type": "object" },
          "storage": { "type": "array" },
          "network": { "type": "array" },
          "custody_posture": { "type": "string", "enum": ["Standard", "Private"] },
          "region_preferences": { "type": "array", "items": { "type": "string" } }
        }
      },
      "authority_ref": { "type": "string" },
      "budget_ref": { "type": "string" },
      "deadline": {
        "type": "object",
        "oneOf": [
          { "required": ["max_duration_s"] },
          { "required": ["not_after"] }
        ]
      },
      "receipt_requirements": { "type": "array", "items": { "type": "string" } },
      "failover_policy_ref": { "type": "string" },
      "redundancy": {
        "type": "object",
        "properties": {
          "posture": { "type": "string", "enum": ["none", "warm_standby", "active_active"] },
          "provider_class_diversity": { "type": "boolean" },
          "budget_multiplier": { "type": "number" }
        }
      }
    }
  }
}
```

`caller_kind` is deliberately **not** an input. It is resolved server-side from
how the call arrived — a tool call is an agent, a console submit is a human —
because a field a caller can set is a field a caller can lie about, and this one
selects the authority path.

Companion reads, both of which already exist behind the public face's allowlist:
`cloud_candidates_list` and `cloud_sources_health`. They are read-only and need
no authority.

### MCP

The same three tools, exposed over MCP with the same names, the same schema and
the same server-side `caller_kind` resolution. MCP transport normalization
already has a check in this estate (`check:mcp-transport-normalization` in the
hypervisor-app workspace); the job tools should be admitted through whatever it
already validates rather than a parallel registration.

---

## 5. Console shape

Drawn and labelled unwired in `brand/src/Composer.dc.html` and served at
`/` → "Submit a job" on the face. Three regions:

1. **The request.** `runtime_class`, `gpu`, `deadline`, `budget_ref`,
   `authority_ref`, `redundancy`. A chosen value is ink on paper; an unfilled
   control is label grey on the surface tint, so the two can never be confused.
   `budget_ref` is a picker over existing budgets, never a free-text amount.
2. **What comes back.** The receipt chain, not a status string, with each
   required receipt kind shown as a chip that fills in as its receipt lands.
3. **The agent call, beside it.** The literal tool call that produces the same
   envelope, so a reader can see that the two entry points are one primitive.

The submit control stays inert until the daemon route exists. The page states
that in words on the surface — "designed, not connected" — because a stub a
reader cannot tell apart from truth is refused.

---

## 6. Reuse points — the eleven seams

Each is where new code attaches. None of them is a rewrite.

| # | Seam | Anchor | Kind |
|---|---|---|---|
| A | Router registration for the job routes | `DAEMON:3592-3599` (intents block), `DAEMON:3554-3562` (placement block) | axum `.route()` chain |
| B | Envelope fields → intent record | `DCR:101` `intent_record`, rows at `DCR:119-121` | `json!` builder |
| C | Envelope shape refusal | `DCR:797` `handle_intent_create`, guards at `DCR:814-817` | sequential `if let` guards returning 422 |
| D | Candidate field emission | `DCR:218` `push_candidate`, `DCR:286-290`; per-provider `VAST:354-359` | `json!` builder |
| E | Candidate source fan-out | `DCR:741` `refresh_candidates`, `DCR:764-766` | flat `await` sequence |
| F | Decision record inputs | `PF:202` `mint_decision`, `PF:260-264` | `json!` builder |
| G | Placement eligibility and the simulator label | `PF:91` `rank_candidates`, `match` at `PF:135-145` | `match` statement |
| H | Provider op dispatch for a new verb | `PR:8958`, `match op` at `PR:9790-9807`, plus the mutation classifier at `PR:9019-9022` | `match` statement |
| I | Wallet challenge facets | `PR:9498` `CapabilityLeaseRequest`, facet copy array `PR:9513-9556`, fed by `vast_gate` at `PR:9395` | struct literal + copy list |
| J | Receipt extras | `PR:483` `provider_receipt_ext`, success `PR:9815`, failure `PR:10118` | `json!` merge |
| K | The single mutation lane | `PF:569` `provider_op` — a thin wrapper delegating to the existing handler, documented at `PF:10-15` | wrapper fn |

**Seam I is the one to get right.** A facet reaches the wallet challenge only if
it is a key on `vast_gate` AND listed in the copy array at `PR:9513-9556`. A job
envelope that binds something the challenge does not carry is a job whose
authority did not actually cover what happened. Anything the envelope adds —
`job_ref`, `deadline`, `redundancy` posture — must be added in both places or
not claimed.

**Seam K is the one not to bypass.** `PF:569` exists so failover drives
mutations through the same handler rather than a second path. A job primitive
that opens its own lane to a provider is the second spine ADR 0051 forbids.

---

## 7. The fee, and why it is not in this unit

`routing_fee_eligibility` is computed at `PF:222-226`:

```rust
let fee_eligibility = if ranked.eligible.len() >= 2 {
    "eligible_future"
} else {
    "not_applicable"
};
```

and every decision and receipt carries `"fee_object_minted": false` (`PF:257`,
`PF:283`) with the note at `PF:284`: *"NOT a RoutingDecisionReceipt — no fee
minted, no charge today; this receipt exists so the placement choice is
challengeable evidence"*.

Two things follow. First, the ≥2 threshold is already implemented, but it counts
`ranked.eligible`, which admits simulator candidates under `sim_harness`
(`PF:135-145`) — so it is a candidate count, not the ≥2 REAL-venue condition the
fee doctrine requires. A `RoutingDecisionReceipt` must count live venues, and
that distinction should be made where the fee object is minted, not here.
Second, minting a fee is a separate unit from submitting a job. M15.3 should
leave `fee_object_minted: false` exactly as it is.

---

## 8. Open questions for the owner

1. **Does the job route mutate, or propose?** The design above assumes
   `CloudJobRequest` is admitted as a proposal that then drives the existing
   ladder. An alternative is a synchronous submit that runs the ladder inline.
   The proposal shape is safer and matches `consume_provider_operation_proposal`
   (`PR:9469`), which already exists for the Akash live lane.
2. **Where does the deadline live once the job is running?** Canon says the job
   is complete when its receipt chain is, which is not the same moment as the
   deadline. Nothing in the daemon currently supervises a job-level deadline.
3. **`redundancy` beyond `none`.** `warm_standby` and `active_active` need
   replica placement, a per-replica exposure set, and a DNS/TLS switch policy,
   none of which exist (`grep -rn 'RedundancyPosture\|warm_standby\|active_active'`
   returns nothing). M15.3 should accept the field, validate it, and refuse
   anything but `none` by name until M15.9.
4. **Intent field inertness.** Six canonical intent fields are stored and never
   read. A job envelope that passes them through inherits that silence. Either
   they gain read sites or the envelope should say plainly that they are
   recorded, not honoured.

---

## 9. What this document is not

It is not an implementation plan with estimates, it is not authorization to
write Rust, and it does not commit anyone to the tool names above. It is the
map an implementer needs so that the first Rust change is a small one in a place
that already exists.
