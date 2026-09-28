# ADR 0058: An Automation Has One Published Head, Owned By Its System; Edits Are Drafts That Publish At The Expected Head

Status: Proposed (awaiting owner decision). The direction below is the owner's, given 2026-09-27;
this record states it against the code so that it can be accepted, amended or declined.

Date: 2026-09-28

Relates to: [ADR 0056](./0056-organize-the-hypervisor-application-estate-by-four-axes-and-retire-missions.md)
(Automations as an owner axis; Amendment 1, plane 4: change sets),
[ADR 0057](./0057-a-data-recipe-revision-carries-its-transform-graph.md) (the first change-set
subject), the Agentgres doctrine's ownership-partitioned serialization
(`docs/architecture/components/agentgres/doctrine.md`, "Ownership-partitioned serialization"), and
R-241 (the adopted Automate app).

## Context

An automation is edited today by patching its registry record in place
(`PATCH /v1/hypervisor/automations/:id`). The record keeps only its last actor
(`acting_principal_ref`), so nothing can say what changed, when, or by whom. The adopted Automate app's
History filters (Condition edited; Activity: Paused, Resumed) therefore have nothing to list (ledger
CCXIV).

The canonical contract is already immutable and revisioned. A `WorkflowTemplate` revision is the exact
steps, an `AutomationSpec` revision is one standing activation over a template, with a
`predecessor_revision_ref`, and an `AutomationRun` freezes the revisions it resolved. But those
revisions are owned by a principal: spec admission refuses unless `owner_ref` equals the authenticated
principal (`automation_contract_routes.rs`, `build_spec`: `automation_contract_owner_mismatch`). They
are also minted lazily, for the person pressing Run now, rather than when a definition is published.
A per-principal chain cannot be one automation's shared history, and a per-automation stream bound to
its first writer refuses every other editor.

Two concerns had been conflated: people and agents EDITING in parallel, and COMMITTING a shared result.
Only the second needs ordering.

## Decision (proposed)

1. **Ownership.** An automation's published definition is owned by the shared workspace or System that
   holds it, not by a person. Users hold explicit rights to edit (make drafts) and to publish. The
   authenticated principal is recorded on every proposed and published change as attribution, and is
   checked for authorization. It never decides where the automation's truth lives. Spec admission's
   `owner_ref == principal` becomes: `owner_ref` is a tenant the principal is authorized to publish
   into.
2. **One canonical head per automation.** The published definition is a single revision chain:
   template and spec revisions, each naming its predecessor. There is exactly one current head.
3. **Drafts are isolated.** Work in progress lives in drafts, one per task or session, each recording
   the base revision it started from. Drafting, agent reasoning and validation proceed concurrently and
   need no coordination. A draft is the change-set plane's second subject kind, `automation`, beside
   `data_recipe`: its tip is the published head, its validation is admission's content checks, and its
   merge is admission itself.
4. **Publishing is the only ordered step.** A publish names its expected head. When the head moved:
   - the publish is refused with an explicit conflict answer naming the base, the current head and the
     draft;
   - the draft stays intact.

   Example: Alice and Bob start from R10. Alice publishes against R10, and admission creates R11. Bob's
   publish against R10 conflicts, and his draft is kept.
5. **Merge, after the first cut.** The system compares base, head and draft. When the changes are
   compatible it proposes a combined result, validates it, and publishes against the new head. Changes
   to separate fields are not sufficient evidence of compatibility, because they can still break a
   shared invariant. Incompatible changes require an explicit choice. For example, a rename and a
   schedule change may merge after validation; two different schedule changes need resolution.
6. **Runs pin exact published revisions**, as canonical runs already do.
7. **History reads the published chain.**
   - Condition edited: a published revision whose trigger or steps differ from its predecessor,
     attributed to the principal who published it.
   - Paused and Resumed: the installation binding's successive revisions.
8. **Live co-typing is optional.** A CRDT is used only if people should type into the same live draft.
   Publishing that draft still passes canonical admission.

## Sequencing

1. Shared ownership, and the per-automation expected-head check on publish.
2. Preserved drafts, and the explicit conflict answer. The adopted editor saves a draft and publishes
   it. History's filters read the chain.
3. Automatic three-way merge with validation.

The legacy registry record stays the executor's input until the published head replaces it, in the same
add → move dependants → remove order ADR 0056 uses.

## Consequences

- There is no second spine. Drafts reuse the change-set plane, publishing reuses spec and template
  admission, and ordering is Agentgres' expected-head admission (the doctrine's "admission of shared
  canonical heads is the only serialization point").
- The adopted editor's representational gaps are separate work. It has no manual trigger and no command
  effect (seed depth `edit.manual-condition-label`). Drafts give it somewhere honest to save; they do
  not add those types.
- Not decided here: the rights model's exact shape (roles, or grants per System), and whether one
  automation may be published into more than one System.

## Evidence

- `automation_contract_routes.rs` `build_spec`: `owner_ref must equal the authenticated principal`.
- `change_set_routes.rs`: "A subject is one adapter" (`SUBJECT_KINDS = ["data_recipe"]`).
- `orchestration_routes.rs` `handle_automation_patch`: patches in place, stamping `acting_principal_ref`.
- The reference History filter enums: `CONDITION_EDITED`, `PAUSED`, `UNPAUSED`
  (`MonitorLogicUpdated`, `MonitorDisabled`, `MonitorReenabled`).
