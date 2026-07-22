# Work-item records

Status: canonical implementation-status record convention.
Canonical owner: this file for the work-item record format and validation rules; each record file for its cut's status truth.
Supersedes: dated status narratives inside implementation-matrix cells for migrated rows.
Superseded by: none.
Last alignment pass: 2026-07-22.
Doctrine status: canonical
Implementation status: built (records validated by `npm run check:work-items`)
Last implementation audit: 2026-07-22 (initial migration: M1 family and M0 census gate records)

One machine-checkable record per implementation cut, using the master
sequencer's work-item vocabulary. These records are the single owner of
implementation **status truth**: the implementation matrix keeps concept
doctrine and canonical ownership, and its cells point here instead of
narrating dated status stories that rot.

Rules:

- Format `ioi.program.work_item.v1`; validate with `npm run check:work-items`.
- `status` uses the sequencer vocabulary:
  `proposed | scoped | active | evidence_ready | verified | blocked |
  superseded | rejected`. Only proof moves a record to `verified`.
- Every `code_anchors[]` entry names a file that must exist (and optionally a
  literal it must contain). Anchors with `present_when: "pr_open"` describe a
  held PR branch: they are validated when the file is present in the current
  checkout and reported as pending otherwise; they can never falsely claim
  merged truth because promotion to `verified` requires `present_when:
  "merged"` anchors that always validate.
- Every `evidence_refs[]` path must exist.
- The current M0 stage projection is additionally gated by
  `docs/evidence/implementation-plan-reconciliation/m0-exit.v1.txt`. The
  work-item checker requires exactly one `M0_EXIT=0` and verifies that the log's
  SHA-256 commitment matches the committed M0 exit report. This compatibility
  wrapper closes no new stage or capability; the generic literal-exit contract
  remains proposed.
- Every `proposed` record must name nonempty `contract_families[]`,
  `dependencies[]`, and `exit_criteria[]` string arrays. At least one exit
  criterion must declare a retained-log success literal such as
  `M2_SELECTED_PROFILE_EXIT=0`; a task or process exit code is not
  evidence for that bar. This admission rule is intentionally prospective and
  does not rewrite already admitted non-proposed records.
- A record changes in the same status-update transaction as the truth it
  describes (master guide section 13.3); the matrix cell pointing at it does
  not change unless doctrine changed.
- These are development-workflow records. They grant nothing, are not product
  contracts, and never enter the architecture contract registry.

## Reconciliation work records

- [`implementation-plan-estate-reconciliation.md`](./implementation-plan-estate-reconciliation.md)
  inventories the plan-bearing estate and routes each fact family to its owner.
- [`m0-m14-plan-gap-audit.md`](./m0-m14-plan-gap-audit.md) records the dated
  stage-by-stage plan-gap audit and quarantined sequencer-amendment proposals.

Both files are non-authoritative work records. They neither own status nor form
an implementation sequence.
