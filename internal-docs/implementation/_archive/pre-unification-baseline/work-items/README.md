# Private work-item records

Status: ignored internal implementation-status record convention.
Authority: the master guide owns sequence; each record owns only its cut's
private status truth. Architecture canon owns doctrine and contains no work
queue or status pointer.
Last alignment pass: 2026-07-22.
Validation: `npm run check:work-items` in an estate checkout that carries this
ignored directory.

One machine-checkable record per implementation cut, using the master
sequencer's work-item vocabulary. These records are the single owner of
private implementation **status truth**. The implementation matrix keeps
concept doctrine and canonical ownership only; it neither points here nor
narrates dated status stories.

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
  `internal-docs/implementation/evidence/m0-exit.v1.txt`. The
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
- A record changes in the same private status-update transaction as the truth it
  describes (master guide section 13.3); the matrix cell pointing at it does
  not change unless doctrine changed.
- These are development-workflow records. They grant nothing, are not product
  contracts, and never enter the architecture contract registry.
