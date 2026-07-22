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
- A record changes in the same status-update transaction as the truth it
  describes (master guide section 13.3); the matrix cell pointing at it does
  not change unless doctrine changed.
- These are development-workflow records. They grant nothing, are not product
  contracts, and never enter the architecture contract registry.
