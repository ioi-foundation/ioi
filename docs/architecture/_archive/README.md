# Architecture Archive

Status: archive index; nothing here is authority.
Doctrine status: archived
Implementation status: n/a

Verbatim historical material moved out of the canonical reading path on
2026-07-05 so canon files stay current-state. Three classes:

- [`change-ledgers/`](./change-ledgers/) — per-slice / per-cut migration
  narration (append-only history; new history goes to git, not here).
- [`implementation-logs/`](./implementation-logs/) — adapter/build logs and
  "what shipped this cut" narration formerly embedded in canon files.
- [`specs/`](./specs/) — former `docs/specs` modules and implementation plans
  that were embedded in doctrine files.

Every file names its source and canonical owner in its front matter. If an
archived statement conflicts with a canonical owner doc, the owner doc wins.
