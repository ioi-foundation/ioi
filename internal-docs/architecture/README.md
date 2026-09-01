# internal-docs/architecture — Proposal, Research, And Private-Protocol Space, Never Canon

Status: directory rule and index; non-canonical.
Authority: `docs/architecture/` owners and accepted ADRs are canonical and win
on drift; nothing in this directory is canon, and this directory must never
become a shadow canon.

## The Rule

Every `.md` file that lands here carries, in its opening lines:

1. a `Status:` line stating what the file is (proposal, synthesis, track
   opener, internal protocol note, formal-model note); and
2. an authority line stating that canonical owner docs and accepted ADRs win
   on drift.

This convention remains as directory guidance in prose; no checker, exemption
table, or standing review gate enforces it after the 2026-08-05 proof-estate
retirement. A file that cannot honestly carry the header does not belong here
— move it. The directory rule was recorded 2026-08-04 alongside the
canon-agenda ratification.

## Active Programs

- [`machine-authority-category-program.md`](./machine-authority-category-program.md)
  — the live evidence, profile-closure, independent-reproduction, adoption, and
  promotion program for the canonical Machine Authority category and IOI
  Authority Protocol. It tracks work; it owns no doctrine or implementation
  status.

## Private Protocol Corpora

- [`protocols/`](./protocols/) — the indexed internal protocol research,
  specification-development, formal, and clean-room-test corpora. They support
  canon owners and never override them.

## Historical Rationale And Completed Tracks

- [`canonical-ioi-thesis-and-canon-change-recommendations.md`](./canonical-ioi-thesis-and-canon-change-recommendations.md)
  — archived executed 2026-08-04/05 canon agenda; retained as rationale and
  closure history only.
- [`licensing-adr-track-opener.md`](./licensing-adr-track-opener.md) — archived
  R-03 decision-space record, succeeded by accepted ADR 0033.
- [`internet-of-intelligence-target-architecture-synthesis.md`](./internet-of-intelligence-target-architecture-synthesis.md)
  — archived promotion-complete 2026-07-11 synthesis; retained as rationale
  history only.

## Historical Change Reports

- [`_meta/changelog/`](./_meta/changelog/) — historical alignment and refactor
  reports.
