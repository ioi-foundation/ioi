# internal-docs/architecture — Proposal And Private-Protocol Space, Never Canon

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

Enforced by `npm run check:internal-architecture-headers`
(`scripts/check-internal-architecture-headers.mjs`). A file that cannot
honestly carry the header does not belong here — move it; there is no
exemption table. Standing liaison rule recorded 2026-08-04 alongside the
canon-agenda ratification.

## Contents

- [`canonical-ioi-thesis-and-canon-change-recommendations.md`](./canonical-ioi-thesis-and-canon-change-recommendations.md)
  — the ratified sequenced canon agenda (owner ruling 2026-08-04) and the IoI
  thesis drafted for canon adoption.
- [`licensing-adr-track-opener.md`](./licensing-adr-track-opener.md) — R-03
  parallel track: decision space and legal-review questions for the licensing
  ADR.
- [`internet-of-intelligence-target-architecture-synthesis.md`](./internet-of-intelligence-target-architecture-synthesis.md)
  — promotion-complete 2026-07-11 synthesis; retained as rationale history.
- [`protocols/`](./protocols/) — private protocol corpora (AFT, ai-url):
  supporting context for canon owners, not owners themselves.
- [`_meta/changelog/`](./_meta/changelog/) — historical alignment and refactor
  reports.
