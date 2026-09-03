# ADR 0049: Accept Owner-Commissioned Automated Independent Review For AFT Research Gates

Status: Accepted

Date: 2026-09-03

## Context

The AFT PQ v1 implementation review (M10) and maximal-visibility theorem
review (M12) require an adversarial reviewer independent of the candidate's
authoring context. The existing packets described that reviewer as a human
specialist. On 2026-09-03 the repository owner explicitly commissioned a
fresh, context-isolated `gpt-daybreak-blue-latest` agent as the qualified
reviewer for these owner-controlled gates and directed the program owner to
remediate its findings and advance the gates.

An automated review can supply reproducible adversarial analysis, clean-room
execution, and an attributable report. It cannot truthfully be represented as
human academic peer review, institutional certification, or third-party
professional assurance.

## Decision

For M10 and M12, an owner-commissioned Daybreak review may satisfy the
independent-review gate when all of the following hold:

1. the reviewer starts without the candidate's authoring conversation and
   works from an immutable annotated tag in a disposable checkout;
2. the exact model and automated nature of the reviewer are disclosed;
3. the reviewer selects its own attacks, reproduces the mandated evidence,
   records every objection, and returns the packet's exact disposition;
4. every substantive repair creates a new immutable candidate and is retested
   by the same reviewer;
5. no unresolved high or critical implementation finding remains at M10, and
   M12 is advanced only to the disposition actually supported by the report;
   and
6. public claims call the result an independent automated review. They must
   not call it human peer review or imply credentials the agent does not have.

This decision changes review provenance, not theorem truth. TLC/TLAPS results,
tests, and a favorable automated report remain evidence bounded to their exact
models, code, and candidate ref.

## Consequences

- The Daybreak reports can close the owner-controlled M10 and M12 independence
  conditions after remediation and exact-candidate retest.
- Human peer review remains valuable external evidence but is no longer a
  blocking condition for those two internal gates.
- Any publication venue, regulator, customer, or relying party may impose an
  additional human-review requirement; this ADR cannot waive it.
- An M12 `UPHELD` disposition closes M12 as
  `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`. It does not authorize M13-M18 or the
  maximal headline. Progress would then require an explicit change to a task
  property or a named additional assumption.
- Review prompts, reports, issue updates, and the implementation ledger retain
  the automated provenance so later readers can distinguish owner policy from
  external peer validation.

## Alternatives rejected

- Silently treating an agent as a human reviewer would make the gate
  misleading and destroy the value of its chain of custody.
- Treating automated review as advisory only would contradict the owner's
  explicit qualification decision and leave the owner-controlled gates
  permanently dependent on unspecified external coordination.
- Allowing the implementation owner to self-review in the authoring context
  would not provide the requested context isolation or independent attack.
