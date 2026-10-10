# ADR 0059: An Omitted Session Authority Profile Names The Operator's Signed Default Connection

- Status: Accepted with the canon change set (queued 2026-09-30; applied with the set once the
  plan's stop target is met)
- Date: 2026-09-30
- Owners: Hypervisor core surfaces / daemon runtime / identity, access and metering
- Amends: [ADR 0052](./0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md)
  Decision 3 ("The default is the empty set, not the workspace")
- Confidence: working_ruling (the owner's set-once rule of 2026-09-29, "set permissions once and
  forget"; the director's ruling of 2026-09-30 on the canon set; owner-reversible)

## Context

ADR 0052 Decision 3 gave every Session a closed authority profile and made its default the empty
set, so that the workspace's connector estate confers nothing on a session. That rule is kept. Its
side effect is not: a run that omits its connections names none, and on the bounded alpha a
session that names no connection takes the per-run exact-effect approval lane. With standing
envelopes qualified under the `deployment_local_operator` tier (ADR 0052 Decision 7), an operator
sets limits on a connection once, yet every run that does not name that connection again still
asks. The owner's set-once rule removes that per-run ask. The default must therefore be a
connection the operator chose and bounded, and nothing wider.

## Decision

1. **An omitted `authority_profile`, or `connection_refs: null`, resolves to the creating
   principal's own signed `default_connection` record**, never another principal's, and to nothing
   else: never to the workspace's estate, never to every bounded connection, never to a connection
   chosen by the daemon. The resolved connector passes the same closed-at-create check as an
   explicit one (Decision 3: "a connector the caller owns"). This reverses Decision 3's empty
   default, and only that part of it.
2. **The record** is one per operator, signed as a standing envelope's mint is, and separate from
   any envelope. Only an explicit signed act writes it: install (the local "This computer"
   connection), marking a connection as the default when setting its limits, and the successor
   pick inside a confirmed Disconnect of the default, recorded before the removal. An envelope's
   renewal or re-set never touches it. Remove limits keeps it and records "keep it stopped" in the
   same act: runs then refuse typed until limits are set again, and no follow-up item is raised.
   A Disconnect made without the principal's confirming factor blocks the connection pending that
   confirmation and keeps the record. "This computer" has no Disconnect. No connection is ever
   promoted to default automatically.
3. **With no default**, a create that omits the profile refuses typed (`no_default_connection`),
   never as an approval. The doors do not reach this state for the installing operator: install
   writes that operator's record, and a confirmed Disconnect of the default signs its successor
   first. A second principal has no install act, so until they set a default their omitted
   creates refuse this way.
4. **Only an explicit empty list names no connection.** That session's executions take the per-run
   exact-effect approval lane, the operator's explicit choice.
5. **Create intents already reserved in the write-ahead log keep the empty profile they were
   reserved with.** From this decision on, the create resolves an omitted profile before it
   reserves the intent, and the intent records the resolved profile, so no replay ever resolves a
   default.
6. **Unchanged from Decision 3:** the workspace confers nothing; the profile is closed at create and
   immutable for the session's life; admission narrows to it; revoking a connector fences every
   session that named it.

## Consequences

- `core-clients-surfaces.md` § *Session authority profile* states the rule, and Decision 3 of ADR
  0052 points here.
- `check:session-authority-profile` replaces its "a session created without a profile carries the
  empty profile" clause with three: an omitted profile names the default connection; with no
  default record it refuses typed `no_default_connection`; `[]` names none. Its mutant restores the
  empty default, and the first clause must fail on it.
- The daemon gains the `default-connections` record family and the session-create change; neither
  is built. Until both land, every door sends the default connection explicitly.
- When typed standing grants qualify (`bounded-alpha-profile.md` § *Declared widenings*), the record
  retires into the grant's default scope (§ *Alpha-only objects and their retirement*).

## Cost Of Being Wrong And Reversal

Reversal restores the empty default. Sessions created meanwhile keep the profile recorded at create,
since a profile is immutable, and the `default-connections` records become inert. No authority is
lost either way: the default names only a connection whose limits the operator set.

## Canonical References

- [`./0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md`](./0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/components/hypervisor/bounded-alpha-profile.md`](../architecture/components/hypervisor/bounded-alpha-profile.md)
