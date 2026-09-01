# ADR 0032: Define "Independently Implemented Client" By Named Axes

- Status: Accepted
- Date: 2026-08-05
- Owners: Hypervisor Core clients and surfaces / daemon runtime / SDK / ADK /
  CLI-headless / schema and conformance
- Refines: ADR 0002, ADR 0013
- Unaffected: client categories and their boundaries (ADR 0002 Decision 1–5);
  execution authority; GoalRun placement
- Confidence: settled for the axis vocabulary and the claim-statement rule;
  which axes any particular release claims stays with that release's evidence.

## Context

Canon repeatedly requires "two independently implemented clients" as evidence
that a contract is real rather than a description of one program's behavior. No
owner defined independence. Four candidate readings circulated informally —
separate transport, separate codegen, separate authoring party, separate binary
— and they are not interchangeable: three are claims about the *contract*, and
only one is a claim about *parties*.

Leaving this undefined has a specific failure mode, not a vague one. A second UI
built on the same client library, in the same repository, by the same team,
generated from the same artifacts, satisfies every colloquial reading of "two
clients" and proves nothing at all: it inherits every assumption the first
client makes, so it cannot detect the assumptions that were never written down.
That is the exact thing a two-client bar exists to catch, and an undefined bar
cannot catch it.

`INV-18` already rules that multiplicity is not independence for *parties*. It
does not speak to implementations, and the two have been conflated.

## Decision

1. **Independence is declared per axis, never as a bare adjective.** Four axes
   exist. A claim of "independently implemented clients" names which axes it
   asserts and, by omission, which it does not. "Independently implemented",
   unqualified, is not a claim; it is a word.

   - **`separate_binary`** — a distinct build artifact and process, not the same
     binary in a second mode, behind a flag, or under a different name. *Proves
     packaging.* Proves nothing about contract understanding.
   - **`separate_codegen`** — the client's types are derived independently from
     the registered contract (regenerated from the schema, or hand-written from
     it), not imported from this repository's generated projections. *Proves the
     registered contract carries enough information to build against.* This axis
     is the one that finds unwritten assumptions.
   - **`separate_transport`** — the client implements framing, encoding, and the
     authentication handshake against the wire specification, rather than
     delegating to a shared client library that owns them. *Proves the wire
     contract is specified rather than merely implemented.*
   - **`separate_authoring_party`** — a different disclosed accountable
     principal authored and maintains it. *Proves adoption by a party whose
     interests are their own.* This is the only axis that carries `INV-18`
     weight.

2. **The first three axes make contract claims; the fourth makes a party
   claim; neither substitutes for the other.** Two clients differing on binary,
   codegen, and transport but authored by one principal establish **contract
   sufficiency** and establish nothing about multi-party independence — the
   principal still controls authority, revocation, truth, verification, risk,
   and settlement (`INV-18`). Two clients authored by separate parties that both
   import this repository's generated code and transport library establish
   **adoption** and establish nothing about contract sufficiency — they inherit
   the same assumptions and fail the same way. A claim that needs both says
   both, with evidence for both.

3. **What a two-client exit proof claims, and what it does not.** A
   sovereign-local or platform exit proof asserting "two independently
   implemented clients" claims **`separate_binary` + `separate_codegen` +
   `separate_transport`**, and does **not** claim `separate_authoring_party`
   unless a disclosed third party in fact authored one of them. The reason is
   structural rather than modest: IOI can author a second client, and IOI cannot
   manufacture a second principal. A proof that claimed the party axis on
   first-party work would be asserting exactly what `INV-18` forbids.
   `separate_authoring_party` is claimable only with the party disclosed, and it
   is then a separate claim with its own evidence, never an upgrade inferred
   from the other three.

4. **What never counts, on any axis.** A second presentation over the same
   client library; a fork of the first client; the same binary in another mode;
   a mock, stub, replay harness, or test double; a client generated from this
   repository's artifacts and then re-skinned; and a client whose divergences
   from the first are fixed by patching the daemon rather than the client.
   The last one is the most dangerous, because it looks like success: if
   satisfying the second client required changing the contract's implementation
   rather than reading its specification, the contract was insufficient and the
   proof recorded the repair, not the property.

5. **The axes are evidence, not permission.** Declaring axes creates no
   authority, no admission path, and no conformance claim by itself. Client
   boundaries remain exactly as ADR 0002 sets them: clients do not own runtime
   truth, and an independently implemented client is still a client.

## Consequences

- Any canon, conformance, or release statement using "independently implemented
  client" now carries its axis list, or it is not a statement.
- A released profile manifest and evidence result can record a two-client claim
  as a set of named axes rather than a boolean, which makes a partial claim
  expressible instead of forcing it to overstate. The former
  `docs/conformance/README.md` index is retired.
- `INV-18`'s scope is clarified rather than changed: it governs the party axis,
  and this ADR supplies the implementation axes it was being stretched to cover.
- No client category, adapter target, or protocol gateway boundary changes.

## Rejected Alternatives

- **Pick one axis and call it independence.** Rejected: each of the four proves
  something different, and collapsing them means every claim is ambiguous about
  which property it established.
- **Require all four for any two-client claim.** Rejected: it would make the bar
  unmeetable by first-party work in principle, which converts a useful
  contract-sufficiency test into a permanently deferred party test, and would
  push implementers toward claiming the party axis dishonestly.
- **Define independence as "different team."** Rejected: organizational
  distance is not a contract property, is unverifiable from outside, and is
  exactly the kind of soft identity `INV-18` refuses.
- **Treat a second UI over the shared client library as a second client.**
  Rejected: it shares the assumptions under test.

## Cost Of Being Wrong And Reversal

If the axis set proves incomplete — a fifth axis matters, or one of the four
turns out not to discriminate — the vocabulary extends by a successor ADR and
existing claims stay readable, because every claim already names its axes.
Nothing here binds a schema, wire format, or authority path, so reversal is a
documentation change. Claims already made remain interpretable under the axis
list they carry.

## Canonical References

- [`0002-execution-authority-and-client-boundaries.md`](./0002-execution-authority-and-client-boundaries.md)
- [`0013-hypervisor-core-clients-surfaces-and-adapters.md`](./0013-hypervisor-core-clients-surfaces-and-adapters.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/foundations/invariants.md`](../architecture/foundations/invariants.md) — `INV-18`
- [`../architecture/foundations/ioi-authority-protocol.md`](../architecture/foundations/ioi-authority-protocol.md)
  — authority-profile manifests and independence disclosure where this ADR is
  applied.
