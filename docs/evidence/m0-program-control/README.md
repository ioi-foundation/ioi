# M0 Program Control and Claim Lock

This directory is evidence and program-control syntax. It does not register an
architecture schema, define a canonical wire contract, implement runtime
capability, or close any production gate.

`m0-exit-report.json` may report `verified` only for the M0 control conditions:
the discovery census is explicitly reviewed, selected owners and unavailable
effects are named, legacy sequencing is non-authoritative, all 58 `PG-*` ids
are mapped without redefining them, and missing baseline evidence is recorded
honestly. It never means that the selected journey or an architecture capability
is terminal.

## Sources

- `review-epoch-anchor.json` is an unsigned hash-chain of review claims
  supplied with this repository snapshot. Every entry is a self-contained
  claim binding the complete lock hash at that point, total identity and
  reviewed-entry commitments, the then-latest lock epoch, program-source
  material, and the complete predecessor entry. Historical entries are
  validated from their retained claim and predecessor commitment; they are
  not recomputed from today's mutable lock partitions. The supplied head must
  bind the supplied complete review lock, latest epoch, and program-source
  material, and the chain must contain the source-pinned repository baseline
  entry. Entries at sequence 6 and below retain their historical Ed25519
  evidence blocks verbatim as immutable retained claims; they are never
  re-verified as signatures, and no key is pinned, read, or trusted.

  These checks establish chain integrity within the supplied snapshot,
  snapshot-head binding, and repository baseline presence. This evidence does
  not establish authorship, accepted-head currentness, or rollback resistance
  between two internally coherent snapshots. Establishing currentness requires
  an accepted-head checkpoint in an outside rollback domain. The `reviewer_id`
  is a self-declared label, not verified reviewer identity or independence.
  This anchor is development-workflow integrity evidence only; it is not part
  of the bounded agency framework's authority model (wallet-network grants,
  sealed intents, receipts), and it deliberately carries no signature ceremony
  that could be mistaken for that model. A prior revision used a machine-local
  Ed25519 ceremony; it proved nothing beyond this hash chain and was retired
  on 2026-07-22.
- `reviewed-entry-lock.json` is the explicit, dated entry-by-entry review lock.
  Each entry date binds a declared review epoch with exact identity-set
  provenance, so newly discovered identities cannot inherit an older review.
  Candidate boundaries remain blocked; UI state and copied fields are never
  accepted as authority.
- `program-control-source.json` freezes the selected minimum-L0 profile, visible
  journey, owner sets, PG dispositions, baselines, release ladder, exclusions,
  blocker ledger, and tracked canon anchors. Its supplied-snapshot attestation
  binds the complete program-source material hash to the supplied signed head
  and projects the bounded assurance posture above.
- The other JSON files are deterministic projections. `manifest.json` binds
  their hashes to all three reviewed sources and the discovered repository
  state.

The implementation guide and PG ledger paths under
`internal-docs/implementation/` are external, ignored, untracked operator
inputs. M0 does not read, hash, require, or bind them as evidence; they may be
absent from a checkout. The path pointers are retained only to name the
operator sequencing context. Tracked `docs/architecture/` canon named in
`canon_basis` is the committed architecture and status evidence authority;
tracked `docs/conformance/` entries provide the selected-profile conformance
evidence.

## Commands

```text
node scripts/m0-program-control.mjs --init
node scripts/m0-program-control.mjs --attest-review docs/evidence/m0-program-control/review-epoch-anchor.json
node scripts/m0-program-control.mjs --write
node scripts/m0-program-control.mjs --check
```

`--init` creates missing unreviewed worksheets with no review date and never
overwrites them. It cannot create reviewed evidence. Given a supplied anchor
whose hash chain and snapshot bindings validate, `--attest-review` performs
the distinct worksheet-to-supplied-snapshot-attested transition. The command
requires the tracked anchor path explicitly; it never discovers an outside
checkpoint, reads a private key, signs, or writes the anchor. Passing this
command does not establish authorship or whether the supplied head is the
latest accepted head.
`--write` is the only generated-artifact write mode and requires reviewed,
valid, supplied-snapshot-attested sources.
`--check` is read-only and verifies only the supplied repository snapshot. It
must pass before generated evidence is consumed, but it is not a freshness or
rollback-resistance oracle.
Bare or invalid invocation prints usage, exits 2, and writes nothing.

## Snapshot updates

A new snapshot entry is authored directly against the tracked anchor;
`--attest-review` only consumes and verifies the resulting evidence:

1. Review the changed discovery entries and update
   `reviewed-entry-lock.json` with one new epoch. Anchor sequence and
   predecessor commitments advance strictly; review dates are nondecreasing so
   distinct review waves on one calendar day do not fabricate a future date.
2. Append one unsigned candidate entry to `review-epoch-anchor.json`. Its
   sequence must increment by one; `predecessor_entry_sha256` is the SHA-256
   commitment of the complete previous anchor entry. Commit the complete
   current lock hash, total entry count, total identity and reviewed-entry
   sets, the current latest lock epoch's identity/date/count commitments, and
   current program-source material. Set `authorship_binding` to
   `self_declared_unsigned` and a self-declared `reviewer_id` label. Preserve
   prior entries verbatim; retained legacy entries may never follow an
   unsigned entry.
3. Update `head` to the complete entry commitment
   (`sha256(stableStringify(entry))`). Then invoke `--attest-review` with the
   tracked anchor path above. Predecessor-incoherent, baseline-absent,
   authorship-overclaiming, or supplied-head-mismatched evidence fails before
   the worksheet changes.
4. If accepted-head currentness is required, publish and verify the accepted
   head commitment through an outside rollback-domain checkpoint. The M0 CLI
   neither discovers nor validates such a checkpoint, so its assurance remains
   `accepted_head_currentness: not_established`.

Run the focused adversarial bar with:

```text
npm run check:m0-program-control
```
