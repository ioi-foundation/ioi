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

- `reviewed-entry-lock.json` is the explicit, dated entry-by-entry review lock.
  Candidate boundaries remain blocked; UI state and copied fields are never
  accepted as authority.
- `program-control-source.json` freezes the selected minimum-L0 profile, visible
  journey, owner sets, PG dispositions, baselines, release ladder, exclusions,
  blocker ledger, and read-only canon anchors.
- The other JSON files are deterministic projections. `manifest.json` binds
  their hashes to the two reviewed sources and the discovered repository state.

The implementation guide and PG ledger under `internal-docs/implementation/`
were read only. They are not copied here, tracked here, or promoted into
architecture canon.

## Commands

```text
node scripts/m0-program-control.mjs --init
node scripts/m0-program-control.mjs --write
node scripts/m0-program-control.mjs --check
```

`--init` creates missing unreviewed worksheets and never overwrites them.
`--write` is the only artifact write mode and requires reviewed, valid sources.
`--check` is read-only and must pass before any generated evidence is consumed.
Bare or invalid invocation prints usage, exits 2, and writes nothing.

Run the focused adversarial bar with:

```text
npm run check:m0-program-control
```
