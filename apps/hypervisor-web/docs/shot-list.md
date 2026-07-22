# Site-Shot Certification — Shot List

This list extends the per-app done bar of the operational application wave:
an app is **site-shot certified** when every shot listed for it meets the
criteria below and regenerates cleanly via `tools/capture-screens.mjs`.
Paths marked `confirm` are finalized at certification time from the app's
actual routes; ids are stable and referenced by `rework-spec.md`.

## Certification criteria (every shot)

1. Captured from a real daemon-served surface — no test flags (standing
   rule), no fixture-only render modes.
2. Shows the seeded receipted demo estate: a scripted governed scenario whose
   receipts, approvals, and lineage are real daemon truth, not lorem.
3. Deterministic: fixed seed data; volatile elements (clocks, spinners)
   settled or masked by the harness before capture.
4. Default viewport 1440×900 @2x unless the shot says otherwise.
5. Regenerates byte-stable enough for review diffing (visual diff, not hash).

## Shell (required before any app certifies)

| id | surface | notes |
|---|---|---|
| `shell-home` | native rail Home | rail shows Home · Projects · Automations · Applications · Sessions |
| `shell-session-approval` | live session with a held approval | the AUTHORITY GATE moment: exact action, Allow/Deny |
| `shell-open-application` | Open Application slot with an app mounted | catalog-launched app in the single slot |
| `shell-receipts` | receipts/lineage trail for a completed run | replaces every "receipts" mock on the site |
| `cli-run` | CLI session start→receipt | terminal capture, monospace-safe |
| `shell-web-org` | Web client, org/approvals view | teams story |
| `gateway-hold` | Authority Gateway exact-action hold | gated on the adoption demo |

## Applications (13)

One `manager` shot (the app's primary operational surface) plus the listed
extras. Every app: manager view must show real objects with provenance, not
empty states.

| app | shots | extras |
|---|---|---|
| Studio | `studio-manager` | `studio-lens` (Studio lens on a live session) |
| Automations | `automations-manager` | `automations-run-history` |
| Ontology | `ontology-manager` | `ontology-object-detail` |
| Data | `data-manager` | `data-source-binding` |
| Governance | `governance-manager` | `governance-approval-policy` |
| Missions | `missions-manager` | `missions-outcome-room` (when rooms land) |
| Provenance | `provenance-manager` | `provenance-receipt-chain` |
| Evaluations | `evaluations-manager` | `evaluations-run-detail` |
| Improvement | `improvement-manager` | `improvement-simulation` |
| Foundry | `foundry-manager` | `foundry-run-plan` |
| Marketplace | `marketplace-manager` | `marketplace-admission` |
| Workbench | `workbench-manager` | `workbench-workspace` |
| Developer Console | `devconsole-manager` | `devconsole-connectors` |

## Seeded demo estate

One scripted scenario feeds every shot (so screens tell one story): a small
governed project with at least one automation, one approval held then
granted, one completed run with full receipt lineage, one ontology-bound
object, and one capability lease visible in Connections. The seeding script
lives with the daemon tooling and must produce identical objects per seed.
