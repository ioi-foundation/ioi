# Repo Maintenance Autonomous System Package

This package is the canonical Phase 5 proof sample for lifecycle clarity over
IOI primitives. It demonstrates a proposal-first filesystem/Git maintenance
system without turning provider names or connector branches into workflow
semantics.

## Lifecycle

`compose -> bind -> simulate -> authorize -> run -> verify -> inspect receipts -> package -> deploy -> promote -> improve`

## Package Contents

- `autonomous-system.manifest.json` defines the first-class Autonomous System
  Package profile.
- `workflow.json` defines the Workflow Composer graph.
- `authority-policy.json` defines wallet-shaped scope and grant posture.
- `approval-profile.json` defines the human gate for proposal-first mutation.
- `evals/propose-safe-doc-fix.json` defines the fixture eval.
- `expected-receipts.json` defines receipt expectations.
- `fixture-repo/README.md` is the bounded repo fixture.
- `gui-run-checklist.md` defines the Autopilot clickthrough checklist.

## Canonical Behavior

The sample must:

1. Read the fixture repo with a typed `file.read` capability.
2. Ask a mounted model capability to draft a docs-only proposal.
3. Pause at an approval gate before `file.apply_patch`.
4. Emit proposal, diff, approval, apply, verification, and package readiness
   receipts.
5. Project as ready for package, evaluation, deployment, and promotion checks
   while still preserving fail-closed run behavior if grants or receipts are
   removed.

## Composer Discovery

Workflow Composer can instantiate this sample through the
`repo-maintenance-package` scratch blueprint. The graph remains a projection of
runtime contracts; React Flow does not own package truth.

For automated GUI validation, launch the composer with:

```bash
VITE_AUTOPILOT_WORKFLOW_DOGFOOD_SCRIPT=repo-maintenance-package
```

The probe should confirm the lifecycle readiness rail shows an Autonomous System
Package summary, six lifecycle categories, model/tool capability refs, authority
scopes, eval fixtures, deployment readiness, and promotion readiness.
