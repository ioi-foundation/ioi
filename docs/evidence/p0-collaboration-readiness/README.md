# P0 Local Collaboration Readiness Evidence

This directory freezes the S1/F-N/D-R comparison protocol before any
claim-bearing cohort is run. It is program evidence only: it does not define a
canonical architecture object, activate an experiment, schedule work, grant
authority, or certify M3-M5 readiness.

`comparison-protocol.v1.json` fixes the matched cohort, arm topology, budgets,
held-out acceptance rubric, actual-cost rules, failure/collapse/privacy/
independence/reliability/economic guardrails, analysis thresholds, retention,
and claim ceiling. F-N is fixed at the strongest complete topology currently
declared by the live multi-harness proof: two implementers, one conductor, and
one held-out verifier. D-R uses the same two contributor paths through bounded
OutcomeRoom children and must collapse back to its original direct GoalRun
without changing its arm label.

`manifest.json` binds the exact protocol bytes. The checker is deliberately
read-only and has no cohort execution path:

```text
npm run check:p0-collaboration-protocol
```

The protocol remains `frozen_not_activated`. M9 owns any later claim-bearing
matched qualification and supported claim level. M10-M11 continue to gate
multi-node continuity and useful-distribution claims.
