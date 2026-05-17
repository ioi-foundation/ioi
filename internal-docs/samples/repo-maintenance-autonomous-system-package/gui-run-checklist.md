# GUI Run Checklist

Use this checklist for the Workflow Composer e2e probe.

1. Open Workflow Composer.
2. Instantiate the `repo-maintenance-package` scratch blueprint.
3. Open the Readiness rail.
4. Confirm the Autonomous System Package summary is visible.
5. Confirm lifecycle rows exist for run, authority, package, evaluation,
   deployment, and promotion readiness.
6. Confirm model capability and fs/Git tool capability counts are non-zero.
7. Confirm authority scope count is non-zero.
8. Run the fixture path or simulated path.
9. Confirm mutation pauses at approval when approval is required.
10. Confirm receipts include proposal, diff artifact, approval decision, apply
    result, and verification expectations.
