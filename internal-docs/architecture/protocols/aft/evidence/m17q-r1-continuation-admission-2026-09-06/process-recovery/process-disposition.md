Process campaign FAILED (exit 101) on unchanged source. Placements 0 and 1
passed exact signature/no-storage refusal, sole-correct execution and terminal
replay. Replies were 288/298 ms; calls 5604/5633 ms. The next probe refused with
FailedPrecondition: effect manifest is not Agentgres-admitted. This is not
classified as startup and has not been accepted as passing. Component logs
are retained. Root cause remains under investigation.

Next source adds initial admission probes at all executors and failure-state
capture after quiescing orchestration writers. No live deadline or admission
assertion is weakened. Original run lacked admission-state capture.
