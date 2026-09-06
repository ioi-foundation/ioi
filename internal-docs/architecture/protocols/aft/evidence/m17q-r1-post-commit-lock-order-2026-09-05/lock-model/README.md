# Two-caller post-commit lock-order model

The release-before-continuation configuration checks all 17 reachable states
and completion under weak fairness. The retained-lock configuration must violate
NoCircularWait: the finalizer owns node state and waits for context while the
sync caller owns context and waits for node state. Raw commands, tool/model hashes
and the required witness are retained in results.json and the logs.

This independent finite model assumes just these two callers and finite local
steps. It is not full runtime transition refinement, global deadlock freedom,
or attribution of the earlier process failure. It is currently a standalone
evidence check; mandatory-runner integration remains pending while the active
process campaign's recorded source hashes are kept fixed.

Integration update: the same three model/config files now reside in `formal/concurrency/`; full formal and M16Q runners require the pair. The focused runner passed, as retained in `focused-runner-result.json`. The earlier pending status describes the initial standalone run.
