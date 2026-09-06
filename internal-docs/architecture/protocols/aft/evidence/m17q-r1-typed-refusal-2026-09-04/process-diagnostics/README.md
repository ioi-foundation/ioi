# Diagnostic repeat: local PASS, prior failure unresolved

All four sole-correct cases passed (256–268 ms valid reply maxima), saturation
completed four operations (maximum valid reply 2470 ms), one conflict effect
executed and the other received a structured conflict refusal, exactly one
durable record existed, and the unrelated effect executed. The completeness
checker passed, and source/log hashes matched at terminal verification.

The only source change from the preceding failed campaign enriched coverage
error diagnostics. It did not repair admission, transport, scheduling, or
reply collection. This passing repetition therefore does not explain or close
the retained saturation failure. That intermittent failure remains a blocker
to qualification, with no claim yet about its cause. A separately recorded
transport-logging run follows for diagnosis, not performance admission.
