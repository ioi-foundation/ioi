# Captured diagnostic run: PASS; earlier failure unresolved

The process campaign and completeness checker passed. Four nonempty
orchestration logs and four workload logs were retained and hash-verified.
Sole-correct reply maxima were 256–282 ms; saturation's maximum was 3284 ms.
One conflict effect executed, the other had structured conflict refusal, exactly
one durable record existed, and the unrelated effect executed.

The event summary records transient connection/enrollment issues. The logs
lack per-operation lifecycle events needed to correlate those issues with a
specific missing/late reply. This passing run therefore does not explain the
previous failed saturation run, nor does its diagnostic logging qualify the
performance envelope. Nonce-bound diagnostic lifecycle events are a subsequent
source change and are not covered by this run. The earlier failure stays open.
