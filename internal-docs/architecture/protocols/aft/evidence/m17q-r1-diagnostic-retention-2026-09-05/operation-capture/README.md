# Nonce-correlated diagnostic run: PASS with workload coverage gap

The campaign and completeness checker passed, and 11 operation lifecycles were
retained across four orchestration logs. All four sole-correct cases passed;
concurrent RPC load had complete member coverage and a maximum valid reply of
2198 ms. One conflicting effect executed and one had structured refusal, with
exactly one durable record; the unrelated effect executed.

The nonce-correlated trace shows that the four RPC-load verifier start times
span 5689.907 ms. At most three logged verifier intervals overlap. Thus the
case named authenticated_saturation does not establish four-way live verifier
overlap or worst-case reserved-lane saturation. The test comment now states
that limit; the full saturation requirement remains open rather than being
redefined around concurrent RPC submission. saturation-overlap.json records
the observation and its source-summary hash. These are wall-clock diagnostic
logs, not replacements for the protocol's monotonic deadline checks.

The earlier intermittent missing-member failure remains unexplained. This
passing repetition cannot close it. Qualifying synchronized worst-case load,
all timing assumptions, runtime refinement, and the final clean R2 candidate
still requires further work. The analyzer and its checks are retained in the
parent directory for reproducible nonce correlation.
