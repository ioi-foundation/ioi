# Agent Model Matrix

- status: `blocked`
- run_id: `2026-04-03T12-08-32-754Z`
- generated_at: `2026-04-03T12:12:33.048Z`
- decision: `keep_default`
- summary: Baseline local smoke leads the retained artifact slice, but the matrix still lacks required workload coverage for artifactQuality, codingCompletion, researchQuality, computerUseCompletion, latencyAndResourcePressure. Keep the shipped default unchanged. Run blocked: Shipped default preset 'ollama-openai' timed out on the first 2 attempted benchmarks, so the local retained environment is unstable for a benchmark-honest comparison.
- missing_coverage: artifactQuality, codingCompletion, researchQuality, computerUseCompletion, latencyAndResourcePressure

| preset | role | availability | artifact judge | artifact verifier | coding | research | computer use | latency |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline local smoke | baseline_local | ready | n/a | 0% | pending | pending | pending | 120107 ms |
