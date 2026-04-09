# Agent Model Matrix

- status: `blocked`
- run_id: `2026-04-05T22-49-58-220Z`
- generated_at: `2026-04-05T22:50:16.168Z`
- comparison_intent: `unavailable`
- decision: `keep_default`
- summary: Planner-grade local OSS (Qwen3 8B) leads the retained artifact slice, but the matrix still lacks required workload coverage for codingCompletion, researchQuality, computerUseCompletion. Keep the shipped default unchanged. Run blocked: Run interrupted by SIGINT.
- missing_coverage: codingCompletion, researchQuality, computerUseCompletion

| preset | deployment | role | base model | artifacts | coding | research | computer use | tool/api | general agent | latency | conformance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Planner-grade local OSS (Qwen3 8B) | local_gpu_8gb_class | planner_verifier | n/a | 0.800 | pending | pending | pending | pending | pending | 14988 ms | run |
| Coding executor local OSS | local_gpu_8gb_class | coding_executor | n/a | run | pending | pending | pending | pending | pending | 1370 ms | run |
