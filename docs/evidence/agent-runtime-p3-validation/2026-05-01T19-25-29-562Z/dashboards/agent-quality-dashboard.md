# Agent Quality Dashboard

| Category | Weight | Required | Metrics |
| --- | --- | --- | --- |
| Base model | screening | no | normalizedScore, passRate, benchmarkCount |
| Artifacts | required | yes | averageValidationScore, verifierPassRate, averageRepairLoopIterations, routeMatchRate |
| Coding | required | yes | taskPassRate, targetedTestPassRate, verifierPassRate |
| Research | required | yes | citationVerifierPassRate, sourceIndependenceRate, synthesisCompleteness |
| Computer use | required | yes | rewardFloorPassRate, postconditionPassRate, meanStepCount |
| Tool/API | screening | no | normalizedScore, taskPassRate, policyPassRate |
| General agent | screening | no | normalizedScore, taskPassRate, reasoningPassRate |
| Latency / resource | required | yes | meanWallClockMs, p95WallClockMs, residentModelBytes, processorKind |
| Conformance / discipline | required | yes | conformancePassRate, comparisonValidityRate, protectedSplitPassRate, rollbackReadinessRate |

## Better-Agent Validation

| Status | Validation | Guide | Evidence |
| --- | --- | --- | --- |
| Complete | Strategy-router tests | guide:2110 | All anchors present |
| Complete | Tool-quality and capability-retirement tests | guide:2112 | All anchors present |
| Complete | Clarification-quality tests | guide:2114 | All anchors present |
| Complete | Recovery-policy tests | guide:2116 | All anchors present |
| Complete | Memory-quality tests | guide:2119 | All anchors present |
| Complete | Delegation-value tests | guide:2122 | All anchors present |
| Complete | Bounded self-improvement gate tests | guide:2124 | All anchors present |
| Complete | Model-routing quality tests | guide:2126 | All anchors present |
| Complete | Operator-collaboration tests | guide:2129 | All anchors present |
| Complete | Regression scorecard tests | guide:2131 | All anchors present |
| Complete | Unified-substrate dogfooding tests | guide:2133 | All anchors present |
| Complete | Harness adapter tests | guide:2136 | All anchors present |
| Complete | Import-boundary tests | guide:2138 | All anchors present |
| Complete | Mock/live substrate tests | guide:2140 | All anchors present |
| Complete | Task-state model tests | guide:2142 | All anchors present |
| Complete | Compaction-state tests | guide:2145 | All anchors present |
| Complete | Uncertainty routing tests | guide:2147 | All anchors present |
| Complete | Probe-loop tests | guide:2150 | All anchors present |
| Complete | Postcondition synthesis tests | guide:2153 | All anchors present |
| Complete | Semantic-impact tests | guide:2156 | All anchors present |
| Complete | Capability-sequence tests | guide:2159 | All anchors present |
| Complete | Negative-learning tests | guide:2162 | All anchors present |
| Complete | Verifier-independence tests | guide:2164 | All anchors present |
| Complete | Cognitive-budget tests | guide:2166 | All anchors present |
| Complete | Drift tests | guide:2168 | All anchors present |
| Complete | Dry-run tests | guide:2170 | All anchors present |
| Complete | Stop-condition tests | guide:2173 | All anchors present |
| Complete | Handoff-quality tests | guide:2176 | All anchors present |
| Complete | Autopilot GUI retained-query tests | guide:2178 | All anchors present |
| Complete | Chat presentation tests | guide:2183 | All anchors present |
| Complete | Thinking/source UX tests | guide:2189 | All anchors present |
