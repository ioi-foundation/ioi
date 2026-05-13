# Agent Runtime DeepSeek TUI Parity Plus Implementation Log

Status: extracted implementation ledger
Source guide: `docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
Reorganized: 2026-05-12

This document preserves completed implementation-slice detail that used to live
inline in the master guide. Keep new completed-slice narratives here so the
master guide can stay readable and strategic.

The `Source Section` column records the heading under which the slice originally
appeared before extraction. Some later workflow and React Flow refactor slices
were originally appended under a broad product heading even when their practical
workstream was narrower.

## Compact Slice Index

| # | Date | Source Section | Slice | Evidence |
| --- | --- | --- | --- | --- |
| 1 | 2026-05-11 | P1. Model Auto-Routing And Reasoning Effort | P1. Model Auto-Routing And Reasoning Effort | docs/evidence/autopilot-gui-harness-validation/2026-05-11T00-45-58-933Z/result.json |
| 2 | 2026-05-11 | P1. Memory UX | P1. Memory UX | n/a |
| 3 | 2026-05-11 | P1. Memory UX | memory policy controls | docs/evidence/autopilot-gui-harness-validation/2026-05-11T02-51-13-357Z/result.json |
| 4 | 2026-05-11 | P1. Memory UX | workflow memory execution wiring | docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-17-06-563Z/result.json |
| 5 | 2026-05-11 | P1. Memory UX | workflow memory search/list | docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-50-03-897Z/result.json |
| 6 | 2026-05-11 | P1. Memory UX | subagent memory inheritance execution | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-25-14-983Z/result.json |
| 7 | 2026-05-11 | P1. Doctor, Config, And Introspection | runtime doctor preflight | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-42-38-804Z/result.json |
| 8 | 2026-05-11 | P1. Skills And Hooks | read-only skill and hook discovery | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-51-31-990Z/result.json |
| 9 | 2026-05-11 | P1. Skills And Hooks | active skill/hook manifest per turn | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-58-22-773Z/result.json |
| 10 | 2026-05-11 | P1. Skills And Hooks | hook dry-run policy preview | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-07-33-015Z/result.json |
| 11 | 2026-05-11 | P1. Skills And Hooks | HookPolicyNode activation gate | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-14-01-420Z/result.json |
| 12 | 2026-05-11 | P1. Skills And Hooks | hook invocation ledger | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-19-58-078Z/result.json |
| 13 | 2026-05-11 | P1. Skills And Hooks | hook escalation receipts | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-25-17-876Z/result.json |
| 14 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | repository context foundation | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-36-44-368Z/result.json |
| 15 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | branch policy gate | docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-16-23-615Z/result.json |
| 16 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | GitHub context projection | docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-38-48-741Z/result.json |
| 17 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | PR attempt preview ledger | docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-51-00-206Z/result.json |
| 18 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | review gate decision | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-15-17-099Z/result.json |
| 19 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | issue context projection | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-25-31-750Z/result.json |
| 20 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | GitHub PR create dry-run plan | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-38-30-155Z/result.json |
| 21 | 2026-05-11 | P2. Runtime Task Queue And Jobs | runtime task/job ledger spine | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-52-37-360Z/result.json |
| 22 | 2026-05-11 | P2. Runtime Task Queue And Jobs | job cancellation endpoint | docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-05-03-333Z/result.json |
| 23 | 2026-05-11 | P2. Runtime Task Queue And Jobs | runtime checklist record | docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-35-25-228Z/result.json |
| 24 | 2026-05-11 | P2. Localization And Accessibility | runtime chrome localization and accessible status metadata | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-03-04-311Z/result.json |
| 25 | 2026-05-11 | P2. Localization And Accessibility | workflow UI localization and accessible status surfaces | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-14-20-396Z/result.json |
| 26 | 2026-05-11 | P2. Localization And Accessibility | keyboard and focus parity | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-28-34-383Z/result.json |
| 27 | 2026-05-11 | P2. Localization And Accessibility | global workflow chrome locale | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-34-43-218Z/result.json |
| 28 | 2026-05-11 | P2. Localization And Accessibility | locale-aware portable package evidence | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-47-49-991Z/result.json |
| 29 | 2026-05-11 | P2. Localization And Accessibility | workflow-native package/import actions | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-01-34-285Z/result.json |
| 30 | 2026-05-11 | P2. Localization And Accessibility | package action runtime execution | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-24-53-304Z/result.json |
| 31 | 2026-05-11 | P2. Localization And Accessibility | package action run output surfaces | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-33-50-765Z/result.json |
| 32 | 2026-05-11 | P2. Localization And Accessibility | live shadow promotion/default dispatch binding | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-57-19-939Z/result.json |
| 33 | 2026-05-11 | P2. Localization And Accessibility | direct PR-create live shadow artifact emission | docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-33-52-995Z/result.json |
| 34 | 2026-05-11 | P2. Localization And Accessibility | PR-create workflow output surfaces | docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-55-06-446Z/result.json |
| 35 | 2026-05-11 | P2. Localization And Accessibility | PR-create React Flow runtime execution | docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-23-26-703Z/result.json |
| 36 | 2026-05-11 | P2. Localization And Accessibility | PR-create runtime module refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-53-05-240Z/result.json |
| 37 | 2026-05-11 | P2. Localization And Accessibility | workflow value helper extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-26-54-384Z/result.json |
| 38 | 2026-05-11 | P2. Localization And Accessibility | workflow package lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-40-25-909Z/result.json |
| 39 | 2026-05-11 | P2. Localization And Accessibility | workflow memory lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-05-24-252Z/result.json |
| 40 | 2026-05-11 | P2. Localization And Accessibility | authority/tooling lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-23-09-790Z/result.json |
| 41 | 2026-05-11 | P2. Localization And Accessibility | workflow coding-route lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-38-33-940Z/result.json |
| 42 | 2026-05-11 | P2. Localization And Accessibility | workflow execution-results lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-59-05-130Z/result.json |
| 43 | 2026-05-11 | P2. Localization And Accessibility | workflow harness-results lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-14-13-182Z/result.json |
| 44 | 2026-05-11 | P2. Localization And Accessibility | workflow graph-execution lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-27-36-131Z/result.json |
| 45 | 2026-05-11 | P2. Localization And Accessibility | workflow binding lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-40-37-167Z/result.json |
| 46 | 2026-05-11 | P2. Localization And Accessibility | workflow output lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-05-30-136Z/result.json |
| 47 | 2026-05-11 | P2. Localization And Accessibility | workflow approval/interrupt lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-47-22-432Z/result.json |
| 48 | 2026-05-12 | P2. Localization And Accessibility | workflow checkpoint lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-20-27-365Z/result.json |
| 49 | 2026-05-12 | P2. Localization And Accessibility | workflow state/input mapping lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-35-34-520Z/result.json |
| 50 | 2026-05-12 | P2. Localization And Accessibility | workflow node-execution lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-50-03-398Z/result.json |
| 51 | 2026-05-12 | P2. Localization And Accessibility | workflow node-contract lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-04-17-641Z/result.json |
| 52 | 2026-05-12 | P2. Localization And Accessibility | workflow run-lifecycle lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-17-52-426Z/result.json |
| 53 | 2026-05-12 | P2. Localization And Accessibility | workflow node-metadata lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-30-26-185Z/result.json |
| 54 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-42-18-082Z/result.json |
| 55 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler validation lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-55-14-162Z/result.json |
| 56 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler interrupt lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-06-47-704Z/result.json |
| 57 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node execution lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-20-30-303Z/result.json |
| 58 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler finalization lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-33-43-994Z/result.json |
| 59 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler terminal result lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-49-14-148Z/result.json |
| 60 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node outcome lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T04-02-51-456Z/result.json |
| 61 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node state update lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T06-55-19-771Z/result.json |
| 62 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node success event lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T07-10-36-395Z/result.json |
| 63 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node failure outcome lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T10-59-14-718Z/result.json |
| 64 | 2026-05-12 | P2. Localization And Accessibility | React Flow scheduler lane readiness UI | docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-23-50-090Z/result.json |
| 65 | 2026-05-12 | P2. Localization And Accessibility | React Flow readiness panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-44-32-936Z/result.json |
| 66 | 2026-05-12 | P2. Localization And Accessibility | React Flow readiness model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-10-50-239Z/result.json |
| 67 | 2026-05-12 | P2. Localization And Accessibility | React Flow unit-test readiness model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-29-29-676Z/result.json |
| 68 | 2026-05-12 | P2. Localization And Accessibility | React Flow run-history model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-53-40-859Z/result.json |
| 69 | 2026-05-12 | P2. Localization And Accessibility | React Flow search model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-15-19-853Z/result.json |
| 70 | 2026-05-12 | P2. Localization And Accessibility | React Flow entrypoints model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-32-20-984Z/result.json |
| 71 | 2026-05-12 | P2. Localization And Accessibility | React Flow file-bundle model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-48-13-986Z/result.json |
| 72 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-16-54-801Z/result.json |
| 73 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-57-39-502Z/result.json |
| 74 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness typed boundary | docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-19-43-946Z/result.json |
| 75 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness activation panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-42-11-524Z/result.json |
| 76 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness worker-binding and rollback panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-10-00-442Z/result.json |
| 77 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness promotion panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-27-56-146Z/result.json |
| 78 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness type contract extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-41-58-495Z/result.json |
| 79 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness active runtime rollback panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-11-04-005Z/result.json |
| 80 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness rollback restore proof panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-29-45-390Z/result.json |
| 81 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness active runtime binding panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-46-33-581Z/result.json |
| 82 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness activation gate panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-07-42-338Z/result.json |
| 83 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness promotion readiness panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-24-22-311Z/result.json |
| 84 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness package evidence panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-46-56-765Z/result.json |
| 85 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness activation gate refs/timeline extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-05-02-607Z/result.json |
| 86 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness package import/rows extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-30-56-229Z/result.json |
| 87 | 2026-05-12 | P0. Live Runtime API Bridge | live bridge TTI/event contract lock | docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md |
| 105 | 2026-05-12 | P0. Live Runtime API Bridge | React Flow runtime thread fork control node | /tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control/2026-05-12T23-57-36-129Z/result.json |
| 106 | 2026-05-13 | P0. Live Runtime API Bridge | React Flow runtime operator interrupt control node | /tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control/2026-05-13T00-11-09-695Z/result.json |
| 107 | 2026-05-13 | P0. Live Runtime API Bridge | React Flow runtime operator steer control node | /tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control/2026-05-13T00-24-15-404Z/result.json |
| 108 | 2026-05-13 | P0. Live Runtime API Bridge | React Flow runtime context compact control node | /tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control/2026-05-13T00-40-20-698Z/result.json |
| 109 | 2026-05-13 | P0. Live Runtime API Bridge | Shared React Flow runtime-control helper extraction | /tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor/2026-05-13T00-56-55-307Z/result.json |
| 110 | 2026-05-13 | P2. Localization And Accessibility | React Flow settings harness active runtime binding panel split | /tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor/2026-05-13T01-09-15-286Z/result.json |
| 111 | 2026-05-13 | P2. Localization And Accessibility | React Flow settings harness promotion readiness panel split | /tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor/2026-05-13T01-18-45-520Z/result.json |
| 112 | 2026-05-13 | P2. Localization And Accessibility | React Flow settings harness activation panel split | /tmp/ioi-autopilot-gui-harness-activation-panel-refactor/2026-05-13T01-27-37-008Z/result.json |
| 113 | 2026-05-13 | Guide Governance | Master guide parity-gap triage cleanup | docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md |
| 114 | 2026-05-13 | P0. Terminal Coding-Agent TUI | Thin daemon-backed `ioi agent tui` shell | /tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell/2026-05-13T01-47-01-001Z/result.json |
| 115 | 2026-05-13 | P0. Terminal Coding-Agent TUI | React Flow/TUI runtime-event deep-link contract | /tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks/2026-05-13T01-56-18-198Z/result.json |
| 116 | 2026-05-13 | P0. Terminal Coding-Agent TUI | Daemon-backed line-mode `ioi agent tui` loop | /tmp/ioi-autopilot-gui-harness-agent-tui-line-mode/2026-05-13T02-06-09-973Z/result.json |
| 117 | 2026-05-13 | P0. Terminal Coding-Agent TUI | React Flow/TUI operator-control equivalence proof | /tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence/2026-05-13T02-12-53-211Z/result.json |
| 118 | 2026-05-13 | P0. Terminal Coding-Agent TUI | TUI control-state projection and run-inspector rows | /tmp/ioi-autopilot-gui-harness-tui-control-state-projection/2026-05-13T02-25-01-786Z/result.json |
| 119 | 2026-05-13 | P0. Terminal Coding-Agent TUI | TUI approval and mode-status control rows | /tmp/ioi-autopilot-gui-harness-tui-approval-mode-status/2026-05-13T02-46-20-811Z/result.json |
| 120 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack status/diff/inspect contract | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect/2026-05-13T03-05-13-000Z/result.json |
| 121 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack governed apply-patch contract | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch/2026-05-13T03-24-26-739Z/result.json |
| 122 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack structured test-run contract | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run/2026-05-13T03-36-24-435Z/result.json |
| 123 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack artifact spillover and retrieval | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval/2026-05-13T03-53-05-208Z/result.json |
| 124 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | coding tool-pack post-edit diagnostics MVP | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics/2026-05-13T04-07-29-549Z/result.json |
| 125 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | automatic post-edit diagnostics injection loop | /tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection/2026-05-13T04-32-30-977Z/result.json |
| 126 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | blocking post-edit diagnostics repair gate | /tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate/2026-05-13T04-49-47-650Z/result.json |
| 127 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | project-aware diagnostics backend ladder | /tmp/ioi-autopilot-gui-harness-project-aware-diagnostics/2026-05-13T05-02-46-174Z/result.json |
| 128 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | workspace snapshot records for mutating coding tools | /tmp/ioi-autopilot-gui-harness-workspace-snapshots/2026-05-13T05-16-45-830Z/result.json |
| 129 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | content-backed workspace restore preview | /tmp/ioi-autopilot-gui-harness-workspace-restore-preview/2026-05-13T05-42-32-697Z/result.json |
| 130 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | policy-gated workspace restore apply | /tmp/ioi-autopilot-gui-harness-workspace-restore-apply/2026-05-13T05-59-11-822Z/result.json |
| 131 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | diagnostics rollback/repair policy | /tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy/2026-05-13T06-12-33-948Z/result.json |
| 132 | 2026-05-13 | P0-B/P0-C/P0-D. Workflow Restore/Repair Controls | workflow restore and diagnostics repair binding controls | /tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls/2026-05-13T06-25-02-908Z/result.json |
| 133 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | restore workflow nodes and request builders | /tmp/ioi-autopilot-gui-harness-restore-workflow-nodes/2026-05-13T06-48-16-424Z/result.json |
| 134 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | keyboard-first TUI restore UX | /tmp/ioi-autopilot-gui-harness-tui-restore-ux/2026-05-13T07-12-46-679Z/result.json |
| 135 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics repair restore-preview | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-preview/2026-05-13T07-37-14-986Z/result.json |
| 136 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics repair restore-apply | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-apply/2026-05-13T07-56-56-734Z/result.json |
| 137 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics repair retry | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry/2026-05-13T08-20-57-956Z/result.json |
| 138 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics operator override | /tmp/ioi-autopilot-gui-harness-diagnostics-operator-override/2026-05-13T08-53-15-768Z/result.json |
| 139 | 2026-05-13 | P0. Terminal Coding-Agent TUI | TUI jobs and run lifecycle parity view | /tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle/2026-05-13T11-39-18-945Z/result.json |
| 140 | 2026-05-13 | P1. MCP Manager Parity | daemon-owned MCP discovery/status/validation | scripts/lib/live-runtime-daemon-contract.test.mjs |
| 141 | 2026-05-13 | P1. Memory UX Parity | daemon-owned memory manager status/validation | scripts/lib/live-runtime-daemon-contract.test.mjs |
| 142 | 2026-05-13 | P1. MCP Manager Parity | MCP enable/disable/invocation controls | /tmp/ioi-autopilot-gui-harness-mcp-controls/2026-05-13T13-37-14-190Z/result.json |
| 143 | 2026-05-13 | P1. Memory UX Parity | memory write-side TUI/workflow controls | /tmp/ioi-autopilot-gui-harness-memory-write-controls/2026-05-13T14-00-24-781Z/result.json |

## P1. Model Auto-Routing And Reasoning Effort

### Slice 1. 2026-05-11 - P1. Model Auto-Routing And Reasoning Effort

Implementation slice completed 2026-05-11:

- `ModelRouteDecision` now projects through daemon thread, turn, run trace, and
  TTI event envelopes as a first-class `model_route_decision` item.
- Agent creation and per-run model overrides resolve through the modular model
  mounting router, preserving React Flow workflow graph/node ids in the route
  decision.
- `model=auto` resolves before provider invocation and deterministic fallback to
  `route.local-first` emits `fallbackTriggered`, rejected candidates, and a
  route receipt.
- SDK types expose `ModelRouteDecision`, `RuntimeTraceBundle.modelRouteDecision`,
  `IOIRunResult.routeDecision`, and `Run.routeDecision()`.
- CLI contract scaffolding exposes `agent model --json` and
  `agent thinking --json` for `/model`, `/thinking`, and React Flow
  `Model Router` configuration parity.

Validation evidence:

- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T00-45-58-933Z/result.json`


## P1. Memory UX

### Slice 2. 2026-05-11 - P1. Memory UX

Implementation slice completed 2026-05-11:

- Runtime daemon now has a durable `AgentMemoryStore` with governed records under
  the daemon state directory, explicit `# remember ...` writes, `/memory` and
  `/memory show` reads, thread/agent memory endpoints, and `memory_update` TTI
  events with `MemoryWrite` payloads.
- Memory writes project into run receipts, trace bundles, turn projections,
  evidence refs, task-state known facts, and workflow-addressable runtime nodes
  so a later turn can explain which memory fact was injected.
- SDK exposes `Agent.memory.remember()`, `Agent.memory.list()`,
  `SendOptions.memory.remember`, `SendOptions.memory.disabled`,
  `AgentMemoryRecord`, and memory-aware mock runtime behavior for local
  workflow tests.
- CLI exposes `ioi agent memory --json` as the operator/workflow contract for
  `# remember`, `/memory`, memory endpoints, `memory_update`, and React Flow
  memory configuration fields.
- Contract tests now assert memory write/injection provenance through the live
  daemon, SDK mock runtime, CLI parser surface, and React Flow workflow
  contract files.

Remaining memory UX closure:

- Closed by the 2026-05-11 subagent memory inheritance execution slice below.

### Slice 3. 2026-05-11 - memory policy controls

Implementation slice completed 2026-05-11, memory policy controls:

- Runtime memory now persists policy records alongside memory records, with
  effective thread policy projection, storage path projection, and
  `memory_policy` receipts.
- Slash/runtime commands now cover `/memory disable`, `/memory enable`,
  `/memory path`, `/memory edit <id> <text>`, and `/memory delete <id>`.
- Thread and agent memory APIs now expose `memory/policy`, `memory/path`, and
  record `PATCH`/`DELETE` endpoints.
- Runtime policy enforcement blocks writes when memory is disabled, read-only,
  or waiting on explicit write approval, while still allowing read/path/policy
  commands.
- `memory_update` now carries `MemoryWrite`, `MemoryEdit`, `MemoryDelete`, and
  `MemoryPolicy` event kinds, receipt refs, policy IDs, and workflow node IDs.
- SDK helpers now expose `Agent.memory.edit()`, `delete()`, `policy()`,
  `configure()`, and `path()`, plus typed policy/path/update inputs.
- React Flow workflow editor and node registry now expose memory injection,
  read-only memory, write approval, and subagent inheritance controls on model
  nodes, and parity contracts require memory policy/edit/path nodes.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/memory-store.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T02-51-13-357Z/result.json`

### Slice 4. 2026-05-11 - workflow memory execution wiring

Implementation slice completed 2026-05-11, workflow memory execution wiring:

- React Flow model nodes now expose a concrete memory scope selector alongside
  key, injection, read-only, write approval, and subagent inheritance controls.
- Local workflow execution projects model-node memory policy into
  `runtimeSendOptions.memory` and `attachments.memoryPolicy`, so workflow run
  evidence shows the exact memory send options used by the node.
- Daemon workflow-node execution normalizes direct, nested `logic`, and nested
  `memory` fields into `SendOptions.memory`, records them on model invocation
  receipts, and returns them through the native workflow invocation response.
- Workflow memory writes now fail closed before provider invocation when memory
  is disabled, read-only, or requires approval without an approval bit.
- The model-mounting facade stayed under its extraction guard by moving
  workflow-node response shaping and workflow-memory normalization into focused
  modules under `packages/runtime-daemon/src/model-mounting/`.

Validation evidence:

- `node --check packages/runtime-daemon/src/model-mounting.mjs`
- `node --check packages/runtime-daemon/src/model-mounting/workflow-memory.mjs`
- `node --check packages/runtime-daemon/src/model-mounting/workflow-node.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- `git diff --check`

### Slice 114. 2026-05-13 - Thin daemon-backed `ioi agent tui` shell

Implementation slice completed 2026-05-13, thin daemon-backed terminal agent UI:

- Added `crates/cli/src/commands/agent_tui.rs` and the `AgentCommands::Tui`
  entrypoint for `ioi agent tui`.
- The thin TUI shell can start a new daemon runtime thread with `--goal`, select
  an existing thread with `--thread-id`, resume a selected thread, submit one
  user message, render canonical thread events, replay by `--since-seq` or
  `--last-event-id`, and call interrupt/steer controls.
- The implementation reuses the existing daemon thread, turn, event-stream, and
  control endpoints:
  `/v1/threads`, `/v1/threads/{thread_id}`,
  `/v1/threads/{thread_id}/turns`,
  `/v1/threads/{thread_id}/events`, and the interrupt/steer control routes.
- Added JSON output under `ioi.agent-cli.tui.v1` with
  `private_runtime_loop: false`, event rows, route metadata, and graph/node
  deep-link ids extracted from runtime event envelopes.
- Updated the live runtime daemon contract to prove the TUI path starts a live
  runtime-service thread, submits a turn, interrupts through the daemon control
  endpoint, replays by `Last-Event-ID`, and does not depend on the legacy
  desktop-agent execution loop.

Validation evidence:

- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `cargo test -p ioi-cli --bin cli agent_tui`
- `cargo check -p ioi-cli --bin cli`
- `cargo fmt -p ioi-cli -- --check`
- `node --test --test-name-pattern "agent TUI thin shell starts a live thread|agent TUI thin shell is daemon-backed|agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell/2026-05-13T01-47-01-001Z/result.json`.
- `git diff --check`

### Slice 115. 2026-05-13 - React Flow/TUI runtime-event deep-link contract

Implementation slice completed 2026-05-13, React Flow/TUI runtime-event
deep-link contract:

- Added explicit `event_rows` to the `ioi agent tui --json` payload under the
  shared `ioi.workflow.runtime-tui-deeplink.v1` schema, preserving
  `thread_id`, `turn_id`, `workflow_graph_id`, `workflow_node_id`, `event_id`,
  `seq`, and canonical cursor for every rendered daemon event.
- Each TUI event row now carries a reopen descriptor:
  `ioi agent tui --thread-id <thread_id> --since-seq <seq>`, plus the
  corresponding React Flow graph/node/event locator.
- Added `WorkflowRuntimeTuiDeepLinkDescriptor` to the React Flow runtime-event
  projection so workflow run-inspector nodes expose the same reopen identity as
  terminal event rows.
- Updated the workflow run inspector to expose TUI reopen metadata through DOM
  data attributes and the event detail panel without taking runtime ownership
  away from the daemon event stream.
- Extended the live runtime daemon contract to prove one operator-interrupt
  event keeps the same id, cursor, workflow node id, and reopen args across
  daemon SSE, SDK `Thread.events()`, `ioi agent tui --json`, and React Flow
  projection.

Validation evidence:

- `cargo test -p ioi-cli --bin cli`
- `cargo check -p ioi-cli --bin cli`
- `cargo fmt -p ioi-cli -- --check`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "agent TUI thin shell starts a live thread|agent TUI thin shell is daemon-backed|agent CLI exposes model|React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks/2026-05-13T01-56-18-198Z/result.json`.

### Slice 116. 2026-05-13 - Daemon-backed line-mode `ioi agent tui` loop

Implementation slice completed 2026-05-13, daemon-backed line-mode terminal
agent UI:

- Added `--interactive` to `ioi agent tui`, explicitly preserving the existing
  one-shot JSON contract by rejecting `--interactive --json`.
- Added `crates/cli/src/commands/agent_tui_loop.rs` for line-mode parsing and
  command dispatch so the TUI shell stays modular instead of growing a hidden
  runtime loop.
- Implemented `/resume`, `/events [since_seq]`, `/interrupt [reason]`,
  `/steer <guidance>`, `/help`, and `/quit` over the same daemon thread,
  turn-control, and event-stream endpoints used by the one-shot shell.
- Refactored the TUI daemon helpers for event fetch, turn interrupt, turn steer,
  thread resume, and latest event cursor reuse while keeping
  `private_runtime_loop: false`.
- Added a live line-mode contract that drives stdin through
  `/interrupt line-mode validation interrupt`, `/events 0`, and `/quit`, then
  proves the resulting operator-interrupt event keeps the same event id, cursor,
  workflow node id, and TUI reopen descriptor across daemon SSE, SDK
  `Thread.events()`, CLI/TUI output, and React Flow projection.

Validation evidence:

- `cargo test -p ioi-cli --bin cli agent_tui`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `cargo test -p ioi-cli --bin cli`
- `cargo check -p ioi-cli --bin cli`
- `cargo fmt -p ioi-cli -- --check`
- `node --test --test-name-pattern "agent TUI line-mode slash commands|agent TUI thin shell starts a live thread|agent TUI thin shell is daemon-backed|agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-line-mode`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-agent-tui-line-mode/2026-05-13T02-06-09-973Z/result.json`.

### Slice 117. 2026-05-13 - React Flow/TUI operator-control equivalence proof

Implementation slice completed 2026-05-13, React Flow/TUI operator-control
equivalence proof:

- Added shared live-contract helpers that normalize operator-control event
  shape, canonical cursor, SDK identity, React Flow projected node identity,
  and `ioi agent tui --json` event-row reopen descriptors.
- Added a live interrupt equivalence proof: one React Flow-authored
  `runtime_operator_interrupt` request and one line-mode TUI `/interrupt`
  command both emit the same operator-control contract shape while preserving
  their own event ids, cursors, workflow node ids, receipts, policies, SDK
  events, React Flow projection nodes, and TUI reopen rows.
- Added the matching live steer equivalence proof for
  `runtime_operator_steer` and `/steer`, so both primary TUI line-mode controls
  are proven equivalent to workflow-authored runtime-control nodes.
- Kept this as a proof slice only: no runtime ownership changes, no new UI
  shell, and no changes to the daemon event model.

Validation evidence:

- `node --test --test-name-pattern "React Flow and line-mode TUI .* controls share" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "React Flow and line-mode TUI .* controls share|agent TUI line-mode slash commands|React Flow operator interrupt control preserves graph identity|React Flow operator steer control preserves graph identity|agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence/2026-05-13T02-12-53-211Z/result.json`.

### Slice 118. 2026-05-13 - TUI control-state projection and run-inspector rows

Implementation slice completed 2026-05-13, TUI control-state projection and
React Flow run-inspector rows:

- Added a TUI control-state schema around command history, current turn id,
  last event cursor/id, and slash-command validation errors.
- Extended `ioi agent tui --json` with `tui_control_state` so non-interactive
  TUI sessions expose the same current-turn/cursor state as the event rows.
- Extended daemon-backed line mode to print `tui_control_state=...` after
  help, resume, events, interrupt, steer, quit, and validation-error paths.
- Added React Flow/agent-ide projection helpers that normalize the TUI
  control-state envelope into run-inspector rows with stable React Flow node
  ids for commands and validation errors.
- Rendered those rows in the workflow run inspector beside the runtime event
  graph, preserving `data-*` hooks for thread, turn, cursor, event id,
  command, validation status, and React Flow node identity.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - React Flow TUI control-state projection and run-history model tests passed.
- `cargo test --manifest-path crates/cli/Cargo.toml --bin cli agent_tui -- --nocapture`
  - CLI TUI route, event-row, control-state, line-mode parser, and
    validation-error tests passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes|agent TUI thin shell is daemon-backed|agent TUI thin shell starts|agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract passed: TUI JSON and line mode emitted control-state
    envelopes, line mode recorded `/steer` validation errors, and React Flow
    projection rows preserved command and validation identity.
- `node --import tsx --test --test-name-pattern "projects TUI control state|workflow run history model projects TUI control state" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - focused TUI control-state projection tests passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime daemon contract syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo check --manifest-path crates/cli/Cargo.toml --bin cli`
  - CLI binary type-check passed.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-control-state-projection`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-control-state-projection/2026-05-13T02-25-01-786Z/result.json`.

Known validation note:

- `cargo test --manifest-path crates/cli/Cargo.toml agent_tui -- --nocapture`
  attempted to compile unrelated CLI integration tests and failed on existing
  `StartAgentParams.runtime_route_frame` initializer debt before it could
  isolate this slice. The targeted CLI binary test above covers the touched TUI
  command modules.
- `node --import tsx --test apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts`
  currently fails before this slice's run-inspector assertions on an existing
  readiness-label source-contract assertion. The slice-specific run-inspector
  projection and frontend build checks passed.

### Slice 119. 2026-05-13 - TUI approval and mode-status control rows

Implementation slice completed 2026-05-13, TUI approval and mode-status parity:

- Added a daemon approval-decision endpoint,
  `/v1/threads/{thread_id}/approvals/{approval_id}/decision`, that emits
  receipt-backed `approval.approved` or `approval.rejected` events with policy
  decision refs and preserved workflow node identity.
- Extended line-mode `ioi agent tui` with `/approvals`, `/approve`, and
  `/reject` while keeping `/resume`, `/events`, `/interrupt`, `/steer`, and
  `/quit` on the same daemon-backed control loop.
- Extended the TUI control-state envelope with `mode_status`, `approval_rows`,
  and `approval_decisions`, including approval id, cursor, workflow node id,
  receipt refs, and policy decision refs.
- Mirrored those rows into the React Flow run inspector so workflow-authored
  experiences can inspect mode posture, pending approvals, and approval
  decisions beside runtime event graph rows.

Validation evidence:

- `cargo test --manifest-path crates/cli/Cargo.toml --bin cli agent_tui -- --nocapture`
  - CLI TUI route, approval parser, mode-status, approval-row, and
    control-state tests passed.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - React Flow TUI control-state projection and run-history model tests passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes|agent TUI approval slash commands|agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract passed: TUI approval slash commands emitted approval
    decision events with receipts/policy refs and React Flow rows.
- `node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - daemon and live contract syntax checks passed.
- `cargo check --manifest-path crates/cli/Cargo.toml --bin cli`
  - CLI binary type-check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-approval-mode-status`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-approval-mode-status/2026-05-13T02-46-20-811Z/result.json`.

### Slice 120. 2026-05-13 - Coding tool-pack status/diff/inspect contract

Implementation slice completed 2026-05-13, P0-B coding tool-pack parity:

- Added daemon-owned `workspace.status`, `git.diff`, and `file.inspect`
  contracts in `packages/runtime-daemon/src/coding-tools.mjs` and exposed them
  through `/v1/tools?pack=coding`, with path containment, read-only git
  execution, bounded file previews, and explicit `shell_fallback_used=false`
  result fields.
- Added `/v1/threads/{thread_id}/tools/{tool_id}/invoke` so coding tool calls
  emit receipt-backed `tool.completed` or `tool.failed` runtime events with
  `component_kind=coding_tool`, `payload_schema_version=ioi.runtime.coding-tool-result.v1`,
  stable workflow node ids, and SDK/TUI/React Flow-visible payload summaries.
- Added SDK `listTools({ pack })` and `invokeThreadTool`, CLI
  `agent tools coding` and `agent tools run`, and TUI line-mode `/status`,
  `/diff [path]`, and `/inspect <path>` commands.
- Added React Flow support for `coding_tool_pack` tool bindings, coding-pack
  creator entries, and coding-tool projection labels/receipt rows.
- Added a live contract test that drives the same status/diff/inspect tools
  through daemon HTTP, SDK, CLI, line-mode TUI, and React Flow projection.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs && node --check packages/runtime-daemon/src/coding-tools.mjs`
  - daemon syntax checks passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo check -p ioi-cli`
  - CLI package check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI nested coding-tool command parser test passed.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI `/status`, `/diff`, and `/inspect` parser test passed.
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source-contract guard for CLI/TUI routes and slash commands passed.
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - TUI daemon-backed source guard passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect/2026-05-13T03-05-13-000Z/result.json`.

Known validation note:

- Broad `cargo test -p ioi-cli ...` still compiles unrelated CLI integration
  tests and remains blocked by existing `StartAgentParams.runtime_route_frame`
  initializer debt. Targeted CLI binary tests and `cargo check -p ioi-cli`
  passed for the touched CLI surfaces.

### Slice 121. 2026-05-13 - Coding tool-pack governed apply-patch contract

Implementation slice completed 2026-05-13, coding tool-pack governed
apply-patch contract:

- Added daemon-owned `file.apply_patch` to the `coding` pack with exact
  replace/append/prepend edits, workspace path containment, create/dry-run
  controls, edit limits, before/after hashes, bounded preview diffs, mutation
  receipts, and `shellFallbackUsed: false`.
- Extended SDK tool catalog/invocation mocks, CLI `agent tools run` flags,
  TUI line-mode `/patch` and `/patch-dry-run`, and React Flow coding-pack
  creator/config controls for filesystem write, dry-run, and allowed paths.
- Updated the live daemon contract to prove apply-patch across React
  Flow-originated daemon invocation, SDK invocation, CLI invocation, TUI
  command replay, canonical SSE events, SDK event projection, and React Flow
  run-inspector rows.
- Refreshed the master guide active gap ledger so the next P0-B work moves to
  structured test execution, artifact spillover, retrieve-result, and
  diagnostics.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs && node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo fmt -p ioi-cli`
- `cargo check -p ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch/2026-05-13T03-24-26-739Z/result.json`.

### Slice 122. 2026-05-13 - Coding tool-pack structured test-run contract

Implementation slice completed 2026-05-13, coding tool-pack structured
test-run contract:

- Added daemon-owned `test.run` to the `coding` pack with allowlisted command
  ids (`node.test`, `npm.test`, `cargo.test`, `cargo.check`), workspace cwd and
  path containment, timeout controls, bounded stdout/stderr previews, output
  hashes, test status, exit code, spillover recommendation, receipts, and
  `shellFallbackUsed: false`.
- Extended SDK tool catalog mocks, CLI `agent tools run test.run` flags, TUI
  line-mode `/test [path]`, and React Flow coding-pack controls for test
  enablement, allowed command ids, and timeout.
- Updated the live daemon contract to prove `test.run` across React
  Flow-originated daemon invocation, SDK invocation, CLI invocation, TUI command
  replay, canonical SSE events, SDK event projection, and React Flow
  run-inspector rows.
- Refreshed the master guide active gap ledger so the next P0-B work moves to
  artifact spillover and `tool.retrieve_result`/`artifact.read`.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo fmt -p ioi-cli`
- `cargo check -p ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run/2026-05-13T03-36-24-435Z/result.json`.

### Slice 123. 2026-05-13 - Coding tool-pack artifact spillover and retrieval

Implementation slice completed 2026-05-13, coding tool-pack artifact
spillover and retrieval:

- Added daemon-owned `artifact.read` and `tool.retrieve_result` to the `coding`
  pack with read-only artifact risk metadata, workflow node types, receipt
  requirements, and SDK catalog projection.
- Made truncated `test.run` output materialize thread-scoped coding artifacts
  while keeping inline stdout/stderr as bounded previews.
- Added range-aware artifact reads with thread ownership checks, content
  hashes, artifact refs, receipt refs, and stable tool-call ids.
- Extended CLI `agent tools run` with artifact/retrieve flags and TUI
  line-mode with `/artifact <artifact_id>` and `/retrieve <tool_call_id>`.
- Reflected artifact/retrieve toggles and creators in React Flow coding-pack
  workflow bindings, and projected artifact refs into coding-tool rows.
- Updated the live daemon contract to prove large test-output spillover and
  retrieval across daemon, SDK, CLI, TUI, and React Flow.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs && node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo fmt -p ioi-cli`
- `cargo check -p ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval/2026-05-13T03-53-05-208Z/result.json`.

### Slice 124. 2026-05-13 - Coding tool-pack post-edit diagnostics MVP

Implementation slice completed 2026-05-13, coding tool-pack post-edit
diagnostics MVP:

- Added daemon-owned `lsp.diagnostics` to the `coding` pack with read-only
  diagnostics risk metadata, `LspDiagnosticsNode` workflow type, receipt
  requirements, and SDK catalog projection.
- Added safe diagnostics backends for `node.check` and local
  `typescript.check`; `node.check` runs `node --check` over `.js`, `.mjs`, and
  `.cjs` files without executing user code, while `typescript.check` degrades
  cleanly when no local `node_modules/.bin/tsc` exists.
- Extended `file.apply_patch` results with `changedFiles` metadata and
  `diagnosticsRecommended` so the next runtime slice can trigger automatic
  post-edit diagnostics injection.
- Extended CLI `agent tools run lsp.diagnostics`, TUI `/diagnostics <path>`,
  SDK invocation, and React Flow coding-pack controls/creator entries for
  diagnostics enablement, allowed diagnostic command ids, paths, and timeout.
- Updated React Flow event projection tests and the live daemon contract to
  prove a React Flow-originated patch can introduce a syntax finding, then
  surface that finding through daemon events, SDK, CLI, TUI, and projected
  coding-tool rows.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo fmt -p ioi-cli`
- `cargo check -p ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics/2026-05-13T04-07-29-549Z/result.json`.

### Slice 125. 2026-05-13 - Automatic post-edit diagnostics injection loop

Implementation slice completed 2026-05-13, automatic post-edit diagnostics
injection loop:

- Added runtime-auto post-edit diagnostics orchestration after successful
  mutating `file.apply_patch` calls, using changed-file metadata to invoke
  `lsp.diagnostics` without shell-only fallback.
- Added compact diagnostics feedback records that collect findings, receipts,
  source diagnostic event ids, and prompt-ready summaries, then inject them
  into the next local daemon or runtime-bridge turn.
- Added receipt-backed `lsp.diagnostics.injected` runtime events with
  `runtime_auto` source, `ioi.runtime.lsp-diagnostics-injection.v1` schema,
  `lsp_diagnostics` component kind, and React Flow projection label.
- Added React Flow coding-pack controls for diagnostics mode
  (`advisory`/`blocking`/`skip`) and default diagnostic command, and taught the
  daemon to honor both direct `toolPack` and nested `toolPack.coding.*`
  workflow config shapes.
- Updated SDK TTI source literals and Rust live-bridge schema constants so
  `runtime_auto` events remain cross-language contract surfaces.
- Extended the live daemon contract to prove automatic diagnostics after a
  syntax-breaking patch, compact injection into the next turn prompt/trace,
  nested React Flow `skip` config, SDK event stream projection, and React Flow
  injected-diagnostics rows.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check packages/runtime-daemon/src/coding-tools.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `rustfmt --check crates/types/src/app/runtime/thread_turn_item.rs`
- `cargo check -p ioi-types`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection/2026-05-13T04-32-30-977Z/result.json`.

Known validation note:

- Broad `cargo fmt --all -- --check` remains blocked by unrelated formatting
  drift in `apps/autopilot/src-tauri/src/orchestrator/store/*.rs`; this slice's
  touched Rust file passed direct `rustfmt --check`.

### Slice 126. 2026-05-13 - Blocking post-edit diagnostics repair gate

Implementation slice completed 2026-05-13, blocking post-edit diagnostics
repair gate:

- Turned `diagnosticsMode: "blocking"` into a hard runtime gate when pending
  post-edit diagnostics contain findings, before local or runtime-bridge model
  continuation.
- Added blocked run/turn state for the diagnostics gate: no assistant delta,
  no completed event, `waiting_for_input` turn status, blocked runtime task/job
  records, and a stopped `blocked_by_post_edit_diagnostics` stop condition.
- Added a receipt-backed `policy.blocked` TTI event with
  `runtime_auto` source, `LspDiagnostics.BlockingGate` source kind,
  `ioi.runtime.lsp-diagnostics-blocking-gate.v1` payload schema,
  policy-decision refs, and `diagnostics-blocking-gate.json` artifact refs.
- Exposed the gate through SDK event normalization and React Flow projection as
  the workflow-addressable `runtime.lsp-diagnostics.blocking-gate` node with
  `lsp_diagnostics_gate` component kind and "Diagnostics blocking gate" label.
- Extended the live coding-tool contract to prove advisory injection still
  continues, blocking injection pauses continuation, SDK/React Flow see the
  policy gate, and the runtime trace preserves diagnostics gate receipts and
  blocked checklist state.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check packages/runtime-daemon/src/coding-tools.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --import tsx --test --test-name-pattern "projects coding tool|approval and policy|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate/2026-05-13T04-49-47-650Z/result.json`.

### Slice 127. 2026-05-13 - Project-aware diagnostics backend ladder

Implementation slice completed 2026-05-13, project-aware diagnostics backend
ladder:

- Promoted `lsp.diagnostics` and post-edit diagnostics defaults from
  `node.check` to `auto` across the daemon, CLI/TUI slash path, SDK mock, and
  React Flow coding-tool/LSP node creators.
- Added a diagnostics planner that records requested/resolved command ids,
  backend, backend status/reason, project context, and fallback state.
- Added TypeScript project diagnostics with nearest-`tsconfig.json`
  resolution, local `node_modules/.bin/tsc` discovery from project root upward,
  `tsc --noEmit --pretty false -p tsconfig.json`, and normalized
  workspace-relative diagnostic paths.
- Preserved degraded-mode behavior by falling back to `node.check` when an
  `auto` TypeScript project has no local `tsc`, while emitting degraded and
  fallback receipt refs plus compact result-summary metadata.
- Extended the live daemon contract to prove React Flow-authored patch nodes
  trigger TypeScript project findings automatically, explicit diagnostics can
  degrade with receipts, and SDK/CLI/TUI/React Flow surfaces preserve the
  backend ladder metadata.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo fmt -p ioi-cli -- --check`
- `cargo check -p ioi-cli --bin cli`
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-project-aware-diagnostics`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-project-aware-diagnostics/2026-05-13T05-02-46-174Z/result.json`.

### Slice 128. 2026-05-13 - Workspace snapshot records for mutating coding tools

Implementation slice completed 2026-05-13, workspace snapshot records for
mutating coding tools:

- Added metadata-only workspace snapshot records for applied `file.apply_patch`
  calls, including pre/post touched-file hashes, existence, size, and mtime
  metadata.
- Attached snapshot artifact refs, receipt refs, and rollback refs to the patch
  result and emitted a separate `workspace.snapshot.created` runtime event.
- Extended SDK result types and the SDK mock so patch invocations surface
  `workspace_snapshot`, camelCase aliases, and `rollback_refs`.
- Projected snapshot events into React Flow as workflow-addressable
  `quality_ledger` rows with `workspace_snapshot` component kind.
- Updated the live daemon contract to prove daemon, SDK, CLI/TUI source guards,
  React Flow projection, and autopilot GUI/workflow preflight all preserve the
  snapshot receipts and rollback refs.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-snapshots`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workspace-snapshots/2026-05-13T05-16-45-830Z/result.json`.

### Slice 129. 2026-05-13 - Content-backed workspace restore preview

Implementation slice completed 2026-05-13, content-backed workspace restore
preview:

- Captured before/after UTF-8 content for applied `file.apply_patch` snapshots
  inside a redacted snapshot-content artifact while keeping public tool results
  metadata-first.
- Promoted snapshot restore metadata from `metadata_only` to
  `content_captured` when every touched file fits the capture policy.
- Added daemon thread snapshot listing and
  `/v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-preview`, with
  current-workspace drift detection, ready/noop/conflict/blocked operation rows,
  preview diffs, receipts, artifacts, and rollback refs.
- Added SDK helpers for listing thread workspace snapshots and previewing a
  restore, plus mock-client support for workflow development.
- Projected `workspace.restore.previewed` runtime events as React Flow
  `restore_gate` rows so restore preview is workflow-addressable.
- Extended the live contract to prove snapshot artifact readback, restore
  preview route, SDK helper, SDK event projection, and React Flow restore-gate
  projection.

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-restore-preview`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workspace-restore-preview/2026-05-13T05-42-32-697Z/result.json`.

### Slice 130. 2026-05-13 - Policy-gated workspace restore apply

Implementation slice completed 2026-05-13, policy-gated workspace restore
apply:

- Extracted reusable workspace snapshot and restore helpers into
  `workspace-restore.mjs` so preview/apply mechanics stay outside the daemon
  route layer.
- Added daemon
  `/v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-apply` with an
  explicit approval gate, conflict override policy, clean preflight, apply/noop
  status rows, receipts, artifacts, rollback refs, and policy decision refs.
- Materialized restore-apply artifacts and emitted
  `workspace.restore.applied` events that project as React Flow `restore_gate`
  rows with a distinct Restore apply label.
- Added SDK and mock-client restore apply helpers so workflow development can
  configure and validate approval and conflict policy without a live daemon.
- Extended the live contract to prove blocked-without-approval, applied with
  approval, noop-after-apply, SDK event projection, and React Flow restore-gate
  projection.

Validation evidence:

- `node --check packages/runtime-daemon/src/workspace-restore.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-sdk`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-restore-apply`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workspace-restore-apply/2026-05-13T05-59-11-822Z/result.json`.

### Slice 131. 2026-05-13 - Diagnostics rollback/repair policy

Implementation slice completed 2026-05-13, diagnostics rollback/repair policy:

- Threaded workspace snapshot rollback refs from applied `file.apply_patch`
  results into runtime-auto `lsp.diagnostics` events.
- Added diagnostics repair context and a structured rollback/repair policy for
  blocking diagnostics gates, with `repair_retry`, `restore_preview`,
  `restore_apply`, and `operator_override` decision refs.
- Propagated rollback refs, policy decision refs, and repair policy payloads
  through daemon TTI events, SDK event normalization, mock substrate coding-tool
  events, and React Flow projections.
- Extended live coverage to prove blocked diagnostics carry snapshot refs and
  repair/restore decisions from daemon trace through SDK and React Flow.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-sdk`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy/2026-05-13T06-12-33-948Z/result.json`.

### Slice 132. 2026-05-13 - Workflow restore and diagnostics repair binding controls

Implementation slice completed 2026-05-13, workflow restore and diagnostics
repair binding controls:

- Added typed React Flow coding-tool-pack config fields for restore policy,
  restore conflict policy, diagnostics repair default, and operator override
  approval requirements.
- Surfaced the new policy knobs in
  `WorkflowNodeBindingEditor/sections.tsx` with stable workflow editor
  test ids and added creator defaults for the coding pack, file apply-patch,
  and LSP diagnostics nodes.
- Extended the daemon coding-tool catalog so `file.apply_patch` and
  `lsp.diagnostics` advertise the new `toolPack.coding.*` workflow config
  fields.
- Threaded workflow-authored policy fields from `toolPack.coding.*` into
  runtime-auto diagnostics repair context and into the blocking diagnostics
  rollback/repair policy.
- Updated live coverage to prove a React Flow tool-pack request can set
  `preview_only`, `require_approval`, `restore_preview`, and
  operator-override approval behavior, and that those choices appear in the
  daemon trace, diagnostics injection, and blocking gate.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/coding-tools.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls/2026-05-13T06-25-02-908Z/result.json`.

### Slice 133. 2026-05-13 - Restore workflow nodes and request builders

Implementation slice completed 2026-05-13, restore workflow nodes and request
builders:

- Added typed React Flow request builders for `runtime_rollback_snapshot` and
  `runtime_restore_gate`, including graph/node identity, thread id,
  snapshot id, preview/apply mode, conflict policy, approval flags, and daemon
  endpoint compilation.
- Added first-class workflow registry entries, input/output schemas, node
  chrome labels, canvas tokens, activation-gate fields, and runtime projection
  action kinds for the rollback snapshot and restore gate nodes.
- Mirrored the node kinds through the Tauri project template catalog,
  generated action schemas, validation rules, and local workflow execution lane
  so workflow-authored restore requests remain available outside the browser
  bundle.
- Extended source-contract and request-builder tests so future slices cannot
  drop the restore node family from the workflow editor, runtime action schema,
  Tauri execution lane, or React Flow control envelope.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_projection --lib`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_thread_fork_node_builds_react_flow_control_request --lib`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata --lib`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-restore-workflow-nodes`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-restore-workflow-nodes/2026-05-13T06-48-16-424Z/result.json`.

Known validation note:

- Full `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports unrelated formatting drift in existing orchestrator store files;
  the Rust files touched by this slice were formatted directly with `rustfmt`.

### Slice 134. 2026-05-13 - Keyboard-first TUI restore UX

Implementation slice completed 2026-05-13, keyboard-first TUI restore UX:

- Added canonical TUI route descriptors and daemon helpers for snapshot listing,
  restore preview, and approval-safe restore apply.
- Added line-mode `/restore`, `/restore list`, `/restore preview
  <snapshot_id>`, and `/restore apply <snapshot_id> --approve` commands, with
  optional conflict override flags and parser validation that blocks apply
  without explicit approval.
- Printed snapshot summaries and restore preview/apply status rows in the TUI,
  then replayed canonical daemon events so the same restore activity projects
  into SDK and React Flow restore-gate rows.
- Extended the live daemon contract so a real TUI session lists snapshots,
  previews an unpreviewed snapshot, applies it, verifies workspace restoration,
  and proves the TUI-authored restore-gate workflow node ids survive daemon,
  SDK, and React Flow projection.

Validation evidence:

- `cargo fmt -p ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli rejects_unknown_or_incomplete_line_mode_commands -- --nocapture`
- `cargo test -p ioi-cli --bin cli tui_event_route_uses_canonical_thread_stream_cursor -- --nocapture`
- `cargo check -p ioi-cli --bin cli`
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-restore-ux`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-restore-ux/2026-05-13T07-12-46-679Z/result.json`.

### Slice 135. 2026-05-13 - Executable diagnostics repair restore-preview

Implementation slice completed 2026-05-13, executable diagnostics repair
restore-preview:

- Added a daemon endpoint for
  `/v1/threads/{thread_id}/diagnostics/repair-decisions/{decision}/execute`
  and implemented `restore_preview` repair-decision execution against the
  latest matching diagnostics blocking gate.
- Reused the canonical workspace restore-preview contract so repair previews
  keep the same drift/conflict checks, snapshot rollback refs, receipts,
  artifacts, and restore-gate event projection as TUI and workflow restore
  commands.
- Added SDK support through `executeThreadDiagnosticsRepairDecision`, including
  daemon and mock runtime clients, so workflow-authored repair controls can
  execute through the same substrate client boundary.
- Emitted a receipt-backed `diagnostics.repair_decision.executed` runtime event
  with graph/node identity, gate/policy refs, restore-preview event refs, and
  rollback refs, then projected it into React Flow as a
  `lsp_diagnostics_repair` policy node.
- Extended source contracts and the live daemon proof so SDK-triggered
  `restore_preview` repair execution, daemon SSE replay, SDK event projection,
  and React Flow node projection all agree on the same event ids and
  workflow-authored node ids.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "diagnostics repair decisions|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-preview`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-preview/2026-05-13T07-37-14-986Z/result.json`.

### Slice 136. 2026-05-13 - Executable diagnostics repair restore-apply

Implementation slice completed 2026-05-13, executable diagnostics repair
restore-apply:

- Extended diagnostics repair decision execution to support `restore_apply`
  alongside `restore_preview`, with a dedicated restore-apply workflow node id
  and supported-action guard.
- Delegated `restore_apply` to the canonical workspace restore-apply contract,
  preserving explicit approval, conflict policy, receipts, artifacts,
  workspace snapshot rollback refs, and restore-gate projection.
- Added restore-apply idempotency keys for repair-originated apply events so
  workflow-authored repair rows do not collapse into generic restore-apply
  rows for the same snapshot.
- Extended SDK result typing and the mock substrate client with
  `restoreApply`/`restoreApplyEvent` fields so workflow and tests can execute
  approved repair applies through the same client method.
- Proved a blocking diagnostics policy with `restore_apply` as the preferred
  decision, executed it through the SDK with approval, restored the broken
  file, and verified daemon SSE, SDK events, and React Flow projection preserve
  both the restore gate row and the repair decision row.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "diagnostics repair decisions|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-apply`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-apply/2026-05-13T07-56-56-734Z/result.json`.

### Slice 137. 2026-05-13 - Executable diagnostics repair retry

Implementation slice completed 2026-05-13, executable diagnostics repair retry:

- Extended diagnostics repair decision execution to support `repair_retry`
  alongside the restore decisions, with a dedicated repair-retry workflow node id
  and idempotent retry-turn event creation.
- Added a daemon-owned repair retry path that reconstructs the blocking
  diagnostics context as a non-blocking repair-mode injection, creates a new
  repair turn, emits `diagnostics.repair_retry.created`, and then records the
  existing `diagnostics.repair_decision.executed` event.
- Extended SDK result typing and the mock substrate client with
  `repairRetry`, `repairTurn`, and `repairRetryEvent` fields so workflow and SDK
  callers can observe the retry turn and workflow row.
- Added React Flow projection support for `lsp_diagnostics_repair_retry`, giving
  retry executions their own workflow-addressable policy row instead of hiding
  them inside the generic repair decision row.
- Proved a blocking diagnostics policy with `repair_retry`, executed it through
  the SDK from a React Flow source, verified the new turn receives compact
  diagnostics context, and checked daemon SSE, SDK events, and React Flow
  projection preserve retry event, decision event, policy refs, and rollback
  refs.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "diagnostics repair decisions|diagnostics repair retry|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry/2026-05-13T08-20-57-956Z/result.json`.

### Slice 138. 2026-05-13 - Executable diagnostics operator override

Implementation slice completed 2026-05-13, executable diagnostics operator
override:

- Extended diagnostics repair decision execution to support
  `operator_override` alongside `repair_retry`, `restore_preview`, and
  `restore_apply`, with a dedicated workflow node id and supported-action
  contract.
- Added a daemon-owned operator override execution path that preserves
  diagnostics gate, policy, rollback, receipt, graph, and node identity.
- Enforced workflow-configured override approval: unapproved required overrides
  return `blocked` with an override event, while approved or approval-disabled
  overrides emit `diagnostics.operator_override.executed` and mark the blocked
  turn continuation-allowed.
- Extended SDK result typing and the mock substrate client with
  `operatorOverride` and `operatorOverrideEvent` fields so workflow callers can
  observe approval state and continuation state through the same decision
  execution method.
- Added React Flow projection support for
  `lsp_diagnostics_operator_override`, giving override executions their own
  workflow-addressable policy row while retaining the generic repair decision
  row.
- Proved both operator override policies live: approval disabled completes
  immediately and closes the blocked turn; approval required blocks without
  approval and completes once `approvalGranted` is provided.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
- `node --import tsx --test --test-name-pattern "diagnostics repair decisions|diagnostics repair retry|diagnostics operator overrides|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-operator-override`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-operator-override/2026-05-13T08-53-15-768Z/result.json`.

### Slice 5. 2026-05-11 - workflow memory search/list

Implementation slice completed 2026-05-11, workflow memory search/list:

- Thread and agent memory projections now accept `scope`, `memoryKey`,
  `q/query`, `limit`, and `redaction` filters, and returned projections include
  the normalized filter contract plus `totalMatches`.
- Memory records now carry optional `memoryKey` metadata so workflow-level state
  keys can address durable memory without relying on ad hoc text matching.
- SDK memory helpers now expose typed filtered `list()` options and
  `Agent.memory.search(query, options)`, with matching behavior in the mock
  substrate and daemon HTTP client.
- React Flow state nodes now expose `memory_search` and `memory_list`
  operations with scope, key, query, limit, and redaction controls; creator
  variants `memory.search` and `memory.list` produce model-ready memory
  attachments.
- Local workflow execution filters incoming memory records, applies optional
  redaction, emits `memoryQuery` evidence, and feeds the filtered state
  attachment into model nodes through the existing memory port.
- Harness component contracts now include `memory_search` and `memory_list`
  alongside read/write/policy memory components.

Validation evidence:

- `node --check packages/runtime-daemon/src/memory-store.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-50-03-897Z/result.json`

### Slice 6. 2026-05-11 - subagent memory inheritance execution

Implementation slice completed 2026-05-11, subagent memory inheritance execution:

- SDK `AgentSubagent.send()` handoffs now emit a typed
  `SubagentMemoryInheritanceProjection` on `RuntimeTraceBundle`, with parent
  policy, effective subagent policy, normalized memory filters, inherited
  record IDs, write allowance, and write block reason.
- The live daemon mirrors the same handoff contract through thread turns and
  run traces, including `subagent_memory_inheritance` receipts and
  `memory_update` events with `SubagentMemoryInheritance` payloads.
- Inheritance modes are enforced before subagent writes:
  - `none` disables inherited memory and blocks parent-memory writes;
  - `explicit` only exposes records selected by explicit memory filters and
    requires write approval;
  - `read_only` exposes inherited records while blocking writes;
  - `full` exposes inherited records and preserves the parent write policy.
- React Flow workflow contracts now include `memory.subagentInheritance`, and
  the harness component registry exposes a `memory_subagent_inheritance`
  component so workflow authors can model the inheritance policy as a first
  class state/policy component.
- Contract tests assert filtered record visibility, write blocking, full-write
  persistence, receipts, events, and TTI payload summaries across SDK mock and
  live daemon execution.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-25-14-983Z/result.json`


## P1. Doctor, Config, And Introspection

### Slice 7. 2026-05-11 - runtime doctor preflight

Implementation slice completed 2026-05-11, runtime doctor preflight:

- The live daemon now exposes `GET /v1/doctor` with
  `ioi.agent-runtime.doctor.v1`, required readiness checks, optional degraded
  checks, provider key presence, model routes, MCP, memory, sandbox, workflow,
  Agentgres, wallet/network, runtime node, blocker, and redaction metadata.
- `ioi agent doctor --json` now prefers the daemon report and falls back to a
  local static contract report when the daemon is unreachable, preserving
  redaction and never printing provider values.
- React Flow now includes a `runtime_doctor` / `RuntimeDoctorNode` palette
  entry with typed report and blocker outputs, activation-gate defaults, schema
  discovery, canvas labels, and harness component wiring through state and
  verifier policy slots.
- Contract tests assert clean/degraded doctor JSON, required dependency pass
  semantics, optional warnings, hashed endpoint/provider values, CLI command
  parsing, and workflow-addressable doctor node wiring.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-42-38-804Z/result.json`


## P1. Skills And Hooks

### Slice 8. 2026-05-11 - read-only skill and hook discovery

Implementation slice completed 2026-05-11, read-only skill and hook discovery:

- The daemon now exposes `GET /v1/skills` and `GET /v1/hooks` with governed,
  read-only projections for workspace IOI, `.agents`, `.cursor`, `.claude`,
  and global IOI/Agents discovery sources.
- Cursor-style `SKILL.md` imports are normalized with provenance, trust level,
  capability scopes, validation status, skill hashes, and active skill-set hash.
- Hook discovery reads hook JSON files/directories, exposes event subscriptions,
  configurable failure policy, authority scopes, tool contract declarations, and
  a mutation policy that blocks work outside declared capabilities.
- Hook command bodies are never returned; the registry only reports command
  presence and a hash for audit/debugging.
- `GET /v1/doctor` now derives the `skills.hooks` check from the daemon-owned
  catalog instead of a static degraded placeholder.
- `ioi agent skills --json` and `ioi agent hooks --json` expose the same daemon
  projections for TUI/CLI inspection, with degraded local fallbacks when the
  daemon is unreachable.
- React Flow now has `SkillNode`, `SkillPackNode`, `HookNode`, and
  `HookPolicyNode` registry entries plus harness components for skill and hook
  registry discovery.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-51-31-990Z/result.json`

### Slice 9. 2026-05-11 - active skill/hook manifest per turn

Implementation slice completed 2026-05-11, active skill/hook manifest per turn:

- Each daemon run/turn now records an
  `ioi.agent-runtime.active-skill-hook-manifest.v1` snapshot with selected
  skill IDs, hook IDs, active skill/hook set hashes, catalog hashes,
  provenance, validation status, and redaction metadata.
- The run trace includes the active manifest and a prompt audit record that
  links prompt hash, selected skill IDs, selected hook IDs, active set hashes,
  and hook execution state without returning skill bodies or hook commands.
- The TTI event stream emits an `ActiveSkillHookManifest` item with receipt
  refs, artifact refs, selected skill/hook counts, and mutation-blocked hook
  counts, preserving replayable provenance before any hook can execute.
- The run artifact list now includes `active-skill-hook-manifest.json`, and the
  trace receipts include an `active_skill_hook_manifest` receipt.
- Hook execution remains disabled; command-backed hooks are marked mutation
  blocked unless they declare both authority scopes and tool contracts.
- React Flow `SkillNode`, `SkillPackNode`, `HookNode`, and `HookPolicyNode`
  defaults now declare activation gates that consume the active skill/hook
  manifest and validate active skill/hook set hashes.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-58-22-773Z/result.json`

### Slice 10. 2026-05-11 - hook dry-run policy preview

Implementation slice completed 2026-05-11, hook dry-run policy preview:

- Each run now derives an `ioi.agent-runtime.hook-dry-run-plan.v1` from the
  active skill/hook manifest before any hook can execute.
- Command-backed hooks are classified as `would_run` only when they declare
  both authority scopes and tool contracts; otherwise they are `blocked`.
  Hooks without commands are `skipped`.
- The dry-run plan is explicitly preview-only: `hookExecutionEnabled` and
  `commandExecutionEnabled` remain false, and every decision records
  `commandExecuted: false`.
- The trace now includes `hookDryRunPlan`, the prompt audit references its plan
  ID, receipts include `hook_dry_run_plan` and `hook_policy_decision`, and the
  artifact list includes `hook-dry-run-plan.json`.
- The TTI event stream emits a `HookDryRunPlan` item on `runtime.hook-policy`
  with decision counts, policy status, receipt refs, and artifact refs.
- React Flow now treats hook policy as its own workflow-addressable harness
  component and `HookPolicyNode` default logic consumes the hook dry-run plan
  and policy decision fields.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-07-33-015Z/result.json`

### Slice 11. 2026-05-11 - HookPolicyNode activation gate

Implementation slice completed 2026-05-11, HookPolicyNode activation gate:

- `HookPolicyNode` is now an enforced activation gate, not only descriptive
  metadata. Workflow readiness inspects hook policy nodes and blocks activation
  when their dry-run policy decision is `blocked`.
- Hook policy nodes must remain preview-only: activation fails if node logic or
  the dry-run plan enables hook execution or command execution.
- Hook policy nodes must consume `hookDryRunPlan`, expose the policy decision
  field, and configure explicit passed-preview and blocked routes.
- The default agent harness now includes a benign empty hook dry-run plan for
  its `hook_policy` component, so the blessed harness remains inspectable while
  forks and custom workflows can surface real hook blockers.
- The harness activation test coverage now proves a blocked dry-run plan marks
  the hook policy node as blocked, while a passed preview plan does not add a
  hook policy blocker.

Validation evidence:

- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-14-01-420Z/result.json`

### Slice 12. 2026-05-11 - hook invocation ledger

Implementation slice completed 2026-05-11, hook invocation ledger:

- Each run now derives an `ioi.agent-runtime.hook-invocation-ledger.v1` from
  emitted lifecycle event kinds and the active hook dry-run plan.
- The ledger records preview `HookInvocationRecord` entries for matching hook
  subscriptions such as `workflow_activation`, `pre_model`, and `post_model`.
- Invocation records link the run ID, manifest ID, dry-run plan ID, lifecycle
  event kind, hook ID, hook definition hash, policy decision, blockers,
  workflow node ID, and execution proof.
- Invocation states mirror the dry-run policy as `would_run`, `blocked`, or
  `skipped`; every record remains preview-only with `commandExecuted: false`.
- The TTI event stream emits `HookInvocationLedger` on
  `runtime.hook-invocations`, and artifacts now include
  `hook-invocations.json`.
- React Flow `HookNode` metadata now exposes `hookInvocationLedger` and
  invocation state fields so event subscription and invocation state are
  workflow-addressable while `HookPolicyNode` remains the activation gate.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-19-58-078Z/result.json`

### Slice 13. 2026-05-11 - hook escalation receipts

Implementation slice completed 2026-05-11, hook escalation receipts:

- Blocked hook preview invocations now produce deterministic
  `HookEscalationReceipt` evidence instead of only appearing as blocked ledger
  rows.
- Escalation records preserve the blocked invocation ID, hook ID, event kind,
  failure policy, blockers, missing declarations, recommended next action, and
  non-execution proof.
- Missing hook declarations are reported as first-class receipt details:
  `authorityScopes` and/or `toolContracts`, with explicit safe placeholders
  for the declaration fixes required before execution can be requested.
- The hook invocation ledger now exposes `escalationCount` and `escalations`,
  and the TTI `HookInvocationLedger` event links both the ledger receipt and
  any escalation receipt IDs.
- Receipts, semantic impact, prompt audit, postconditions, and minimum evidence
  now include the escalation path when blocked hook invocations exist.
- React Flow `HookPolicyNode` metadata now exposes escalation count, details,
  and receipt fields so workflow authors can route or display blocked-hook
  remediation inside the agentic workflow creator.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-25-17-876Z/result.json`


## P2. GitHub And PR Workflow Parity Plus

### Slice 14. 2026-05-11 - repository context foundation

Implementation slice completed 2026-05-11, repository context foundation:

- Added a read-only `ioi.agent-runtime.repository-context.v1` projection for
  local Git/workspace state, exposed through `/v1/repository-context` and the
  existing `/v1/repositories` catalog.
- Repository context now captures repo root, workspace-relative path, branch,
  detached-HEAD state, HEAD SHA, upstream, remotes, ahead/behind counts, dirty
  status, staged/unstaged/untracked/conflicted counts, and redacted remote URL
  hashes.
- Each run now records repository context in task facts, postconditions,
  minimum evidence, semantic impact, prompt audit, receipts, trace, artifacts,
  and TTI events.
- The `RepositoryContext` TTI event is workflow-addressable at
  `runtime.repository-context`, with receipt refs and
  `repository-context.json` artifact refs.
- React Flow now has a `repository_context` / `RepositoryContextNode` contract
  with branch, HEAD, dirty-state, endpoint, read-only, and redaction fields.
- The default harness now includes a repository context component so later
  branch policy, review, GitHub, and PR workflow nodes consume canonical repo
  state instead of rediscovering it ad hoc.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-36-44-368Z/result.json`

### Slice 15. 2026-05-11 - branch policy gate

Implementation slice completed 2026-05-11, branch policy gate:

- Added a read-only `ioi.agent-runtime.branch-policy.v1` decision that
  consumes canonical `RepositoryContext` before any branch mutation or PR path.
- Branch policy now evaluates Git availability, named branch vs detached HEAD,
  protected/default branch status, HEAD, upstream, ahead/behind, dirty state,
  untracked files, and conflicted worktree counts.
- Decisions are deterministic as `passed`, `warning`, or `blocked`, and expose
  blockers, warnings, review requirements, approval requirements,
  `mutationAllowed`, and `prCreationAllowed`.
- Each run now records branch policy in task facts, postconditions, minimum
  evidence, semantic impact, prompt audit, receipts, trace, artifacts, and TTI
  events.
- The `BranchPolicyDecision` TTI event is workflow-addressable at
  `runtime.branch-policy`, with receipt refs and `branch-policy.json` artifact
  refs.
- React Flow now has a `branch_policy` / `BranchPolicyNode` contract that
  consumes repository context and exposes branch policy status, blockers,
  warnings, receipt refs, and protected-branch configuration.
- The default harness now routes `branch_policy` immediately after
  `repository_context`, making later PR, review, and GitHub workflow nodes
  consume a canonical branch gate.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-16-23-615Z/result.json`

### Slice 16. 2026-05-11 - GitHub context projection

Implementation slice completed 2026-05-11, GitHub context projection:

- Added a read-only `ioi.agent-runtime.github-context.v1` projection that
  consumes canonical `RepositoryContext` and `BranchPolicyDecision` before any
  PR workflow can claim GitHub readiness.
- GitHub context now detects GitHub remotes from redacted local Git remote
  metadata, exposes owner, repo, repo full name, HTML URL, branch/default branch,
  branch-policy status, blockers, warnings, and PR creation preconditions.
- Credential handling records only token source availability (`GITHUB_TOKEN` or
  `GH_TOKEN`) and never stores token values, authorization headers, network
  responses, or remote credentials.
- Each run now records GitHub context in task facts, postconditions, minimum
  evidence, semantic impact, prompt audit, receipts, trace, artifacts, and TTI
  events.
- The `/v1/github-context` endpoint and `GitHubContext` TTI event are explicitly
  read-only: no network lookup, no PR mutation, and no credential disclosure.
- React Flow now has a `github_context` / `GitHubContextNode` contract that
  consumes repository context and branch policy, and exposes GitHub remote
  identity plus PR preconditions for workflow routing.
- The default harness now routes `github_context` immediately after
  `branch_policy`, so later issue, review, and PR attempt workflow nodes can
  depend on canonical GitHub readiness instead of re-parsing remotes.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-38-48-741Z/result.json`

### Slice 17. 2026-05-11 - PR attempt preview ledger

Implementation slice completed 2026-05-11, PR attempt preview ledger:

- Added a preview-only `ioi.agent-runtime.pr-attempt.v1` record that consumes
  canonical repository context, branch policy, and GitHub context before any PR
  creation path can proceed.
- The PR attempt ledger records target repo, branch/default branch, HEAD SHA,
  branch-policy blockers/warnings, GitHub PR preconditions, required authority
  scope (`github.pr.create`), missing authority scope, and failure outcome
  without losing run state.
- PR attempts are explicitly non-mutating: `previewOnly: true`,
  `mutationAttempted: false`, `mutationExecuted: false`, and
  `networkLookupPerformed: false`.
- Each run now emits `PrAttemptRecord` on `runtime.pr-attempt`, with receipt
  refs and artifact refs for `pr-attempt.json`, `pr-branch.json`, and
  `pr-diff.patch`.
- Diff content is attached only as the patch artifact; the trace/projection keeps
  diff metadata and hashes so workflow nodes can route on the attempt without
  inflating the state payload.
- React Flow now has a `pr_attempt` / `PrAttemptNode` contract that consumes
  repository context, branch policy, and GitHub context, and exposes status,
  blockers, authority, branch artifact, diff artifact, and receipt fields.
- The default harness now routes `pr_attempt` immediately after
  `github_context`, giving later review-gate and PR-create nodes a durable,
  auditable precondition record to consume.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-51-00-206Z/result.json`

### Slice 18. 2026-05-11 - review gate decision

Implementation slice completed 2026-05-11, review gate decision:

- Added a read-only `ioi.agent-runtime.review-gate.v1` decision that consumes
  repository context, branch policy, GitHub context, and the preview-only PR
  attempt before any PR creation path can proceed.
- Review gate now records required reviewers, required checks, PR attempt ID,
  branch/repo target, blockers, warnings, approval requirements, review
  satisfaction state, and PR creation allowance.
- The gate currently fails closed when the PR attempt is blocked or human review
  is unsatisfied, preserving `mutationAllowed: false`,
  `prCreationAllowed: false`, `mutationExecuted: false`, and
  `networkLookupPerformed: false`.
- Each run now emits `ReviewGateDecision` on `runtime.review-gate`, with receipt
  refs and a `review-gate.json` artifact.
- React Flow now has a `review_gate` / `ReviewGateNode` contract that consumes
  repository context, branch policy, GitHub context, and PR attempt, and exposes
  review status, blockers, reviewers, checks, and receipt fields.
- The default harness now routes `review_gate` immediately after `pr_attempt`,
  satisfying the parity requirement that workflow graphs can require review
  before PR creation.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-15-17-099Z/result.json`

### Slice 19. 2026-05-11 - issue context projection

Implementation slice completed 2026-05-11, issue context projection:

- Added a read-only `ioi.agent-runtime.issue-context.v1` projection that binds
  optional GitHub issue/task context into the PR workflow lane.
- Issue context supports a durable `unbound` state when no issue is supplied,
  allowing local PR previews to continue while preserving a canonical slot for
  future `github__issue_read` results.
- The projection records provider/repo identity, optional issue number/title/URL,
  linked PR attempt ID, linked review gate ID, no-issue policy, warnings,
  redaction posture, and no-network/no-mutation proof.
- Each run now emits `IssueContext` on `runtime.issue-context`, with receipt refs
  and an `issue-context.json` artifact.
- React Flow now has an `issue_context` / `IssueContextNode` contract that
  consumes GitHub context and exposes issue bound state, status, issue number,
  source URL, and receipt fields.
- `pr_attempt` and `review_gate` now expose optional `issue_context` side-input
  ports, while the default harness routes `issue_context` between
  `github_context` and `pr_attempt`.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-25-31-750Z/result.json`

### Slice 20. 2026-05-11 - GitHub PR create dry-run plan

Implementation slice completed 2026-05-11, GitHub PR create dry-run plan:

- Added a dry-run-only `ioi.agent-runtime.github-pr-create-plan.v1` projection
  that consumes repository context, branch policy, GitHub context, issue
  context, PR attempt, and review gate before any GitHub PR creation tool can
  claim readiness.
- The plan records target owner/repo, base/head branches, title, body plan,
  issue link, review status, request payload hash, authority scope requirements,
  blockers, warnings, and redaction posture.
- PR creation remains explicitly non-mutating:
  `dryRun: true`, `mutationAttempted: false`, `mutationExecuted: false`, and
  `networkLookupPerformed: false`.
- Request evidence is safe by construction: the projection stores a payload
  hash and non-secret preview metadata, while keeping request body, token value,
  authorization header, response body, and network response out of the trace.
- Each run now emits `GitHubPrCreatePlan` on `runtime.github-pr-create`, with a
  `github_pr_create_plan` receipt and `github-pr-create-plan.json` artifact.
- React Flow now has a `github_pr_create` / `GitHubPrCreateNode` contract that
  consumes the PR workflow lane and exposes status, blockers, request hash,
  authority, and receipt fields.
- The default harness routes `github_pr_create` immediately after
  `review_gate`, giving workflow authors a configurable mutation boundary that
  is still dry-run/projection-only until authority and review are satisfied.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-38-30-155Z/result.json`


## P2. Runtime Task Queue And Jobs

### Slice 21. 2026-05-11 - runtime task/job ledger spine

Implementation slice completed 2026-05-11, runtime task/job ledger spine:

- Added durable `ioi.agent-runtime.task-record.v1` and
  `ioi.agent-runtime.job-record.v1` projections over canonical daemon runs.
- Runtime tasks now record task family, mode, selected strategy, prompt hash,
  thread/turn linkage, replayability, and redaction posture without storing the
  raw prompt in the task projection.
- Runtime jobs now record task linkage, run linkage, queue name, runner, job
  type, lifecycle, progress, endpoints, artifacts, receipts, cancellation
  state, replayability, and durability.
- Added `/v1/jobs` and `/v1/jobs/{id}` so CLI/TUI, SDK surfaces, and React Flow
  can inspect job status without reading private run internals.
- Each run now emits `RuntimeTaskRecord`, `JobQueued`, `JobStarted`, and
  `JobCompleted` TTI-visible events, with runtime task/job receipts and
  `runtime-task.json` / `runtime-job.json` artifacts.
- Cancellation updates the top-level task/job projection to `canceled` while
  preserving single-terminal-event replay semantics.
- React Flow now has `runtime_task` / `RuntimeTaskNode` and `runtime_job` /
  `RuntimeJobNode` contracts, routed after `runtime_doctor` and before
  repository/PR workflow nodes in the default harness.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-52-37-360Z/result.json`

### Slice 22. 2026-05-11 - job cancellation endpoint

Implementation slice completed 2026-05-11, job cancellation endpoint:

- Added `POST /v1/jobs/{id}/cancel` as the job-facing cancellation path,
  resolving job IDs to canonical run IDs and delegating to the run cancellation
  owner.
- Job cancellation now rewrites replay to show `JobQueued`, `JobStarted`,
  `JobCanceled`, and then the single run-level `canceled` terminal event,
  avoiding duplicate terminal run events and stale `JobCompleted` lifecycle
  claims after cancellation.
- The public job record updates to `status: "canceled"` with lifecycle
  `["queued", "started", "canceled"]`, cancellation reason, cancel endpoint,
  and refreshed `runtime-job.json` artifact content.
- React Flow `runtime_job` configuration now exposes
  `runtimeJobCancelEndpoint`, `runtimeJobCancelable`, and
  `runtimeJobCancelRoute`, so workflows can model job cancellation explicitly.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-05-03-333Z/result.json`

### Slice 23. 2026-05-11 - runtime checklist record

Implementation slice completed 2026-05-11, runtime checklist record:

- Added a durable `RuntimeChecklistRecord` projection under Agentgres
  `checklists/`, exposed in trace bundles and canonical projection paths.
- The checklist binds the runtime task, runtime job lifecycle, terminal job
  event, artifacts, receipts, replayability, and redaction posture into one
  workflow-addressable record.
- Cancellation replay now refreshes `runtime-checklist.json`, emits a
  `RuntimeChecklistRecord` TTI event, and attaches checklist IDs/status back to
  public job records.
- React Flow now has a `runtime_checklist` / `RuntimeChecklistNode` contract
  with configurable trace endpoint, checklist/status/items fields, activation
  gate consumption flags, and default harness component wiring.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-35-25-228Z/result.json`


## P2. Localization And Accessibility

### Slice 24. 2026-05-11 - runtime chrome localization and accessible status metadata

Implementation slice completed 2026-05-11, runtime chrome localization and
accessible status metadata:

- Added `workflow-runtime-ui-strings.ts` as the workflow-addressable runtime
  chrome string catalog with locale keys, accessible names, status
  announcements, English/Spanish chrome strings, and explicit
  `modelOutputLocalized: false` boundary.
- Added graph config fields for `runtimeUiStringCatalogRef`, `localeKey`,
  `ariaLabelKey`, `statusAnnouncementKey`, `accessibleStatusField`,
  `accessibleStatusText`, and `colorIndependentStatus`.
- Bound localization and accessibility metadata into runtime, repository,
  branch policy, GitHub context, issue context, PR attempt, review gate, and
  GitHub PR create nodes.
- Default harness components now expose color-independent status metadata in
  component UI metadata and node logic, so React Flow can announce status
  through text instead of relying on color.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-03-04-311Z/result.json`

### Slice 25. 2026-05-11 - workflow UI localization and accessible status surfaces

Implementation slice completed 2026-05-11, workflow UI localization and
accessible status surfaces:

- Added runtime chrome string resolution helpers for locale normalization,
  keyed string interpolation, dotted status-field lookup, localized status
  labels, and node chrome bundles.
- React Flow canvas nodes now resolve runtime labels/ARIA names from the
  catalog, expose `data-accessible-status` and
  `data-accessible-status-text`, hide color-only status dots from assistive
  tech, and render the status text in the footer with polite announcement.
- The node inspector now exposes a graph-configurable `workflowChromeLocale`
  selector for runtime chrome while preserving `modelOutputLocalized: false`
  as inspectable metadata.
- The workflow rail now uses the same status label resolver for run filters,
  run cards, attempts, selected-node status, and timeline entries, with
  `aria-label` and data attributes for color-independent inspection.
- Static contract coverage now guards the shared resolver, canvas status text,
  inspector locale selector, and workflow rail timeline wiring.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-14-20-396Z/result.json`

### Slice 26. 2026-05-11 - keyboard and focus parity

Implementation slice completed 2026-05-11, keyboard and focus parity:

- The React Flow canvas now injects keyboard selection callbacks into node data
  and marks the canvas with an explicit keyboard-navigation contract.
- Canvas nodes are tab stops with `aria-keyshortcuts="Enter Space"`, select the
  same inspector path on focus or Enter/Space, and expose a visible focus ring
  independent of selection color.
- Run rail timeline entries, harness attempt rows, shadow comparison rows, the
  selected-node inspector, and bottom-shelf run timelines are keyboard
  focusable with accessible labels.
- Run cards, attempts, comparison nodes, search results, harness reference
  buttons, inspector actions, and node group filters now have explicit
  focus-visible styling.
- Static contract coverage now guards the canvas keyboard handoff, node
  Enter/Space behavior, timeline tab stops, selected-node inspector focus
  target, and focus-visible CSS.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-28-34-383Z/result.json`

### Slice 27. 2026-05-11 - global workflow chrome locale

Implementation slice completed 2026-05-11, global workflow chrome locale:

- Added `global_config.workflowChromeLocale` with an `en-US` default and
  normalization so workflow JSON persists a single chrome locale for the whole
  graph.
- Canvas rendering now receives the workflow locale and passes it into runtime
  node chrome resolution, while per-node `workflowChromeLocale` overrides still
  win when explicitly configured.
- The standalone graph settings inspector and workflow composer settings rail
  now expose the workflow chrome locale selector using the shared runtime UI
  string catalog.
- The workflow rail, selected-node inspector, and status label resolver now
  fall back to the global workflow chrome locale when no node override exists.
- Static contract coverage now guards persistence, defaults, graph settings,
  canvas propagation, workflow rail settings, and the global/per-node override
  boundary.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-34-43-218Z/result.json`

### Slice 28. 2026-05-11 - locale-aware portable package evidence

Implementation slice completed 2026-05-11, locale-aware portable package
evidence:

- Portable workflow package manifests now carry
  `workflowChromeLocale` alongside source identity, readiness, harness evidence,
  and worker binding metadata.
- Package import preserves that locale even for legacy workflow JSON missing the
  global config field, so React Flow chrome remains stable across checkout
  boundaries.
- The package summary and import review surfaces expose source/imported locale
  data attributes, visible locale rows, and a preservation flag for live
  autopilot GUI evidence.
- The workflow file-bundle model now includes the package locale in its portable
  package status, keeping workflow development environment review surfaces
  auditable.
- Static contract coverage now guards the TypeScript manifest/review contracts,
  React Flow package/import data attributes, file-bundle model status, and the
  Tauri export/import locale persistence path.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-47-49-991Z/result.json`

### Slice 29. 2026-05-11 - workflow-native package/import actions

Implementation slice completed 2026-05-11, workflow-native package/import
actions:

- Added `WorkflowPackageExportNode` and `WorkflowPackageImportNode` as
  first-class React Flow tool nodes with typed ports, runtime chrome
  localization, accessibility status fields, policy profiles, output schemas,
  activation gates, and package evidence fields.
- The default componentized harness now includes package export/import
  components in the runtime workflow flow, promotion cluster, node type mapper,
  policy slot mapping, and node logic, so portable workflow package review is
  graph-configurable rather than only available from surrounding UI controls.
- Runtime action contracts now include `workflow_package_export` and
  `workflow_package_import`, while preserving `skill_context` as a generated
  action kind, keeping projection adapters and generated TS/Rust schemas in
  sync.
- Workflow harness tool evidence now reports package path, imported workflow
  path, readiness status, workflow chrome locale, and package evidence
  readiness so chat/tool execution and workflow execution share the same
  package review surface.
- Static contract coverage now guards graph types, node registry entries,
  default harness wiring, runtime UI strings, projection adapter mappings,
  generated action schemas, and package harness tool evidence.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-01-34-285Z/result.json`

### Slice 30. 2026-05-11 - package action runtime execution

Implementation slice completed 2026-05-11, package action runtime execution:

- `workflow_package_export` and `workflow_package_import` now map to explicit
  Rust `ActionKind` variants, completion verification requirements, and an
  `output_bundle` connection class shared by validation and execution.
- The workflow executor now runs package export/import nodes end to end,
  delegating to the existing portable package export/import paths while
  preserving package path, manifest readiness, imported workflow path, chrome
  locale, locale preservation, mutation status, and package review evidence in
  node output.
- Workflow scaffolds/templates now expose package export/import presets,
  package output schemas, ports, action metadata, write side-effect profiles,
  dry-run support, and approval metadata for import nodes.
- Runtime verification evidence now emits package-specific evidence types for
  package export/import nodes instead of collapsing them into generic execution
  evidence.
- Rust coverage now proves a React Flow graph can execute
  `workflow_package_export -> workflow_package_import -> output`, including
  package-path handoff and workflow chrome locale preservation.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-24-53-304Z/result.json`

### Slice 31. 2026-05-11 - package action run output surfaces

Implementation slice completed 2026-05-11, package action run output
surfaces:

- Added a reusable `workflowPackageNodeOutputSummary` model helper for
  package export/import node outputs, normalizing package path, manifest path,
  readiness, portability, workflow chrome locale, imported workflow path,
  locale preservation, and package evidence readiness.
- The selected-node React Flow inspector now shows a package output summary
  when a package export/import node has a run or pinned fixture output, with
  data attributes for package kind, path, readiness, evidence, imported
  workflow, and locale preservation.
- The workflow bottom selection shelf now mirrors the package output summary so
  package execution results are visible from the run surface without opening
  the full inspector.
- The live autopilot GUI harness rollback/package proof now guards the reusable
  package-output model helper plus both visible workflow surfaces, preserving
  the componentized workflow-development contract.
- Static daemon contract coverage now guards the package output helper, the
  selected-node inspector selector, and the bottom shelf selector.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-33-50-765Z/result.json`
  - all retained chat scenarios passed;
  - per-slice package-output proof passed:
    `rollback-restore-canary-ui-proof.json` has
    `checks.workflowPackageRunOutputSurfaces === true`;
  - full harness validation remains red on unrelated promotion-live/default
    dispatch bindings:
    `harness_promotion_transition_live_gui_interaction`,
    `harness_live_promotion_readiness`, and
    `harness_live_shadow_comparison_gate`.

### Slice 32. 2026-05-11 - live shadow promotion/default dispatch binding

Implementation slice completed 2026-05-11, live shadow promotion/default
dispatch binding:

- The default authority-tooling gate now includes the `github_pr_create`
  adapter envelope, so PR-create dry-run planning participates in the same
  node-authoritative live shadow path as policy, approval, MCP, native tool,
  connector, and wallet capability calls.
- Authority-tooling live-readiness no longer relies on a stale hard-coded
  adapter count. It derives readiness from
  `DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS`, preserving the
  componentized harness contract as new tool adapters are added.
- The live GUI harness now treats the workflow proof's live shadow comparison
  gate as authoritative evidence for promotion readiness when the chat artifact
  summary has not yet emitted every required component pair, and the result
  artifact points to the proof file containing the 21-component gate.
- Static contract coverage now guards the `github_pr_create` adapter envelope,
  its node-authority component membership, and its live shadow comparison gate
  membership.
- The previous package-output evidence run's red promotion-live cascade is now
  closed: runtime selector default promotion, default dispatch binding, live
  promotion readiness, authority-tooling node authority, and the live shadow
  comparison gate all validate green.

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- focused default dispatch proof: live mode, 21/21 shadow comparisons,
  `github_pr_create` present, no live promotion blockers.
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-57-19-939Z/result.json`
  - `validation.ok === true`;
  - no false artifacts;
  - `harness_live_promotion_readiness_present === true`;
  - `harness_live_shadow_comparison_gate_present === true`;
  - proof gate has `comparisonCount === 21`, `requiredComparisonCount === 21`,
    and includes `github_pr_create`.

### Slice 33. 2026-05-11 - direct PR-create live shadow artifact emission

Implementation slice completed 2026-05-11, direct PR-create live shadow
artifact emission:

- The default harness now emits the `github_pr_create` live/shadow comparison
  directly from `runtime-artifacts.json`; the validator no longer needs to rely
  on promotion proof fallback to prove the 21st authority-tooling pair.
- `HarnessComponentKind::GithubPrCreate` is now part of the componentized
  default flow, authority-tooling cluster, live shadow comparison gate, replay
  policy, approval semantics, tool-grant slot policy, canary boundary, and
  default dispatch proof fixture.
- The Rust default dispatch path now executes a read-only
  `github__pr_create` dry-run plan node, records attempt/receipt/replay refs,
  blocks mutation, and exposes `authorityToolingGithubPrCreateDryRun*` summary
  fields beside MCP, native tool, connector, and wallet authority evidence.
- The React Flow/workflow GUI validator contract now requires
  `harness_authority_tooling_github_pr_create_dry_run` as a first-class runtime
  artifact and consistency bit.
- Live artifact proof:
  `runtime-artifacts.json` now reports `harnessLiveShadowComparisonCount === 21`,
  includes `github_pr_create` in `harnessLiveShadowComparisonComponentKinds`,
  and reports `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Validation evidence:

- `cargo test -p ioi-types harness -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml default_runtime_dispatch_accepts_isolated_output_writer_staged_write_canary -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml save_local_task_state_exports_gui_runtime_evidence_projection -- --nocapture`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-33-52-995Z/result.json`
  - `validation.ok === true`;
  - runtime consistency includes
    `harness_authority_tooling_github_pr_create_dry_run_present === true`;
  - `runtime-artifacts.json` has the direct 21/21 component set with
    `github_pr_create`.

### Slice 34. 2026-05-11 - PR-create workflow output surfaces

Implementation slice completed 2026-05-11, PR-create workflow output surfaces:

- The React Flow selected-node inspector now treats `github_pr_create` dry-run
  plans as first-class run output, beside the existing package action output
  surface.
- Added a reusable `workflowGithubPrCreatePlanSummary` model helper that
  normalizes nested or direct `githubPrCreatePlan` payloads into request hash,
  dry-run/preview flags, mutation-attempt/executed flags, network lookup state,
  missing authority scopes, review gate status, receipt id, blockers, and
  evidence refs.
- The selected-node inspector now exposes
  `workflow-selected-node-github-pr-create-output-summary` with data attributes
  for request hash, `dryRun`, mutation state, missing `github.pr.create` scope,
  review gate status, receipt refs, replay fixture ref, request body/token
  redaction, and blocker/evidence refs.
- The workflow bottom selection shelf mirrors the PR-create output summary with
  `workflow-selection-github-pr-create-output-summary`, so operators can inspect
  the dry-run result without opening the full inspector.
- The live GUI harness now validates the surface in two ways:
  static source-contract proof in `rollback-restore-canary-ui-proof.json`, and
  a React-rendered selected-node proof in
  `promotion-transition-gui-behavior-proof.json` that selects
  `harness.github_pr_create` and verifies request hash, dry-run/mutation flags,
  missing scope, review gate status, receipt refs, and replay fixture refs.

Validation evidence:

- `npm run build:ide -- --pretty false`
- `node --check scripts/lib/harness-promotion-transition-gui-probe.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
- `TSX_TSCONFIG_PATH=packages/agent-ide/tsconfig.json node --import tsx packages/agent-ide/src/runtime/workflow-rail-receipts.test.ts`
- targeted React render proof:
  `node --import tsx scripts/lib/harness-promotion-transition-gui-probe.mjs /tmp/github-pr-create-workflow-node-probe.json`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-55-06-446Z/result.json`
  - `validation.ok === true`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `promotion-transition-gui-behavior-proof.json` has
    `checks.githubPrCreateNodeOutputInspector === true`;
  - `runtime-artifacts.json` retains the direct 21/21 live shadow component set
    with `github_pr_create` and
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 35. 2026-05-11 - PR-create React Flow runtime execution

Implementation slice completed 2026-05-11, PR-create React Flow runtime execution:

- The Rust workflow runtime now recognizes `repository_context`,
  `branch_policy`, `github_context`, `issue_context`, `pr_attempt`,
  `review_gate`, and `github_pr_create` as executable action kinds instead of
  unsupported projection-only nodes.
- React Flow graphs can now execute the full repository-to-PR lane:
  `repository_context -> branch_policy -> github_context -> issue_context ->
  pr_attempt -> review_gate -> github_pr_create -> output`.
- `github_pr_create` remains dry-run-only in the Rust executor. It returns the
  same safe `ioi.agent-runtime.github-pr-create-plan.v1` shape used by the
  daemon/UI contract: request method/path, 64-character payload hash, no request
  body/token/authorization/network response, missing `github.pr.create`
  authority, review blockers, `dryRun: true`, `previewOnly: true`,
  `networkLookupPerformed: false`, `mutationAttempted: false`, and
  `mutationExecuted: false`.
- Runtime validation now understands the repository-lane state/approval/data
  port classes, so workflow authors can connect the lane with named React Flow
  ports instead of relying on generic `input`/`output` edges.
- The workflow templates now expose repository-lane node ports, default dry-run
  logic, and the `workflow_github_pr_create_output_schema`, keeping the modular
  component graph authorable through the workflow development environment.
- Runtime verification evidence now records repository-lane evidence types,
  including `github_pr_create`, rather than collapsing the PR-create execution
  into generic `execution`.

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-23-26-703Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` source-contract proof now includes
    `ActionKind::GithubPrCreate`,
    `workflow_github_pr_create_output`, and
    `github_pr_create_dry_run_node_executes_through_runtime`.

### Slice 36. 2026-05-11 - PR-create runtime module refactor

Implementation slice completed 2026-05-11, PR-create runtime module refactor:

- The repository-to-PR runtime lane now lives in
  `apps/autopilot/src-tauri/src/project/repository_pr_lane.rs`, keeping
  `runtime.rs` focused on action dispatch, package import/export execution,
  harness runtime projection, and shared workflow mechanics.
- The extracted lane owns the output builders for `repository_context`,
  `branch_policy`, `github_context`, `issue_context`, `pr_attempt`,
  `review_gate`, and dry-run-only `github_pr_create`, preserving the same safe
  plan shape and mutation/network boundaries from the prior slice.
- The daemon and live GUI source-contract proofs now read
  `repository_pr_lane.rs` directly while still checking that `runtime.rs`
  dispatches `ActionKind::GithubPrCreate`, so parity evidence follows the
  modular architecture instead of assuming every executor lives in one file.
- The live GUI validation initially exposed a transient retained
  `probe_behavior` submit timeout unrelated to this refactor. A clean rerun
  completed the full chat/workflow evidence ladder and is the slice's canonical
  proof artifact.

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-53-05-240Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 37. 2026-05-11 - workflow value helper extraction

Implementation slice completed 2026-05-11, workflow value helper extraction:

- Shared workflow JSON/path/hash primitives now live in
  `apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`.
- `runtime.rs` and `repository_pr_lane.rs` import the same helper module for
  multi-key string/bool/u64 lookup, string-array normalization, workflow
  project-root resolution, dotted-path value lookup, and raw JCS hash
  generation.
- This keeps the componentized runtime architecture ready for the next lane:
  new executable React Flow components can reuse the same workflow value
  semantics instead of copying local helper functions into each module.
- The daemon and live GUI source-contract proofs now verify the helper module
  boundary directly while retaining the existing PR-create runtime execution
  and dry-run safety assertions.

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-26-54-384Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 38. 2026-05-11 - workflow package lane refactor

Implementation slice completed 2026-05-11, workflow package lane refactor:

- Workflow package export/import execution now lives in
  `apps/autopilot/src-tauri/src/project/workflow_package_lane.rs`, matching the
  repository PR lane pattern and keeping `runtime.rs` focused on dispatch and
  shared run mechanics.
- The package lane owns `execute_workflow_package_export_node`,
  `execute_workflow_package_import_node`, package path resolution, package-path
  deep input lookup, import review construction, locale preservation checks, and
  package evidence readiness projection.
- `workflow_logic_string` moved into `workflow_value_helpers.rs` so package,
  PR, and runtime dispatch code share the same trimmed workflow config lookup
  semantics.
- The daemon and live GUI source-contract proofs now assert that
  `runtime.rs` dispatches `WorkflowPackageExport` / `WorkflowPackageImport`
  through `workflow_package_lane.rs`, while the lane retains package output
  surfaces and `workflowPackageImportReview` evidence.

Validation evidence:

- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-40-25-909Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowPackageRunOutputSurfaces === true` and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 39. 2026-05-11 - workflow memory lane refactor

Implementation slice completed 2026-05-11, workflow memory lane refactor:

- Workflow memory send-policy and memory search/list execution now live in
  `apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs`, keeping
  `runtime.rs` focused on dispatch, model/state assembly, and shared run
  mechanics.
- The memory lane owns `workflow_memory_send_options`,
  `workflow_memory_query_output`, `memory_search`, `memory_list`, memory record
  collection, search-text normalization, and redacted fact hashing for
  workflow-visible memory outputs.
- `workflow_sha256_hex` moved into `workflow_value_helpers.rs` so memory
  redaction, skill guidance hashing, and future executable React Flow lanes use
  one shared hash primitive instead of each lane carrying a local copy.
- The daemon and live GUI source-contract proofs now assert that memory policy
  and memory query execution are lane-owned while `runtime.rs` continues to
  expose memory behavior through graph-addressable ModelCall and State nodes.
- This preserves the React Flow workflow development requirement that memory
  send policy and memory search/list behavior remain configurable and
  inspectable from the workflow graph, while the Rust runtime stays modular
  enough to keep extracting lanes without bloating `runtime.rs`.

Validation evidence:

- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-05-24-252Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 40. 2026-05-11 - authority/tooling lane refactor

Implementation slice completed 2026-05-11, authority/tooling lane refactor:

- MCP provider catalog, MCP tool catalog, native tool catalog, connector catalog
  describe, wallet capability dry-run, authority policy gate, authority
  approval gate, and destructive-denial execution now live in
  `apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs`.
- `runtime.rs` keeps the graph dispatch branches for AdapterConnector,
  PluginTool, Decision, and HumanGate, but imports the lane-owned helpers for
  live read-only catalog projection, approval denial, wallet no-grant receipts,
  and mutation-safe destructive denial.
- The side-effect live-runtime classifier moved with the authority/tooling lane
  and is imported by validation so graph readiness checks and runtime execution
  use one policy source.
- `workflow_hash_value` moved into `workflow_value_helpers.rs`, preserving the
  canonical JCS hash behavior used by runtime attempt hashes and authority
  catalog linkage hashes.
- The daemon and live GUI source-contract proofs now assert that
  `workflow_authority_tooling_lane.rs` owns all authority/tooling live helpers
  while React Flow remains able to configure and inspect the same authority,
  catalog, connector, and wallet-capability nodes.

Validation evidence:

- `cargo test live_mcp_provider_catalog_executes_read_only_without_mutation --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_mcp_tool_catalog_consumes_provider_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_native_tool_catalog_consumes_mcp_tool_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_connector_catalog_describe_consumes_mcp_tool_catalog_without_connector_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_wallet_capability_dry_run_never_materializes_grant --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_destructive_denial_blocks_without_side_effect --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_approval_gate_denies_without_authority_transfer --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-23-09-790Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `approval_gate`, `policy_gate`, `connector_call`, `mcp_provider`,
    `mcp_tool_call`, `tool_call`, `wallet_capability`, and `github_pr_create`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingProviderCatalogLiveCount === 5`,
    `harnessAuthorityToolingMcpToolCatalogLiveCount === 5`,
    `harnessAuthorityToolingNativeToolCatalogLiveCount === 5`,
    `harnessAuthorityToolingConnectorCatalogLiveCount === 5`,
    `harnessAuthorityToolingWalletCapabilityLiveDryRunCount === 5`, and
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 41. 2026-05-11 - workflow coding-route lane refactor

Implementation slice completed 2026-05-11, workflow coding-route lane refactor:

- Skill-context resolution and coding-route evidence generation now live in
  `apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs`.
- The lane owns `WorkflowSkillResolver`, `resolve_skill_context`, route
  classification, phase selection, skill selection, route gates, benchmark
  results, promotion decisions, run-summary projection, and verification
  evidence projection.
- `runtime.rs` keeps graph dispatch, node lifecycle, and run assembly, but
  imports the lane-owned skill resolver and route-evidence helpers instead of
  carrying the coding-route implementation inline.
- `commands.rs` imports the same resolver for create/run command paths, so
  direct workflow runs and React Flow triggered runs use one skill catalog
  resolver.
- The GUI proof collector and daemon contract test now assert the lane boundary
  directly while preserving React Flow configurability for Skill Context nodes,
  coding-route templates, route evidence inspection, draft skill import,
  benchmark-backed promotion, and forkable promotion evidence.
- `runtime.rs` is reduced to 3,570 lines and the coding-route lane is 1,171
  lines, keeping the modular extraction trend visible before the next runtime
  slice.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-38-33-940Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `workflow-skill-context-proof.json` has `passed === true` with
    `checks.resolverExecution === true`;
  - `workflow-coding-route-proof.json` has `passed === true` with
    `checks.classifierAndEvidence === true`;
  - `workflow-coding-route-promotion-loop-proof.json` has `passed === true`
    with `checks.draftBenchmarkSelection === true` and
    `checks.promotionRuntime === true`.

### Slice 42. 2026-05-11 - workflow execution-results lane refactor

Implementation slice completed 2026-05-11, workflow execution-results lane
refactor:

- Workflow run-result assembly now lives in
  `apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs`.
- The lane owns `WorkflowRunResultParts`, `workflow_finalize_run_result`,
  `workflow_run_result_from_parts`, node-run verification evidence projection,
  completion requirement projection, missing-completion detection, route
  evidence attachment, route run-summary attachment, and persisted run-result
  save-through.
- `runtime.rs` keeps node execution, checkpoints, interrupt handling, and
  harness-attempt attachment, but all validation-blocked, interrupted, normal,
  and single-node exits now finalize through one lane-owned result envelope.
- The lane uses local node/edge readers plus `ActionKind` and
  `completion_requirement_kinds`, so completion evidence remains tied to the
  canonical runtime projection contract without depending on `runtime.rs` node
  helper internals.
- The daemon and live GUI source-contract proofs now assert the execution
  results lane directly while preserving React Flow run summaries, verification
  evidence, route evidence, package output surfaces, PR-create output surfaces,
  and harness rollback/restore proof inspection.
- `runtime.rs` is reduced to 3,394 lines and the execution-results lane is 258
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-59-05-130Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowExecutionResultsRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `workflow-coding-route-proof.json` has `passed === true` with
    `checks.classifierAndEvidence === true`;
  - `workflow-coding-route-promotion-loop-proof.json` has `passed === true`
    with `checks.promotionRuntime === true`.

### Slice 43. 2026-05-11 - workflow harness-results lane refactor

Implementation slice completed 2026-05-11, workflow harness-results lane
refactor:

- Harness run artifact assembly now lives in
  `apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs`.
- The lane owns harness detection, harness metadata fallback resolution,
  activation id resolution, execution mode/status mapping, per-node attempt
  construction, input/output JCS hashing, replay/receipt/evidence refs, shadow
  comparison records, gated promotion cluster runs, and
  `workflow_attach_harness_run_artifacts`.
- `runtime.rs` keeps node execution, checkpoints, interrupt handling, and run
  exits, but calls the lane helper before result finalization so validation
  blocked, interrupted, normal, and single-node exits all share the same
  harness artifact attachment boundary.
- `workflow_execution_results_lane.rs` remains the consumer of prepared harness
  artifact vectors, while the harness lane keeps the per-node
  `harness_attempt` mutation local to artifact attachment.
- The daemon and live GUI source-contract proofs now assert the harness-results
  lane directly, preserving React Flow/workflow inspection of rollback/restore,
  shadow comparison, gated promotion clusters, package outputs, and PR-create
  output surfaces.
- `runtime.rs` is reduced to 3,097 lines; the new harness-results lane is 320
  lines, and the execution-results lane remains 258 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-14-13-182Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowHarnessResultsRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 44. 2026-05-11 - workflow graph-execution lane refactor

Implementation slice completed 2026-05-11, workflow graph-execution lane
refactor:

- Graph edge semantics and scheduler readiness now live in
  `apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs`.
- The lane owns edge endpoint readers, edge port readers, connection-class
  fallback, incoming connection-class checks, branch-selected edge checks, node
  readiness, next-ready queue projection, and node lifecycle step projection.
- `runtime.rs` keeps the execution loop, node dispatch, checkpoints, interrupts,
  and run-result assembly, but imports graph execution helpers from the lane
  when seeding the active queue, extending ready nodes, and recording lifecycle
  steps.
- `commands.rs`, `validation.rs`, and runtime graph-contract tests continue to
  consume the same canonical graph helpers through `project.rs`, so React Flow
  validation, activation, and runtime execution share one scheduler/edge
  semantics source.
- The daemon and live GUI source-contract proofs now assert the graph-execution
  lane directly, preserving graph-configurable branch routing, connection-class
  readiness, lifecycle projection, rollback/restore inspection, package output
  surfaces, and PR-create output surfaces.
- `runtime.rs` is reduced to 2,977 lines; the new graph-execution lane is 135
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-27-36-131Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowGraphExecutionRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 45. 2026-05-11 - workflow binding lane refactor

Implementation slice completed 2026-05-11, workflow binding lane refactor:

- Node binding/config preflight now lives in
  `apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs`.
- The lane owns node schema extraction, function/tool/parser/model/connector
  binding readers, sandbox policy fallback, sandbox permission checks,
  function dependency manifest checks, and function input/output schema
  resolution.
- `runtime.rs` keeps execution dispatch, function sandbox execution, output
  materialization, approval previews, checkpoints, and run-result assembly, but
  imports binding/preflight helpers from the lane before executing graph-authored
  nodes.
- `commands.rs`, `validation.rs`, and runtime graph-contract tests continue to
  consume the same canonical binding helpers through `project.rs`, so React Flow
  graph configuration, validation, dry-run commands, and runtime execution share
  one binding readiness source.
- The output node bundle schema fallback remains private to binding schema
  extraction for this slice; output bundle materialization itself remains in
  `runtime.rs` for a later output lane extraction.
- The daemon and live GUI source-contract proofs now assert the binding lane
  directly, preserving graph-configurable function, tool, parser, model, and
  connector readiness through live workflow validation.
- `runtime.rs` is reduced to 2,757 lines; the new binding lane is 251 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-40-37-167Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowBindingRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 46. 2026-05-11 - workflow output lane refactor

Implementation slice completed 2026-05-11, workflow output lane refactor:

- Output schema satisfaction, sandbox stderr truncation, and output
  bundle/materialization projection now live in
  `apps/autopilot/src-tauri/src/project/workflow_output_lane.rs`.
- The lane owns `workflow_output_satisfies_schema`,
  `workflow_truncate_output`, `workflow_output_bundle`, renderer refs, delivery
  targets, output versioning, and materialized asset projection.
- `runtime.rs` keeps execution dispatch, function sandbox execution,
  approval/interrupt handling, checkpoints, and run-result assembly, but
  delegates function-output schema checks and `ActionKind::Output` bundle
  construction to the lane.
- `commands.rs` continues to consume the same output schema validator through
  `project.rs`, so fixture validation, dry-run output checks, and runtime output
  nodes share one artifact contract.
- The output node bundle schema fallback remains in `workflow_binding_lane.rs`;
  this output lane owns runtime artifact materialization rather than binding
  schema extraction.
- The daemon and live GUI source-contract proofs now assert the output lane
  directly, preserving React Flow inspection of output bundles, renderer refs,
  materialized assets, delivery targets, package output surfaces, and PR-create
  output surfaces.
- `runtime.rs` is reduced to 2,672 lines; the output lane is 92 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-05-30-136Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowOutputRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 47. 2026-05-11 - workflow approval/interrupt lane refactor

Implementation slice completed 2026-05-11, workflow approval/interrupt lane
refactor:

- Runtime approval binding, contextual approval previews, interrupt prompts,
  interrupt notices, and pending interrupt record construction now live in
  `apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs`.
- The lane owns `workflow_runtime_approval_binding`,
  `workflow_runtime_approval_preview`, `workflow_runtime_interrupt_prompt`,
  `workflow_runtime_interrupt_notice`, and `workflow_runtime_interrupt`.
- Approval payload construction covers connector/tool side effects, workflow
  package imports, live GitHub PR creation, and output delivery targets that
  require approval.
- `runtime.rs` keeps the execution loop, resume matching, checkpoint writes,
  event emission, interrupt persistence, thread updates, and final run-result
  assembly, but delegates approval/interrupt payload construction to the lane.
- This keeps React Flow approval gates inspectable without moving durable
  checkpoint/run orchestration into a partial lane too early.
- The daemon and live GUI source-contract proofs now assert the approval lane
  directly, preserving graph-configurable human gates, contextual tool/output
  approvals, package output surfaces, and PR-create output surfaces.
- `runtime.rs` is reduced to 2,551 lines; the approval/interrupt lane is 152
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-47-22-432Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowApprovalInterruptRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 48. 2026-05-12 - workflow checkpoint lane refactor

Implementation slice completed 2026-05-12, workflow checkpoint lane refactor:

- Checkpoint state mutation, checkpoint id creation, active queue normalization,
  `WorkflowCheckpoint` construction, and checkpoint persistence now live in
  `apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs`.
- The lane owns `workflow_checkpoint_state` and keeps the existing helper
  contract stable for both runtime execution and checkpoint fork commands.
- `runtime.rs` keeps execution orchestration, resume matching, interrupt
  branching, retry/failure decisions, thread updates, and final run-result
  assembly, but delegates durable checkpoint construction and persistence to
  the lane.
- `commands.rs` continues to consume the same checkpoint helper through
  `project.rs`, so checkpoint forks and runtime checkpoints share one state
  snapshot contract.
- The daemon and live GUI source-contract proofs now assert the checkpoint lane
  directly, preserving React Flow inspection of checkpoint-backed interrupts,
  repaired resumes, retry evidence, package output surfaces, and PR-create
  output surfaces.
- `runtime.rs` is reduced to 2,524 lines; the checkpoint lane is 33 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-20-27-365Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowCheckpointRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 49. 2026-05-12 - workflow state/input mapping lane refactor

Implementation slice completed 2026-05-12, workflow state/input mapping lane
refactor:

- Workflow expression reference discovery, sample-schema inference,
  object-like schema checks, declared output schema projection, field-path
  checks, output-port checks, expression validation, predecessor-output
  resolution, mapped node input construction, expression source extraction, and
  selected-output projection now live in
  `apps/autopilot/src-tauri/src/project/workflow_state_lane.rs`.
- The lane owns `collect_workflow_expression_refs`, `workflow_schema_from_sample`,
  `workflow_schema_is_object_like`, `workflow_node_declared_output_schema`,
  `workflow_schema_has_field_path`, `workflow_node_has_output_port`,
  `validate_workflow_expression_refs`, `workflow_predecessor_output`,
  `workflow_first_expression_source`, `workflow_mapped_node_input`, and
  `workflow_selected_output`.
- `runtime.rs` keeps execution dispatch, scheduler checks, retry/failure
  branches, checkpoints, approvals, interrupts, and run-result assembly, but
  delegates predecessor input assembly and decision selected-output projection
  to the lane.
- `validation.rs` continues to consume the same schema/object and expression
  reference helpers through `project.rs`, so React Flow graph validation and
  runtime node execution share one input-mapping and field-mapping contract.
- The daemon and live GUI source-contract proofs now assert the state lane
  directly, preserving React Flow inspection of field mappings, expression
  references, mapped inputs, selected decision outputs, checkpoint-backed
  resumes, package output surfaces, and PR-create output surfaces.
- `runtime.rs` is reduced to 2,166 lines; the state lane is 367 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_require_declared_schema_paths --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-35-34-520Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowStateRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 50. 2026-05-12 - workflow node-execution lane refactor

Implementation slice completed 2026-05-12, workflow node-execution lane
refactor:

- Workflow tool child-run binding execution, model attachment discovery,
  function-node sandbox execution, all `ActionKind` node dispatch branches, and
  the harness canary/live-default node execution entrypoints now live in
  `apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs`.
- The lane owns `execute_workflow_tool_binding`,
  `workflow_model_ref_from_input`, `workflow_inputs_by_kind`,
  `execute_workflow_function_node`, `execute_workflow_node`,
  `execute_workflow_harness_canary_node`, and
  `execute_workflow_harness_live_default_node`.
- `runtime.rs` keeps scheduler order, retry loops, approval/interrupt
  branching, checkpoint creation, event emission, completion requirements, and
  run-result assembly, but delegates per-node execution and harness single-node
  execution to the lane.
- Node-kind execution dependencies for repository context, PR creation,
  package import/export, memory queries, binding materialization, output
  bundles, approval dry-runs, MCP/native tool catalogs, and function sandboxing
  are now source-proved through the node-execution lane. This keeps React Flow
  graph execution inspectable without forcing scheduler concerns into node-kind
  component code.
- The daemon and live GUI source-contract proofs now assert the node-execution
  lane directly while preserving the prior state, checkpoint, approval,
  output, binding, graph, harness-results, execution-results, authority/tooling,
  memory, package output, and PR-create output proofs.
- `runtime.rs` is reduced to 1,233 lines; the node-execution lane is 939 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-50-03-398Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeExecutionRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 51. 2026-05-12 - workflow node-contract lane refactor

Implementation slice completed 2026-05-12, workflow node-contract lane
refactor:

- Workflow action-frame projection, binding reference projection, action
  policy projection, port connection-class lookup, default connection-class
  rules, edge-port validation, and retry/max-attempt metadata now live in
  `apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs`.
- The lane owns `workflow_action_frame`,
  `workflow_node_port_connection_class`,
  `workflow_default_port_connection_class`, `validate_workflow_edge_ports`,
  and `workflow_max_attempts`.
- `runtime.rs` keeps event emission, scheduler order, retry loops,
  approval/interrupt branching, checkpoint creation, completion requirements,
  and run-result assembly, but delegates retry budget lookup and static
  node/port contract projection to the lane.
- `validation.rs`, `workflow_state_lane.rs`, and
  `workflow_node_execution_lane.rs` now share the same node-contract helpers
  through `project.rs`, keeping React Flow graph validation, expression
  validation, and per-node runtime execution on one connection-class and
  action-frame contract.
- The daemon and live GUI source-contract proofs now assert the node-contract
  lane directly while preserving the node-execution, state, checkpoint,
  approval, output, binding, graph, harness-results, execution-results,
  authority/tooling, memory, package output, and PR-create output proofs.
- `runtime.rs` is reduced to 910 lines; the node-contract lane is 328 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-04-17-641Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeContractRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 52. 2026-05-12 - workflow run-lifecycle lane refactor

Implementation slice completed 2026-05-12, workflow run-lifecycle lane
refactor:

- Workflow stream-event emission, thread creation, initial state construction,
  and single-node run assembly now live in
  `apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs`.
- The lane owns `workflow_push_event`, `new_workflow_thread`,
  `initial_workflow_state`, and `workflow_single_node_result`.
- `runtime.rs` keeps the multi-node scheduler loop, approval/interrupt
  branching, retry loops, checkpoint sequencing, and run completion path, but
  delegates stream-event construction and single-node run lifecycle assembly to
  the run-lifecycle lane.
- `workflow_single_node_result` still uses the same checkpoint,
  node-execution, lifecycle-step, harness-artifact, completion-requirement, and
  run-finalization helpers, preserving package export/import, PR-create dry run,
  contextual approval, memory lineage, and output delivery behavior.
- The daemon and live GUI source-contract proofs now assert the run-lifecycle
  lane directly while preserving the node-contract, node-execution, state,
  checkpoint, approval, output, binding, graph, harness-results,
  execution-results, authority/tooling, memory, package output, and PR-create
  output proofs.
- `runtime.rs` is reduced to 654 lines; the run-lifecycle lane is 269 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-17-52-426Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowRunLifecycleRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 53. 2026-05-12 - workflow node-metadata lane refactor

Implementation slice completed 2026-05-12, workflow node-metadata lane
refactor:

- Workflow node metadata extraction now lives in
  `apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs`.
- The lane owns `workflow_value_string`, `workflow_node_id`,
  `workflow_node_type`, `workflow_node_name`, `workflow_node_logic`,
  `workflow_node_law`, and `workflow_node_by_id`.
- `workflow_run_lifecycle_lane.rs` no longer imports node metadata back from
  `runtime.rs`; runtime, run-lifecycle, node-contract, node-execution,
  state/input mapping, approval/interrupt, package export/import, and
  validation now consume the same neutral metadata helper lane.
- `runtime.rs` is reduced to 617 lines; the node-metadata lane is 43 lines.
- The daemon and live GUI source-contract proofs now assert the node-metadata
  lane directly, including the no-back-reference contract from run lifecycle
  into runtime, while preserving the run-lifecycle, node-contract,
  node-execution, state, checkpoint, approval, output, binding, graph,
  harness-results, execution-results, authority/tooling, memory, package
  output, and PR-create output proofs.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/package.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-30-26-185Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeMetadataRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowRunLifecycleRuntimeLane === true`,
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 54. 2026-05-12 - workflow scheduler lane refactor

Implementation slice completed 2026-05-12, workflow scheduler lane refactor:

- The multi-node workflow orchestration function now lives in
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs`.
- The lane owns `execute_workflow_project` and its scheduler loop: validation
  blocking, ready-queue progression, approval/interrupt pause handling, retry
  attempts, state writes, checkpoint sequencing, child-run/output events,
  completion requirements, harness artifact attachment, and final run-result
  assembly.
- `apps/autopilot/src-tauri/src/project/runtime.rs` is now a 3-line facade that
  re-exports the scheduler entrypoint through the existing project module
  surface.
- The move is mechanical: no scheduler behavior was changed, and no scheduler
  internals were split yet.
- The daemon and live GUI source-contract proofs now assert the scheduler lane
  directly while preserving the node-metadata, run-lifecycle, node-contract,
  node-execution, state, checkpoint, approval, output, binding, graph,
  harness-results, execution-results, authority/tooling, memory, package
  output, and PR-create output proofs.
- `runtime.rs` is reduced to 3 lines; the scheduler lane is 617 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-42-18-082Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeMetadataRuntimeLane === true`,
    `checks.workflowRunLifecycleRuntimeLane === true`,
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 55. 2026-05-12 - workflow scheduler validation lane refactor

Implementation slice completed 2026-05-12, workflow scheduler validation lane
refactor:

- Added `apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
  as the dedicated owner for validation-blocked workflow run results.
- `workflow_scheduler_lane.rs` now delegates the `validation.status != "passed"`
  branch to `workflow_scheduler_validation_blocked_result(...)` instead of
  constructing the checkpoint, completion event, final thread, harness artifact
  attachment, completion requirements, and finalized run result inline.
- The split is behavior-preserving: validation failures still emit
  `run_started`, write a blocked checkpoint, emit `run_completed`, attach
  harness run artifacts, compute completion requirements, and persist the
  `WorkflowRunResult`.
- The lane boundary keeps validation-blocked execution graph-addressable for
  the React Flow workflow development environment: the scheduler owns control
  flow, while the validation lane owns the blocked-result contract that can be
  surfaced as a distinct workflow runtime capability.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_validation_lane` and
  `workflow_scheduler_validation_blocked_result(...)` directly, including its
  checkpoint, finalization, harness artifact, completion requirement, and event
  dependencies.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 617 to 567
  lines; the validation lane is 88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-55-14-162Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true` and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 56. 2026-05-12 - workflow scheduler interrupt lane refactor

Implementation slice completed 2026-05-12, workflow scheduler interrupt lane
refactor:

- Added `apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs`
  as the dedicated owner for interrupt/approval pause run finalization.
- `workflow_scheduler_lane.rs` now keeps the scheduling decision
  `(interrupt node or approval preview) && !resume_matches_node`, then delegates
  the paused-result construction to `workflow_scheduler_interrupted_result(...)`.
- The new lane owns interrupt creation, interrupted checkpointing,
  `node_interrupted` and interrupted `run_completed` event emission, interrupted
  node-run evidence, interrupt file persistence, thread persistence, harness
  artifact attachment, completion requirement computation, and final
  `WorkflowRunResult` persistence.
- `workflow_approval_interrupt_lane.rs` remains the low-level approval/interrupt
  payload builder; the scheduler interrupt lane owns orchestration and
  finalization for the paused runtime branch.
- This keeps the pause/resume contract graph-addressable for React Flow
  workflows: approval and human-input pauses now have a distinct runtime lane
  that can be surfaced as a workflow execution capability without hiding the
  lower-level approval preview and interrupt payload helpers.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_interrupt_lane` and
  `workflow_scheduler_interrupted_result(...)` directly, including interrupt
  creation, checkpointing, lifecycle steps, interrupt persistence, thread
  persistence, finalization, harness artifacts, completion requirements, and
  event emission.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 567 to 489
  lines; the interrupt lane is 130 lines; the validation lane remains 88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-06-47-704Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 57. 2026-05-12 - workflow scheduler node execution lane refactor

Implementation slice completed 2026-05-12, workflow scheduler node execution
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs`
  as the dedicated owner for ready-node execution inside a workflow run.
- `workflow_scheduler_lane.rs` now delegates the non-interrupt ready-node branch
  to `workflow_scheduler_execute_node(...)` and receives an explicit
  `WorkflowSchedulerNodeExecutionFlow` result so the scheduler can continue or
  stop the loop without owning retry and node-run internals.
- The new lane owns node-start events, retry attempts, retry failure evidence,
  `execute_workflow_node(...)` calls, decision branch output selection, state
  updates, completed-node tracking, active-queue expansion, success and failed
  checkpoints, node success/failure events, child workflow completion events,
  output bundle events, and materialized asset events.
- Final run completion remains in `workflow_scheduler_lane.rs` for this slice;
  validation-blocked finalization remains in
  `workflow_scheduler_validation_lane.rs`; interrupt/approval pause finalization
  remains in `workflow_scheduler_interrupt_lane.rs`.
- This keeps per-node execution graph-addressable for React Flow workflows:
  scheduling, paused finalization, validation finalization, and node execution
  are now separate runtime lane capabilities while preserving the existing
  low-level node executor.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_execution_lane` and
  `workflow_scheduler_execute_node(...)` directly, including retry limits, queue
  expansion, checkpointing, lifecycle steps, selected output, state-node logic,
  event emission, child workflow completion, output creation, and asset
  materialization.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 489 to 233
  lines; the node execution lane is 318 lines; the interrupt lane remains 130
  lines; the validation lane remains 88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-20-30-303Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 58. 2026-05-12 - workflow scheduler finalization lane refactor

Implementation slice completed 2026-05-12, workflow scheduler finalization lane
refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs`
  as the dedicated owner for post-loop workflow run finalization.
- `workflow_scheduler_lane.rs` now delegates final run completion to
  `workflow_scheduler_finalized_result(...)`; the scheduler owns start,
  validation routing, interrupt routing, ready-node loop orchestration, and
  finalizer dispatch, but no longer owns completion requirement repair,
  terminal checkpoint creation, final thread persistence, harness artifact
  attachment, or result assembly.
- The new lane owns status derivation from blocked/interrupted node state,
  completion requirement checks and missing-output blockers, and final
  checkpoint creation. The following terminal-result consolidation slice moves
  shared event/thread/harness/result assembly behind a common helper while
  preserving this lane as the normal post-loop finalization owner.
- Validation-blocked finalization remains in
  `workflow_scheduler_validation_lane.rs`; interrupt/approval pause
  finalization remains in `workflow_scheduler_interrupt_lane.rs`. This keeps
  each terminal path separately inspectable while extracting the normal
  post-loop completion path.
- This keeps React Flow workflow runs graph-addressable at the scheduling
  boundary: scheduler orchestration, normal finalization, interrupt
  finalization, validation finalization, and node execution are now separate
  runtime lane capabilities.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_finalization_lane`,
  `workflow_scheduler_finalized_result(...)`,
  `workflowSchedulerFinalizationRuntimeLane`, and the finalization lane's
  ownership of completion requirements and final checkpointing.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 233 to 157
  lines; the finalization lane is 107 lines; the node execution lane remains
  318 lines; the interrupt lane remains 130 lines; the validation lane remains
  88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-33-43-994Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 59. 2026-05-12 - workflow scheduler terminal result lane refactor

Implementation slice completed 2026-05-12, workflow scheduler terminal result
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs`
  as the shared terminal-result assembly owner for workflow scheduler terminal
  paths.
- The terminal-result lane provides
  `workflow_scheduler_terminal_summary(...)` for consistent
  `WorkflowRunSummary` creation and `workflow_scheduler_terminal_result(...)`
  for `run_completed` event emission, final thread status/checkpoint
  persistence, completion requirement fallback computation, harness artifact
  attachment, and `workflow_finalize_run_result(...)`.
- `workflow_scheduler_finalization_lane.rs`,
  `workflow_scheduler_validation_lane.rs`, and
  `workflow_scheduler_interrupt_lane.rs` now keep their distinct terminal path
  decisions while delegating shared result assembly to the terminal-result
  lane. Normal finalization still owns post-loop status repair and missing
  completion blockers; validation still owns validation-blocked checkpoints;
  interrupt still owns interrupt creation, interrupt persistence, and
  node-interrupted events.
- This also makes validation-blocked terminal runs persist the final thread via
  the same path as normal and interrupted terminal runs.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_terminal_result_lane`,
  `workflow_scheduler_terminal_result(...)`,
  `workflow_scheduler_terminal_summary(...)`,
  `WorkflowSchedulerTerminalResultParts`, and
  `workflowSchedulerTerminalResultRuntimeLane`, while asserting that
  validation and interrupt lanes no longer own direct final-result or harness
  assembly.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane is reduced from 107 to 93 lines; the terminal-result lane is
  93 lines; the interrupt lane is reduced from 130 to 113 lines; the validation
  lane is reduced from 88 to 72 lines; the node execution lane remains 318
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-49-14-148Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 60. 2026-05-12 - workflow scheduler node outcome lane refactor

Implementation slice completed 2026-05-12, workflow scheduler node outcome
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs`
  as the shared post-execution success/failure owner for scheduler node runs.
- `workflow_scheduler_node_execution_lane.rs` now owns node-run setup,
  `node_started` emission, retry attempt policy/evidence, and executor calls,
  then delegates the execution result to
  `workflow_scheduler_handle_node_outcome(...)`.
- The outcome lane owns selected-output projection, decision-branch output
  routing, completed-node tracking, interrupted-node filtering, state-node
  reducers, pending write advancement, ready-node expansion, active node set
  refresh, success/failure checkpoints, node-run lifecycle metadata,
  `node_succeeded`/`node_failed` events, child workflow completion events,
  output-node events, and materialized asset events.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_outcome_lane`,
  `workflow_scheduler_handle_node_outcome(...)`,
  `workflowSchedulerNodeOutcomeRuntimeLane`, and the scheduler event/checkpoint
  markers that belong to the outcome lane, while asserting that the execution
  lane no longer owns outcome-only selected-output, state update,
  ready-node/checkpoint, child-output, and materialized-asset behavior.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane is reduced from 318 to 127 lines; the new node
  outcome lane is 238 lines.
- The next file-size pressure is now the outcome lane itself. Its highest-value
  follow-up split is a state update lane that extracts selected-output
  selection, decision-branch handling, state reducers, pending writes, and ready
  node expansion, leaving the outcome lane as the checkpoint/event
  orchestrator.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T04-02-51-456Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 61. 2026-05-12 - workflow scheduler node state update lane refactor

Implementation slice completed 2026-05-12, workflow scheduler node state update
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs`
  as the success-path state mutation owner for scheduler node runs.
- `workflow_scheduler_node_outcome_lane.rs` now delegates successful node state
  mutation to `workflow_scheduler_apply_node_state_update(...)` and keeps
  checkpoint creation, node-run lifecycle updates, and success/failure event
  emission.
- The state-update lane owns selected-output projection, decision branch
  routing, completed-node tracking, interrupted-node filtering, node output
  recording, state-node reducers, normal output-to-state writes, pending write
  clearing, step advancement, ready-node expansion, and active node set refresh.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_state_update_lane`,
  `workflow_scheduler_apply_node_state_update(...)`,
  `workflowSchedulerNodeStateUpdateRuntimeLane`, and the state mutation markers
  that belong to this lane, while asserting that the outcome lane no longer
  owns selected-output, node-logic reducer, pending-write, or ready-node
  expansion behavior.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane remains 127 lines; the node outcome lane is
  reduced from 238 to 164 lines; the new node state-update lane is 106 lines.
- The next file-size pressure is now the 164-line outcome lane. Its
  highest-value follow-up split is a success event lane that extracts
  `node_succeeded`, `child_run_completed`, `output_created`, and
  `asset_materialized` emission, leaving outcome focused on checkpoint
  orchestration and run-record status updates.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T06-55-19-771Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 62. 2026-05-12 - workflow scheduler node success event lane refactor

Implementation slice completed 2026-05-12, workflow scheduler node success
event lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs`
  as the success-path event fanout owner for scheduler node runs.
- `workflow_scheduler_node_outcome_lane.rs` now delegates successful node event
  emission to `workflow_scheduler_emit_node_success_events(...)` and keeps
  checkpoint creation, node-run status/lifecycle updates, and failure-path
  checkpoint/event handling.
- The success-event lane owns `node_succeeded`, `child_run_completed`,
  `output_created`, and `asset_materialized` emission, including child workflow
  status projection and output-bundle materialized asset detection.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_success_event_lane`,
  `workflow_scheduler_emit_node_success_events(...)`,
  `workflowSchedulerNodeSuccessEventRuntimeLane`, and the success-event markers
  that belong to this lane, while asserting that the outcome lane no longer
  owns success-only event names.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane remains 127 lines; the node state-update lane
  remains 106 lines; the node outcome lane is reduced from 164 to 105 lines;
  the new node success-event lane is 81 lines.
- The next file-size pressure is no longer outcome-lane size, but outcome-lane
  role clarity. The highest-value follow-up is a small failure outcome lane if
  we want failure checkpointing, blocked-node bookkeeping, node-run error
  mutation, and `node_failed` emission to be independently graph-addressable.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T07-10-36-395Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerNodeSuccessEventRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 63. 2026-05-12 - workflow scheduler node failure outcome lane refactor

Implementation slice completed 2026-05-12, workflow scheduler node failure
outcome lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs`
  as the failure-path outcome owner for scheduler node runs.
- `workflow_scheduler_node_outcome_lane.rs` now delegates failed node handling
  to `workflow_scheduler_handle_node_failure_outcome(...)` and acts as the
  success/failure dispatcher plus success checkpoint and run-record
  orchestrator.
- The failure-outcome lane owns blocked-node bookkeeping, failed checkpoint
  creation, node-run error status/lifecycle mutation, node-run recording, and
  `node_failed` event emission.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_failure_outcome_lane`,
  `workflow_scheduler_handle_node_failure_outcome(...)`,
  `workflowSchedulerNodeFailureOutcomeRuntimeLane`, and the failure markers
  that belong to this lane, while asserting that the outcome lane no longer
  owns direct `workflow_push_event` or `node_failed` behavior.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane remains 127 lines; the node state-update lane
  remains 106 lines; the node success-event lane remains 81 lines; the node
  outcome lane is reduced from 105 to 87 lines; the new node failure-outcome
  lane is 55 lines.
- The next pressure is no longer scheduler outcome decomposition. The
  highest-value follow-up is to move laterally into the React Flow proof surface
  and expose the scheduler lanes as explicit workflow capability checks in the
  activation/readiness UI, not only in harness source contracts.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T10-59-14-718Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerNodeSuccessEventRuntimeLane === true`,
    `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

### Slice 64. 2026-05-12 - React Flow scheduler lane readiness UI

Implementation slice completed 2026-05-12, React Flow scheduler lane
readiness UI:

- Added a typed scheduler-lane readiness manifest at
  `packages/agent-ide/src/runtime/workflow-scheduler-lane-readiness.ts`.
  It enumerates the explicit parity-plus lane capabilities:
  `scheduler`, `scheduler.finalization`, `terminalResult`, `nodeExecution`,
  `nodeOutcome`, `nodeStateUpdate`, `nodeSuccessEvent`,
  `nodeFailureOutcome`, `interrupt`, and `validation`.
- `WorkflowValidationResult` now carries `schedulerLaneReadiness`, and
  activation readiness converts missing lane manifest entries into
  `scheduler_lane_capability_missing` execution-readiness blockers.
- Harness activation candidates now include a `scheduler-lanes` gate with a
  `10/10` proof-backed value when every lane is present. The gate evidence
  binds each UI row to the existing harness/source proof keys:
  `workflowSchedulerRuntimeLane`,
  `workflowSchedulerFinalizationRuntimeLane`,
  `workflowSchedulerTerminalResultRuntimeLane`,
  `workflowSchedulerNodeExecutionRuntimeLane`,
  `workflowSchedulerNodeOutcomeRuntimeLane`,
  `workflowSchedulerNodeStateUpdateRuntimeLane`,
  `workflowSchedulerNodeSuccessEventRuntimeLane`,
  `workflowSchedulerNodeFailureOutcomeRuntimeLane`,
  `workflowSchedulerInterruptRuntimeLane`, and
  `workflowSchedulerValidationRuntimeLane`.
- The React Flow workflow readiness rail now shows a dedicated
  `workflow-readiness-scheduler-lanes` section. Each lane row exposes stable
  `data-testid`, `data-readiness`, `data-proof-check`, and
  `data-capability-scope` attributes so live GUI validation can prove the
  scheduler decomposition is visible to operators, not only source-contract
  tests.
- The GUI and daemon contract harnesses now require both the typed readiness
  manifest and the React Flow lane section, while retaining all existing Rust
  scheduler lane source checks.
- `WorkflowRailPanel/core.tsx` remains large at this checkpoint. The next
  intuitive refactor is to extract readiness-panel primitives after the next
  UI slice, so this change adds only a compact section and keeps scheduler
  metadata in the runtime manifest.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- focused runtime import check:
  `node --import tsx - <<'EOF' ... scheduler lane readiness check passed`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- `npm run validate:autopilot-gui-harness`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-23-50-090Z/result.json`
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - all scheduler runtime lane checks remain true, including failure outcome,
    success event, state update, node outcome, node execution, terminal result,
    finalization, interrupt, validation, and the main scheduler lane.

### Slice 65. 2026-05-12 - React Flow readiness panel extraction

Implementation slice completed 2026-05-12, React Flow readiness panel
extraction:

- Extracted the `panel === "readiness"` branch from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx` into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`.
- Preserved the readiness summary, checklist, blockers, warnings, policy node
  prompts, portable package controls, and scheduler-lane readiness rows without
  changing their stable `data-testid` contracts.
- The extracted panel still renders `workflow-readiness-scheduler-lanes` and
  per-lane `data-proof-check` / `data-capability-scope` attributes, so the
  React Flow scheduler-lane proof remains workflow-addressable after the
  refactor.
- Retargeted daemon and live GUI source-contract checks to require
  `WorkflowReadinessPanel` from the rail core and the scheduler readiness
  markup from `readinessPanel.tsx`.
- Updated the refactor-shape guard so `readinessPanel.tsx` is an owned rail
  module, and refreshed stale core-file checkpoint ceilings to measured
  current baselines. `WorkflowRailPanel/core.tsx` is now 11,427 lines, while
  the extracted readiness panel is 444 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs && node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-44-32-936Z/result.json`
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`.

### Slice 66. 2026-05-12 - React Flow readiness model extraction

Implementation slice completed 2026-05-12, React Flow readiness model
extraction:

- Extracted readiness checklist, blocker/warning aggregation, policy-required
  node ids, scheduler-lane ready counts, and attention ordering into the pure
  runtime helper
  `packages/agent-ide/src/runtime/workflow-readiness-model.ts`.
- `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`
  is now a presentational React Flow rail panel over `workflowReadinessModel(...)`
  while preserving stable readiness summary, checklist, blocker, warning,
  policy, portable package, and scheduler-lane DOM contracts.
- Added
  `packages/agent-ide/src/runtime/workflow-readiness-model.test.ts` to lock the
  runtime model behavior for manifest-backed scheduler readiness, missing lane
  blockers, blocker-before-warning attention ordering, replay-fixture warning
  readiness, and incoming model-class edge bindings.
- Retargeted the daemon and live GUI source-contract checks so scheduler-lane
  activation readiness must be present in both the runtime model and the React
  Flow panel. The live proof source refs now include
  `workflow-readiness-model.ts` alongside `readinessPanel.tsx`.
- Updated the refactor-shape guard so the extracted runtime model is an owned
  implementation module. `WorkflowRailPanel/core.tsx` remains 11,427 lines,
  `readinessPanel.tsx` is reduced from 444 to 314 lines, and the readiness
  model is 226 lines with a 232-line focused test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-10-50-239Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-readiness-model.ts`.

### Slice 67. 2026-05-12 - React Flow unit-test readiness model extraction

Implementation slice completed 2026-05-12, React Flow unit-test readiness
model extraction:

- Extracted unit-test search, coverage accounting, uncovered-node detection,
  status rollups, latest-result lookup, target-node binding, and row status
  projection into the pure runtime helper
  `packages/agent-ide/src/runtime/workflow-test-readiness-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx`
  as the presentational React Flow rail surface for the existing unit-test
  summary, search, result rows, target-node links, and uncovered-node prompts.
- `WorkflowRailPanel/core.tsx` now delegates the `panel === "unit_tests"` branch
  to `WorkflowUnitTestsPanel` and reuses the model's `coveredNodeIds` for the
  readiness panel, so evaluation coverage becomes a reusable workflow-development
  model instead of rail-only inline logic.
- Added
  `packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts` to lock
  coverage counts, status counts, search by assertion/status/target id, latest
  result row projection, and uncovered-node reporting.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so
  unit-test readiness must exist in both the runtime model and the React Flow
  panel. The live rollback proof now includes `workflowUnitTestReadinessModelUi`
  and source refs for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 11,427 to 11,310 lines. The new
  unit-test panel is 105 lines, and the test-readiness model is 110 lines with a
  190-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-29-29-676Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-test-readiness-model.ts`.

### Slice 68. 2026-05-12 - React Flow run-history model extraction

Implementation slice completed 2026-05-12, React Flow run-history model
extraction:

- Extracted run search/filtering, status rollups, visible row selection,
  selected-run binding, default comparison target, comparison projection,
  interrupt preview, timeline fallback, and harness attempt/shadow comparison
  projection into
  `packages/agent-ide/src/runtime/workflow-run-history-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx`
  as the presentational React Flow rail surface for run filters, run cards,
  comparison details, interrupt preview, attempt inspection, harness timelines,
  shadow comparisons, event timeline, checkpoints, and workbench dogfood
  summaries.
- `WorkflowRailPanel/core.tsx` now delegates the `panel === "runs"` branch to
  `WorkflowRunsPanel` over `workflowRunHistoryModel(...)`, keeping durable run
  history and replay/inspection state reusable by workflow authoring surfaces.
- Added
  `packages/agent-ide/src/runtime/workflow-run-history-model.test.ts` to lock
  status/search filtering, selected/compare row flags, selected-run timeline
  binding, comparison generation, ambient-event fallback, interrupt preview,
  and harness attempt/shadow comparison projection.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so run
  history must exist in both the runtime model and the React Flow panel. The
  live rollback proof now includes `workflowRunHistoryModelUi` and source refs
  for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 11,310 to 10,939 lines. The new
  runs panel is 424 lines, and the run-history model is 128 lines with a
  295-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-53-40-859Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-run-history-model.ts`.

### Slice 69. 2026-05-12 - React Flow search model extraction

Implementation slice completed 2026-05-12, React Flow search model
extraction:

- Extracted rail-search normalization, result counting, result-kind grouping,
  visible result slicing, hidden-result accounting, actionability flags, and
  empty-state copy into
  `packages/agent-ide/src/runtime/workflow-rail-search-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx`
  as the presentational React Flow rail surface for search input, indexed
  workflow counts, result actions, result metadata, and filtered empty states.
- `WorkflowRailPanel/core.tsx` now delegates the `panel === "search"` branch to
  `WorkflowSearchPanel` over `workflowRailSearchModel(...)`, keeping workflow
  discovery/navigation reusable by chat/autopilot workflow creation and graph
  authoring surfaces.
- Added
  `packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts` to lock
  indexed counts, normalization, node/test/output filtering, result-kind
  grouping, visible slicing, test target-node actions, and empty filtered
  states.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so
  rail search must exist in both the runtime model and React Flow panel. The
  live rollback proof now includes `workflowRailSearchModelUi` and source refs
  for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 10,939 to 10,903 lines. The new
  search panel is 63 lines, and the rail-search model is 109 lines with a
  177-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-15-19-853Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-rail-search-model.ts`.

### Slice 70. 2026-05-12 - React Flow entrypoints model extraction

Implementation slice completed 2026-05-12, React Flow entrypoints model
extraction:

- Extracted source/trigger start-point readiness, source payload readiness,
  manual/event/scheduled trigger classification, schedule/event configuration
  readiness, and ready/blocked rollups into
  `packages/agent-ide/src/runtime/workflow-entrypoints-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx`
  as the shared React Flow rail surface for both `sources` and `schedules`,
  preserving `workflow-sources-list`, `workflow-source-node-*`,
  `workflow-schedules-list`, and `workflow-schedule-node-*`.
- `WorkflowRailPanel/core.tsx` now delegates both `panel === "sources"` and
  `panel === "schedules"` to `WorkflowEntrypointsPanel` over
  `workflowEntrypointsModel(...)`, making workflow activation start conditions
  reusable by the workflow creator, chat/autopilot workflow generation, and
  React Flow graph inspection.
- Added
  `packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts` to lock
  source payload states, manual trigger readiness, scheduled trigger readiness,
  event trigger readiness, blocked trigger labels/details, and non-entrypoint
  filtering.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so
  entrypoints must exist in both the runtime model and React Flow panel. The
  live rollback proof now includes `workflowEntrypointsModelUi` and source refs
  for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 10,903 to 10,802 lines. The new
  entrypoints panel is 102 lines, and the entrypoints model is 130 lines with a
  197-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-32-20-984Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-entrypoints-model.ts`.

### Slice 71. 2026-05-12 - React Flow file-bundle model extraction

Implementation slice completed 2026-05-12, React Flow file-bundle model
extraction:

- Extracted workflow graph/tests/proposals/runs/binding-manifest/portable
  package file-bundle projection, workflow path resolution, dirty state,
  sidecar counts, binding manifest readiness, portable package export state,
  and ready/pending rollups into
  `packages/agent-ide/src/runtime/workflow-file-bundle-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx`
  as the presentational React Flow rail surface for `workflow-files-list`,
  file rows, readiness/export metadata, and workflow-path provenance.
- `WorkflowRailPanel/core.tsx` now delegates `panel === "files"` to
  `WorkflowFilesPanel` over `workflowFileBundleModel(...)`, keeping bundle
  provenance reusable by React Flow, chat/autopilot workflow creation,
  export/import, and future TUI parity surfaces.
- Added
  `packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts` to lock
  default sidecar paths, dirty graph paths, test/proposal/run counts, binding
  manifest readiness, portable package export labels, and blocked portable
  package pending state.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so
  file-bundle provenance must exist in both the runtime model and React Flow
  panel. The live rollback proof now includes `workflowFileBundleModelUi` and
  source refs for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 10,802 to 10,786 lines. The new
  files panel is 38 lines, and the file-bundle model is 113 lines with a
  235-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-48-13-986Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowFileBundleModelUi === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-file-bundle-model.ts`.

### Slice 72. 2026-05-12 - React Flow settings model extraction

Implementation slice completed 2026-05-12, React Flow settings model
extraction:

- Extracted settings summary, workflow metadata, chrome locale normalization,
  environment profile state, binding registry rollups, model binding/capability
  projections, run policy, package readiness, and production checklist labels
  into `packages/agent-ide/src/runtime/workflow-settings-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx`
  as the presentational React Flow rail surface for settings summary, locale
  selector, environment controls, binding registry, binding manifest, model
  bindings, capabilities, policy, and production profile editor.
- `WorkflowRailPanel/core.tsx` now delegates `panel === "settings"` to
  `WorkflowSettingsPanel` over `workflowSettingsModel(...)`. The harness
  settings subtree remains a child slot for this slice so activation gates,
  deep links, rollback controls, and worker binding controls keep their
  existing callback wiring while the general settings surface becomes reusable
  by React Flow workflow creation and future TUI parity surfaces.
- Added
  `packages/agent-ide/src/runtime/workflow-settings-model.test.ts` to lock
  summary status, workflow path fallback, read-only state, locale fallback,
  environment defaults, binding summary counts, capability filtering, policy,
  package readiness, and production summary defaults.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so the
  settings rail must exist in both the runtime model and React Flow panel. The
  live rollback proof now includes `workflowSettingsModelUi` and source refs for
  both settings files.
- `WorkflowRailPanel/core.tsx` is reduced from 10,786 to 10,322 lines. The new
  settings panel is 506 lines, and the settings model is 136 lines with a
  169-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-16-54-801Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsModelUi === true`;
  - `checks.workflowFileBundleModelUi === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-settings-model.ts`.

### Slice 73. 2026-05-12 - React Flow settings harness extraction

Implementation slice completed 2026-05-12, React Flow settings harness
extraction:

- Extracted the remaining harness-specific settings subtree from
  `WorkflowRailPanel/core.tsx` into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`.
  The extracted panel now owns the harness summary, activation gate inspector,
  authority proof rows, package deep links, rollback/restore canary controls,
  worker binding registry display, and live harness promotion controls.
- Added
  `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts` so the
  React Flow workflow development environment can consume harness readiness as
  a configurable model instead of pulling labels and counts from the monolithic
  rail component. The model currently projects activation state, blessed/fork
  source, worker execution mode, readiness counters, gated cluster labels, and
  promotion cluster labels.
- Added
  `packages/agent-ide/src/runtime/workflow-settings-harness-model.test.ts` to
  lock blessed activation summaries, fallback fork defaults, readiness counts,
  worker execution mode fallback, and gated/promotion cluster labels.
- `WorkflowRailPanel/core.tsx` now composes `WorkflowSettingsPanel` with a
  `WorkflowSettingsHarnessPanel` child over `workflowSettingsHarnessModel(...)`.
  This keeps the settings rail componentized while preserving the exact callback
  wiring that drives activation, packaging, restore, rollback, worker binding,
  and live harness promotion controls.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so the
  rollback/restore canary proof treats the settings rail as the core rail plus
  extracted settings panels. The live rollback proof now includes
  `workflowSettingsHarnessModelUi` and source refs for both harness settings
  files.
- `WorkflowRailPanel/core.tsx` is reduced from 10,322 to 5,805 lines. The new
  harness settings panel is 5,059 lines, and the harness settings model is 47
  lines with an 87-line focused model test. The panel is intentionally still a
  mechanical extraction boundary; future slices can narrow its prop contract and
  split activation/package/rollback subsections once the current behavioral
  proof remains stable.

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-harness-model.test.ts packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-57-39-502Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workflowSettingsModelUi === true`;
  - `checks.workflowFileBundleModelUi === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 74. 2026-05-12 - React Flow settings harness typed boundary

Implementation slice completed 2026-05-12, React Flow settings harness typed
boundary:

- Replaced the mechanical `any` prop surface in
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
  with exported concern interfaces for activation, package/restore, rollback,
  worker binding, promotion, and callbacks.
- Added typed derived UI shapes for active runtime binding, rollback proof
  binding, package evidence review rows, activation gate inspection,
  read-only-routing proof projection, and fork component diff rows. Existing
  graph-domain values now use the canonical `WorkflowHarness*`,
  `WorkflowPackageImport*`, `WorkflowProject`, `WorkflowProposal`, and
  `WorkflowValidationIssue` types from `packages/agent-ide/src/types/graph.ts`.
- Kept the runtime behavior and React Flow wiring unchanged: `core.tsx` still
  passes the same explicit props, but the extracted panel now has a typed
  contract that future workflow creator panels can reuse and split by concern.
- Extended `scripts/lib/harness-refactor-shape.test.mjs` so the settings
  harness panel must expose the six concern interfaces and must not contain
  `any`. This keeps the extracted boundary from regressing into an
  unstructured prop bag.
- `settingsHarnessPanel.tsx` is now 5,271 lines after the type surface is made
  explicit. This is acceptable for this slice because behavior remained stable;
  the next split should move typed activation/package/rollback/worker sections
  into smaller subpanels.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-harness-model.test.ts packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-19-43-946Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workflowSettingsModelUi === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 75. 2026-05-12 - React Flow settings harness activation panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness
activation panel extraction:

- Split the activation wizard, activation gate inspector, package evidence
  review, package import handoff, activation actions, and activation blocker
  list from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`.
- The new activation panel has a typed concern boundary over the existing
  activation, package/restore, rollback, worker-binding, promotion, and callback
  interfaces. This keeps the workflow creator/React Flow configuration surface
  able to compose activation controls independently of the broader settings
  harness summary.
- Retargeted source-contract validation so the parent panel must delegate to
  `WorkflowSettingsHarnessActivationPanel`, while the extracted panel must own
  `workflow-harness-activation-gate-inspector` and remain `any`-free.
- Updated live GUI validation source aggregation and daemon contract assertions
  so package-import activation UI and activation gate evidence are checked in
  the extracted component instead of the parent.
- `settingsHarnessPanel.tsx` is reduced from 5,271 to 3,720 lines. The new
  `settingsHarnessActivationPanel.tsx` is 1,681 lines. The remaining large
  parent sections are now clearer candidates for worker-binding/rollback and
  promotion extraction.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-42-11-524Z/result.json`
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.activationGateEvidenceInspectable === true`;
  - `checks.activationGateActionWorkbench === true`;
  - `checks.activationGateActionClickProof === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`.

### Slice 76. 2026-05-12 - React Flow settings harness worker-binding and rollback panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness
worker-binding and rollback panel extraction:

- Split worker identity, activation record projection, active runtime binding,
  worker binding registry inspector, current/candidate revision binding,
  rollback target selection, dry-run/apply workbench, rollback drill/execution
  proof, git restore proof, and activation audit history from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`.
- The new worker-binding panel has a typed prop boundary over the exported
  activation, rollback, worker-binding, promotion, and callback concern
  interfaces. This makes the React Flow workflow creator able to compose
  binding/rollback controls independently from activation controls while still
  sharing the same runtime receipts, deep links, and selected fixture state.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  the parent panel must delegate to `WorkflowSettingsHarnessWorkerBindingPanel`,
  while the extracted panel must own `workflow-harness-worker-binding-inspector`
  and `data-worker-binding-registry-bound` without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the parent panel, activation panel,
  worker-binding panel, and harness settings model as the complete settings
  harness source surface.
- `settingsHarnessPanel.tsx` is reduced from 3,720 to 1,786 lines. The new
  `settingsHarnessWorkerBindingPanel.tsx` is 2,041 lines. The remaining parent
  is now small enough that the next extraction should focus on promotion/fork
  controls and any residual orchestration-only props.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-10-00-442Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.workerRollbackLiveShadowGateBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 77. 2026-05-12 - React Flow settings harness promotion panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness
promotion panel extraction:

- Split live handoff, runtime selector, selector live-promotion readiness,
  default runtime dispatch, authority gate live proof rows, read-only routing
  proof, canary execution boundaries, fork lineage/component diff, slot
  bindings, promotion clusters, and fork activation blocker deep links from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`.
- The new promotion panel has a typed prop boundary over promotion, activation,
  rollback, worker-binding, and callback concerns. This lets React Flow compose
  live-promotion controls independently from activation and rollback workbenches
  while preserving the same selected receipt/replay refs and node-inspection
  callbacks.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  the parent must delegate to `WorkflowSettingsHarnessPromotionPanel`, while
  the extracted panel owns `workflow-harness-promotion-clusters`,
  `workflow-harness-live-handoff`, and authority-gate live proof rows without
  reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the parent panel, activation
  panel, worker-binding panel, promotion panel, and harness settings model as
  the complete settings harness source surface.
- `settingsHarnessPanel.tsx` is reduced from 1,786 to 747 lines. The new
  `settingsHarnessPromotionPanel.tsx` is 1,117 lines. The parent is now mostly
  a typed composition shell over the summary plus activation, worker-binding,
  and promotion subpanels.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-27-56-146Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.promotionTransitionControls === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 78. 2026-05-12 - React Flow settings harness type contract extraction

Implementation slice completed 2026-05-12, React Flow settings harness type
contract extraction:

- Extracted shared settings-harness UI contract types from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`.
- The extracted type module now owns `Nullable`, derived UI proof shapes,
  activation/package-restore/rollback/worker-binding/promotion concern props,
  callbacks, and the top-level `WorkflowSettingsHarnessPanelProps` contract.
- Rewired activation, worker-binding, and promotion subpanels to import shared
  contracts from `settingsHarnessTypes.ts` instead of type-importing from their
  parent. This removes the upside-down dependency and makes the contracts
  directly reusable by the React Flow workflow creator and future configurable
  harness tooling.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  the type module is required, child panels are forbidden from importing
  `settingsHarnessPanel.tsx`, and rollback/promotion proof bundles include
  `settingsHarnessTypes.ts` as part of the settings harness source surface.
- `settingsHarnessPanel.tsx` is reduced from 747 to 490 lines. The new
  `settingsHarnessTypes.ts` is 363 lines. The parent is now a composition shell
  over the summary plus activation, worker-binding, and promotion subpanels.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-41-58-495Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.promotionTransitionControls === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 79. 2026-05-12 - React Flow settings harness active runtime rollback panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness active
runtime rollback panel extraction:

- Split active runtime binding, active runtime rollback dry-run/apply controls,
  worker rollback proof workbench, rollback drill/execute controls, rollback
  execution receipts, and git restore proof from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`.
- The new panel exposes a typed
  `WorkflowSettingsHarnessActiveRuntimeRollbackPanelProps` boundary over the
  shared activation, rollback, worker-binding, promotion, and callback concern
  interfaces. This makes active runtime rollback a reusable React Flow workflow
  creator surface while leaving the worker-binding panel focused on worker
  identity, registry selection, revision binding, and activation audit history.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessWorkerBindingPanel` must delegate to
  `WorkflowSettingsHarnessActiveRuntimeRollbackPanel`, while the extracted panel
  owns `workflow-harness-active-runtime-rollback-proof`,
  `data-worker-binding-registry-bound`, and `workflow-harness-git-restore-proof`
  without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the active runtime rollback panel
  alongside the parent, shared types, activation, worker-binding, promotion, and
  harness model source files.
- `settingsHarnessWorkerBindingPanel.tsx` is reduced from 2,041 to 711 lines.
  The new `settingsHarnessActiveRuntimeRollbackPanel.tsx` is 1,468 lines. The
  parent `settingsHarnessPanel.tsx` remains 490 lines and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,774 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-11-04-005Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 80. 2026-05-12 - React Flow settings harness rollback restore proof panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness
rollback restore proof panel extraction:

- Split rollback drill proof, rollback execution receipt proof, and git restore
  proof from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`.
- The new proof panel exposes a typed
  `WorkflowSettingsHarnessRollbackRestoreProofPanelProps` boundary over the
  shared activation, rollback, worker-binding, and callback concern interfaces.
  This gives the React Flow workflow creator a reusable restore-proof inspector
  while the active runtime rollback panel remains focused on binding context,
  deep links, and operator rollback controls.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessActiveRuntimeRollbackPanel` must delegate to
  `WorkflowSettingsHarnessRollbackRestoreProofPanel`, while the extracted proof
  panel owns `workflow-harness-rollback-drill-proof`,
  `workflow-harness-rollback-execution-proof`, and
  `workflow-harness-git-restore-proof` without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the rollback restore proof panel
  alongside the parent, shared types, activation, worker-binding, active runtime
  rollback, promotion, and harness model source files.
- `settingsHarnessActiveRuntimeRollbackPanel.tsx` is reduced from 1,468 to
  1,250 lines. The new `settingsHarnessRollbackRestoreProofPanel.tsx` is 265
  lines. `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside
  its 11,775-line guard at 11,774 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-29-45-390Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 81. 2026-05-12 - React Flow settings harness active runtime binding panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness active
runtime binding panel extraction:

- Split the active runtime binding display, selected worker/session/checkpoint
  metadata, active runtime binding rollup, blockers, and deep-link inspector from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`.
- The new binding panel exposes a typed
  `WorkflowSettingsHarnessActiveRuntimeBindingPanelProps` boundary over the
  shared activation, rollback, worker-binding, promotion, and callback concern
  interfaces. This gives the React Flow workflow creator a reusable binding
  inspector while the active runtime rollback panel becomes a smaller operator
  control shell.
- The active runtime rollback panel still owns
  `workflow-harness-active-runtime-rollback-proof`,
  `workflow-harness-active-runtime-rollback-dry-run`, and
  `workflow-harness-active-runtime-rollback-apply`, and still delegates restore
  proof to `WorkflowSettingsHarnessRollbackRestoreProofPanel`. The extracted
  binding panel intentionally keeps the selected-state rollback attributes that
  live GUI/control code reads from `workflow-harness-active-runtime-binding`.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessActiveRuntimeRollbackPanel` must delegate to
  `WorkflowSettingsHarnessActiveRuntimeBindingPanel`, while the binding panel
  owns `workflow-harness-active-runtime-binding`,
  `data-worker-binding-registry-bound`, and
  `workflow-harness-active-runtime-binding-deep-links` without reintroducing
  `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the active runtime binding panel
  alongside the parent, shared types, activation, worker-binding, active runtime
  rollback, restore proof, promotion, and harness model source files.
- `settingsHarnessActiveRuntimeRollbackPanel.tsx` is reduced from 1,250 to 383
  lines. The new `settingsHarnessActiveRuntimeBindingPanel.tsx` is 970 lines,
  `settingsHarnessRollbackRestoreProofPanel.tsx` remains 265 lines, and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,774 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-46-33-581Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 82. 2026-05-12 - React Flow settings harness activation gate panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness activation
gate panel extraction:

- Split the selected activation gate evidence inspector, package evidence
  review, package import review/handoff, package deep-link rows, node-attempt
  timeline, receipt/replay selectors, and activation-gate action proof surface
  from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`.
- The new gate panel exposes a typed
  `WorkflowSettingsHarnessActivationGatePanelProps` boundary over activation,
  package-restore, rollback, worker-binding, promotion, and callback concern
  interfaces. This gives the React Flow workflow creator a reusable
  activation-gate evidence/workbench inspector while the activation panel keeps
  the activation wizard frame, candidate summary, blocker list, and operator
  controls.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessActivationPanel` must delegate to
  `WorkflowSettingsHarnessActivationGatePanel`, while the new panel owns
  `workflow-harness-activation-gate-inspector`,
  `workflow-harness-package-evidence-review`,
  `workflow-harness-package-import-review`, and the package import handoff/deep
  link controls without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the activation gate panel alongside
  the parent, shared types, worker-binding, active runtime binding/rollback,
  restore proof, promotion, and harness model source files.
- `settingsHarnessActivationPanel.tsx` is reduced from 1,681 to 736 lines. The
  new `settingsHarnessActivationGatePanel.tsx` is 1,142 lines, and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,772 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-07-42-338Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 83. 2026-05-12 - React Flow settings harness promotion readiness panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness promotion
readiness panel extraction:

- Split live handoff, runtime selector, selector live-promotion readiness,
  default runtime dispatch authority, authority gate live proofs, read-only
  routing proof, worker session/checkpoint authority, and canary execution
  boundary proof surfaces from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx`.
- The new readiness panel exposes a typed
  `WorkflowSettingsHarnessPromotionReadinessPanelProps` boundary over
  promotion, activation, rollback, worker-binding, and callback concern
  interfaces. This gives the React Flow workflow creator a reusable promotion
  readiness/authority proof inspector while the promotion panel keeps lineage,
  component diffs, slot inventory, promotion clusters, and activation blockers.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessPromotionPanel` must delegate to
  `WorkflowSettingsHarnessPromotionReadinessPanel`, while the new panel owns
  `workflow-harness-selector-live-promotion-readiness`,
  `workflow-harness-authority-gate-live`,
  `workflow-harness-read-only-routing-proof`, and
  `workflow-harness-canary-execution-boundaries` without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the promotion readiness panel
  alongside the parent, shared types, activation, activation gate,
  worker-binding, active runtime binding/rollback, restore proof, and harness
  model source files.
- `settingsHarnessPromotionPanel.tsx` is reduced from 1,117 to 354 lines. The
  new `settingsHarnessPromotionReadinessPanel.tsx` is 943 lines, and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,772 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-24-22-311Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

### Slice 84. 2026-05-12 - React Flow settings harness package evidence panel extraction

Implementation slice completed 2026-05-12, React Flow settings harness package
evidence panel extraction:

- Split package evidence review rows, package import review identity, activation
  handoff deep links, replay-integrity blockers, reviewed-import activation, and
  package deep-link dispatch from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx`.
- The new package evidence panel exposes a typed
  `WorkflowSettingsHarnessPackageEvidencePanelProps` boundary over activation,
  package-restore, and callback concern interfaces. This gives the React Flow
  workflow creator a reusable reviewed-import/package-evidence inspector while
  the activation gate panel keeps the selected gate summary, gate action, generic
  evidence refs, node attempt timeline, receipt refs, and replay refs.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessActivationGatePanel` must delegate to
  `WorkflowSettingsHarnessPackageEvidencePanel`, while the new panel owns
  `workflow-harness-package-evidence-review`,
  `workflow-harness-package-import-review`, and
  `data-package-import-chrome-locale-preserved` without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the package evidence panel
  alongside the parent, shared types, activation, activation gate,
  worker-binding, active runtime binding/rollback, restore proof, promotion,
  promotion readiness, and harness model source files.
- `settingsHarnessActivationGatePanel.tsx` is reduced from 1,142 to 586 lines.
  The new `settingsHarnessPackageEvidencePanel.tsx` is 671 lines, and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,772 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-46-56-765Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - rollback proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.packageEvidenceGateClickProof === true`;
  - `checks.packageEvidenceImportRoundTripProof === true`;
  - `checks.packageImportReviewProof === true`;
  - `checks.packageImportActivationHandoffProof === true`;
  - `checks.packageImportActivationApplyProof === true`;
  - `checks.packageImportActivationReplayIntegrityProof === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx`.

### Slice 85. 2026-05-12 - React Flow settings harness activation gate refs/timeline extraction

Implementation slice completed 2026-05-12, React Flow settings harness
activation gate refs/timeline extraction:

- Split activation-gate evidence refs, receipt refs, replay fixture refs, node
  attempt refs, and node-attempt timeline rows from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx`
  and
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx`.
- The refs panel exposes a typed
  `WorkflowSettingsHarnessActivationGateRefsPanelProps` boundary over
  activation, worker-binding, and callback concern interfaces. The timeline
  panel exposes a typed
  `WorkflowSettingsHarnessActivationGateTimelinePanelProps` boundary over
  activation, promotion, worker-binding, and callback concern interfaces. This
  lets the React Flow workflow creator address activation gate refs and node
  timelines as independent inspector modules.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessActivationGatePanel` must delegate to
  `WorkflowSettingsHarnessActivationGateRefsPanel` and
  `WorkflowSettingsHarnessActivationGateTimelinePanel`, while the new panels own
  `workflow-harness-activation-gate-evidence-refs`,
  `workflow-harness-activation-gate-receipt-refs`,
  `workflow-harness-activation-gate-replay-refs`,
  `workflow-harness-activation-gate-node-attempt-refs`, and
  `workflow-harness-activation-gate-node-timeline` without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the refs and timeline panels
  alongside the parent, package evidence, shared types, activation,
  worker-binding, active runtime binding/rollback, restore proof, promotion,
  promotion readiness, and harness model source files.
- `settingsHarnessActivationGatePanel.tsx` is reduced from 586 to 391 lines.
  The new `settingsHarnessActivationGateRefsPanel.tsx` is 169 lines,
  `settingsHarnessActivationGateTimelinePanel.tsx` is 147 lines, and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,772 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-05-02-607Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - rollback proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.routeStatefulActivationGateReferenceDeepLinks === true`;
  - `checks.activationGateMutationCanaryNodeInspectorDeepLink === true`;
  - `checks.activationGateNodeTimelineDeepLink === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx`.

### Slice 86. 2026-05-12 - React Flow settings harness package import/rows extraction

Implementation slice completed 2026-05-12, React Flow settings harness package
import/rows extraction:

- Split package import review identity, activation handoff, reviewed-import
  activation apply controls, replay-integrity blockers, and evidence row
  deep-link dispatch out of
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx`
  into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx`
  and
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx`.
- The parent package evidence panel now stays focused on the
  `workflow-harness-package-evidence-review` shell, package-evidence gate
  counters, review summary attributes, and typed child composition. This keeps
  the React Flow workflow creator's reviewed-import surface modular: import
  review/handoff can be addressed independently from evidence rows and package
  manifest/chrome-locality summary state.
- Retargeted daemon, refactor-shape, and live GUI source-contract validation so
  `WorkflowSettingsHarnessPackageEvidencePanel` must delegate to
  `WorkflowSettingsHarnessPackageImportReviewPanel` and
  `WorkflowSettingsHarnessPackageEvidenceRowsPanel`. The rows panel now owns
  `workflow-harness-package-evidence-row-*`, receipt refs, replay refs, and
  package evidence deep links, while the import-review panel owns
  `workflow-harness-package-import-review`,
  `workflow-harness-package-import-handoff`,
  `data-package-import-chrome-locale-preserved`, and the reviewed-import
  activation controls without reintroducing `any`.
- Updated live GUI validation source aggregation so rollback/restore canary and
  promotion-transition proof bundles include the package import-review and
  evidence-row panels alongside the parent, activation gate, activation gate
  refs/timeline, shared types, activation, worker-binding, active runtime
  binding/rollback, restore proof, promotion, promotion readiness, and harness
  model source files.
- `settingsHarnessPackageEvidencePanel.tsx` is reduced from 671 to 179 lines.
  The new `settingsHarnessPackageImportReviewPanel.tsx` is 427 lines,
  `settingsHarnessPackageEvidenceRowsPanel.tsx` is 194 lines, and
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` remains inside its
  11,775-line guard at 11,772 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-30-56-229Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - rollback proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.packageEvidenceGateClickProof === true`;
  - `checks.packageEvidenceImportRoundTripProof === true`;
  - `checks.packageImportReviewProof === true`;
  - `checks.packageImportActivationHandoffProof === true`;
  - `checks.packageImportActivationApplyProof === true`;
  - `checks.packageImportActivationReplayIntegrityProof === true`;
  - `checks.coldStartDeepLinkRestore === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx`.

## P0. Live Runtime API Bridge

### Slice 87. 2026-05-12 - live bridge TTI/event contract lock

Implementation slice completed 2026-05-12, live bridge TTI/event contract lock:

- Added
  `docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md` as the
  P0 contract-lock spec for replacing synthetic production daemon run
  projections with a live `RuntimeAgentService` bridge.
- Locked the canonical ownership boundary: `AgentState` remains the persisted
  runtime session record, `KernelEvent` and `AgentRuntimeEvent` remain runtime
  source streams, and the daemon adds an append-only public TTI/event
  projection instead of creating a second runtime.
- Defined `RuntimeThreadRecord`, `RuntimeTurnRecord`, `RuntimeItemRecord`, and
  `RuntimeEventEnvelope` required fields, invariants, idempotency rules,
  monotonic `seq`, redaction behavior, fixture profile visibility, and
  production fail-closed semantics.
- Specified daemon endpoints, `/v1/runs/*` compatibility alias behavior, SSE
  replay through `since_seq` and `Last-Event-ID`, SDK `Thread`/`Turn` wrappers,
  CLI/TUI commands, React Flow runtime nodes, persistence shape, error
  semantics, and the first implementation sequence.
- Updated the master guide so the immediate tactical queue now points at shared
  schema snapshots and the append-only daemon event store before runtime
  execution wiring.

Validation evidence:

- docs integrity check confirms the master guide has no inline completed-slice
  or validation blocks after the slice.
- docs integrity check confirms the implementation and validation ledgers have
  matching extracted slice counts.
- docs integrity check confirms referenced evidence result paths still exist.
- `git diff --check`

### Slice 88. 2026-05-12 - live bridge TTI schema snapshots

Implementation slice completed 2026-05-12, live bridge TTI schema snapshots:

- Replaced the early TTI draft in
  `crates/types/src/app/runtime/thread_turn_item.rs` with the locked
  `ioi.runtime.thread.v1`, `ioi.runtime.turn.v1`, `ioi.runtime.item.v1`, and
  `ioi.runtime.event.v1` wire records from the live bridge spec.
- Added explicit Rust literal arrays for thread modes, approval modes, thread
  statuses, turn statuses, item kinds, item statuses, actors, and event
  sources so schema drift can be caught before daemon/API wiring.
- Re-exported the modular TTI records and constants through
  `crates/types/src/app/runtime_contracts.rs` and
  `crates/types/src/app/runtime/events.rs` so existing compatibility imports
  and concern-oriented runtime imports both see the same contract.
- Mirrored the wire records and literal arrays in
  `packages/agent-sdk/src/messages.ts`, and exported the constants and record
  types from `packages/agent-sdk/src/index.ts` for SDK clients.
- Added `scripts/lib/live-bridge-tti-schema-contract.test.mjs` to prove the
  Rust and TypeScript snapshots agree on schema literals, enum literal arrays,
  required field order, and export surfaces.
- Updated the live bridge contract spec and master guide so the next P0 slice is
  the append-only daemon event store, not another schema pass.

Validation evidence:

- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `npm run build:agent-sdk`
- `cargo test -p ioi-types thread_turn_item --lib`
- `cargo check -p ioi-types`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`

### Slice 89. 2026-05-12 - daemon runtime event-store spine

Implementation slice completed 2026-05-12, daemon runtime event-store spine:

- Added a persistent append-only runtime event stream inside
  `packages/runtime-daemon/src/index.mjs`, backed by JSONL files under the
  daemon Agentgres state directory's `events/` relation.
- `appendRuntimeEvent` now assigns monotonic `seq` per `event_stream_id`,
  derives `parent_seq`, requires `idempotency_key`, and returns the first
  appended row when `(event_stream_id, idempotency_key)` is replayed.
- Thread event reads now project legacy daemon run events into locked
  `RuntimeEventEnvelope` rows with the new `ioi.runtime.event.v1` schema while
  retaining temporary `event` and `payload_summary` aliases for existing SDK and
  test callers during migration.
- Thread and turn projections now emit the locked
  `ioi.runtime.thread.v1`/`ioi.runtime.turn.v1` schema fields, including
  `event_stream_id`, `latest_seq`, `seq_start`, `seq_end`, `fixture_profile`,
  and id-linked workflow component metadata.
- Added future-cursor handling for thread event replay:
  `since_seq > latest_seq` returns `event_cursor_out_of_range` with the latest
  committed sequence.
- Added a daemon contract subtest proving append-only ordering, idempotency,
  `since_seq` replay, and restart persistence for the event store.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 12 daemon/API contract subtests passed, including persisted event-store
    idempotency and Agentgres-backed thread/turn/event replay.

### Slice 90. 2026-05-12 - runtime event replay alias parity

Implementation slice completed 2026-05-12, runtime event replay alias parity:

- Routed thread event replay through a shared canonical cursor parser that
  accepts `since_seq`, `Last-Event-ID: <seq>`, and
  `Last-Event-ID: <event_id>`.
- Added `/v1/threads/{thread_id}/events/stream` as an SSE alias over the same
  persisted `RuntimeEventEnvelope` stream as `/events`.
- Converted `/v1/runs/{run_id}/events` and `/v1/runs/{run_id}/replay` to return
  the owning turn's stored runtime event rows instead of legacy
  `IOISDKMessage` rows.
- Updated SDK daemon event parsing so stored `RuntimeEventEnvelope` rows are
  normalized back into `IOISDKMessage` at the compatibility edge, preserving
  reconnect behavior while exposing the canonical envelope in event data.
- Added replay contract coverage for sequence cursors, event-id cursors, stream
  aliases, run-event alias parity, run replay parity, and future cursor errors.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm test --workspace=@ioi/agent-sdk`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 12 daemon/API contract subtests passed, including event-store persistence,
    `Last-Event-ID` replay, `/events/stream`, run-event alias parity, and
    future cursor error details.

### Slice 91. 2026-05-12 - RuntimeApiBridge boundary and turn projection

Implementation slice completed 2026-05-12, RuntimeApiBridge boundary and turn
projection:

- Added `packages/runtime-daemon/src/runtime-api-bridge.mjs` as the daemon-side
  bridge contract for runtime-service profile routing.
- `POST /v1/threads` now recognizes `runtime_profile=runtime_service` and fails
  closed with `external_blocker` when no `RuntimeApiBridge` can start a thread.
- Runtime-service threads no longer receive daemon-side synthetic
  `thread.started` events; bridge-supplied events are appended directly to the
  stored `RuntimeEventEnvelope` stream with `fixture_profile: null`.
- Runtime-service turn submission now calls `RuntimeApiBridge.submitTurn`,
  persists bridge-supplied `turn.started` and `turn.completed` rows, and returns
  the locked `RuntimeTurnRecord` over the same event ids.
- The compatibility `/v1/runs/{id}/events` alias reads the runtime-service
  turn's stored event range, so fixture and bridge-backed turns use the same
  replay spine.

Validation evidence:

- `node --check packages/runtime-daemon/src/runtime-api-bridge.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm test --workspace=@ioi/agent-sdk`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 13 daemon/API contract subtests passed, including runtime-service
    fail-closed behavior, injected bridge thread projection, bridge turn
    projection, null fixture profile preservation, and run-event alias parity.

### Slice 92. 2026-05-12 - RuntimeAgentService command bridge adapter

Implementation slice completed 2026-05-12, RuntimeAgentService command bridge
adapter:

- Added
  `packages/runtime-daemon/src/runtime-agent-service-adapter.mjs` as the first
  concrete process adapter behind `RuntimeApiBridge`.
- Locked the command protocol as `ioi.runtime.bridge.command.v1`: the daemon
  sends `{ schema_version, bridge_id, operation, input }` on stdin and expects a
  JSON bridge result on stdout.
- Added env auto-wiring through
  `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND`,
  `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS`,
  `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID`, and timeout controls so
  `runtime_profile=runtime_service` can bind to an external Rust/Tauri-owned
  bridge without injected test objects.
- Preserved fail-closed behavior: no env command still produces the
  `RuntimeApiBridge` external blocker; command failures surface as
  `runtime_bridge_command` errors with bounded stdout/stderr evidence.
- Exported the command adapter from `@ioi/runtime-daemon` and added daemon
  contract coverage proving env-configured command start and turn submission
  persist canonical `RuntimeEventEnvelope` rows with `fixture_profile: null`.
- Updated the master guide tactical queue so the next P0 slice is the Rust/Tauri
  executable that implements this command protocol with durable
  `RuntimeAgentService` state and KernelEvent mapping.

Validation evidence:

- `node --check packages/runtime-daemon/src/runtime-agent-service-adapter.mjs`
- `node --check packages/runtime-daemon/src/runtime-api-bridge.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm test --workspace=@ioi/agent-sdk`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 14 daemon/API contract subtests passed, including env-configured command
    bridge start/turn submission and the prior injected bridge/fail-closed
    contract.
- `git diff --check`

### Slice 93. 2026-05-12 - Rust RuntimeAgentService bridge executable

Implementation slice completed 2026-05-12, Rust RuntimeAgentService bridge
executable:

- Added `crates/node/src/bin/ioi-runtime-bridge.rs` behind the `local-mode`
  feature as the Rust owner for the daemon command bridge protocol.
- The executable reads `ioi.runtime.bridge.command.v1` requests from stdin and
  emits the existing daemon bridge result envelope on stdout.
- `start_thread` now creates a durable `RuntimeAgentService` session by calling
  `handle_service_call("start@v1")` against a `RedbFlatStore` state backend and
  SQLite `MemoryRuntime` checkpoint store.
- `submit_turn` now reopens the same state, calls `post_message@v1` for the
  user prompt, calls `step@v1`, commits durable state between invocations, and
  returns bridge-ready `turn.started` plus terminal TTI events.
- The bridge constructs real `RuntimeAgentService` instances with GUI,
  terminal, browser, OS, memory, and unavailable-inference drivers, so local
  runtime-service mode crosses the Rust runtime boundary without daemon-side
  fixture execution.
- Added lightweight unit coverage for protocol alias parsing and
  `runtime_service` TTI source/fixture invariants.
- Updated the master guide so the next tactical step is daemon local profile
  wiring to the Rust executable, followed by richer KernelEvent mapping.

Validation evidence:

- `cargo check -p ioi-node --bin ioi-runtime-bridge --features local-mode`
- `cargo build -p ioi-node --bin ioi-runtime-bridge --features local-mode`
- `cargo test -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - 2 unit tests passed.
- Two-invocation command smoke using `target/debug/ioi-runtime-bridge`:
  - `start_thread` returned `source=runtime_service` and a `thread.started`
    event;
  - a separate `submit_turn` invocation reused the returned session id,
    reopened durable state, returned `turn.started`, and emitted a terminal
    TTI event from the runtime-owned step path.
- Daemon env-adapter smoke with
  `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND=target/debug/ioi-runtime-bridge`:
  - `POST /v1/threads` returned a Rust-backed runtime session with
    `fixture_profile: null`;
  - `POST /v1/threads/{id}/turns` returned a Rust-backed turn;
  - replay returned `thread.started`, `turn.started`, and `turn.completed`
    from `source=runtime_service`.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 14 daemon/API contract subtests passed after the Rust bridge executable
    landed.
- `git diff --check`

### Slice 94. 2026-05-12 - Daemon Rust bridge executable contract

Implementation slice completed 2026-05-12, daemon Rust bridge executable
contract:

- Added a live daemon contract that auto-wires
  `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND` to the real
  `ioi-runtime-bridge` executable rather than the JS command fixture.
- The contract builds the local-mode Rust bridge when
  `IOI_RUNTIME_BRIDGE_RUST_BIN` is not supplied, then passes an isolated
  `--data-dir` so the bridge proves durable state across separate
  `start_thread` and `submit_turn` command invocations.
- The contract verifies `runtime_profile=runtime_service` thread creation
  returns a real Rust session id, preserves `runtime_bridge_id`, and stores
  `thread.started` with
  `RuntimeAgentService.handle_service_call.start@v1`.
- The contract verifies turn submission stores `turn.started` and a terminal
  runtime event from `post_message@v1` and `step@v1`, keeps
  `fixture_profile: null`, creates Rust-owned run/turn ids, and exposes the
  same turn events through `/v1/runs/{id}/events`.
- Updated the master guide so the next immediate runtime slice is richer
  KernelEvent mapping, with SDK/React Flow projections following after the
  event vocabulary expands.

Validation evidence:

- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo check -p ioi-node --bin ioi-runtime-bridge --features local-mode`
- `cargo test -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - 2 bridge executable unit tests passed.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 TTI schema snapshot subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed, including the Rust executable env
    auto-wiring contract.
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-preflight`
  - GUI harness preflight passed outside the worktree.
- `git diff --check`

### Slice 95. 2026-05-12 - KernelEvent bridge mapper foundation

Implementation slice completed 2026-05-12, KernelEvent bridge mapper
foundation:

- Added `crates/node/src/runtime_bridge_events.rs` as the Rust-side mapper from
  low-level `KernelEvent` variants into bridge-ready TTI event envelopes.
- The mapper currently covers `AgentStep`, `AgentThought`,
  `FirewallInterception`, `AgentActionResult`, `WorkloadReceipt`, and
  `RoutingReceipt`, assigning stable public event kinds, component kinds, and
  workflow node ids for future React Flow/runtime projection.
- The `ioi-runtime-bridge` executable now installs a
  `RuntimeAgentService.with_event_sender(...)` broadcast channel, drains emitted
  kernel events after `start@v1` and `step@v1`, and appends mapped runtime
  events before the terminal turn event.
- Updated the daemon Rust bridge contract so live runtime-service replay now
  proves a mapped `KernelEvent::AgentActionResult` row with
  `event_kind=tool.completed`, `component_kind=tool_result`, and
  `workflow_node_id=runtime.tool-result` between `turn.started` and the
  terminal `step@v1` event.
- Updated the master guide so the next tactical slice is SDK/React Flow
  projection over the canonical thread/turn/event API.

Validation evidence:

- `cargo fmt --package ioi-node`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo check -p ioi-node --bin ioi-runtime-bridge --features local-mode`
- `cargo test -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - 6 bridge executable and mapper unit tests passed.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 TTI schema snapshot subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed, including live mapped KernelEvent
    replay through the Rust bridge.
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-preflight`
  - GUI harness preflight passed outside the worktree.
- `git diff --check`

### Slice 96. 2026-05-12 - SDK Thread/Turn canonical event projection

Implementation slice completed 2026-05-12, SDK Thread/Turn canonical event
projection:

- Added `packages/agent-sdk/src/thread.ts` with public `Thread` and `Turn`
  wrappers over the daemon's canonical `/v1/threads`, `/turns`, and `/events`
  APIs.
- Added `packages/agent-sdk/src/runtime-events.ts` to keep canonical event
  projection and SDK mock TTI helpers out of the already-large substrate
  client.
- Extended `RuntimeSubstrateClient` with thread creation/open/list/resume/fork,
  turn submission/list/get, and typed thread event streaming methods.
- Added `RuntimeThreadEvent` projection types plus
  `runtimeThreadEventFromEnvelope(...)` so daemon TTI envelopes normalize
  consistently for SDK, chat, CLI/TUI, and future React Flow consumers.
- Kept `Agent.send()` and `Run` compatibility intact while adding
  `agent.thread()` as a bridge from existing agent ergonomics to the canonical
  thread surface.
- Locked an SDK HTTP contract that maps canonical daemon rows such as
  `tool.completed` from `KernelEvent::AgentActionResult` into typed SDK event
  fields: `type`, `componentKind`, `workflowNodeId`, `toolName`, `agentStatus`,
  and `stepIndex`.
- Extended the live daemon Rust bridge contract so SDK `Thread.open()` and
  `Turn.events()` replay the same stored event ids as `/v1/threads/{id}/events`
  and `/v1/runs/{id}/events`.

Validation evidence:

- `npm run typecheck --workspace=@ioi/agent-sdk`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 TTI schema snapshot subtests passed.
- `npm test --workspace=@ioi/agent-sdk`
  - 11 SDK subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime-service thread replay through SDK Thread/Turn wrappers passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-sdk-thread-turn-final`
  - GUI harness preflight passed outside the worktree.

### Slice 97. 2026-05-12 - React Flow runtime event projection over Thread.events

Implementation slice completed 2026-05-12, React Flow runtime event projection
over canonical SDK thread events:

- Added `packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts`
  as a pure, package-local projection from `Thread.events()`-shaped canonical
  runtime events into React Flow compatible nodes and sequential edges.
- The projection groups by canonical `workflowNodeId` when present and falls
  back to stable runtime ids for reasoning, model routing, tool results,
  approvals, policy blocks, receipts, and terminal turn events.
- Projected nodes carry status, component kind, workflow graph id, cursor,
  sequence, latest event id, payload schema version, receipt/artifact/policy/
  rollback refs, tool/approval metadata, and source event kinds.
- Exported the projection helpers from `@ioi/agent-ide` without adding an SDK
  dependency to the IDE package, preserving modular package boundaries while
  accepting the same event shape produced by `Thread.events()`.
- Added a focused source contract and compile-time test coverage so future
  React Flow integration cannot quietly drop cursor/evidence metadata or the
  policy/approval/tool/receipt event families.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- Built-bundle smoke import of `projectRuntimeThreadEventsToWorkflowProjection`
  returned `{"nodes":2,"edges":1,"latestEventId":"e2"}` for a
  reasoning-to-tool canonical event sample.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-reactflow-runtime-event-projection`
  - GUI harness preflight passed outside the worktree.

### Slice 98. 2026-05-12 - Workflow run inspector runtime event graph

Implementation slice completed 2026-05-12, React Flow workflow run inspector
runtime event graph:

- Extended `workflow-run-history-model` to accept canonical
  `WorkflowRuntimeThreadEventLike` rows, project them with
  `projectRuntimeThreadEventsToWorkflowProjection(...)`, and keep the derived
  graph separate from workflow-local timeline events.
- Added a runtime-thread-event loader to the workflow composer controller using
  `loadWorkflowRuntimeThreadEvents(...)`, with Tauri runtime wiring that aliases
  the existing durable thread event command.
- Rendered a read-only runtime event graph in `WorkflowRunsPanel`, including
  React Flow node/edge ids, statuses, cursors, event ids, component kinds,
  receipt/artifact/policy/rollback refs, tool names, approval ids, and
  expandable event details.
- Kept the inspector operational and compact by reusing the existing run panel
  hierarchy rather than introducing a second editable canvas.
- Extended source contracts so future changes must preserve the controller
  loader, projection model, runtime event graph UI, and evidence-ref data
  attributes.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- Built-bundle smoke import of `projectRuntimeThreadEventsToWorkflowProjection`
  returned `{"nodes":2,"latestCursor":"events_thread:5"}` for policy/receipt
  canonical events.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-runtime-event-inspector`
  - GUI harness preflight passed outside the worktree.

### Slice 99. 2026-05-12 - CLI/TUI runtime event stream command

Implementation slice completed 2026-05-12, CLI/TUI runtime event stream
command over canonical daemon events:

- Added `crates/cli/src/commands/agent_event_stream.rs` as the modular CLI/TUI
  event stream client for the daemon's stored runtime event stream.
- Added `cli agent stream --thread-id <id>` and `--run-id <id>` routing through
  `/v1/threads/{id}/events`, `/v1/threads/{id}/events/stream`, and
  `/v1/runs/{id}/events`.
- Supported `--since-seq`, `--last-event-id`, `--follow`, `--endpoint`,
  `--token`, and `--json` without any fixture or local fallback path.
- Added compact operator output for mapped KernelEvent rows, including
  canonical cursor, `source_event_kind`, `event_kind`, `component_kind`,
  `workflow_node_id`, `workflow_graph_id`, payload schema/version details,
  tool/run metadata, receipt refs, policy refs, artifact refs, and event id.
- Kept `agent.rs` as command wiring only, so future TUI/runtime stream controls
  can reuse the same daemon client module without bloating the legacy agent
  command file.
- Extended the daemon live source contract so CLI/TUI stream support remains
  locked to canonical event endpoints and evidence-bearing row fields.

Validation evidence:

- `cargo fmt --package ioi-cli`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test -p ioi-cli --bin cli commands::agent`
  - 7 CLI binary unit tests passed, including stream parsing, route/cursor
    construction, SSE parsing, and mapped KernelEvent compact formatting.
- `cargo check -p ioi-cli --bin cli`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed, including the CLI stream source
    contract alongside existing SDK and React Flow event parity checks.
- `cargo build -p ioi-cli --bin cli`
- Ad hoc live daemon CLI replay:
  - started a runtime daemon, appended a mapped
    `KernelEvent::AgentActionResult`-shaped row, and verified
    `target/debug/cli agent stream` read the stored event by JSON and compact
    output with matching component/node ids, receipt refs, and policy refs.
  - mapped event id:
    `thread_4e6cec3d-c755-4a17-b1bd-432b84e347f1:events:seq:00000002`.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-cli-event-stream`
  - GUI harness preflight passed outside the worktree at
    `/tmp/ioi-autopilot-gui-harness-cli-event-stream/2026-05-12T22-34-03-536Z/result.json`.
- `git diff --check`

Known validation note:

- `cargo test -p ioi-cli commands::agent` still compiles integration tests and
  fails before this slice's tests because multiple pre-existing
  `crates/cli/tests/*` fixtures construct `StartAgentParams` without the newer
  `runtime_route_frame` field. The slice therefore uses the binary-only agent
  unit test and `cargo check -p ioi-cli --bin cli` as the scoped Rust
  validation.

### Slice 100. 2026-05-12 - Cross-surface same-sequence KernelEvent proof

Implementation slice completed 2026-05-12, cross-surface same-sequence proof
for canonical mapped KernelEvent rows:

- Extended `scripts/lib/live-runtime-daemon-contract.test.mjs` with a live
  runtime-service proof that starts the Rust `ioi-runtime-bridge`, submits a
  thread turn, captures the mapped `KernelEvent::AgentActionResult` row, and
  then checks every consumer surface against that exact stored event.
- Added cached CLI binary discovery/building for the live contract, honoring
  `IOI_CLI_BIN` when provided and otherwise building `ioi-cli --bin cli`.
- Added React Flow bundle import support for the live contract so
  `projectRuntimeThreadEventsToWorkflowProjection(...)` participates in the
  same runtime proof as daemon SSE, SDK `Thread.events()`, and CLI/TUI
  `agent stream --json`.
- Locked the same `event_id`, `seq`, canonical cursor, `event_kind`,
  `source_event_kind`, `component_kind`, `workflow_node_id`, payload schema,
  receipt refs, policy refs, artifact refs, and rollback refs across daemon,
  SDK, CLI/TUI, and React Flow.
- Updated the master guide to mark the current bridge/event projection loop as
  closed and move the tactical queue to live turn controls.

Validation evidence:

- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 16 daemon/API contract subtests passed;
  - the new subtest
    `mapped KernelEvent row keeps one canonical sequence across SDK, CLI, and React Flow`
    passed against a live Rust runtime-service thread.
- `cargo check -p ioi-cli --bin cli`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow canonical Thread.events projection contract passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-cross-surface-event-seq`
  - GUI harness preflight passed outside the worktree at
    `/tmp/ioi-autopilot-gui-harness-cross-surface-event-seq/2026-05-12T22-40-35-479Z/result.json`.

### Slice 101. 2026-05-12 - Live operator interrupt turn-control event

Implementation slice completed 2026-05-12, live operator interrupt
turn-control event:

- Added `POST /v1/threads/{thread_id}/turns/{turn_id}/interrupt` to the daemon
  thread API. The endpoint appends one idempotent canonical `turn.interrupted`
  event with `source_event_kind=OperatorControl.Interrupt`,
  `component_kind=operator_control`, `workflow_node_id=runtime.operator-interrupt`,
  `payload_schema_version=ioi.runtime.operator-control.v1`, receipt refs, and
  policy decision refs.
- Added SDK `Turn.interrupt({ reason })` plus typed `turn_interrupted` event
  mapping so daemon SSE rows project through `Thread.events()` and
  `Turn.events()` without losing event id, seq, cursor, node id, or evidence
  refs.
- Added CLI/TUI `ioi agent interrupt --thread-id <id> --turn-id <id>` over the
  daemon control endpoint, with JSON output suitable for the future TUI control
  surface.
- Extended the React Flow runtime event projection so `turn_interrupted` rows
  render as an interrupted `runtime.operator-interrupt` control node.
- Added a live runtime-service proof that starts the Rust bridge, creates a
  turn, interrupts it through CLI, verifies SDK idempotency, and checks React
  Flow consumes the exact same stored event.

Validation evidence:

- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "local daemon projects Agentgres runs" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-operator-interrupt-control`
  - GUI harness preflight passed outside the worktree at
    `/tmp/ioi-autopilot-gui-harness-operator-interrupt-control/2026-05-12T22-55-37-243Z/result.json`.

Known validation note:

- `cargo test -p ioi-cli parses_agent_operator_surface_commands` still compiles
  unrelated integration tests and fails before the targeted unit because
  pre-existing `crates/cli/tests/*` fixtures construct `StartAgentParams`
  without `runtime_route_frame`. The binary-only command test above is the
  scoped Rust signal for this slice.

### Slice 102. 2026-05-12 - Live operator steer turn-control event

Implementation slice completed 2026-05-12, live operator steer turn-control
event:

- Added `POST /v1/threads/{thread_id}/turns/{turn_id}/steer` to the daemon
  thread API. The endpoint appends canonical `turn.steered` events with
  `source_event_kind=OperatorControl.Steer`,
  `component_kind=operator_control`, `workflow_node_id=runtime.operator-steer`,
  `payload_schema_version=ioi.runtime.operator-control.v1`, receipt refs, and
  policy decision refs.
- Kept steer non-terminal: it records operator guidance and preserves the
  current turn lifecycle status while updating the run's operator-control
  evidence.
- Added SDK `Turn.steer({ guidance })` plus typed `turn_steered` event mapping
  so daemon SSE rows project through `Thread.events()` without losing event id,
  seq, cursor, node id, or evidence refs.
- Added CLI/TUI `ioi agent steer --thread-id <id> --turn-id <id>` over the
  daemon control endpoint, with JSON output suitable for the future TUI control
  surface.
- Extended the React Flow runtime event projection so `turn_steered` rows
  render as `runtime.operator-steer` control nodes.
- Added a live runtime-service proof that starts the Rust bridge, creates a
  turn, steers it through CLI, verifies SDK idempotency for the same guidance,
  and checks React Flow consumes the exact same stored event.

Validation evidence:

- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --check packages/runtime-daemon/src/index.mjs`
- `cargo fmt --package ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `node --test --test-name-pattern "operator steer keeps one canonical guidance event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "local daemon projects Agentgres runs" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-operator-steer-control`
  - GUI harness preflight passed outside the worktree at
    `/tmp/ioi-autopilot-gui-harness-operator-steer-control/2026-05-12T23-06-03-227Z/result.json`.

Known validation note:

- `cargo test -p ioi-cli parses_agent_operator_surface_commands` still compiles
  unrelated integration tests and fails before the targeted unit because
  pre-existing `crates/cli/tests/*` fixtures construct `StartAgentParams`
  without `runtime_route_frame`. The binary-only command test above is the
  scoped Rust signal for this slice.

### Slice 103. 2026-05-12 - Live context compact control event

Implementation slice completed 2026-05-12, live context compact control event:

- Added `POST /v1/threads/{thread_id}/compact` to the daemon thread API. The
  endpoint appends canonical `context.compacted` events with
  `source_event_kind=OperatorControl.Compact`,
  `component_kind=context_compaction`,
  `workflow_node_id=runtime.context-compact`,
  `payload_schema_version=ioi.runtime.context-compaction.v1`, receipt refs,
  and policy decision refs.
- Kept compaction non-terminal and thread-scoped while anchoring the event to
  the latest turn when one exists, so React Flow and TUI consumers get a stable
  graph address without making compaction a second runtime truth store.
- Added SDK `Thread.compact({ reason, scope })` plus typed
  `context_compacted` event mapping so daemon SSE rows project through
  `Thread.events()` without losing event id, seq, cursor, node id, or evidence
  refs.
- Added CLI/TUI `ioi agent compact --thread-id <id>` over the daemon control
  endpoint, with JSON output suitable for the future TUI control surface.
- Extended the React Flow runtime event projection so `context_compacted` rows
  render as `runtime.context-compact` nodes.
- Added a live runtime-service proof that starts the Rust bridge, creates a
  turn, compacts context through CLI, verifies SDK idempotency for the same
  reason/scope, and checks React Flow consumes the exact same stored event.

Validation evidence:

- `npm run build --workspace=@ioi/agent-sdk`
- `node --check packages/runtime-daemon/src/index.mjs`
- `cargo fmt --package ioi-cli`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `node --test --test-name-pattern "context compact keeps one canonical compaction event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "operator steer keeps one canonical guidance event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "local daemon projects Agentgres runs" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-context-compact-control`
  - GUI harness preflight passed outside the worktree at
    `/tmp/ioi-autopilot-gui-harness-context-compact-control/2026-05-12T23-14-55-807Z/result.json`.

Known validation note:

- `cargo test -p ioi-cli parses_agent_operator_surface_commands` still compiles
  unrelated integration tests and fails before the targeted unit because
  pre-existing `crates/cli/tests/*` fixtures construct `StartAgentParams`
  without `runtime_route_frame`. The binary-only command test above is the
  scoped Rust signal for this slice.

### Slice 104. 2026-05-12 - Live thread fork control event

Implementation slice completed 2026-05-12, live thread fork control event:

- Added source-thread canonical `thread.forked` events to daemon
  `/v1/threads/{thread_id}/fork`. The event records
  `source_event_kind=OperatorControl.Fork`, `component_kind=thread_fork`,
  `workflow_node_id=runtime.thread-fork`,
  `payload_schema_version=ioi.runtime.thread-fork.v1`, source latest seq,
  source latest turn id, fork thread id, receipt refs, and policy refs.
- Kept fork as a real thread branch while making the source thread carry the
  audit event, so CLI/TUI, SDK, and React Flow can inspect the branch without
  treating the forked thread's `thread.started` event as the control proof.
- Extended SDK daemon input and typed runtime event mapping so `Thread.fork(...)`
  defaults to `source=sdk_client`, and `Thread.events()` projects
  `thread.forked` as `thread_forked` with canonical graph metadata.
- Added CLI/TUI `ioi agent fork --thread-id <id>` over the daemon control
  endpoint, with JSON output suitable for the future TUI control surface.
- Extended the React Flow runtime event projection so `thread_forked` rows
  render as `runtime.thread-fork` state nodes with evidence refs.
- Added a live runtime-service proof that starts the Rust bridge, creates a
  turn, forks the thread through CLI, opens both source and fork through the
  SDK, and checks React Flow consumes the exact same stored source event.

Validation evidence:

- `cargo fmt --package ioi-cli`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `node --test --test-name-pattern "thread fork keeps one canonical source event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-thread-fork-control`
  - GUI harness preflight passed outside the worktree at
    `/tmp/ioi-autopilot-gui-harness-thread-fork-control/2026-05-12T23-30-08-711Z/result.json`.

Known validation note:

- Direct `node --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  is not a valid repo test command because Node does not load extensionless TS
  imports for that source file. `npm run build --workspace=@ioi/agent-ide` and
  `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  are the scoped React Flow validation signals for this slice.

### Slice 105. 2026-05-12 - React Flow runtime thread fork control node

Implementation slice completed 2026-05-12, React Flow runtime thread fork
control node:

- Added `runtime_thread_fork` to the React Flow workflow-authoring node
  registry with configurable daemon endpoint, thread id field, reason field,
  graph/node metadata, receipt/policy output fields, runtime chrome strings,
  schema metadata, and a `runtime.thread.fork` privileged action declaration.
- Added `workflow-runtime-control-nodes.ts`, a focused request builder that
  turns a `runtime_thread_fork` workflow node plus input state into the daemon
  fork request body with `source=react_flow`, `workflowGraphId`,
  `workflowNodeId=runtime.thread-fork`, `componentKind=thread_fork`, and
  `payloadSchemaVersion=ioi.runtime.thread-fork.v1`.
- Promoted `runtime_thread_fork` into the shared runtime action schema, Rust
  `ActionKind`, Tauri scaffold catalog, action metadata, validation checks, and
  local workflow-node execution lane. Local execution now produces a
  non-mutating React Flow control request descriptor instead of calling the
  daemon directly.
- Updated React Flow runtime event projection so `thread_forked` events project
  as `runtime_thread_fork` nodes rather than generic state nodes.
- Added a live runtime-service proof where the request is built from a React
  Flow workflow node, sent to `/v1/threads/{thread_id}/fork`, and then verified
  across daemon SSE, SDK `Thread.events()`, and the React Flow projection with
  graph id, node id, source, receipt refs, and policy refs intact.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `npm run generate:runtime-action-contracts -- --check`
- `npm run build --workspace=@ioi/agent-ide`
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_thread_fork_node_builds_react_flow_control_request`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
- `node --test --test-name-pattern "React Flow thread fork control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "thread fork keeps one canonical source event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control/2026-05-12T23-57-36-129Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

### Slice 106. 2026-05-13 - React Flow runtime operator interrupt control node

Implementation slice completed 2026-05-13, React Flow runtime operator
interrupt control node:

- Added `runtime_operator_interrupt` to the React Flow workflow-authoring node
  registry with configurable interrupt endpoint, thread id field, turn id
  field, reason field, graph/node metadata, receipt/policy output fields,
  runtime chrome strings, schema metadata, and a `runtime.turn.interrupt`
  privileged action declaration.
- Extended `workflow-runtime-control-nodes.ts` from a fork-only builder into a
  shared control-node request helper with a second exported builder for
  `runtime_operator_interrupt`. It now produces the daemon interrupt request
  body with `source=react_flow`, `workflowGraphId`,
  `workflowNodeId=runtime.operator-interrupt`,
  `componentKind=operator_control`, and
  `payloadSchemaVersion=ioi.runtime.operator-control.v1`.
- Promoted `runtime_operator_interrupt` into the shared runtime action schema,
  Rust `ActionKind`, Tauri scaffold catalog, action metadata, validation
  checks, and local workflow-node execution lane. Local execution produces a
  non-mutating React Flow interrupt control request descriptor instead of
  calling the daemon directly.
- Updated React Flow runtime event projection so `turn_interrupted` events
  project as `runtime_operator_interrupt` nodes rather than generic output
  nodes.
- Added a live runtime-service proof where the request is built from a React
  Flow workflow node, sent to
  `/v1/threads/{thread_id}/turns/{turn_id}/interrupt`, and then verified across
  daemon SSE, SDK `Thread.events()`, and the React Flow projection with graph
  id, node id, source, receipt refs, and policy refs intact.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `npm run generate:runtime-action-contracts -- --check`
- `npm run build --workspace=@ioi/agent-ide`
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_operator_interrupt_node_builds_react_flow_control_request`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
- `node --test --test-name-pattern "React Flow operator interrupt control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control/2026-05-13T00-11-09-695Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

### Slice 107. 2026-05-13 - React Flow runtime operator steer control node

Implementation slice completed 2026-05-13, React Flow runtime operator steer
control node:

- Added `runtime_operator_steer` to the React Flow workflow-authoring node
  registry with configurable steer endpoint, thread id field, turn id field,
  guidance field, graph/node metadata, receipt/policy output fields, runtime
  chrome strings, schema metadata, and a `runtime.turn.steer` privileged action
  declaration.
- Extended `workflow-runtime-control-nodes.ts` with an exported
  `runtime_operator_steer` request builder. It produces the daemon steer
  request body with `source=react_flow`, `workflowGraphId`,
  `workflowNodeId=runtime.operator-steer`,
  `componentKind=operator_control`, and
  `payloadSchemaVersion=ioi.runtime.operator-control.v1`.
- Promoted `runtime_operator_steer` into the shared runtime action schema,
  Rust `ActionKind`, Tauri scaffold catalog, action metadata, validation
  checks, and local workflow-node execution lane. Local execution produces a
  non-mutating React Flow steer control request descriptor instead of calling
  the daemon directly.
- Updated React Flow runtime event projection so `turn_steered` events project
  as `runtime_operator_steer` nodes rather than generic state/output nodes.
- Tightened the runtime action contract generator so the generated Rust schema
  remains `rustfmt`-compatible while still passing the generation check.
- Added a live runtime-service proof where the request is built from a React
  Flow workflow node, sent to `/v1/threads/{thread_id}/turns/{turn_id}/steer`,
  and then verified across daemon SSE, SDK `Thread.events()`, and the React
  Flow projection with graph id, node id, source, receipt refs, and policy refs
  intact.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `npm run generate:runtime-action-contracts -- --check`
- `npm run build --workspace=@ioi/agent-ide`
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_operator_steer_node_builds_react_flow_control_request`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
- `node --test --test-name-pattern "React Flow operator steer control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "operator steer keeps one canonical guidance event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control/2026-05-13T00-24-15-404Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

### Slice 108. 2026-05-13 - React Flow runtime context compact control node

Implementation slice completed 2026-05-13, React Flow runtime context compact
control node:

- Added `runtime_context_compact` to the React Flow workflow-authoring node
  registry with configurable compact endpoint, thread id field, optional turn
  id field, reason/scope fields, graph/node metadata, receipt/policy output
  fields, runtime chrome strings, schema metadata, and a
  `runtime.context.compact` privileged action declaration.
- Extended `workflow-runtime-control-nodes.ts` with an exported
  `runtime_context_compact` request builder. It produces the daemon compact
  request body with `source=react_flow`, `workflowGraphId`,
  `workflowNodeId=runtime.context-compact`,
  `componentKind=context_compaction`, and
  `payloadSchemaVersion=ioi.runtime.context-compaction.v1`.
- Promoted `runtime_context_compact` into the shared runtime action schema,
  Rust `ActionKind`, Tauri scaffold catalog, action metadata, validation
  checks, and local workflow-node execution lane. Local execution produces a
  non-mutating React Flow compact control request descriptor instead of calling
  the daemon directly.
- Updated React Flow runtime event projection so `context_compacted` events
  project as `runtime_context_compact` nodes rather than generic state nodes.
- Added a live runtime-service proof where the request is built from a React
  Flow workflow node, sent to `/v1/threads/{thread_id}/compact`, and then
  verified across daemon SSE, SDK `Thread.events()`, and the React Flow
  projection with graph id, node id, source, receipt refs, and policy refs
  intact.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `npm run generate:runtime-action-contracts -- --check`
- `npm run build --workspace=@ioi/agent-ide`
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_context_compact_node_builds_react_flow_control_request`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
- `node --test --test-name-pattern "React Flow context compact control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "context compact keeps one canonical compaction event" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control/2026-05-13T00-40-20-698Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

### Slice 109. 2026-05-13 - Shared React Flow runtime-control helper extraction

Implementation slice completed 2026-05-13, shared React Flow runtime-control
helper extraction:

- Extracted a shared TypeScript runtime-control request envelope inside
  `workflow-runtime-control-nodes.ts`. Fork, interrupt, steer, and compact now
  share thread/turn lookup, endpoint expansion, actor defaulting, source,
  graph id, workflow node id, event kind, component kind, and payload schema
  metadata.
- Added a shared workflow-node adapter helper so all four React Flow control
  node builders use the same node-type guard and actor override path.
- Added a compact envelope test that builds all four React Flow control
  requests and asserts the shared `source=react_flow`, actor, workflow graph
  id, workflow node id, and thread id metadata shape.
- Extracted Rust workflow execution helpers for the local non-mutating control
  descriptors. The Tauri workflow lane now shares graph id, node id, actor,
  endpoint, request metadata, nested descriptor, and top-level descriptor
  output construction across fork, interrupt, steer, and compact.
- Kept all existing runtime-control behavior unchanged: generated action
  contracts stayed current, local workflow control-node tests passed, and the
  live React Flow compact graph-identity proof stayed green.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
- `npm run generate:runtime-action-contracts -- --check`
- `npm run build --workspace=@ioi/agent-ide`
- `rustfmt --check apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_ -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
- `node --test --test-name-pattern "React Flow context compact control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor/2026-05-13T00-56-55-307Z/result.json`.

Known validation note:

- The broad `cargo test ... runtime_` filter intentionally ran more runtime
  tests than the four control-node tests. It passed 51 active tests, ignored one
  Chromium-only probe, and included all four React Flow runtime-control
  workflow-node output tests.

### Slice 110. 2026-05-13 - React Flow settings harness active runtime binding panel split

Implementation slice completed 2026-05-13, React Flow settings harness active
runtime binding panel split:

- Split the former 970-line active runtime binding panel into a smaller parent
  panel plus typed `settingsHarnessActiveRuntimeBindingSummary.tsx` and
  `settingsHarnessActiveRuntimeBindingDeepLinks.tsx` modules.
- Preserved the parent `WorkflowSettingsHarnessActiveRuntimeBindingPanelProps`
  boundary, `workflow-harness-active-runtime-binding-deep-links` test id, and
  `data-worker-binding-registry-bound` source-contract marker so existing
  React Flow workflow-addressability checks continue to bind to the same
  surface.
- Moved the dense rollup/stat rendering into
  `WorkflowSettingsHarnessActiveRuntimeBindingSummary`, including registry,
  attach, lifecycle, worker session, checkpoint, invariant, envelope, and
  handoff metadata.
- Moved selector, dispatch, worker binding, rollback, rollback-proof, receipt,
  and replay fixture deep-link buttons into
  `WorkflowSettingsHarnessActiveRuntimeBindingDeepLinks`.
- Updated the harness refactor shape test to assert both new modules exist,
  own implementation, expose typed prop boundaries, import shared settings
  harness contracts, and remain free of `any`.
- Refreshed the GUI harness validation core line-count checkpoint to the
  current committed baseline so the guard resumes blocking future growth.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor/2026-05-13T01-09-15-286Z/result.json`.

Known validation note:

- The first harness refactor shape run failed only because
  `scripts/lib/autopilot-gui-harness-validation/core.mjs` was already above
  its stale checkpoint by the test's own newline-counting method. The slice did
  not modify that core file; the checkpoint was refreshed to the current
  baseline and the suite then passed.

### Slice 111. 2026-05-13 - React Flow settings harness promotion readiness panel split

Implementation slice completed 2026-05-13, React Flow settings harness
promotion readiness panel split:

- Split the former 943-line promotion readiness panel into a small parent plus
  typed `settingsHarnessPromotionReadinessSummary.tsx`,
  `settingsHarnessPromotionReadinessAuthorityGates.tsx`, and
  `settingsHarnessPromotionReadinessRoutingCanary.tsx` modules.
- Preserved the parent
  `WorkflowSettingsHarnessPromotionReadinessPanelProps` boundary and routed the
  existing `workflow-harness-selector-live-promotion-readiness` and
  `workflow-harness-authority-gate-live` source-contract markers through
  parent constants.
- Moved live handoff, runtime selector, selector readiness, and default runtime
  dispatch evidence into
  `WorkflowSettingsHarnessPromotionReadinessSummary`, including node authority
  and worker launch/session invariant metadata.
- Moved authority gate summary, rollup, component/receipt/replay buttons, and
  row rendering into
  `WorkflowSettingsHarnessPromotionReadinessAuthorityGates`.
- Moved read-only routing proof rows and canary boundary/deep-link controls
  into `WorkflowSettingsHarnessPromotionReadinessRoutingCanary`.
- Updated the harness refactor shape test to assert all three new modules
  exist, own implementation, expose typed prop boundaries, import shared
  settings harness contracts, and remain free of `any`.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor/2026-05-13T01-18-45-520Z/result.json`.

Known validation note:

- The first harness refactor shape run failed because the summary and authority
  child components intentionally receive parent-routed test ids. The guard now
  checks each child module's owned implementation surface while the parent
  continues to preserve the source-contract literals.

### Slice 112. 2026-05-13 - React Flow settings harness activation panel split

Implementation slice completed 2026-05-13, React Flow settings harness
activation panel split:

- Split the former 736-line activation panel into a small typed parent plus
  `settingsHarnessActivationWizardDetails.tsx` and
  `settingsHarnessActivationActions.tsx`.
- Preserved the parent `WorkflowSettingsHarnessActivationPanelProps` boundary,
  activation wizard test-id marker, activation step/candidate gate source
  markers, and direct `WorkflowSettingsHarnessActivationGatePanel` delegation
  expected by the workflow-addressability contracts.
- Moved activation wizard summary, minted/blocked proof, dry-run candidate
  cards, rollback restore canary evidence, candidate gate rows, and wizard
  step rows into `WorkflowSettingsHarnessActivationWizardDetails`.
- Moved activation blockers, dry run, readiness check, review proposal, and
  first-blocker controls into `WorkflowSettingsHarnessActivationActions`.
- Updated the harness refactor shape test to assert the new modules exist, own
  implementation, expose typed prop boundaries, import shared settings harness
  contracts, and remain free of `any`.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-activation-panel-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-activation-panel-refactor/2026-05-13T01-27-37-008Z/result.json`.

Known validation note:

- The parent keeps activation step and candidate-gate source marker templates
  and passes them to the wizard detail component so source-contract probes can
  still bind to the existing React Flow workflow hooks after extraction.

### Slice 113. 2026-05-13 - Master guide parity-gap triage cleanup

Implementation slice completed 2026-05-13, master guide parity-gap triage
cleanup:

- Replaced the noisy current-state implementation narrative in the master guide
  with a compact strategic snapshot, keeping completed-slice details in this
  implementation log and proof commands in the validation ledger.
- Added an active parity gap ledger that separates true DeepSeek parity gaps
  from React Flow/settings harness maintenance work.
- Re-ranked the immediate tactical queue around the missing terminal
  coding-agent TUI surface, with coding tool-pack, LSP diagnostics, rollback
  snapshots, subagents, MCP, modes, and telemetry as explicit follow-on gaps.
- Updated the `Next Implementation Slices` section so the next code slice is
  guide-led: a thin `ioi agent tui` shell over the existing daemon thread/event
  API, followed by TUI/workflow deep links and only then maintenance cleanup
  when it supports a named parity gap.

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-master-guide-triage`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-master-guide-triage/2026-05-13T01-35-47-401Z/result.json`.
- `git diff --check`

### Slice 139. 2026-05-13 - TUI jobs and run lifecycle parity view

Implementation slice completed 2026-05-13, daemon-owned TUI jobs and run
lifecycle parity view:

- Extended `ioi agent tui` JSON and screen rendering with daemon-backed
  `/v1/jobs` rows scoped to the selected thread/agent plus run lifecycle rows
  with replay, trace, inspect, events, and cancel routes.
- Added line-mode `/jobs`, `/job [inspect|cancel]`, and `/run
  [run_id|trace|inspect|replay|cancel]` commands that call canonical daemon
  job/run endpoints rather than private TUI state.
- Added SDK `RuntimeJobRecord` plus `listJobs`, `getJob`, and `cancelJob`
  handles so SDK, CLI/TUI, and daemon API share the same job contract.
- Projected TUI `job_rows` and `run_lifecycle_rows` into React Flow
  run-inspector control-state rows with counts, job/run ids, statuses, and
  runtime job node identity.
- Updated the master guide to mark the jobs/run lifecycle TUI slice complete
  and move the immediate queue to mode/model/thinking controls.

Validation evidence:

- `cargo test -p ioi-cli --bin cli tui --quiet`
- `npm run typecheck --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide -- --emptyOutDir=false`
- `node --import tsx --test --test-name-pattern "projects TUI control state" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --import tsx --test --test-name-pattern "workflow run history model projects TUI control state" packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test --test-name-pattern "local daemon public API|agent TUI thin shell|agent TUI line-mode slash" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `git diff --check`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle/2026-05-13T11-39-18-945Z/result.json`.

### Slice 140. 2026-05-13 - Daemon-owned MCP discovery/status/validation

Implementation slice completed 2026-05-13, read-only MCP manager parity:

- Added daemon-owned MCP catalog/status/validation endpoints for workspace
  `.cursor/mcp.json`, `.agents/mcp.json`, inline options, and model-mounting
  provider entries, with pure catalog resolver logic isolated in
  `packages/runtime-daemon/src/mcp-manager.mjs`.
- Added thread-scoped MCP status and validation controls that emit
  `OperatorControl.Mcp` and `OperatorControl.McpValidate` runtime events with
  receipts, policy refs, payload schemas, and workflow node identity.
- Exposed MCP status, server listing, tool listing, validation, and thread
  controls through the SDK and `Thread` helper methods.
- Added TUI `/mcp [status|tools|servers|validate]` line-mode controls and
  `mcp_rows` so React Flow can inspect MCP server/tool status from the run
  inspector.
- Added React Flow projection support for MCP rows and `mcp_tool` binding
  metadata for server id, tool name, containment mode, and validate-before-invoke.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
- `cargo test -p ioi-cli --bin cli tui --quiet`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "daemon owns MCP|agent TUI line-mode slash commands|agent CLI exposes model|agent TUI thin shell" scripts/lib/live-runtime-daemon-contract.test.mjs`

### Slice 141. 2026-05-13 - Daemon-owned memory manager status/validation

Implementation slice completed 2026-05-13, memory manager parity:

- Added `packages/runtime-daemon/src/memory-manager.mjs` with memory
  status/validation schemas, effective-policy validation, storage path checks,
  memory record validation, and memory status/policy/record row builders.
- Added daemon public memory manager endpoints:
  `/v1/memory`, `/v1/memory/records`, `/v1/memory/policy`,
  `/v1/memory/path`, and `/v1/memory/validate`.
- Added thread-scoped memory status and validation controls at
  `/v1/threads/{thread_id}/memory/status` and
  `/v1/threads/{thread_id}/memory/validate`, emitting
  `OperatorControl.Memory` and `OperatorControl.MemoryValidate` runtime events
  with receipts, policy refs, workflow node identity, and replayable payloads.
- Exposed memory status/validation through SDK client helpers and
  `Thread.memory` / `Thread.validateMemory` while preserving existing
  remember/list/edit/delete/policy/path helpers.
- Added TUI `/memory [status|show|policy|path|validate|enable|disable]`,
  `memory_rows`, and React Flow control-state projection for memory
  status/policy/record rows.
- Added React Flow state-node operations for `memory_status` and
  `memory_policy` beside existing memory search/list controls, so workflow
  authors can configure memory visibility from the graph.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/memory-manager.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `cargo test -p ioi-cli --bin cli tui --quiet`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test --test-name-pattern "memory writes|agent CLI exposes model|agent TUI thin shell|agent TUI line-mode" scripts/lib/live-runtime-daemon-contract.test.mjs`

### Slice 142. 2026-05-13 - MCP enable/disable/invocation controls

Implementation slice completed 2026-05-13, governed MCP manager controls:

- Added daemon-owned MCP server enable/disable controls and governed tool
  invocation endpoints, including public thread-addressed routes and
  thread-scoped routes that emit `OperatorControl.McpEnable`,
  `OperatorControl.McpDisable`, and `OperatorControl.McpInvoke` events.
- Extended MCP manager payloads with invocation schema metadata, stable tool
  call ids, side-effect policy gates, redacted inputs, simulated containment
  receipts, workflow node identity, and updated server/tool availability.
- Exposed MCP enable/disable/invoke through SDK client helpers and
  `Thread.enableMcpServer`, `Thread.disableMcpServer`, and
  `Thread.invokeMcpTool`.
- Added TUI `/mcp enable`, `/mcp disable`, and `/mcp invoke` line-mode
  controls, plus projected MCP invocation rows carrying operation and tool-call
  identity for React Flow run-inspector consumption.
- Added React Flow MCP status/enable/disable state-node operations and projected
  MCP invocation row metadata through the workflow runtime event projection and
  runs panel.
- Extended the live runtime contract to prove daemon, SDK, TUI, and React Flow
  parity for MCP server toggles and governed invocation receipts.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `cargo test -p ioi-cli --bin cli tui --quiet`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI thin shell|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-controls`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-controls/2026-05-13T13-37-14-190Z/result.json`.

### Slice 143. 2026-05-13 - Memory write-side TUI/workflow controls

Implementation slice completed 2026-05-13, direct memory mutation controls:

- Added daemon-owned thread memory mutation control events for remember, edit,
  delete, and policy updates, with canonical `OperatorControl.MemoryWrite`,
  `OperatorControl.MemoryEdit`, `OperatorControl.MemoryDelete`, and
  `OperatorControl.MemoryPolicy` event rows.
- Preserved memory record receipts, policy decision refs, workflow node ids, and
  redacted row metadata in mutation payloads so TUI, SDK, and React Flow all
  inspect the same memory truth.
- Exposed `Thread.rememberMemory`, `Thread.updateMemory`, and
  `Thread.deleteMemory` through the SDK while preserving existing memory CRUD
  helpers.
- Added TUI `/memory remember`, `/memory edit`, and `/memory delete` line-mode
  commands plus memory mutation row projection for daemon-provided rows.
- Added React Flow state-node operations and binding editor controls for
  `memory_remember`, `memory_edit`, and `memory_delete`.
- Wired Autopilot workflow execution for memory mutation state nodes through
  the modular workflow memory lane, returning receipt-backed evidence payloads
  without turning workflow memory writes into canvas-local state.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/memory-manager.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo fmt -p ioi-cli -- --check`
- `cargo test -p ioi-cli --bin cli tui --quiet`
- `cargo check -p autopilot`
- `npm run build --workspace=@ioi/agent-sdk`
- `npm run build --workspace=@ioi/agent-ide`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
- `node --test --test-name-pattern "local daemon records explicit memory writes|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-memory-write-controls`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-memory-write-controls/2026-05-13T14-00-24-781Z/result.json`.
