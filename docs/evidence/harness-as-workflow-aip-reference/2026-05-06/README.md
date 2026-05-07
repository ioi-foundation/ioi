# Harness-As-Workflow AIP Reference Screenshots

Captured: 2026-05-06
Source: user-provided screenshots from a read-only Palantir AIP Pipeline Builder
session.
Purpose: reference evidence for graph ergonomics, right-rail mechanics,
focused group workbenches, and bottom-workbench behavior in the
agent-runtime harness-as-workflow leg.

These screenshots are not product requirements and should not be treated as
visual design direction. They are evidence for interaction patterns to map into
IOI's own workflow and runtime substrate.

## Screenshot Index

| File | Reference mechanics |
| --- | --- |
| `01-main-graph-right-rail.png` | Main graph altitude with right-side output inventory, output settings, posture banner, legend, and bottom shelf. |
| `02-main-graph-selected-node.png` | Main graph with selected grouped node and right rail/bottom shelf still available. |
| `03-main-graph-selection-preview.png` | Main graph with selection preview empty state and output cards in the right rail. |
| `04-expanded-group-collapsed-data.png` | Focused expanded group view with bottom table shell and mini graph in the rail. |
| `05-expanded-group-output-table.png` | Expanded group with output table preview, columns, row sample, and mini graph. |
| `06-expanded-group-output-table-mini-graph.png` | Expanded group showing output table plus mini graph and right rail output inventory. |
| `07-graph-plus-transform-bottom-workbench.png` | Graph plus bottom transform workbench, showing how detail can be exposed without losing graph context. |

## Mapped Requirements

- Collapsible/expandable grouped nodes must preserve typed boundary ports.
- Collapsed groups must roll up warnings, blockers, receipt health, tests,
  replay status, policy requirements, and live/shadow divergence.
- Expanded groups should be deep-linkable and should expose a focused workbench
  for inner-node steps.
- The right rail should support multiple operational modes: receipts/outputs,
  search, live-vs-shadow change comparison, activation/deploy posture, runtime
  settings, schedules/triggers, component tree, tests, sources/inputs, policy,
  and capabilities.
- A mini graph should remain available while a group is expanded so users keep
  whole-harness orientation.
- The bottom shelf should be selection-sensitive and should switch between
  preview, IO, warnings, fixtures, checkpoints, proposal diff, tests, and run
  output.
- Input/output previews should expose schema fields, redaction state, sample
  counts, event counts, receipt refs, replay rows, and run attempts.
