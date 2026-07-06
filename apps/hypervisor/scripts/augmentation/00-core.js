// WS-I / WS-F — injected IOI-native surface (the IOI-native cockpit panel + owned Run Timeline).
//
// The seeded reference cockpit has no slot for IOI-native objects (operator authority, environment
// lifecycle/isolation posture + services/tasks/ports, the WorkRun patch branch + its
// model-driven turns, the scoped terminal, receipts). This vanilla script mounts an IOI-native
// panel beside the cockpit (same mechanism as the brand boot-guard) that reads AND drives the
// daemon via /api/ioi/*. It owns no truth — the daemon is the source.
//
// CANONICAL OWNERSHIP: Hypervisor owns its conversation surface. On the workbench we REPLACE the
// seeded transcript in-pane with our Run Timeline (mounted as an iframe to /__ioi/run-timeline,
// the owned governed-work surface), keeping the native composer so follow-ups still post through
// the adapter. This is the one place we deliberately edit the seeded SPA's DOM (the transcript region of
// [data-testid=environment-agent-execution-conversation]); everything else stays hands-off.
//
// Boundary: daemon EXECUTES · wallet AUTHORIZES crossings · agentgres RECORDS (receipts).
(function () {
  if (window.__ioiAugmentationMounted) return;
  window.__ioiAugmentationMounted = true;

