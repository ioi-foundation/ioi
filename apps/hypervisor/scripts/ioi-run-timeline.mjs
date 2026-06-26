// Hypervisor's OWN transcript primitive: the Run / Activity Timeline projection.
//
// Hypervisor is a workbench for GOVERNED work, not a generic chat — so we own the conversation
// surface instead of borrowing the harvested SPA's chat pane. This module projects a run (the
// app-side view of a daemon execution) into a structured timeline whose every section is real
// daemon/run truth (NO FAKES — absent data becomes a named empty state, never a placeholder):
//
//   1. request    — the user's ask
//   2. activity   — agent status / thinking / tool + the governed-work steps (authority → grant → exec)
//   3. response   — the agent's answer
//   4. artifacts  — files changed / drafts / terminal events
//   5. proof      — authority grant + receipts + proposal/lease refs (the governance audit trail)
//   6. followUps  — the next governed actions available from here
//
// The projection is pure: the serve layer fetches daemon records (authority receipts, drafts) and
// passes them in; the daemon EXECUTES + RECORDS, this only PRESENTS.

const PHASE_BY_STATUS = {
  waiting: "AGENT_EXECUTION_PHASE_PENDING",
  running: "AGENT_EXECUTION_PHASE_RUNNING",
  done: "AGENT_EXECUTION_PHASE_STOPPED",
  failed: "AGENT_EXECUTION_PHASE_FAILED",
};

// Classify a governed-work step so the UI can icon/colour it without re-parsing prose.
function classifyActivity(text) {
  const t = String(text || "").toLowerCase();
  if (/authority|authoriz|grant|wallet/.test(t)) return "authority";
  if (/working|agent working|executing|harness/.test(t)) return "tool";
  if (/draft|proposal|pull[- ]request/.test(t)) return "artifact";
  if (/^done$|complete/.test(t)) return "done";
  if (/fail|blocked|error/.test(t)) return "error";
  if (/thinking|preparing|requesting/.test(t)) return "thinking";
  return "status";
}

function runFiles(run) {
  const files = [];
  for (const g of run?.changedFiles || []) {
    if (Array.isArray(g?.files)) for (const f of g.files) files.push(typeof f === "string" ? f : f?.path);
    else if (typeof g === "string") files.push(g);
    else if (g?.path) files.push(g.path);
  }
  return [...new Set(files.filter(Boolean))];
}

function terminalEvents(run) {
  // The harness returns terminal_events; surface command/output lines (bounded) as artifacts.
  const out = [];
  for (const e of run?.transcript || []) {
    const text = String(e?.text || "").trim();
    if (!text || text.startsWith("__HYPERVISOR")) continue;
    out.push({ stream: e?.stream || "stdout", text: text.length > 600 ? text.slice(0, 600) + "…" : text });
    if (out.length >= 20) break;
  }
  return out;
}

// Derive the governed next-actions available from the run's current state.
function followUps(run) {
  const ups = [];
  if (run?.envId) {
    ups.push({ label: "Open editor", kind: "editor", href: `/__ioi/editor/open?environmentId=${encodeURIComponent(run.envId)}` });
    ups.push({ label: "Open workbench", kind: "workbench", href: `/details/${encodeURIComponent(run.envId)}` });
  }
  if (run?.status === "done" && !run?.proposalRef) {
    ups.push({ label: "Create PR draft", kind: "pr", prompt: "Create a pull request for the current changes." });
  }
  if (runFiles(run).length) ups.push({ label: "Review changed files", kind: "files", count: runFiles(run).length });
  return ups;
}

export function projectRunTimeline(run, extra = {}) {
  if (!run) return null;
  const { authorityReceipts = [], drafts = [] } = extra;
  const files = runFiles(run);

  // --- 2) activity: governed-work steps (timestamped history) ---
  const activity = (run.activityLog || []).map((s) => ({ kind: classifyActivity(s.text), text: s.text, at: s.at }));
  if (!activity.length && run.activity) activity.push({ kind: classifyActivity(run.activity), text: run.activity, at: run.updatedAt });

  // --- 5) proof: the governance audit trail (authority crossing + receipts + refs) ---
  const myReceipts = (authorityReceipts || []).filter((r) => {
    const blob = JSON.stringify(r || {});
    return (run.authority?.requestHash && blob.includes(run.authority.requestHash)) ||
           (run.authority?.policyHash && blob.includes(run.authority.policyHash)) ||
           (run.sessionRef && blob.includes(run.sessionRef));
  });
  const proof = {
    authority: run.authority || null,
    receipts: myReceipts,
    leaseRef: run.capabilityLeaseRef || null,
    proposalRefs: [run.proposalRef].filter(Boolean),
    stateRoot: run.stateRoot || null, // #3 — tamper-evident handle of the durable daemon record
    // when no authority was minted (no gate), say so plainly rather than implying ungoverned exec
    note: run.authority ? null : (run.status === "done" || run.status === "failed" ? "No wallet gate was required for this run." : null),
  };

  // --- 4) artifacts ---
  const artifacts = {
    files,
    drafts: (drafts || []).filter((d) => d?.environment_id === run.envId).map((d) => ({
      id: d.draft_id, title: d.title, reviewState: d.review_state, summary: d.artifact_refs?.summary,
      patch: d.artifact_refs?.patch, changedFiles: d.changed_files || [], remotePublish: d.remote_publish || null,
    })),
    terminals: terminalEvents(run),
  };

  // --- the turn (the run model is single-turn today; the shape supports multi-turn) ---
  const turn = {
    id: `${run.id}-t1`,
    request: run.prompt ? { text: run.prompt, at: run.createdAt, blockId: run.userInputBlockId } : null,
    activity,
    response: (run.status === "done" || run.status === "failed")
      ? { text: run.status === "failed" ? (run.error || "Run failed.") : (run.summary || "Run complete."), at: run.updatedAt, failed: run.status === "failed" }
      : null,
    artifacts,
    proof,
    followUps: followUps(run),
  };

  return {
    schema_version: "ioi.hypervisor.run-timeline.v1",
    runId: run.id,
    environmentId: run.envId || null,
    sessionRef: run.sessionRef || null,
    title: run.name || (run.prompt ? run.prompt.slice(0, 80) : "Agent session"),
    status: run.status,
    phase: PHASE_BY_STATUS[run.status] || "AGENT_EXECUTION_PHASE_PENDING",
    activeStatus: run.activity || null,
    stateRoot: run.stateRoot || null, // #3 durability handle (daemon-recorded)
    durable: !!run.stateRoot,
    createdAt: run.createdAt,
    updatedAt: run.updatedAt,
    turns: [turn],
  };
}
