// Hypervisor's OWN transcript primitive: the Run / Activity Timeline projection.
//
// Hypervisor is a workbench for GOVERNED work, not a generic chat — so we own the conversation
// surface instead of borrowing the product-ui bundle's chat pane. This module projects a run (the
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
  awaiting_operator_approval: "AGENT_EXECUTION_PHASE_PENDING",
  awaiting_wallet_authority: "AGENT_EXECUTION_PHASE_PENDING",
  done: "AGENT_EXECUTION_PHASE_STOPPED",
  denied: "AGENT_EXECUTION_PHASE_STOPPED",
  failed: "AGENT_EXECUTION_PHASE_FAILED",
};

// M13.4 truth-rebind: the daemon's session record, its receipts and its workspace events are the
// panes' source of truth. The serve's run cache contributes the request text, the activity log and
// the parked-approval state; everything about lifecycle, receipts, leases and written files that
// the daemon holds is projected FROM the daemon records passed in `extra` and labelled as such.
function daemonReceiptSummary(receipt) {
  if (!receipt || typeof receipt !== "object") return null;
  return {
    id: receipt.id || null,
    kind: receipt.kind || null,
    status: receipt.status || null,
    exitStatus: receipt.exit_status ?? receipt.exitStatus ?? null,
    lane: receipt.lane || null,
    capabilityLeaseRef: receipt.capability_lease_ref || null,
    authorityScopeRefs: Array.isArray(receipt.authority_scope_refs) ? receipt.authority_scope_refs : [],
    startedAt: receipt.started_at || null,
    recordedAt: receipt.recorded_at || receipt.finished_at || receipt.recovered_at || null,
    source: "daemon-runtime",
  };
}

function daemonChangedFiles(sessionEvents) {
  const groups = sessionEvents?.workspace_diff?.changed_file_groups
    || (sessionEvents?.events || []).find((e) => e?.changed_file_groups)?.changed_file_groups
    || sessionEvents?.changed_file_groups
    || [];
  const files = [];
  for (const group of groups) for (const f of group?.files || group?.paths || []) files.push({ path: typeof f === "string" ? f : (f.path || f.file || String(f)), group: group?.kind || group?.label || null, source: "daemon-runtime" });
  return files;
}

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
  const { authorityReceipts = [], drafts = [], hasConnector = false, session = null, sessionReceipts = [], sessionEvents = null } = extra;
  const cachedFiles = runFiles(run);
  const daemonFiles = daemonChangedFiles(sessionEvents);
  const files = cachedFiles.length ? cachedFiles : daemonFiles.map((f) => f.path);
  const publishReceipts = Array.isArray(run.publishReceipts) ? run.publishReceipts : [];

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
  const daemonReceipts = (sessionReceipts || []).map(daemonReceiptSummary).filter(Boolean);
  const executeReceipt = daemonReceipts.find((r) => r.kind === "hypervisor.session.execute") || null;
  const proof = {
    // The session as the DAEMON holds it: lifecycle truth and the receipt refs on the record.
    session: session ? {
      ref: session.session_ref || run.sessionRef || null,
      lifecycleState: session.lifecycle_state || null,
      environmentRef: session.environment_ref || null,
      latestReceiptRefs: Array.isArray(session.latest_receipt_refs) ? session.latest_receipt_refs : [],
      authorityProfile: session.authority_profile || null,
      source: "daemon-runtime",
    } : null,
    daemonReceipts,
    authority: run.authority || null,
    receipts: myReceipts,
    leaseRef: run.capabilityLeaseRef || executeReceipt?.capabilityLeaseRef || null,
    proposalRefs: [run.proposalRef].filter(Boolean),
    publishReceipts: publishReceipts.map((p) => ({ branch: p.branch, remoteUrl: p.remote_url, commit: p.commit_sha, grantRef: p.grant_ref, at: p.published_at })),
    stateRoot: run.stateRoot || null, // #3 — tamper-evident handle of the durable daemon record
    // when no authority was minted (no gate), say so plainly rather than implying ungoverned exec
    note: run.authority ? null : (run.status === "done" || run.status === "failed" ? "No wallet gate was required for this run." : null),
  };

  // --- 4) artifacts ---
  const artifacts = {
    files,
    daemonFiles,
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
    // The parked operator decision, reachable from wherever the run was submitted: the exact
    // effect and its commitments, and the serve's approve/deny endpoints under the operator's own
    // session. Approving signs exactly this challenge; denying mints nothing.
    approval: run.pendingApproval ? {
      state: run.status === "awaiting_operator_approval" ? "awaiting" : (run.pendingApproval.decision || "decided"),
      kind: run.pendingApproval.kind || null,
      sessionRef: run.pendingApproval.session_ref || run.sessionRef || null,
      intent: run.pendingApproval.intent || run.prompt || null,
      policyHash: run.pendingApproval.policy_hash || null,
      requestHash: run.pendingApproval.request_hash || null,
      audience: run.pendingApproval.audience || null,
      requiredScopes: run.pendingApproval.required_scopes || [],
      requestedAt: run.pendingApproval.requested_at || null,
      decision: run.pendingApproval.decision || null,
      decidedAt: run.pendingApproval.decided_at || null,
      approveUrl: run.status === "awaiting_operator_approval" ? `/__ioi/runs/${encodeURIComponent(run.id)}/approve` : null,
      denyUrl: run.status === "awaiting_operator_approval" ? `/__ioi/runs/${encodeURIComponent(run.id)}/deny` : null,
    } : null,
    response: (run.status === "done" || run.status === "failed")
      ? { text: run.status === "failed" ? (run.error || "Run failed.") : (run.summary || "Run complete."), at: run.updatedAt, failed: run.status === "failed" }
      : null,
    artifacts,
    proof,
    followUps: (() => {
      const ups = followUps(run);
      // Governed "Publish PR" command (the wallet-authorized SCM crossing) — offered only when there
      // are changes to publish, a usable connector is registered, and it hasn't been published yet.
      if (hasConnector && run.status === "done" && files.length && !publishReceipts.length) {
        ups.push({ label: "Publish PR", kind: "publish", post: `/__ioi/run-publish/${run.id}` });
      }
      return ups;
    })(),
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
