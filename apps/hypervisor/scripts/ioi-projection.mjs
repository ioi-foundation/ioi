// IOI projection layer — maps the daemon's governed objects onto the borrowed UI's
// Gitpod-shaped contract. PROJECTION ONLY.
//
// Boundary discipline (do not inflate any plane beyond its verb):
//   daemon      EXECUTES  — owns the governed objects (Project/Session/WorkRun/Env/Events)
//   wallet.net  AUTHORIZES — only where an action crosses into delegated authority
//                            (secret release, spend, decryption, declassification, restore/apply)
//   agentgres   RECORDS   — evidence/receipts/state roots; surfaced as *refs* only
//   IOI L1      SETTLES
//
// Mappers here translate daemon shapes -> UI shapes. They must never imply wallet or
// agentgres "do" the work, and must not become a second source of truth (the daemon is
// the source of truth; this is a view).

// ---- Session (daemon thread -> Gitpod agentExecution) ----
export function threadToAgentExecution(t) {
  const id = t.thread_id || t.id;
  const running = (t.status || "active") === "active";
  const phase = running ? "AGENT_EXECUTION_PHASE_RUNNING" : "AGENT_EXECUTION_PHASE_STOPPED";
  const session = t.session_id || id;
  const title = t.title && t.title.trim() && t.title.trim() !== "." ? t.title.trim() : "Untitled session";
  return {
    id,
    metadata: {
      name: title,
      creator: { id: "local-operator", principal: "PRINCIPAL_USER" },
      createdAt: t.created_at,
      updatedAt: t.updated_at || t.created_at,
      role: "AGENT_EXECUTION_ROLE_DEFAULT",
    },
    spec: {
      specVersion: "2",
      session,
      desiredPhase: running ? "PHASE_RUNNING" : "PHASE_STOPPED",
      agentId: t.agent_id || "00000000-0000-0000-0000-000000007800",
      // HarnessBinding ref (daemon-owned). Surfaced as a ref; wallet authority is only
      // invoked by the daemon at delegated-authority crossings, never here.
      harnessBindingRef: t.harness_binding_id || null,
      codeContext: t.workspace ? { environmentId: t.workspace } : {},
      limits: {},
    },
    status: {
      statusVersion: String(t.latest_seq || 1),
      session,
      phase,
      // WorkRun ref (daemon-owned). The borrowed UI is session-centric and folds the
      // WorkRun into the session; we expose the latest run/turn as a ref.
      latestWorkRunRef: t.latest_turn_id || null,
      // agentgres RECORDS evidence; surfaced as refs only.
      evidenceRefs: Array.isArray(t.evidence_refs) ? t.evidence_refs : [],
    },
  };
}

// ---- WorkRun (daemon run) status -> a coarse phase the session view can show ----
export function runPhase(run) {
  const s = (run && (run.status || run.state)) || "";
  if (/run|active|progress/i.test(s)) return "WORK_RUN_PHASE_RUNNING";
  if (/done|complete|success|finish/i.test(s)) return "WORK_RUN_PHASE_SUCCEEDED";
  if (/fail|error/i.test(s)) return "WORK_RUN_PHASE_FAILED";
  if (/cancel|stop/i.test(s)) return "WORK_RUN_PHASE_STOPPED";
  return "WORK_RUN_PHASE_QUEUED";
}

// ---- Project (daemon project -> Gitpod project) ----
// The daemon is the source of truth; this maps its project record to the UI shape.
export function daemonProjectToGitpod(p) {
  return {
    id: p.id || p.project_id,
    metadata: {
      organizationId: p.organization_id || p.organizationId || "",
      name: p.name || p.title || "Untitled project",
      creator: { id: "local-operator", principal: "PRINCIPAL_USER" },
      createdAt: p.created_at || p.createdAt,
      updatedAt: p.updated_at || p.updatedAt || p.created_at,
    },
    initializer: p.initializer || { specs: [] },
    environmentClasses: p.environment_classes || p.environmentClasses || [],
  };
}
