// IOI agent-run registry — the compose→run spine for the served reference app.
//
// CreateAgentSession (the /ai composer's submit) maps to a REAL daemon loop:
//   create environment → start (real workspace + git) → create env-bound session →
//   challenge for the execution-authority hashes → mint a signed wallet grant →
//   sessions/:id/execute (the generic-cli-local harness drives the local model and edits
//   the env workspace). The execute is long-running, so CreateAgentSession returns as soon
//   as the env exists and the run is registered; the harness runs async and this registry
//   tracks status + transcript + changed files for GetAgentExecution / ListAgentExecutions
//   and the conversation stream. The daemon EXECUTES; this is an app-side view of its run.
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";
import { daemonEnvToGitpod } from "./ioi-projection.mjs";

const runs = new Map(); // agentExecutionId -> run
const nowIso = () => new Date().toISOString();
let counter = 0;
const genId = (prefix) => `${prefix}_${Date.now().toString(36)}${(counter++).toString(36)}`;

export function getRun(id) {
  return runs.get(id);
}
export function listRuns() {
  return [...runs.values()];
}

// Extract the user's task text from the connect-es CreateAgentSession request, which serializes
// the InitialInput oneof a few ways depending on client version. Defensive across shapes.
export function extractPrompt(body) {
  // Compose sends the task via SendToAgentExecution.userInput.inputs[].text.content (also
  // CreateAgentSession.initialInput.inputs[...]). Defensive across both shapes + client versions.
  const inputs = body?.userInput?.inputs || body?.initialInput?.inputs || body?.initial_input?.inputs || [];
  for (const item of inputs) {
    const text = item?.text?.content ?? item?.input?.value?.content ?? item?.value?.content ?? item?.content;
    if (typeof text === "string" && text.trim()) return text.trim();
  }
  for (const key of ["text", "prompt", "input", "content", "message"]) {
    if (typeof body?.[key] === "string" && body[key].trim()) return body[key].trim();
  }
  if (typeof body?.initialInput?.text === "string" && body.initialInput.text.trim()) return body.initialInput.text.trim();
  return "";
}

// Extract the chosen environment class id from the CreateEnvironment spec (oneof flattened).
export function extractEnvClass(body) {
  const specs = [
    body?.createEnvironment?.spec,
    body?.createEnvironmentFromProject?.spec,
    body?.environment?.createEnvironment?.spec,
    body?.environment?.value?.spec,
    body?.environment?.spec,
    body?.spec,
  ].filter(Boolean);
  for (const spec of specs) {
    const cls =
      spec?.machine?.class ?? spec?.machineClass ?? spec?.machine_class ?? spec?.environmentClassId ?? spec?.class;
    if (typeof cls === "string" && cls.trim()) return cls.trim();
  }
  const flat = body?.environmentClassId || body?.environment_class_id || body?.machineClass;
  return typeof flat === "string" && flat.trim() ? flat.trim() : null;
}

function deriveName(prompt) {
  const clean = (prompt || "").replace(/\s+/g, " ").trim();
  if (!clean) return "Agent session";
  return clean.length > 60 ? `${clean.slice(0, 57)}…` : clean;
}

// Project a registry run onto the Gitpod AgentExecution shape the SPA renders.
export function runToAgentExecution(run) {
  const phase =
    run.status === "running" || run.status === "waiting"
      ? "AGENT_EXECUTION_PHASE_RUNNING"
      : run.status === "failed"
        ? "AGENT_EXECUTION_PHASE_FAILED"
        : "AGENT_EXECUTION_PHASE_STOPPED";
  const convo = `/__ioi/agent-runs/${run.id}/conversation`;
  return {
    id: run.id,
    metadata: {
      name: run.name,
      creator: { id: "local-operator", principal: "PRINCIPAL_USER" },
      createdAt: run.createdAt,
      updatedAt: run.updatedAt,
      role: "AGENT_EXECUTION_ROLE_DEFAULT",
    },
    spec: {
      specVersion: "2",
      session: run.sessionRef,
      desiredPhase: run.status === "running" ? "PHASE_RUNNING" : "PHASE_STOPPED",
      agentId: run.agentId,
      harnessBindingRef: run.sessionRef,
      codeContext: { environmentId: run.envId },
      limits: {},
    },
    status: {
      statusVersion: String(run.statusVersion),
      session: run.sessionRef,
      phase,
      conversationUrl: convo,
      transcriptUrl: convo,
      // history → empty-but-valid JSON; live → a long-lived keepalive SSE (held open so the SPA
      // does NOT reconnect-loop). Both at the same endpoint, which branches on the Accept header.
      conversationUrls: { history: convo, live: convo, blobs: "" },
      currentActivity: run.activity,
      iterations: run.iterations,
      inputTokensUsed: 0,
      outputTokensUsed: 0,
      cachedInputTokensUsed: 0,
      contextWindowLength: 0,
      usedEnvironments: [{ environmentId: run.envId }],
    },
  };
}

// Start a real agent run. `daemonBase` is the hypervisor-daemon origin. Returns the immediate
// projection ({ agentExecutionId, environment, userInputBlockId }) once the env exists; the
// harness executes asynchronously and updates the run in place.
export async function startAgentRun({ daemonBase, prompt, environmentClassId }) {
  const base = daemonBase.replace(/\/$/, "");
  const dj = async (method, path, payload) => {
    const res = await fetch(base + path, {
      method,
      headers: payload ? { "content-type": "application/json" } : undefined,
      body: payload ? JSON.stringify(payload) : undefined,
    });
    const text = await res.text();
    let parsed = {};
    try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { _raw: text }; }
    return { status: res.status, body: parsed };
  };

  const cls = environmentClassId || "local-workspace-v0";
  const created = await dj("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: cls, project_id: "ai-session" } });
  const envRecord = created.body?.environment;
  const envId = envRecord?.id;
  if (!envId) throw new Error(`env create failed (${created.status})`);
  const started = await dj("POST", `/v1/hypervisor/environments/${encodeURIComponent(envId)}/start`);
  const envGitpod = daemonEnvToGitpod(started.body?.environment || envRecord);

  const id = genId("agent");
  const sessionRef = `session:ai-${id}`;
  await dj("POST", "/v1/hypervisor/sessions", { session_ref: sessionRef, project_ref: "project:ai", environment_id: envId });

  const run = {
    id,
    agentId: genId("agentdef"),
    envId,
    env: envGitpod,
    sessionRef,
    prompt,
    name: deriveName(prompt),
    status: "running",
    activity: "Provisioning environment…",
    iterations: 1,
    statusVersion: 1,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    transcript: [],
    changedFiles: [],
    summary: null,
    error: null,
  };
  runs.set(id, run);

  // Async harness execution (challenge → mint → execute). Never throws into the caller.
  void executeRun(run, base, dj);

  return { agentExecutionId: id, environment: envGitpod, userInputBlockId: genId("blk"), envId };
}

// Register a run bound to an ALREADY-created environment (the compose flow's StartAgent step:
// CreateEnvironment made the env, StartAgent binds the agent to codeContext.environmentId). No
// prompt yet — the harness kicks off on SendToAgentExecution.
export function registerAgentRun({ envId }) {
  const id = genId("agent");
  const run = {
    id,
    agentId: genId("agentdef"),
    envId,
    env: null,
    sessionRef: `session:ai-${id}`,
    sessionStarted: false,
    prompt: null,
    name: "Agent session",
    status: "waiting",
    activity: "Ready for instructions…",
    iterations: 1,
    statusVersion: 1,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    transcript: [],
    changedFiles: [],
    summary: null,
    error: null,
  };
  runs.set(id, run);
  return run;
}

// Attach the task prompt to a run and kick off the real harness execution (bound session →
// challenge → mint grant → execute). The compose flow calls this via SendToAgentExecution.
export async function sendToAgentRun({ daemonBase, runId, prompt }) {
  const run = runs.get(runId);
  if (!run) return false;
  run.prompt = prompt;
  run.name = deriveName(prompt);
  run.status = "running";
  bump(run, "Agent working in the environment…");
  const base = daemonBase.replace(/\/$/, "");
  const dj = async (method, path, payload) => {
    const res = await fetch(base + path, {
      method,
      headers: payload ? { "content-type": "application/json" } : undefined,
      body: payload ? JSON.stringify(payload) : undefined,
    });
    const text = await res.text();
    let parsed = {};
    try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { _raw: text }; }
    return { status: res.status, body: parsed };
  };
  if (!run.sessionStarted) {
    // The session binds to the env's workspace — but the compose flow may not have finished
    // starting the env yet. Ensure it's started (real workspace_root) BEFORE binding, else the
    // session falls back to a throwaway temp dir and the editor (bound to the env) won't see edits.
    await ensureEnvStarted(dj, run.envId);
    await dj("POST", "/v1/hypervisor/sessions", { session_ref: run.sessionRef, project_ref: "project:ai", environment_id: run.envId });
    run.sessionStarted = true;
  }
  void executeRun(run, base, dj);
  return true;
}

// Idempotently start the env and wait until it has a real workspace_root (so a bound session +
// the editor operate on the same files). Returns the workspace_root or null on timeout.
async function ensureEnvStarted(dj, envId) {
  const path = `/v1/hypervisor/environments/${encodeURIComponent(envId)}`;
  for (let i = 0; i < 40; i++) {
    const g = await dj("GET", path);
    const wsRoot = g.body?.environment?.status?.workspace_root;
    if (wsRoot) return wsRoot;
    if (i === 0) await dj("POST", `${path}/start`).catch(() => {});
    await new Promise((r) => setTimeout(r, 750));
  }
  return null;
}

function bump(run, activity) {
  if (activity) run.activity = activity;
  run.updatedAt = nowIso();
  run.statusVersion += 1;
}

async function executeRun(run, base, dj) {
  const execPath = `/v1/hypervisor/sessions/${encodeURIComponent(run.sessionRef)}/execute`;
  try {
    bump(run, "Requesting execution authority…");
    const challenge = await dj("POST", execPath, { intent: run.prompt });
    const policyHash = challenge.body?.approval?.policy_hash;
    const requestHash = challenge.body?.approval?.request_hash;
    if (!policyHash || !requestHash) {
      // Already authorized (no gate) or an unexpected response — treat the challenge as the result.
      finalize(run, challenge);
      return;
    }
    bump(run, "Authorizing run (wallet grant)…");
    const grant = mintApprovalGrant({ policyHash, requestHash });
    bump(run, "Agent working in the environment…");
    const result = await dj("POST", execPath, { intent: run.prompt, wallet_approval_grant: grant });
    finalize(run, result);
  } catch (error) {
    run.status = "failed";
    run.error = String(error?.message || error);
    bump(run, `Failed: ${run.error}`);
  }
}

function finalize(run, result) {
  const body = result.body || {};
  if (result.status === 200) {
    run.status = "done";
    run.transcript = Array.isArray(body.terminal_events) ? body.terminal_events : [];
    run.changedFiles = Array.isArray(body.changed_file_groups) ? body.changed_file_groups : [];
    run.capabilityLeaseRef = body.capability_lease_ref || null;
    run.summary = harnessSummary(run.transcript) || "Run complete.";
    bump(run, "Done");
  } else {
    run.status = "failed";
    run.error = body?.message || body?.reason || `execute ${result.status}`;
    bump(run, `Blocked: ${run.error}`);
  }
}

// Pull the harness's final summary line out of its transcript (the __HYPERVISOR_HARNESS_RESULT__
// sentinel carries a JSON summary; otherwise fall back to the last meaningful stdout line).
function harnessSummary(transcript) {
  for (const event of transcript) {
    const text = String(event?.text || "");
    const marker = text.indexOf("__HYPERVISOR_HARNESS_RESULT__");
    if (marker >= 0) {
      try {
        const parsed = JSON.parse(text.slice(marker + "__HYPERVISOR_HARNESS_RESULT__".length).trim());
        if (parsed.summary) return parsed.summary;
      } catch { /* ignore */ }
    }
  }
  const lines = transcript.map((e) => String(e?.text || "")).filter((t) => t && !t.startsWith("__HYPERVISOR"));
  return lines[lines.length - 1] || null;
}
