// T7-B — typed Hypervisor daemon client + the single Session Execution Binding resolver.
//
// The native operator surfaces and the Workbench adapter consume ONE client. Every method maps to
// a real daemon route; nothing is JS-owned truth. In the browser the base is same-origin (the
// `/api/ioi` adapter passes `/v1/*` straight through to the daemon); headless callers (the
// verifier) pass the daemon origin directly. The UI must consume `resolveSessionExecutionBinding`
// instead of separately guessing how an environment, thread, and WorkRun relate.

export interface SessionExecutionBinding {
  binding_ref: string;
  binding_id: string;
  session_ref: string;
  environment_ref: string;
  thread_ref: string | null;
  work_run_ref: string | null;
  model_configuration_ref: string;
  authority_context_ref: string;
  adapter_refs: Record<string, string>;
  event_stream_refs: { environment: string | null; thread: string | null; work_run: string | null };
  receipt_refs: string[];
  state_root_ref: string;
  environment_status?: {
    phase?: string;
    readiness?: { mode?: string; reasons?: string[] };
    components?: Record<string, { phase?: string }>;
    workspace_root?: string | null;
  };
}

export interface EnvironmentSummary {
  id: string;
  status?: {
    phase?: string;
    readiness?: { mode?: string; reasons?: string[] };
    components?: Record<string, { phase?: string; detail?: string }>;
    workspace_root?: string | null;
    ports?: Array<{ port?: number; exposure_state?: string }>;
  };
  spec?: { environment_class_id?: string; project_id?: string | null };
}

export interface ProviderInfo {
  provider_ref: string;
  status: string;
  reason: string;
  capabilities: Record<string, unknown>;
}

export interface ResolveBindingInput {
  environmentRef?: string;
  environmentId?: string;
  sessionRef?: string;
  threadRef?: string;
  workRunRef?: string;
}

const idOf = (ref: string | null | undefined): string => (ref ? ref.split(":").pop() ?? ref : "");

export class HypervisorDaemonClient {
  constructor(private readonly base: string = "") {}

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return (text ? JSON.parse(text) : {}) as T;
  }

  // --- environments ---
  listEnvironments(): Promise<{ environments?: EnvironmentSummary[] }> {
    return this.req("GET", "/v1/hypervisor/environments");
  }
  getEnvironment(id: string): Promise<{ environment?: EnvironmentSummary }> {
    return this.req("GET", `/v1/hypervisor/environments/${encodeURIComponent(id)}`);
  }
  createEnvironment(spec: Record<string, unknown>): Promise<{ environment?: EnvironmentSummary }> {
    return this.req("POST", "/v1/hypervisor/environments", { spec });
  }
  environmentAction(id: string, action: "start" | "stop" | "archive" | "restore" | "delete"): Promise<{ environment?: EnvironmentSummary }> {
    return this.req("POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/${action}`);
  }

  // --- providers / resource / authority (status projections) ---
  listProviders(): Promise<{ providers?: ProviderInfo[] }> {
    return this.req("GET", "/v1/hypervisor/providers");
  }
  authorityProviders(): Promise<unknown> {
    return this.req("GET", "/v1/hypervisor/authority/providers");
  }
  resourcePools(): Promise<unknown> {
    return this.req("GET", "/v1/hypervisor/resource/pools");
  }
  vmToolchain(): Promise<unknown> {
    return this.req("GET", "/v1/hypervisor/authority/posture");
  }

  // --- workruns ---
  listWorkRuns(): Promise<{ workRuns?: Array<Record<string, unknown>> }> {
    return this.req("GET", "/v1/hypervisor/workruns");
  }
  createWorkRun(environmentId: string, objective?: unknown): Promise<{ workRun?: Record<string, unknown> }> {
    return this.req("POST", "/v1/hypervisor/workruns", { environment_id: environmentId, objective });
  }
  executeWorkRun(id: string): Promise<Record<string, unknown>> {
    return this.req("POST", `/v1/hypervisor/workruns/${encodeURIComponent(id)}/execute`);
  }
  getWorkRun(id: string): Promise<{ workRun?: Record<string, unknown> }> {
    return this.req("GET", `/v1/hypervisor/workruns/${encodeURIComponent(id)}`);
  }

  // --- threads (conversation owner; the binding never owns turns) ---
  createThread(body: Record<string, unknown> = {}): Promise<{ thread_id?: string; session_id?: string } & Record<string, unknown>> {
    return this.req("POST", "/v1/threads", body);
  }

  // --- session execution binding ---
  createBinding(input: ResolveBindingInput): Promise<{ binding?: SessionExecutionBinding }> {
    const environment_ref = input.environmentRef ?? (input.environmentId ? `environment:${input.environmentId}` : undefined);
    return this.req("POST", "/v1/hypervisor/session-execution-bindings", {
      environment_ref,
      session_ref: input.sessionRef,
      thread_ref: input.threadRef,
      work_run_ref: input.workRunRef,
    });
  }
  getBinding(id: string): Promise<{ binding?: SessionExecutionBinding }> {
    return this.req("GET", `/v1/hypervisor/session-execution-bindings/${encodeURIComponent(idOf(id))}`);
  }
  bindingEvents(id: string): Promise<{ binding_ref?: string; events?: Array<Record<string, unknown>> }> {
    return this.req("GET", `/v1/hypervisor/session-execution-bindings/${encodeURIComponent(idOf(id))}/events`);
  }
  bindingInput(id: string, data: unknown): Promise<Record<string, unknown>> {
    return this.req("POST", `/v1/hypervisor/session-execution-bindings/${encodeURIComponent(idOf(id))}/input`, { data });
  }

  // --- env-files (collision-safe, scoped to the env workspace) ---
  envFiles(environmentId: string, op: string, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.req("POST", "/v1/hypervisor/env-files", { environment_id: environmentId, op, ...extra });
  }

  // --- terminals (interactive PTY) ---
  createTerminal(environmentRef: string, cols: number, rows: number): Promise<Record<string, unknown>> {
    return this.req("POST", "/v1/hypervisor/terminals", { environment_ref: environmentRef, cols, rows });
  }
  async terminalStream(id: string, since: number): Promise<{ output: string; offset: number; running: boolean }> {
    const res = await fetch(`${this.base}/v1/hypervisor/terminals/${encodeURIComponent(id)}/stream?since=${since}`);
    const text = await res.text();
    const line = text.split("\n").find((l) => l.startsWith("data: ") && l.includes("\"output\""));
    if (!line) return { output: "", offset: since, running: true };
    const data = JSON.parse(line.slice("data: ".length)) as { output?: string; offset?: number; running?: boolean };
    return { output: data.output ?? "", offset: data.offset ?? since, running: data.running ?? true };
  }
  terminalInput(id: string, data: string): Promise<Record<string, unknown>> {
    return this.req("POST", `/v1/hypervisor/terminals/${encodeURIComponent(id)}/input`, { data });
  }
  terminalResize(id: string, cols: number, rows: number): Promise<Record<string, unknown>> {
    return this.req("POST", `/v1/hypervisor/terminals/${encodeURIComponent(id)}/resize`, { cols, rows });
  }
  terminalClose(id: string): Promise<Record<string, unknown>> {
    return this.req("POST", `/v1/hypervisor/terminals/${encodeURIComponent(id)}/close`);
  }

  /**
   * The single resolver every surface uses. Maps UI context (an environment, optionally an existing
   * thread/WorkRun) into ONE Session Execution Binding. Creates a real thread + WorkRun when the
   * caller asks for a fully-bound execution context and none was supplied.
   */
  async resolveSessionExecutionBinding(input: ResolveBindingInput & { ensureThread?: boolean }): Promise<SessionExecutionBinding | null> {
    let threadRef = input.threadRef;
    if (!threadRef && input.ensureThread) {
      const t = await this.createThread({});
      const tid = t.thread_id ?? (t as { id?: string }).id;
      if (tid) threadRef = `thread:${tid}`;
    }
    const created = await this.createBinding({ ...input, threadRef });
    return created.binding ?? null;
  }
}

/** Same-origin in the browser (the /api/ioi adapter passes /v1/* through); override for headless. */
export function createHypervisorDaemonClient(base?: string): HypervisorDaemonClient {
  if (base !== undefined) return new HypervisorDaemonClient(base);
  if (typeof window !== "undefined" && window.location?.origin) return new HypervisorDaemonClient(window.location.origin);
  return new HypervisorDaemonClient("");
}
