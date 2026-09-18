import type { IncomingMessage, ServerResponse } from "node:http";

import { createRuntimeSubstrateClient } from "../../../../../packages/agent-sdk/dist/index.js";
import {
  GOVERNANCE_LIST_REFS,
  GOVERNANCE_NULLABLE_REFS,
  GOVERNANCE_SCALAR_REFS,
  ORCHESTRATION_MODES,
  ORCHESTRATION_SCHEMA_VERSION,
  ORCHESTRATION_STATUSES,
  OrchestrationRefusal,
  Orchestrations,
  orchestrationIdTail,
  type OrchestrationGovernance,
  type OrchestrationMode,
} from "../../../../../packages/ioi-ai-orchestration/dist/index.js";
import type { IoiDaemonAuthority, IoiDaemonGateway, IoiDaemonResponse } from "./ioi-daemon.ts";

export interface OrchestrationRouteTools {
  json(res: ServerResponse, status: number, body: unknown): void;
  relay(res: ServerResponse, r: IoiDaemonResponse): void;
  readIoiObject(req: IncomingMessage, res: ServerResponse, message: string): Promise<Record<string, unknown> | null>;
  closedIoiObject(res: ServerResponse, value: Record<string, unknown>, allowed: readonly string[], label: string): boolean;
  boundedIoiText(value: unknown, maximum: number): string | null;
  canonicalIoiRef(value: unknown, schemes: readonly string[]): string | null;
  canonicalIoiRefs(value: unknown, schemes: readonly string[]): string[] | null;
}

const GOVERNANCE_LIST_SCHEMES: Record<(typeof GOVERNANCE_LIST_REFS)[number], readonly string[]> = {
  constraint_refs: ["constraint", "policy", "budget"],
  acceptance_criteria_refs: ["rubric", "gate", "policy"],
  collaboration_terms_refs: ["terms"],
  artifact_license_rights_retention_and_export_policy_refs: ["policy", "license"],
  ontology_profile_refs: ["ontology", "semantic-profile", "ontology-mapping"],
  scorecard_and_guardrail_refs: ["benchmark", "rubric", "gate", "policy"],
  verifier_path_refs: ["verifier-path", "verifier_path"],
  resource_and_budget_refs: ["resource-pool", "resource_pool", "budget", "goal-budget", "order"],
};
const GOVERNANCE_NULLABLE_SCHEMES: Record<(typeof GOVERNANCE_NULLABLE_REFS)[number], readonly string[]> = {
  settlement_policy_ref: ["policy"],
  multi_party_collaboration_ref: ["collaboration"],
};
const GOVERNANCE_FIELDS: readonly string[] = [...GOVERNANCE_SCALAR_REFS, ...GOVERNANCE_LIST_REFS, ...GOVERNANCE_NULLABLE_REFS];

interface DaemonRefusal {
  status: number;
  body: unknown;
}

function daemonRefusal(error: unknown): DaemonRefusal | null {
  const status = (error as { status?: unknown })?.status;
  if (typeof status !== "number" || status < 400 || status > 599) return null;
  const details = (error as { details?: { daemon?: unknown } })?.details;
  const message = error instanceof Error ? error.message : String(error);
  return { status, body: details?.daemon ?? { error: { code: "daemon_refused", message } } };
}

export function createOrchestrationRoutes(ioiDaemon: IoiDaemonGateway, tools: OrchestrationRouteTools) {
  const { json, relay, readIoiObject, closedIoiObject, boundedIoiText, canonicalIoiRef, canonicalIoiRefs } = tools;

  function isDaemonResponse(value: IoiDaemonAuthority | IoiDaemonResponse): value is IoiDaemonResponse {
    return typeof (value as IoiDaemonResponse).status === "number";
  }

  function ownerRefOf(authority: IoiDaemonAuthority): string {
    return authority.principal.tenant_refs[0] ?? `user://${authority.principal.principal_id}`;
  }

  function composerFor(authority: IoiDaemonAuthority, systemId: string): Orchestrations {
    const client = createRuntimeSubstrateClient({ endpoint: authority.endpoint, headers: authority.headers });
    return new Orchestrations(client, { system_id: systemId, owner_ref: ownerRefOf(authority) });
  }

  function failure(res: ServerResponse, error: unknown): void {
    if (error instanceof OrchestrationRefusal) {
      const status =
        error.code === "orchestration_absent"
          ? 404
          : /_(?:malformed|required|invalid)$/u.test(error.code)
            ? 400
            : 409;
      return json(res, status, { error: error.code, message: error.message, details: error.details });
    }
    const refused = daemonRefusal(error);
    if (refused) return relay(res, { status: refused.status, text: JSON.stringify(refused.body) });
    json(res, 502, {
      error: "daemon_unavailable",
      message: error instanceof Error ? error.message : "The daemon did not answer the composition.",
    });
  }

  function systemIdOf(value: unknown): string | null {
    return canonicalIoiRef(value, ["system"]);
  }

  async function principalSystems(req: IncomingMessage, user: string): Promise<string[] | IoiDaemonResponse> {
    const projection = await ioiDaemon.request(req, user, "GET", "/v1/hypervisor/autonomous-systems/projection");
    if (projection.status !== 200) return projection;
    let body: unknown;
    try {
      body = JSON.parse(projection.text);
    } catch {
      return { status: 502, text: JSON.stringify({ error: "invalid_daemon_response", message: "The Systems projection was not JSON." }) };
    }
    const systems = (body as { systems?: unknown })?.systems;
    if (!Array.isArray(systems)) {
      return { status: 502, text: JSON.stringify({ error: "invalid_daemon_response", message: "The Systems projection carried no systems." }) };
    }
    return systems
      .map((row) => (row as { system_id?: unknown; status?: unknown }) ?? {})
      .filter((row) => row.status === "active")
      .map((row) => systemIdOf(row.system_id))
      .filter((id): id is string => id !== null);
  }

  function governanceOf(res: ServerResponse, source: unknown): OrchestrationGovernance | null {
    const governance =
      source !== null && typeof source === "object" && !Array.isArray(source) ? (source as Record<string, unknown>) : null;
    if (!governance || !closedIoiObject(res, governance, GOVERNANCE_FIELDS, "orchestration governance")) return null;
    const result: Record<string, unknown> = {};
    for (const field of GOVERNANCE_SCALAR_REFS) {
      const ref = canonicalIoiRef(governance[field], ["policy"]);
      if (!ref) {
        json(res, 400, { error: "bad_request", message: `${field} must be a canonical policy:// ref.` });
        return null;
      }
      result[field] = ref;
    }
    for (const field of GOVERNANCE_LIST_REFS) {
      const refs = canonicalIoiRefs(governance[field], GOVERNANCE_LIST_SCHEMES[field]);
      if (!refs) {
        json(res, 400, { error: "bad_request", message: `${field} must be unique canonical refs of the required kind.` });
        return null;
      }
      result[field] = refs;
    }
    for (const field of GOVERNANCE_NULLABLE_REFS) {
      const value = governance[field];
      if (value === undefined || value === null) {
        result[field] = null;
        continue;
      }
      const ref = canonicalIoiRef(value, GOVERNANCE_NULLABLE_SCHEMES[field]);
      if (!ref) {
        json(res, 400, { error: "bad_request", message: `${field} must be a canonical ref or null.` });
        return null;
      }
      result[field] = ref;
    }
    return result as OrchestrationGovernance;
  }

  function admissionOf(admitted: { receipt_ref?: unknown; operation_ref?: unknown; admission?: { idempotency_key?: unknown } }) {
    return {
      receipt_ref: typeof admitted.receipt_ref === "string" ? admitted.receipt_ref : null,
      operation_ref: typeof admitted.operation_ref === "string" ? admitted.operation_ref : null,
      idempotency_key: typeof admitted.admission?.idempotency_key === "string" ? admitted.admission.idempotency_key : null,
    };
  }

  async function handle(
    req: IncomingMessage,
    res: ServerResponse,
    user: string,
    method: string,
    path: string,
    url: URL,
  ): Promise<boolean> {
    if (method === "GET" && path === "/api/ioi/orchestrations") {
      const authority = await ioiDaemon.authority(req, user);
      if (isDaemonResponse(authority)) return relay(res, authority), true;
      const requested = url.searchParams.get("system_id");
      let systems: string[];
      if (requested !== null) {
        const systemId = systemIdOf(requested);
        if (!systemId) return json(res, 400, { error: "bad_request", message: "system_id must be a canonical system:// ref." }), true;
        systems = [systemId];
      } else {
        const resolved = await principalSystems(req, user);
        if (!Array.isArray(resolved)) return relay(res, resolved), true;
        systems = resolved;
      }
      const orchestrations: unknown[] = [];
      const unavailable: unknown[] = [];
      const counted: unknown[] = [];
      for (const systemId of systems) {
        try {
          const entries = await composerFor(authority, systemId).list();
          counted.push({ system_id: systemId, count: entries.length });
          for (const entry of entries) orchestrations.push({ system_id: systemId, ...entry });
        } catch (error) {
          const refused = daemonRefusal(error);
          unavailable.push({
            system_id: systemId,
            status: refused?.status ?? 0,
            error: refused?.body ?? { error: "daemon_unavailable", message: error instanceof Error ? error.message : String(error) },
          });
        }
      }
      json(res, 200, {
        ok: true,
        schema_version: ORCHESTRATION_SCHEMA_VERSION,
        systems: counted,
        orchestrations,
        unavailable,
      });
      return true;
    }

    if (method === "POST" && path === "/api/ioi/orchestrations") {
      const source = await readIoiObject(req, res, "Orchestration input must be a JSON object.");
      if (!source || !closedIoiObject(res, source, ["system_id", "objective", "objective_ref", "mode", "governance"], "Orchestration input")) {
        return true;
      }
      const systemId = systemIdOf(source.system_id);
      const objective = boundedIoiText(source.objective, 4_096);
      const mode = source.mode;
      const objectiveRef =
        source.objective_ref === undefined || source.objective_ref === null || source.objective_ref === ""
          ? null
          : canonicalIoiRef(source.objective_ref, ["goal", "task", "service"]);
      if (!systemId || !objective || !ORCHESTRATION_MODES.includes(mode as OrchestrationMode)) {
        json(res, 400, {
          error: "bad_request",
          message: "A bounded System, an objective and a declared orchestration mode are required.",
        });
        return true;
      }
      if (source.objective_ref !== undefined && source.objective_ref !== null && source.objective_ref !== "" && !objectiveRef) {
        json(res, 400, { error: "bad_request", message: "objective_ref must be a canonical goal://, task:// or service:// ref." });
        return true;
      }
      const governance = governanceOf(res, source.governance);
      if (!governance) return true;
      const authority = await ioiDaemon.authority(req, user);
      if (isDaemonResponse(authority)) return relay(res, authority), true;
      try {
        const composed = await composerFor(authority, systemId).compose({
          objective,
          objective_ref: objectiveRef,
          mode: mode as OrchestrationMode,
          composed_by_ref: `user://${authority.principal.principal_id}`,
          governance,
        });
        json(res, 201, {
          ok: true,
          system_id: systemId,
          orchestration: composed.orchestration,
          head: composed.head,
          thread_id: composed.handle.thread_id,
          replayed: composed.admitted.replayed === true,
          admission: admissionOf(composed.admitted),
        });
      } catch (error) {
        failure(res, error);
      }
      return true;
    }

    const scoped = path.match(/^\/api\/ioi\/orchestrations\/([^/]+)(?:\/(graph|replay|delegations|transition|goal-runs\/attach|goal-runs\/detach))?$/u);
    if (!scoped) return false;
    let decoded: string;
    try {
      decoded = decodeURIComponent(scoped[1]!);
    } catch {
      decoded = "";
    }
    const tail = orchestrationIdTail(decoded);
    const action = scoped[2] ?? null;
    if (!tail) return json(res, 400, { error: "bad_request", message: "Invalid orchestration id." }), true;

    if (method === "GET" && (action === null || action === "graph" || action === "replay" || action === "delegations")) {
      const systemId = systemIdOf(url.searchParams.get("system_id"));
      if (!systemId) return json(res, 400, { error: "bad_request", message: "system_id must name the bounded System as a canonical system:// ref." }), true;
      const authority = await ioiDaemon.authority(req, user);
      if (isDaemonResponse(authority)) return relay(res, authority), true;
      const composer = composerFor(authority, systemId);
      try {
        if (action === null) {
          const opened = await composer.open(tail);
          json(res, 200, { ok: true, system_id: systemId, orchestration: opened.orchestration, head: opened.head, revisions: opened.revisions.length, thread_id: opened.handle.thread_id });
        } else if (action === "graph") {
          json(res, 200, { ok: true, system_id: systemId, graph: await composer.graph(tail) });
        } else if (action === "replay") {
          const opened = await composer.open(tail);
          json(res, 200, { ok: true, system_id: systemId, orchestration_id: opened.orchestration.orchestration_id, head: opened.head, revisions: opened.revisions, admissions: opened.admissions });
        } else {
          const opened = await composer.open(tail);
          const listed = await opened.handle.delegations();
          json(res, 200, { ok: true, system_id: systemId, thread_id: opened.handle.thread_id, subagents: listed.subagents ?? [] });
        }
      } catch (error) {
        failure(res, error);
      }
      return true;
    }

    if (method === "POST" && (action === "goal-runs/attach" || action === "goal-runs/detach")) {
      const source = await readIoiObject(req, res, "Orchestration membership input must be a JSON object.");
      if (!source || !closedIoiObject(res, source, ["system_id", "goal_run_ref", "expected_head"], "Orchestration membership input")) return true;
      const systemId = systemIdOf(source.system_id);
      const goalRunRef = canonicalIoiRef(source.goal_run_ref, ["goal"]);
      const expectedHead = boundedIoiText(source.expected_head, 128);
      if (!systemId || !goalRunRef || !/^goal:\/\/gr_[A-Za-z0-9_-]+$/u.test(goalRunRef) || !expectedHead || !/^sha256:[0-9a-f]{64}$/u.test(expectedHead)) {
        json(res, 400, { error: "bad_request", message: "A bounded System, a canonical goal://gr_ ref and the exact expected_head are required." });
        return true;
      }
      const authority = await ioiDaemon.authority(req, user);
      if (isDaemonResponse(authority)) return relay(res, authority), true;
      const composer = composerFor(authority, systemId);
      try {
        const revised =
          action === "goal-runs/attach"
            ? await composer.attachGoalRun(tail, goalRunRef, expectedHead)
            : await composer.detachGoalRun(tail, goalRunRef, expectedHead);
        json(res, 200, { ok: true, system_id: systemId, membership_transition: revised.action, member_stamp: revised.member_stamp ?? null, orchestration: revised.orchestration, head: revised.head, admission: admissionOf(revised.admitted) });
      } catch (error) {
        failure(res, error);
      }
      return true;
    }

    if (method === "POST" && action === "transition") {
      const source = await readIoiObject(req, res, "Orchestration transition input must be a JSON object.");
      if (!source || !closedIoiObject(res, source, ["system_id", "status", "expected_head"], "Orchestration transition input")) return true;
      const systemId = systemIdOf(source.system_id);
      const expectedHead = boundedIoiText(source.expected_head, 128);
      const status = source.status;
      if (!systemId || !ORCHESTRATION_STATUSES.includes(status as never) || !expectedHead || !/^sha256:[0-9a-f]{64}$/u.test(expectedHead)) {
        json(res, 400, { error: "bad_request", message: "A bounded System, a declared status and the exact expected_head are required." });
        return true;
      }
      const authority = await ioiDaemon.authority(req, user);
      if (isDaemonResponse(authority)) return relay(res, authority), true;
      try {
        const revised = await composerFor(authority, systemId).transition(tail, status, expectedHead);
        json(res, 200, { ok: true, system_id: systemId, transition: revised.orchestration.status, orchestration: revised.orchestration, head: revised.head, admission: admissionOf(revised.admitted) });
      } catch (error) {
        failure(res, error);
      }
      return true;
    }

    json(res, 405, { error: "method_not_allowed", message: "That orchestration route does not take this method." });
    return true;
  }

  return { handle };
}
