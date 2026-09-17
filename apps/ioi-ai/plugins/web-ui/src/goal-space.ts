import { html, nothing, render, type TemplateResult } from "lit";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Check,
  ChevronRight,
  CircleOff,
  GitFork,
  Network,
  RefreshCw,
  ShieldCheck,
  Target,
  Users,
} from "lucide";
import { reportSigninRequired, type SigninRequired, withBase } from "./core-bridge";
import { deepLinkPath, UI_BASE } from "./deep-link";
import {
  activationId,
  errorDetail,
  goalSpaceTabForKey,
  goalRunId,
  goalTitle,
  kernelOwnerBindings,
  listAt,
  numberAt,
  orchestrationId,
  orchestrationTitle,
  requiredKernelBindingsComplete,
  shortRef,
  textAt,
  type GoalSpaceTab,
  type JsonRecord,
} from "./goal-space-contract";
import { appState, replacePanePreservingFocus } from "./shell";
import {
  clearGoalActivationRecovery,
  createGoalActivationRecovery,
  readGoalActivationRecovery,
  writeGoalActivationRecovery,
  type GoalActivationRecovery,
} from "./goal-space-recovery";
import { focusByKey } from "./pane-focus";
import { fieldSelect, icon } from "./ui";
import { assertIdentityEpoch, captureIdentityEpoch } from "./identity-epoch";
import {
  GoalSpaceResponseContractError,
  isCanonicalReceiptRef,
  isCanonicalWorkResultRef,
  validateActivationResponse,
  validateAdmittedActivationResponse,
  validateGoalDetail,
  validateGoalEvents,
  validateGoalRunCreate,
  validateGoalRunList,
  validateGoalRunReconcile,
  validateGoalRunStart,
  validateOrchestrationCompose,
  validateOrchestrationDelegations,
  validateOrchestrationDetail,
  validateOrchestrationGraph,
  validateOrchestrationList,
  validateOrchestrationMembership,
  validateOrchestrationReplay,
  type OrchestrationDetailResponse,
  type OrchestrationListEntry,
  type ValidatedActivationResponse,
} from "./goal-space-response";

interface RequestFailure {
  status: number;
  body: unknown;
}

interface ActivationReview {
  response: JsonRecord;
  grantText: string;
  submitting: boolean;
  error: RequestFailure | null;
}

interface GoalDetail {
  run: JsonRecord;
  events: unknown;
  loading: boolean;
  error: RequestFailure | null;
  eventsError: RequestFailure | null;
  mutation: GoalMutation | null;
}

interface GoalMutation {
  kind: "start" | "reconcile";
  submitting: boolean;
  uncertain: boolean;
  grantText: string;
  idempotencyKey: string;
  error: RequestFailure | null;
}

interface OrchestrationDetail {
  entry: OrchestrationDetailResponse;
  graph: unknown;
  replay: unknown;
  delegations: unknown;
  loading: boolean;
  errors: string[];
  mutation: OrchestrationMutation | null;
}

interface OrchestrationMutation {
  action: "attach" | "detach";
  submitting: boolean;
  uncertain: boolean;
  error: RequestFailure | null;
}

const state = {
  tab: "goals" as GoalSpaceTab,
  goals: [] as JsonRecord[],
  orchestrations: [] as OrchestrationListEntry[],
  systemId: null as string | null,
  loading: false,
  listErrors: [] as string[],
  detailGoal: null as GoalDetail | null,
  detailOrchestration: null as OrchestrationDetail | null,
  activation: null as ActivationReview | null,
  activationRecoveryId: null as string | null,
  activating: false,
  composerOpen: false,
  runComposerOpen: false,
  orchestrationComposerOpen: false,
  creatingRun: false,
  composingOrchestration: false,
  runCreateError: null as RequestFailure | null,
  orchestrationComposeError: null as RequestFailure | null,
  notice: "",
  principal: null as string | null,
  requestSequence: 0,
  detailRequestSequence: 0,
  activationRequestSequence: 0,
  writeRequestSequence: 0,
  navigationSequence: 0,
};

const ORCHESTRATION_GOVERNANCE_EXAMPLE = JSON.stringify(
  {
    stop_policy_ref: "policy://your-orchestration/stop",
    visibility_policy_ref: "policy://your-orchestration/visibility",
    participation_policy_ref: "policy://your-orchestration/participation",
    privacy_policy_ref: "policy://your-orchestration/privacy",
    contribution_policy_ref: "policy://your-orchestration/contribution",
    cooperation_surplus_policy_ref: "policy://your-orchestration/cooperation-surplus",
    coordination_policy_ref: "policy://your-orchestration/coordination",
    ordering_and_merge_policy_ref: "policy://your-orchestration/ordering",
    conflict_and_failover_policy_ref: "policy://your-orchestration/failover",
    constraint_refs: [],
    acceptance_criteria_refs: [],
    collaboration_terms_refs: [],
    artifact_license_rights_retention_and_export_policy_refs: [],
    ontology_profile_refs: [],
    scorecard_and_guardrail_refs: [],
    verifier_path_refs: [],
    resource_and_budget_refs: [],
  },
  null,
  2,
);

class IoiRequestError extends Error implements RequestFailure {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown) {
    const detail = errorDetail(body);
    super(detail.message);
    this.name = "IoiRequestError";
    this.status = status;
    this.body = body;
  }
}

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : {};
}

function recoveryStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function readRecovery(principal: string): GoalActivationRecovery | null {
  const storage = recoveryStorage();
  return storage ? readGoalActivationRecovery(storage, principal) : null;
}

function writeRecovery(recovery: GoalActivationRecovery): boolean {
  const storage = recoveryStorage();
  if (!storage) return false;
  try {
    writeGoalActivationRecovery(storage, recovery);
    return readGoalActivationRecovery(storage, recovery.principal)?.idempotencyKey === recovery.idempotencyKey;
  } catch {
    return false;
  }
}

function clearRecovery(principal: string | null): void {
  const storage = recoveryStorage();
  if (!storage || !principal) return;
  try {
    clearGoalActivationRecovery(storage, principal);
  } catch {
    void 0;
  }
}

async function ioiApi<T>(path: string, validate: (value: unknown) => T, init?: RequestInit): Promise<T> {
  const identityEpoch = captureIdentityEpoch();
  const response = await fetch(withBase(path), {
    headers: { "content-type": "application/json" },
    ...init,
  });
  const raw = await response.text();
  assertIdentityEpoch(identityEpoch);
  let body: unknown;
  try {
    body = raw ? JSON.parse(raw) : {};
  } catch {
    throw new IoiRequestError(502, {
      error: "invalid_daemon_response",
      message: "The daemon returned a non-JSON response.",
    });
  }
  if (!response.ok) {
    if (response.status === 401) reportSigninRequired(body as SigninRequired);
    throw new IoiRequestError(response.status, body);
  }
  try {
    return validate(body);
  } catch (error) {
    if (!(error instanceof GoalSpaceResponseContractError)) throw error;
    throw new IoiRequestError(502, {
      error: "invalid_daemon_response",
      message: error.message,
    });
  }
}

function failure(error: unknown): RequestFailure {
  if (error instanceof IoiRequestError) return error;
  return {
    status: 0,
    body: {
      error: "daemon_unavailable",
      message: error instanceof Error ? error.message : "Daemon unavailable.",
    },
  };
}

function uncertainFailure(error: RequestFailure): boolean {
  return error.status === 0 || error.status >= 500;
}

function statusOf(value: unknown): string {
  return textAt(value, "status") ?? textAt(value, "state") ?? "unknown";
}

function dateLabel(value: unknown): string {
  const raw = textAt(value, "updated_at") ?? textAt(value, "created_at");
  if (!raw) return "No timestamp";
  const parsed = new Date(raw);
  return Number.isNaN(parsed.valueOf()) ? raw : parsed.toLocaleString();
}

function orchestrationDateLabel(orchestration: JsonRecord): string {
  return dateLabel({
    updated_at: textAt(orchestration, "system_binding", "updated_at"),
    created_at: textAt(orchestration, "composed_at"),
  });
}

function systemQuery(): string {
  return state.systemId ? `?system=${encodeURIComponent(state.systemId)}` : "";
}

function updateLocation(item: string | null, replace = false): void {
  const next = `${deepLinkPath(UI_BASE, "goals", null, null, item)}${item?.startsWith("orchestration:") ? systemQuery() : ""}`;
  if (`${location.pathname}${location.search}` === next) return;
  if (replace) history.replaceState(null, "", next);
  else history.pushState(null, "", next);
}

function systemFromLocation(): string | null {
  const system = new URLSearchParams(location.search).get("system");
  return system && system.startsWith("system://") ? system : null;
}

function onGoalTabKeydown(event: KeyboardEvent): void {
  const next = goalSpaceTabForKey(state.tab, event.key);
  if (!next) return;
  event.preventDefault();
  selectTab(next);
}

function sectionTitle(title: string, detail?: string): TemplateResult {
  return html`<div class="goal-section-title">
    <span>${title}</span>${detail ? html`<small>${detail}</small>` : nothing}
  </div>`;
}

function statusBadge(status: string): TemplateResult {
  return html`<span class="goal-status goal-status-${status.replace(/[^a-z0-9_-]/gi, "-").toLowerCase()}"
    >${status}</span
  >`;
}

function errorPanel(input: RequestFailure, title = "The daemon refused this action"): TemplateResult {
  const detail = errorDetail(input.body);
  const body = asRecord(input.body);
  const approval = asRecord(body.error).approval ?? body.approval ?? body.authority_challenge;
  return html`
    <section class="goal-error" role="alert">
      <span class="goal-error-icon">${icon(AlertTriangle, 17)}</span>
      <div>
        <strong>${title}</strong>
        <p>${detail.message}</p>
        <code>${detail.code}${input.status ? ` · HTTP ${input.status}` : ""}</code>
        ${approval
          ? html`<details>
              <summary>Authority coordinates</summary>
              <pre>${JSON.stringify(approval, null, 2)}</pre>
            </details>`
          : nothing}
      </div>
    </section>
  `;
}

function loadingPane(label: string): void {
  if (!appState.mainEl) return;
  const host = document.createElement("div");
  host.className = "pane goal-space-pane";
  render(html`<div class="goal-loading" role="status"><span class="spinner"></span><span>${label}</span></div>`, host);
  replacePanePreservingFocus(host);
}

function goalRow(run: JsonRecord): TemplateResult {
  const id = goalRunId(run);
  const status = statusOf(run);
  return html`
    <button
      class="goal-list-row"
      type="button"
      data-focus-key=${id ? `goal-row-${id}` : ""}
      ?disabled=${!id}
      @click=${() => id && void openGoal(id)}
    >
      <span class="goal-list-icon">${icon(Target, 18)}</span>
      <span class="goal-list-copy">
        <strong>${goalTitle(run)}</strong>
        <small>${shortRef(textAt(run, "goal_ref") ?? id)} · ${dateLabel(run)}</small>
      </span>
      ${statusBadge(status)} ${icon(ChevronRight, 16)}
    </button>
  `;
}

function orchestrationRow(entry: OrchestrationListEntry): TemplateResult {
  const orchestration = entry.orchestration;
  const id = orchestrationId(orchestration);
  const status = statusOf(orchestration);
  return html`
    <button
      class="goal-list-row"
      type="button"
      data-focus-key=${id ? `orchestration-row-${id}` : ""}
      ?disabled=${!id}
      @click=${() => id && void openOrchestration(id, entry.system_id)}
    >
      <span class="goal-list-icon orchestration">${icon(Network, 18)}</span>
      <span class="goal-list-copy">
        <strong>${orchestrationTitle(orchestration)}</strong>
        <small>${shortRef(entry.system_id)} · ${entry.revisions} revision${entry.revisions === 1 ? "" : "s"} · ${orchestrationDateLabel(orchestration)}</small>
      </span>
      ${statusBadge(status)} ${icon(ChevronRight, 16)}
    </button>
  `;
}

function activationForm(): TemplateResult {
  return html`
    <form class="goal-activation-form" @submit=${draftActivation}>
      <div class="goal-composer-heading">
        <div>
          <span class="goal-eyebrow">Durable outcome</span>
          <h2>Activate a goal</h2>
          <p>This creates a reviewable draft. It does not start a Session or a harness.</p>
        </div>
        <button class="icon-btn subtle" type="button" aria-label="Close goal activation" @click=${closeComposer}>
          ${icon(CircleOff, 17)}
        </button>
      </div>
      <label for="goal-text">What outcome should persist?</label>
      <textarea
        id="goal-text"
        data-focus-key="goal-text"
        name="goal_text"
        required
        minlength="4"
        maxlength="32768"
        placeholder="Research the safest deployment path and produce a verified recommendation."
      ></textarea>
      <label for="goal-constraints">Constraints <span>one per line, optional</span></label>
      <textarea
        id="goal-constraints"
        data-focus-key="goal-constraints"
        name="constraints"
        class="goal-constraints"
        placeholder="Do not exceed the approved budget&#10;Cite primary evidence"
      ></textarea>
      <div class="goal-form-foot">
        <span>${icon(ShieldCheck, 15)} Identity, profile, execution ceiling, and authority are daemon-resolved.</span>
        <button class="btn primary" type="submit" data-focus-key="goal-draft-submit" ?disabled=${state.activating}>
          ${state.activating ? "Preparing review…" : "Review activation"}
        </button>
      </div>
    </form>
  `;
}

function runnableGoalForm(): TemplateResult {
  return html`
    <form class="goal-activation-form goal-run-form" @submit=${createRunnableGoal}>
      <div class="goal-composer-heading">
        <div>
          <span class="goal-eyebrow">Hypervisor execution target</span>
          <h2>Create a runnable GoalRun</h2>
          <p>Binds durable goal identity to one existing, owner-matched Hypervisor Session workspace.</p>
        </div>
        <button class="icon-btn subtle" type="button" aria-label="Close runnable GoalRun" @click=${closeRunComposer}>
          ${icon(CircleOff, 17)}
        </button>
      </div>
      <label for="goal-run-text">Normalized goal</label>
      <textarea
        id="goal-run-text"
        data-focus-key="goal-run-text"
        name="goal"
        required
        minlength="4"
        maxlength="32768"
        placeholder="Implement the bounded change and return daemon-verifiable evidence."
      ></textarea>
      <div class="goal-form-grid">
        <label for="goal-run-session">
          <span>Target Session</span>
          <input
            id="goal-run-session"
            data-focus-key="goal-run-session"
            name="session_ref"
            required
            maxlength="320"
            pattern="session:.+"
            placeholder="session:hyp-…"
          />
        </label>
        <label for="goal-run-model-route">
          <span>Model route <small>optional</small></span>
          <input
            id="goal-run-model-route"
            data-focus-key="goal-run-model-route"
            name="model_route_ref"
            maxlength="500"
            placeholder="model-route://…"
          />
        </label>
      </div>
      ${state.runCreateError
        ? errorPanel(
            state.runCreateError,
            uncertainFailure(state.runCreateError) ? "GoalRun creation result is uncertain" : "GoalRun was not created",
          )
        : nothing}
      <div class="goal-form-foot">
        <span>${icon(ShieldCheck, 15)} Creation resolves owner, workspace, harness profiles, and route truth in the daemon.</span>
        <button class="btn primary" type="submit" data-focus-key="goal-run-create" ?disabled=${state.creatingRun}>
          ${state.creatingRun ? "Creating owner record…" : "Create runnable GoalRun"}
        </button>
      </div>
    </form>
  `;
}

function orchestrationComposerForm(): TemplateResult {
  return html`
    <form class="goal-activation-form goal-orchestration-form" @submit=${composeOrchestration}>
      <div class="goal-composer-heading">
        <div>
          <span class="goal-eyebrow">Composed from thread primitives</span>
          <h2>Compose an orchestration</h2>
          <p>A coordinating thread is created first; the record that makes it durable is admitted under the bounded System.</p>
        </div>
        <button class="icon-btn subtle" type="button" aria-label="Close orchestration composer" @click=${closeOrchestrationComposer}>
          ${icon(CircleOff, 17)}
        </button>
      </div>
      <div class="goal-form-grid">
        <label for="orchestration-system">
          <span>Active bounded System</span>
          <input
            id="orchestration-system"
            data-focus-key="orchestration-system"
            name="system_id"
            required
            maxlength="500"
            placeholder="system://…"
            value=${state.systemId ?? ""}
          />
        </label>
        <label for="orchestration-goal">
          <span>Objective GoalRun (optional)</span>
          <input
            id="orchestration-goal"
            data-focus-key="orchestration-goal"
            name="objective_ref"
            maxlength="500"
            placeholder="goal://gr_…"
          />
        </label>
      </div>
      <label for="orchestration-objective">Objective</label>
      <textarea
        id="orchestration-objective"
        data-focus-key="orchestration-objective"
        name="objective"
        required
        maxlength="4096"
        placeholder="Coordinate the bounded work and keep every step re-readable from the daemon."
      ></textarea>
      <label for="orchestration-mode">Mode</label>
      ${fieldSelect({
        id: "orchestration-mode",
        name: "mode",
        focusKey: "orchestration-mode",
        className: "goal-orchestration-mode",
        value: "private_goal",
        onChange: () => undefined,
        options: [
          html`<option value="private_goal">Private goal</option>`,
          html`<option value="permissioned_team">Permissioned team</option>`,
        ],
      })}
      <label for="orchestration-governance">
        Governance coordinates
        <span>closed JSON · policy refs are declared, never minted by this client</span>
      </label>
      <textarea
        id="orchestration-governance"
        data-focus-key="orchestration-governance"
        class="goal-governance"
        name="governance"
        required
        spellcheck="false"
        placeholder=${ORCHESTRATION_GOVERNANCE_EXAMPLE}
      ></textarea>
      ${state.orchestrationComposeError
        ? errorPanel(
            state.orchestrationComposeError,
            uncertainFailure(state.orchestrationComposeError)
              ? "Orchestration composition result is uncertain"
              : "The orchestration was not composed",
          )
        : nothing}
      <div class="goal-form-foot">
        <span>${icon(ShieldCheck, 15)} The kernel owns the thread; the seam derives the binding, the head and the receipt.</span>
        <button class="btn primary" type="submit" data-focus-key="orchestration-compose" ?disabled=${state.composingOrchestration}>
          ${state.composingOrchestration ? "Composing…" : "Compose orchestration"}
        </button>
      </div>
    </form>
  `;
}

function activationReview() {
  const review = state.activation;
  if (!review) return nothing;
  const response = review.response;
  const activation = asRecord(response.activation);
  const profile = asRecord(response.resolved_profile);
  const authority = asRecord(response.authority_decision);
  const ceiling = asRecord(response.goal_run_execution_ceiling);
  const maxTotal = numberAt(ceiling, "max_total_invocations");
  const maxParallel = numberAt(ceiling, "max_parallel_invocations");
  const hash = textAt(response, "activation_hash") ?? "";
  const id = activationId(activation);
  const recovery = state.principal ? readRecovery(state.principal) : null;
  const canRetryRecovery = !id || !hash ? Boolean(state.activationRecoveryId || recovery) : false;
  return html`
    <section class="goal-review" aria-labelledby="goal-review-heading">
      <div class="goal-composer-heading">
        <div>
          <span class="goal-eyebrow">Exact-byte crossing</span>
          <h2 id="goal-review-heading" tabindex="-1" data-focus-key="goal-review-heading">Review before activation</h2>
          <p>Approval applies only to this retained draft hash. Changed bytes require another review.</p>
        </div>
        ${statusBadge(textAt(activation, "status") ?? "draft")}
      </div>
      <dl class="goal-facts">
        <div>
          <dt>Goal</dt>
          <dd>${textAt(response, "goal_draft", "goal_text") ?? "—"}</dd>
        </div>
        <div>
          <dt>Activation</dt>
          <dd><code>${textAt(activation, "activation_id") ?? "—"}</code></dd>
        </div>
        <div>
          <dt>Retained hash</dt>
          <dd><code>${hash}</code></dd>
        </div>
        <div>
          <dt>Profile revision</dt>
          <dd><code>${textAt(profile, "revision_ref") ?? "—"}</code></dd>
        </div>
        <div>
          <dt>Profile hash</dt>
          <dd><code>${textAt(profile, "content_hash") ?? "—"}</code></dd>
        </div>
        <div>
          <dt>Authority</dt>
          <dd>${textAt(authority, "decision") ?? "authority required"}</dd>
        </div>
        <div>
          <dt>Required scope</dt>
          <dd>
            <code>${textAt(authority, "required_scope") ?? "scope:goal.run.create"}</code>
          </dd>
        </div>
        <div>
          <dt>Execution ceiling</dt>
          <dd>
            ${maxTotal === null || maxParallel === null
              ? "Unavailable from the retained activation bytes"
              : `${maxTotal} total · ${maxParallel} parallel`}
          </dd>
        </div>
      </dl>
      <label class="goal-grant-label" for="goal-wallet-grant">
        Wallet approval grant
        <span>The daemon will return the exact policy/request hashes if this is omitted or stale.</span>
      </label>
      <textarea
        id="goal-wallet-grant"
        data-focus-key="goal-wallet-grant"
        class="goal-grant"
        spellcheck="false"
        placeholder="Paste the signed wallet_approval_grant JSON when authority is required."
        .value=${review.grantText}
        @input=${(event: Event) => {
          review.grantText = (event.target as HTMLTextAreaElement).value;
        }}
      ></textarea>
      ${review.error ? errorPanel(review.error) : nothing}
      <div class="goal-review-actions">
        <button class="btn" type="button" data-focus-key="goal-discard-activation" @click=${resetActivation}>
          Discard draft from this view
        </button>
        ${canRetryRecovery
          ? html`<button
              class="btn primary"
              type="button"
              data-focus-key="goal-retry-activation"
              ?disabled=${state.activating}
              @click=${retryActivationReview}
            >
              ${state.activating ? "Recovering retained draft…" : "Retry retained recovery"}
            </button>`
          : html`<button
              class="btn primary"
              type="button"
              data-focus-key="goal-submit-activation"
              ?disabled=${review.submitting || !id || !hash}
              @click=${submitActivation}
            >
              ${review.submitting ? "Submitting exact hash…" : "Approve and activate"}
            </button>`}
      </div>
    </section>
  `;
}

function homePane(): TemplateResult {
  const items = state.tab === "goals" ? state.goals : state.orchestrations;
  const unavailable = state.listErrors.find((message) =>
    message.startsWith(state.tab === "goals" ? "GoalRuns unavailable:" : "Orchestrations unavailable:"),
  );
  let rows: unknown;
  if (items.length) rows = state.tab === "goals" ? state.goals.map(goalRow) : state.orchestrations.map(orchestrationRow);
  else if (state.loading) {
    rows = html`<div class="goal-loading" role="status">
      <span class="spinner"></span><span>Loading owner truth…</span>
    </div>`;
  } else if (unavailable) {
    rows = html`<div class="goal-empty" role="alert">
      ${icon(AlertTriangle, 25)}
      <strong>${state.tab === "goals" ? "GoalRuns could not be loaded" : "Orchestrations could not be loaded"}</strong>
      <span>${unavailable}</span>
    </div>`;
  } else {
    rows = html`<div class="goal-empty">
      ${icon(state.tab === "goals" ? Target : Network, 25)}
      <strong>${state.tab === "goals" ? "No visible GoalRuns" : "No visible orchestrations"}</strong>
      <span>The daemon returned an honest empty projection for this principal.</span>
    </div>`;
  }
  return html`
    <div class="goal-hero">
      <div>
        <span class="goal-eyebrow">ioi.ai · Goal Space</span>
        <h1>Intent becomes governed work.</h1>
        <p>
          GoalRuns and orchestrations are ioi.ai compositions over thread primitives. Threads, forks, Sessions,
          launch recipes, and harness bindings remain Hypervisor truth.
        </p>
      </div>
      <div class="goal-hero-actions">
        <button class="goal-activate secondary" type="button" data-focus-key="goal-create-runnable" @click=${openRunComposer}>
          ${icon(Network, 18)}<span>Runnable GoalRun</span>
        </button>
        <button class="goal-activate" type="button" data-focus-key="goal-activate" @click=${openComposer}>
          ${icon(Target, 18)}<span>Activate goal</span>
        </button>
        <button class="goal-activate secondary" type="button" data-focus-key="orchestration-compose-open" @click=${openOrchestrationComposer}>
          ${icon(Users, 18)}<span>Compose orchestration</span>
        </button>
      </div>
    </div>
    <div class="goal-truth-strip" role="note">
      ${icon(ShieldCheck, 16)}
      <span>Ordinary chat never silently creates a GoalRun. Activation is a separate exact-hash review.</span>
    </div>
    ${state.composerOpen ? activationForm() : nothing}
    ${state.runComposerOpen ? runnableGoalForm() : nothing}
    ${state.orchestrationComposerOpen ? orchestrationComposerForm() : nothing}
    ${state.activation ? activationReview() : nothing}
    <div class="goal-tabs" role="tablist" aria-label="Goal Space objects">
      <button
        id="goal-tab-goals"
        type="button"
        role="tab"
        aria-selected=${state.tab === "goals" ? "true" : "false"}
        aria-controls="goal-panel-goals"
        tabindex=${state.tab === "goals" ? "0" : "-1"}
        data-focus-key="goal-tab-goals"
        class=${state.tab === "goals" ? "active" : ""}
        @click=${() => selectTab("goals")}
        @keydown=${onGoalTabKeydown}
      >
        Goals <span>${state.goals.length}</span>
      </button>
      <button
        id="goal-tab-orchestrations"
        type="button"
        role="tab"
        aria-selected=${state.tab === "orchestrations" ? "true" : "false"}
        aria-controls="goal-panel-orchestrations"
        tabindex=${state.tab === "orchestrations" ? "0" : "-1"}
        data-focus-key="goal-tab-orchestrations"
        class=${state.tab === "orchestrations" ? "active" : ""}
        @click=${() => selectTab("orchestrations")}
        @keydown=${onGoalTabKeydown}
      >
        Orchestrations <span>${state.orchestrations.length}</span>
      </button>
    </div>
    <section
      id=${`goal-panel-${state.tab}`}
      role="tabpanel"
      aria-labelledby=${`goal-tab-${state.tab}`}
      tabindex="0"
      class="goal-tab-panel"
    >
      ${state.listErrors.length
        ? html`<div class="goal-list-errors" role="status">
            ${state.listErrors.map((message) => html`<p>${message}</p>`)}
          </div>`
        : nothing}
      <div class="goal-object-list">${rows}</div>
    </section>
  `;
}

function refLine(label: string, value: unknown): TemplateResult {
  return html`<div class="goal-ref-line">
    <span>${label}</span><code title=${typeof value === "string" ? value : ""}>${shortRef(value)}</code>
  </div>`;
}

function canonicalRefs(value: unknown, key: string, scheme: "receipt" | "work-result"): string[] {
  const valid = scheme === "receipt" ? isCanonicalReceiptRef : isCanonicalWorkResultRef;
  return listAt(asRecord(value), key).filter((item): item is string => valid(item));
}

function pipelineProjection(run: JsonRecord): TemplateResult {
  const bindings = kernelOwnerBindings(run);
  const roomRef = textAt(run, "outcome_room_ref");
  const receipts = canonicalRefs(run, "receipt_refs", "receipt");
  const results = canonicalRefs(run, "work_result_refs", "work-result");
  return html`
    <section class="goal-pipeline" aria-labelledby="goal-pipeline-title">
      <div class="goal-section-title">
        <span id="goal-pipeline-title">Canonical pipeline</span><small>Four owner layers</small>
      </div>
      <ol>
        <li>
          <span class="goal-layer-index">1</span>
          <span class="goal-layer-icon">${icon(Target, 18)}</span>
          <div>
            <strong>Intent and plan</strong>
            <p>${goalTitle(run)}</p>
          </div>
          ${statusBadge(statusOf(run))}
        </li>
        <li>
          <span class="goal-layer-index">2</span>
          <span class="goal-layer-icon">${icon(Users, 18)}</span>
          <div>
            <strong>Shared work</strong>
            <p>${roomRef ? shortRef(roomRef) : "Direct path · no OutcomeRoom bound"}</p>
          </div>
          ${roomRef ? statusBadge("bound") : statusBadge("not-required")}
        </li>
        <li>
          <span class="goal-layer-index">3</span>
          <span class="goal-layer-icon">${icon(Activity, 18)}</span>
          <div>
            <strong>Execution substrate</strong>
            <p>
              ${requiredKernelBindingsComplete(run)
                ? "Five kernel owners are bound."
                : "Canonical execution chain is incomplete."}
            </p>
          </div>
          ${requiredKernelBindingsComplete(run) ? statusBadge("bound") : statusBadge("blocked")}
        </li>
        <li>
          <span class="goal-layer-index">4</span>
          <span class="goal-layer-icon">${icon(ShieldCheck, 18)}</span>
          <div>
            <strong>Evidence and outcome</strong>
            <p>${results.length} results · ${receipts.length} receipt refs</p>
          </div>
          ${statusBadge(results.length ? "evidence" : "waiting")}
        </li>
      </ol>
      <div class="goal-kernel-grid">
        ${bindings.map(
          (binding) => html`
            <div class="goal-kernel-row ${binding.value ? "bound" : "missing"}">
              <span>${binding.value ? icon(Check, 15) : icon(CircleOff, 15)}</span>
              <div>
                <strong>${binding.label}</strong
                ><code>${binding.value ? shortRef(binding.value) : "owner ref absent"}</code>
              </div>
            </div>
          `,
        )}
      </div>
    </section>
  `;
}

function goalMutationPanel(detail: GoalDetail, id: string | null): TemplateResult {
  const status = statusOf(detail.run);
  const mutation = detail.mutation;
  const available = status === "draft" ? "start" : status === "active" ? "reconcile" : null;
  const label = available === "start" ? "Start governed execution" : "Reconcile verified candidates";
  return html`
    <section class="goal-card goal-card-wide">
      ${sectionTitle("Execution lifecycle", "Daemon-owned effects")}
      ${available
        ? html`<div class="goal-action-row">
            <div>
              <strong>${available === "start" ? "Run admitted harness work" : "Commit the reconciled result"}</strong>
              <p>
                ${available === "start"
                  ? "The daemon resolves live route and harness facts, then crosses wallet authority before any effect."
                  : "Only verified candidate output can cross into the target Session workspace."}
              </p>
            </div>
            <button
              class="btn primary"
              type="button"
              data-focus-key=${available === "start" ? "goal-start" : "goal-reconcile"}
              ?disabled=${!id || mutation?.submitting === true || mutation?.uncertain === true}
              @click=${() => id && void mutateGoal(detail, id, available)}
            >
              ${mutation?.submitting && mutation.kind === available ? "Submitting to daemon…" : label}
            </button>
          </div>`
        : html`<div class="goal-proof">
            ${icon(status === "complete" ? Check : CircleOff, 18)}
            <div>
              <strong>${status === "complete" ? "Reconciliation complete" : `Lifecycle state: ${status}`}</strong>
              <span>The projection above is daemon owner truth; this client does not manufacture a terminal result.</span>
            </div>
          </div>`}
      ${mutation?.error
        ? errorPanel(
            mutation.error,
            mutation.uncertain
              ? `${mutation.kind === "start" ? "Start" : "Reconcile"} result is uncertain`
              : `${mutation.kind === "start" ? "Start" : "Reconcile"} was refused`,
          )
        : nothing}
      ${mutation?.error && mutation.error.status === 403
        ? html`<div class="goal-mutation-form">
            <label class="goal-grant-label" for="goal-lifecycle-grant">
              Wallet approval grant
              <span>Paste only the grant signed for the policy/request hashes shown above.</span>
            </label>
            <textarea
              id="goal-lifecycle-grant"
              data-focus-key="goal-lifecycle-grant"
              class="goal-grant"
              spellcheck="false"
              .value=${mutation.grantText}
              @input=${(event: Event) => {
                mutation.grantText = (event.target as HTMLTextAreaElement).value;
              }}
              placeholder="Paste the exact wallet_approval_grant JSON."
            ></textarea>
            <div class="goal-review-actions">
              <span class="goal-muted">A changed or stale grant is refused without a client-side fallback.</span>
              <button
                class="btn primary"
                type="button"
                data-focus-key="goal-lifecycle-retry"
                ?disabled=${mutation.submitting}
                @click=${() => id && void mutateGoal(detail, id, mutation.kind)}
              >
                ${mutation.submitting ? "Submitting exact grant…" : `Retry ${mutation.kind}`}
              </button>
            </div>
          </div>`
        : nothing}
    </section>
  `;
}

function goalDetailPane(detail: GoalDetail): TemplateResult {
  const run = detail.run;
  const id = goalRunId(run);
  const receipts = canonicalRefs(run, "receipt_refs", "receipt");
  return html`
    <button class="goal-back" type="button" data-focus-key="goal-back" @click=${closeDetail}>
      ${icon(ArrowLeft, 16)} All Goal Spaces
    </button>
    <header class="goal-detail-head">
      <div>
        <span class="goal-eyebrow">GoalRun · daemon owner projection</span>
        <h1 tabindex="-1" data-focus-key="goal-detail-heading">${goalTitle(run)}</h1>
        <p><code>${textAt(run, "goal_ref") ?? id ?? "unknown"}</code></p>
      </div>
      ${statusBadge(statusOf(run))}
    </header>
    <div class="goal-detail-actions">
      <button class="btn" type="button" data-focus-key="goal-reload" @click=${() => id && void openGoal(id, true)}>
        ${icon(RefreshCw, 15)} Reload owner truth
      </button>
    </div>
    ${detail.loading
      ? html`<div class="goal-loading" role="status">
          <span class="spinner"></span><span>Loading GoalRun owner truth…</span>
        </div>`
      : nothing}
    ${detail.error ? errorPanel(detail.error, "GoalRun could not be loaded") : nothing}
    ${detail.error ? nothing : pipelineProjection(run)}
    <div class="goal-detail-grid">
      <section class="goal-card">
        ${sectionTitle("Owner facts")} ${refLine("Owner", textAt(run, "owner_ref"))}
        ${refLine("Profile revision", textAt(run, "goal_run_profile_revision_ref"))}
        ${refLine("Profile hash", textAt(run, "goal_run_profile_content_hash"))}
        ${refLine("Execution ceiling", textAt(run, "goal_run_execution_ceiling_revision_ref"))}
        ${refLine("Room", textAt(run, "outcome_room_ref"))}
      </section>
      <section class="goal-card">
        ${sectionTitle("Receipt evidence", `${receipts.length} refs`)}
        ${receipts.length
          ? receipts.slice(0, 12).map((value) => refLine("Receipt", value))
          : html`<p class="goal-muted">No receipt refs are visible in this projection.</p>`}
      </section>
      <section class="goal-card goal-card-wide">
        ${sectionTitle("Goal replay", "Owner events")}
        ${detail.eventsError
          ? errorPanel(detail.eventsError, "GoalRun events could not be loaded")
          : detail.loading
            ? html`<p class="goal-muted" role="status">Loading admitted events…</p>`
            : detail.events
              ? html`<details class="goal-json">
                  <summary>Inspect admitted events</summary>
                  <pre>${JSON.stringify(detail.events, null, 2)}</pre>
                </details>`
              : html`<p class="goal-muted">No event projection was returned.</p>`}
      </section>
      ${goalMutationPanel(detail, id)}
    </div>
  `;
}

function orchestrationDetailPane(detail: OrchestrationDetail): TemplateResult {
  const orchestration = detail.entry.orchestration;
  const systemId = detail.entry.system_id;
  const id = orchestrationId(orchestration);
  const goalRef = textAt(orchestration, "objective_ref");
  const members = listAt(orchestration, "member_goal_run_refs").filter(
    (value): value is string => typeof value === "string",
  );
  const memberAction = goalRef && members.includes(goalRef) ? "detach" : "attach";
  const closed = statusOf(orchestration) === "closed";
  const nodes = listAt(detail.graph, "nodes").map(asRecord);
  const kindCount = (kind: string): number => nodes.filter((node) => node.kind === kind).length;
  return html`
    <button class="goal-back" type="button" data-focus-key="goal-back" @click=${closeDetail}>
      ${icon(ArrowLeft, 16)} All Goal Spaces
    </button>
    <header class="goal-detail-head orchestration">
      <div>
        <span class="goal-eyebrow">Orchestration · composed over thread primitives</span>
        <h1 tabindex="-1" data-focus-key="orchestration-detail-heading">${orchestrationTitle(orchestration)}</h1>
        <p>
          <code>${textAt(orchestration, "orchestration_id") ?? id ?? "unknown"}</code>
        </p>
      </div>
      ${statusBadge(statusOf(orchestration))}
    </header>
    <div class="goal-detail-actions">
      <button
        class="btn"
        type="button"
        data-focus-key="orchestration-reload"
        @click=${() => id && void openOrchestration(id, systemId, true)}
      >
        ${icon(RefreshCw, 15)} Reload from the daemon
      </button>
      <button
        class="btn primary"
        type="button"
        data-focus-key="orchestration-membership"
        ?disabled=${!id ||
        !goalRef ||
        closed ||
        detail.mutation?.submitting === true ||
        detail.mutation?.uncertain === true}
        @click=${() => id && goalRef && void mutateOrchestrationMembership(detail, id, goalRef, memberAction)}
      >
        ${detail.mutation?.submitting
          ? "Admitting the revision…"
          : memberAction === "attach"
            ? "Attach objective GoalRun"
            : "Detach objective GoalRun"}
      </button>
    </div>
    ${detail.loading
      ? html`<div class="goal-loading" role="status">
          <span class="spinner"></span><span>Loading orchestration projections…</span>
        </div>`
      : nothing}
    ${detail.errors.length
      ? html`<div class="goal-list-errors" role="status">
          ${detail.errors.map((message) => html`<p>${message}</p>`)}
        </div>`
      : nothing}
    ${detail.mutation?.error
      ? errorPanel(
          detail.mutation.error,
          detail.mutation.uncertain
            ? "Orchestration membership result is uncertain"
            : "Orchestration membership revision was refused",
        )
      : nothing}
    <div class="goal-orchestration-spine" aria-label="Orchestration composition">
      <div>
        ${icon(Network, 18)}<strong>Coordinating thread</strong
        ><span>${shortRef(textAt(orchestration, "thread_ref"))}</span>
      </div>
      <span>${icon(ChevronRight, 15)}</span>
      <div>${icon(GitFork, 18)}<strong>Bounded System</strong><span>${shortRef(systemId)}</span></div>
      <span>${icon(ChevronRight, 15)}</span>
      <div>${icon(ShieldCheck, 18)}<strong>Seam head</strong><span>${shortRef(detail.entry.head)}</span></div>
    </div>
    <div class="goal-detail-grid">
      <section class="goal-card">
        ${sectionTitle("Record binding")} ${refLine("System", systemId)}
        ${refLine("Scope", textAt(orchestration, "orchestration_ref"))}
        ${refLine("Owner", textAt(orchestration, "owner_ref"))}
        ${refLine("Composed by", textAt(orchestration, "composed_by_ref"))}
        ${refLine("Payload root", textAt(orchestration, "system_binding", "payload_root"))}
        ${refLine("Head", detail.entry.head)}
      </section>
      <section class="goal-card">
        ${sectionTitle("Composed graph")}
        <div class="goal-metric">
          <span>${kindCount("subagent")}</span><small>delegations</small>
        </div>
        <div class="goal-metric">
          <span>${kindCount("record")}</span><small>records in scope</small>
        </div>
        <div class="goal-metric">
          <span>${detail.entry.revisions}</span><small>revisions on record</small>
        </div>
      </section>
      <section class="goal-card goal-card-wide">
        ${sectionTitle("Membership", "Exact-head revisions")}
        <div class="goal-blocker">
          ${icon(GitFork, 19)}
          <div>
            <strong>
              ${members.length ? `${members.length} GoalRun${members.length === 1 ? "" : "s"} attached` : "No GoalRun attached"}
            </strong>
            <p>
              Attaching or detaching a GoalRun is a revision of this record on the head shown above; the seam refuses a
              stale head by name. The GoalRun's own projection does not yet name its orchestration.
            </p>
            ${members.map((member) => html`<code>${member}</code>`)}
          </div>
        </div>
      </section>
      <section class="goal-card goal-card-wide">
        ${sectionTitle("Replay", "The record's chain")}
        ${detail.replay
          ? html`<details class="goal-json">
              <summary>Inspect every revision and its admission</summary>
              <pre>${JSON.stringify(detail.replay, null, 2)}</pre>
            </details>`
          : html`<p class="goal-muted">Replay is unavailable for this orchestration.</p>`}
      </section>
      <section class="goal-card goal-card-wide">
        ${sectionTitle("Projection evidence")}
        <div class="goal-projection-jsons">
          <details class="goal-json">
            <summary>Composed graph</summary>
            <pre>${JSON.stringify(detail.graph, null, 2)}</pre>
          </details>
          <details class="goal-json">
            <summary>Delegations</summary>
            <pre>${JSON.stringify(detail.delegations, null, 2)}</pre>
          </details>
        </div>
      </section>
    </div>
  `;
}

function draw(focusKey?: string): void {
  if (!appState.mainEl || appState.currentView !== "goals") return;
  const host = document.createElement("div");
  host.className = "pane goal-space-pane";
  let content: TemplateResult;
  if (state.detailGoal) content = goalDetailPane(state.detailGoal);
  else if (state.detailOrchestration) content = orchestrationDetailPane(state.detailOrchestration);
  else content = homePane();
  render(
    html`${content}
      <div class="goal-live" aria-live="polite">${state.notice}</div>`,
    host,
  );
  replacePanePreservingFocus(host);
  if (focusKey) requestAnimationFrame(() => appState.mainEl && focusByKey(appState.mainEl, focusKey));
}

function selectTab(tab: GoalSpaceTab): void {
  state.navigationSequence++;
  state.tab = tab;
  updateLocation(null);
  draw(`goal-tab-${tab}`);
}

function openRunComposer(): void {
  state.composerOpen = false;
  state.orchestrationComposerOpen = false;
  state.runComposerOpen = true;
  state.runCreateError = null;
  draw("goal-run-text");
}

function closeRunComposer(): void {
  state.writeRequestSequence++;
  state.runComposerOpen = false;
  state.creatingRun = false;
  state.runCreateError = null;
  draw("goal-create-runnable");
}

function openOrchestrationComposer(): void {
  state.composerOpen = false;
  state.runComposerOpen = false;
  state.orchestrationComposerOpen = true;
  state.orchestrationComposeError = null;
  draw("orchestration-system");
}

function closeOrchestrationComposer(): void {
  state.writeRequestSequence++;
  state.orchestrationComposerOpen = false;
  state.composingOrchestration = false;
  state.orchestrationComposeError = null;
  draw("orchestration-compose-open");
}

async function createRunnableGoal(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (state.creatingRun || !state.principal) return;
  const form = event.currentTarget as HTMLFormElement;
  const data = new FormData(form);
  const principal = state.principal;
  const sequence = ++state.writeRequestSequence;
  state.creatingRun = true;
  state.runCreateError = null;
  state.notice = "Asking the daemon to resolve a runnable GoalRun.";
  draw();
  try {
    const run = await ioiApi("/api/ioi/goals", validateGoalRunCreate, {
      method: "POST",
      body: JSON.stringify({
        goal: String(data.get("goal") ?? "").trim(),
        session_ref: String(data.get("session_ref") ?? "").trim(),
        model_route_ref: String(data.get("model_route_ref") ?? "").trim() || null,
      }),
    });
    if (sequence !== state.writeRequestSequence || state.principal !== principal) return;
    const id = goalRunId(run);
    if (!id) return;
    state.runComposerOpen = false;
    state.notice = "Runnable GoalRun admitted. Start remains a separate wallet-gated crossing.";
    await refreshLists(false);
    if (sequence !== state.writeRequestSequence || state.principal !== principal) return;
    await openGoal(id);
  } catch (error) {
    if (sequence !== state.writeRequestSequence || state.principal !== principal) return;
    state.runCreateError = failure(error);
    state.notice = "GoalRun creation did not report admission. Refresh owner truth before retrying an uncertain transport failure.";
  } finally {
    if (sequence === state.writeRequestSequence && state.principal === principal) {
      state.creatingRun = false;
      draw();
    }
  }
}

async function composeOrchestration(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (state.composingOrchestration || !state.principal) return;
  const form = event.currentTarget as HTMLFormElement;
  const data = new FormData(form);
  let governance: unknown;
  try {
    governance = JSON.parse(String(data.get("governance") ?? ""));
  } catch {
    state.orchestrationComposeError = {
      status: 400,
      body: { error: "governance_invalid_json", message: "Governance coordinates must be valid JSON." },
    };
    draw("orchestration-governance");
    return;
  }
  const principal = state.principal;
  const sequence = ++state.writeRequestSequence;
  state.composingOrchestration = true;
  state.orchestrationComposeError = null;
  state.notice = "Composing: the coordinating thread first, then the record under the bounded System.";
  draw();
  try {
    const composed = await ioiApi("/api/ioi/orchestrations", validateOrchestrationCompose, {
      method: "POST",
      body: JSON.stringify({
        system_id: String(data.get("system_id") ?? "").trim(),
        objective: String(data.get("objective") ?? "").trim(),
        objective_ref: String(data.get("objective_ref") ?? "").trim() || null,
        mode: String(data.get("mode") ?? "private_goal"),
        governance,
      }),
    });
    if (sequence !== state.writeRequestSequence || state.principal !== principal) return;
    const id = orchestrationId(composed.orchestration);
    if (!id) return;
    state.orchestrationComposerOpen = false;
    state.systemId = composed.system_id;
    state.notice = composed.admission
      ? "Orchestration composed; the seam admitted its record with a receipt."
      : "Orchestration record replayed: the seam already held this exact admission.";
    await refreshLists(false);
    if (sequence !== state.writeRequestSequence || state.principal !== principal) return;
    await openOrchestration(id, composed.system_id);
  } catch (error) {
    if (sequence !== state.writeRequestSequence || state.principal !== principal) return;
    state.orchestrationComposeError = failure(error);
    state.notice = uncertainFailure(state.orchestrationComposeError)
      ? "Orchestration composition result is uncertain. Reload the list before retrying."
      : "Orchestration composition was refused; no local identity was invented.";
  } finally {
    if (sequence === state.writeRequestSequence && state.principal === principal) {
      state.composingOrchestration = false;
      draw();
    }
  }
}

async function mutateGoal(detail: GoalDetail, id: string, kind: "start" | "reconcile"): Promise<void> {
  const principal = state.principal;
  if (!principal || detail.mutation?.submitting) return;
  const mutation =
    detail.mutation?.kind === kind
      ? detail.mutation
      : {
          kind,
          submitting: false,
          uncertain: false,
          grantText: "",
          idempotencyKey: `ioi-ai-reconcile-${crypto.randomUUID()}`,
          error: null,
        };
  detail.mutation = mutation;
  let walletGrant: unknown = null;
  if (mutation.grantText.trim()) {
    try {
      walletGrant = JSON.parse(mutation.grantText);
      if (walletGrant === null || typeof walletGrant !== "object" || Array.isArray(walletGrant)) throw new Error();
    } catch {
      mutation.error = {
        status: 400,
        body: { error: "wallet_approval_grant_invalid_json", message: "Wallet approval grant must be a JSON object." },
      };
      draw("goal-lifecycle-grant");
      return;
    }
  }
  const sequence = ++state.writeRequestSequence;
  mutation.submitting = true;
  mutation.uncertain = false;
  mutation.error = null;
  state.notice = `${kind === "start" ? "Starting" : "Reconciling"} through daemon owner truth.`;
  draw();
  try {
    const result = await ioiApi(
      `/api/ioi/goals/${encodeURIComponent(id)}/${kind}`,
      (value) => (kind === "start" ? validateGoalRunStart(value, id) : validateGoalRunReconcile(value, id)),
      {
        method: "POST",
        body: JSON.stringify({
          ...(kind === "reconcile" ? { idempotency_key: mutation.idempotencyKey } : {}),
          ...(walletGrant ? { wallet_approval_grant: walletGrant } : {}),
        }),
      },
    );
    if (
      sequence !== state.writeRequestSequence ||
      state.principal !== principal ||
      state.detailGoal !== detail ||
      detail.mutation !== mutation
    )
      return;
    mutation.grantText = "";
    detail.run = result.run;
    detail.mutation = null;
    state.notice = kind === "start" ? "GoalRun effects completed; reconciliation is now available." : "GoalRun reconciliation committed daemon truth.";
    await openGoal(id, true);
  } catch (error) {
    if (
      sequence !== state.writeRequestSequence ||
      state.principal !== principal ||
      state.detailGoal !== detail ||
      detail.mutation !== mutation
    )
      return;
    mutation.grantText = "";
    mutation.error = failure(error);
    mutation.uncertain = uncertainFailure(mutation.error);
    mutation.submitting = false;
    state.notice = mutation.uncertain
      ? `${kind === "start" ? "Start" : "Reconcile"} result is uncertain. Reload owner truth before retrying.`
      : `${kind === "start" ? "Start" : "Reconcile"} was refused; the loaded owner projection is unchanged.`;
    draw();
  }
}

async function mutateOrchestrationMembership(
  detail: OrchestrationDetail,
  id: string,
  goalRunRef: string,
  action: "attach" | "detach",
): Promise<void> {
  const principal = state.principal;
  const goalId = goalRunId({ goal_ref: goalRunRef });
  if (!principal || !goalId || !detail.entry.head || detail.mutation?.submitting) return;
  const mutation: OrchestrationMutation = { action, submitting: true, uncertain: false, error: null };
  detail.mutation = mutation;
  const sequence = ++state.writeRequestSequence;
  state.notice = `${action === "attach" ? "Attaching" : "Detaching"} the objective GoalRun as a revision on the exact head.`;
  draw();
  try {
    const result = await ioiApi(
      `/api/ioi/orchestrations/${encodeURIComponent(id)}/goal-runs/${action}`,
      (value) => validateOrchestrationMembership(value, id, goalId, action),
      {
        method: "POST",
        body: JSON.stringify({
          system_id: detail.entry.system_id,
          goal_run_ref: goalRunRef,
          expected_head: detail.entry.head,
        }),
      },
    );
    if (
      sequence !== state.writeRequestSequence ||
      state.principal !== principal ||
      state.detailOrchestration !== detail ||
      detail.mutation !== mutation
    )
      return;
    detail.entry = { ...detail.entry, orchestration: result.orchestration, head: result.head };
    detail.mutation = null;
    state.notice = `Objective GoalRun ${action === "attach" ? "attached to" : "detached from"} the orchestration; the seam admitted the revision.`;
    await openOrchestration(id, detail.entry.system_id, true);
  } catch (error) {
    if (
      sequence !== state.writeRequestSequence ||
      state.principal !== principal ||
      state.detailOrchestration !== detail ||
      detail.mutation !== mutation
    )
      return;
    mutation.error = failure(error);
    mutation.uncertain = uncertainFailure(mutation.error);
    mutation.submitting = false;
    state.notice = mutation.uncertain
      ? "Orchestration membership result is uncertain. Reload from the daemon before another revision."
      : "Orchestration membership revision was refused; the loaded record is unchanged.";
    draw();
  }
}

function openComposer(): void {
  if (state.activation) {
    draw("goal-review-heading");
    return;
  }
  const recovery = state.principal ? readRecovery(state.principal) : null;
  if (recovery) {
    state.notice = "A retained activation already occupies this principal's recovery slot.";
    void resumeActivation(recovery);
    return;
  }
  state.runComposerOpen = false;
  state.orchestrationComposerOpen = false;
  state.composerOpen = true;
  draw("goal-text");
}

function closeComposer(): void {
  state.composerOpen = false;
  draw("goal-activate");
}

function resetActivation(): void {
  state.activationRequestSequence++;
  if (state.activation) state.activation.grantText = "";
  state.activation = null;
  state.activationRecoveryId = null;
  state.composerOpen = true;
  clearRecovery(state.principal);
  updateLocation(null, true);
  state.notice = "Activation draft remains daemon-owned; it was only removed from this view.";
  draw("goal-text");
}

function activationRequestBody(recovery: GoalActivationRecovery): string {
  return JSON.stringify({
    goal_text: recovery.goalText,
    constraints: recovery.constraints,
    project_ref: null,
    idempotency_key: recovery.idempotencyKey,
  });
}

async function retainActivationReview(
  validated: ValidatedActivationResponse,
  recovery: GoalActivationRecovery | null,
  replaceLocation: boolean,
): Promise<void> {
  const { response, goalRun } = validated;
  const admittedId = goalRunId(goalRun);
  if (admittedId) {
    if (state.activation) state.activation.grantText = "";
    state.activation = null;
    state.activationRecoveryId = null;
    clearRecovery(state.principal);
    await openGoal(admittedId, replaceLocation);
    return;
  }
  const id = activationId(response.activation);
  state.activationRecoveryId = id;
  if (recovery && id) {
    recovery.activationId = id;
    writeRecovery(recovery);
  }
  state.activation = {
    response,
    grantText: "",
    submitting: false,
    error: null,
  };
  state.composerOpen = false;
  if (id) updateLocation(`activation:${id}`, replaceLocation);
  state.notice = "Draft retained. Review the exact activation hash before approval.";
  draw();
}

async function draftActivation(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (state.activating) return;
  const form = event.currentTarget as HTMLFormElement;
  const data = new FormData(form);
  const goalText = String(data.get("goal_text") ?? "").trim();
  const constraints = String(data.get("constraints") ?? "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const principal = state.principal;
  if (!principal) return;
  const retained = readRecovery(principal);
  if (retained) {
    state.notice = "A retained activation already occupies this principal's recovery slot.";
    await resumeActivation(retained);
    return;
  }
  const recovery = createGoalActivationRecovery(principal, goalText, constraints, `ioi-ai-${crypto.randomUUID()}`);
  if (!writeRecovery(recovery)) {
    state.activation = {
      response: {},
      grantText: "",
      submitting: false,
      error: {
        status: 0,
        body: {
          error: "goal_activation_recovery_unavailable",
          message: "Activation was not sent because durable browser recovery storage is unavailable.",
        },
      },
    };
    state.composerOpen = false;
    state.notice = "Activation was not sent without a durable retry coordinate.";
    draw("goal-review-heading");
    return;
  }
  const sequence = ++state.activationRequestSequence;
  state.activating = true;
  state.notice = "Preparing daemon-owned activation review.";
  draw();
  try {
    const response = await ioiApi("/api/ioi/goal-activations", validateActivationResponse, {
      method: "POST",
      body: activationRequestBody(recovery),
    });
    if (sequence !== state.activationRequestSequence || state.principal !== principal) return;
    await retainActivationReview(response, recovery, false);
  } catch (error) {
    if (sequence !== state.activationRequestSequence || state.principal !== principal) return;
    state.activation = {
      response: {},
      grantText: "",
      submitting: false,
      error: failure(error),
    };
    state.composerOpen = false;
    state.notice = "Activation draft was not admitted.";
  } finally {
    if (sequence === state.activationRequestSequence && state.principal === principal) {
      state.activating = false;
      draw();
    }
  }
}

async function recoverActivation(id: string, replaceLocation = true): Promise<void> {
  const principal = state.principal;
  if (!principal) return;
  const sequence = ++state.activationRequestSequence;
  state.activationRecoveryId = id;
  state.activating = true;
  state.notice = "Recovering daemon-owned activation truth.";
  draw();
  try {
    const response = await ioiApi(`/api/ioi/goal-activations/${encodeURIComponent(id)}`, (value) =>
      validateActivationResponse(value, id),
    );
    if (sequence !== state.activationRequestSequence || state.principal !== principal) return;
    const recovery = readRecovery(principal);
    await retainActivationReview(response, recovery?.activationId === id ? recovery : null, replaceLocation);
  } catch (error) {
    if (sequence !== state.activationRequestSequence || state.principal !== principal) return;
    state.activation = {
      response: {},
      grantText: "",
      submitting: false,
      error: failure(error),
    };
    state.composerOpen = false;
    state.notice = "The retained activation could not be recovered.";
    updateLocation(`activation:${id}`, replaceLocation);
  } finally {
    if (sequence === state.activationRequestSequence && state.principal === principal) {
      state.activating = false;
      draw();
    }
  }
}

function retryActivationReview(): void {
  if (state.activationRecoveryId) {
    void recoverActivation(state.activationRecoveryId, true);
    return;
  }
  const recovery = state.principal ? readRecovery(state.principal) : null;
  if (recovery) void resumeActivation(recovery);
}

async function resumeActivation(recovery: GoalActivationRecovery): Promise<void> {
  if (recovery.activationId) {
    await recoverActivation(recovery.activationId, true);
    return;
  }
  const sequence = ++state.activationRequestSequence;
  state.activating = true;
  state.notice = "Resuming the retained idempotent activation request.";
  draw();
  try {
    const response = await ioiApi("/api/ioi/goal-activations", validateActivationResponse, {
      method: "POST",
      body: activationRequestBody(recovery),
    });
    if (sequence !== state.activationRequestSequence || state.principal !== recovery.principal) return;
    await retainActivationReview(response, recovery, true);
  } catch (error) {
    if (sequence !== state.activationRequestSequence || state.principal !== recovery.principal) return;
    state.activation = {
      response: {},
      grantText: "",
      submitting: false,
      error: failure(error),
    };
    state.composerOpen = false;
    state.notice = "The retained activation request remains pending recovery.";
  } finally {
    if (sequence === state.activationRequestSequence && state.principal === recovery.principal) {
      state.activating = false;
      draw();
    }
  }
}

async function submitActivation(): Promise<void> {
  const review = state.activation;
  if (!review || review.submitting) return;
  const principal = state.principal;
  if (!principal) return;
  const sequence = ++state.activationRequestSequence;
  const id = activationId(review.response.activation);
  const hash = textAt(review.response, "activation_hash");
  if (!id || !hash) return;
  let grant: unknown = null;
  if (review.grantText.trim()) {
    try {
      grant = JSON.parse(review.grantText);
    } catch {
      review.error = {
        status: 400,
        body: {
          error: "wallet_approval_grant_invalid_json",
          message: "Wallet approval grant must be valid JSON.",
        },
      };
      draw();
      return;
    }
  }
  review.submitting = true;
  review.error = null;
  state.notice = "Submitting the exact reviewed activation hash.";
  draw();
  try {
    const admittedResponse = await ioiApi(
      `/api/ioi/goal-activations/${encodeURIComponent(id)}/submit`,
      (value) => validateAdmittedActivationResponse(value, id, hash),
      {
        method: "POST",
        body: JSON.stringify({
          expected_activation_hash: hash,
          ...(grant ? { wallet_approval_grant: grant } : {}),
        }),
      },
    );
    if (sequence !== state.activationRequestSequence || state.principal !== principal || state.activation !== review)
      return;
    review.grantText = "";
    state.activation = null;
    state.activationRecoveryId = null;
    clearRecovery(state.principal);
    state.notice = "GoalRun admitted with daemon receipts.";
    await refreshLists(false);
    if (
      sequence !== state.activationRequestSequence ||
      state.principal !== principal ||
      appState.currentView !== "goals"
    )
      return;
    const admittedId = goalRunId(admittedResponse.goalRun);
    if (admittedId) await openGoal(admittedId);
    else draw();
  } catch (error) {
    if (sequence !== state.activationRequestSequence || state.principal !== principal || state.activation !== review)
      return;
    review.grantText = "";
    review.error = failure(error);
    review.submitting = false;
    state.notice = "Activation remains unadmitted. Resolve the typed authority or hash refusal and retry.";
    draw();
  }
}

async function refreshLists(showLoading = true): Promise<void> {
  const sequence = ++state.requestSequence;
  state.loading = true;
  state.listErrors = [];
  if (showLoading) loadingPane("Loading daemon-owned Goal Spaces…");
  const [goals, orchestrations] = await Promise.allSettled([
    ioiApi("/api/ioi/goals", validateGoalRunList),
    ioiApi(
      `/api/ioi/orchestrations${state.systemId ? `?system_id=${encodeURIComponent(state.systemId)}` : ""}`,
      validateOrchestrationList,
    ),
  ]);
  if (sequence !== state.requestSequence) return;
  if (goals.status === "fulfilled") state.goals = goals.value;
  else {
    const detail = errorDetail(failure(goals.reason).body);
    state.listErrors.push(`GoalRuns unavailable: ${detail.message}`);
    state.goals = [];
  }
  if (orchestrations.status === "fulfilled") {
    state.orchestrations = orchestrations.value.orchestrations;
    for (const unavailable of orchestrations.value.unavailable) {
      state.listErrors.push(
        `Orchestrations unavailable: ${shortRef(unavailable.system_id)} answered ${unavailable.status}: ${errorDetail(unavailable.error).message}`,
      );
    }
  } else {
    const detail = errorDetail(failure(orchestrations.reason).body);
    state.listErrors.push(`Orchestrations unavailable: ${detail.message}`);
    state.orchestrations = [];
  }
  state.loading = false;
}

export async function openGoal(id: string, replace = false, navigation = ++state.navigationSequence): Promise<void> {
  const sequence = ++state.detailRequestSequence;
  state.detailOrchestration = null;
  const detail: GoalDetail = {
    run: {},
    events: null,
    loading: true,
    error: null,
    eventsError: null,
    mutation: null,
  };
  state.detailGoal = detail;
  updateLocation(id, replace);
  draw();
  const [goal, events] = await Promise.allSettled([
    ioiApi(`/api/ioi/goals/${encodeURIComponent(id)}`, (value) => validateGoalDetail(value, id)),
    ioiApi(`/api/ioi/goals/${encodeURIComponent(id)}/events`, (value) => validateGoalEvents(value, id)),
  ]);
  if (
    sequence !== state.detailRequestSequence ||
    navigation !== state.navigationSequence ||
    state.detailGoal !== detail
  )
    return;
  if (goal.status === "fulfilled") detail.run = goal.value;
  else detail.error = failure(goal.reason);
  if (events.status === "fulfilled") detail.events = events.value;
  else detail.eventsError = failure(events.reason);
  detail.loading = false;
  draw();
}

export async function openOrchestration(
  id: string,
  systemId: string,
  replace = false,
  navigation = ++state.navigationSequence,
): Promise<void> {
  const sequence = ++state.detailRequestSequence;
  state.detailGoal = null;
  state.systemId = systemId;
  const detail: OrchestrationDetail = {
    entry: { system_id: systemId, orchestration: {}, head: "", revisions: 0, thread_id: "" },
    graph: null,
    replay: null,
    delegations: null,
    loading: true,
    errors: [],
    mutation: null,
  };
  state.detailOrchestration = detail;
  updateLocation(`orchestration:${id}`, replace);
  draw();
  const base = `/api/ioi/orchestrations/${encodeURIComponent(id)}`;
  const query = `?system_id=${encodeURIComponent(systemId)}`;
  const responses = await Promise.allSettled([
    ioiApi(`${base}${query}`, (value) => validateOrchestrationDetail(value, id)),
    ioiApi(`${base}/graph${query}`, (value) => validateOrchestrationGraph(value, id)),
    ioiApi(`${base}/replay${query}`, (value) => validateOrchestrationReplay(value, id)),
    ioiApi(`${base}/delegations${query}`, validateOrchestrationDelegations),
  ]);
  if (
    sequence !== state.detailRequestSequence ||
    navigation !== state.navigationSequence ||
    state.detailOrchestration !== detail
  )
    return;
  const [entry, graph, replay, delegations] = responses;
  if (entry.status === "fulfilled") detail.entry = entry.value;
  else detail.errors.push(`Orchestration unavailable: ${errorDetail(failure(entry.reason).body).message}`);
  if (graph.status === "fulfilled") detail.graph = graph.value;
  else detail.errors.push(`Graph unavailable: ${errorDetail(failure(graph.reason).body).message}`);
  if (replay.status === "fulfilled") detail.replay = replay.value;
  else detail.errors.push(`Replay unavailable: ${errorDetail(failure(replay.reason).body).message}`);
  if (delegations.status === "fulfilled") detail.delegations = delegations.value;
  else detail.errors.push(`Delegations unavailable: ${errorDetail(failure(delegations.reason).body).message}`);
  detail.loading = false;
  draw();
}

function closeDetail(): void {
  const goalId = state.detailGoal ? goalRunId(state.detailGoal.run) : null;
  const orchestration = state.detailOrchestration ? orchestrationId(state.detailOrchestration.entry.orchestration) : null;
  state.detailRequestSequence++;
  state.writeRequestSequence++;
  state.navigationSequence++;
  state.detailGoal = null;
  state.detailOrchestration = null;
  updateLocation(null);
  let focusKey = "goal-tab-goals";
  if (goalId) focusKey = `goal-row-${goalId}`;
  else if (orchestration) focusKey = `orchestration-row-${orchestration}`;
  draw(focusKey);
}

export function routeGoalSpaceHistory(item: string | null): void {
  const navigation = ++state.navigationSequence;
  state.activationRequestSequence++;
  state.detailRequestSequence++;
  state.writeRequestSequence++;
  if (!item) {
    state.detailGoal = null;
    state.detailOrchestration = null;
    if (state.activation) state.activation.grantText = "";
    state.activation = null;
    state.activationRecoveryId = null;
    state.composerOpen = false;
    draw("goal-tab-goals");
    return;
  }
  if (item.startsWith("orchestration:")) {
    const systemId = systemFromLocation() ?? state.systemId;
    if (systemId) void openOrchestration(item.slice("orchestration:".length), systemId, true, navigation);
    else orchestrationLinkWithoutSystem();
  } else if (item.startsWith("activation:")) void recoverActivation(item.slice("activation:".length), true);
  else void openGoal(item, true, navigation);
}

function orchestrationLinkWithoutSystem(): void {
  state.detailGoal = null;
  state.detailOrchestration = null;
  state.tab = "orchestrations";
  state.notice = "This orchestration link names no bounded System; choose it from the list.";
  updateLocation(null, true);
  draw("goal-tab-orchestrations");
}

export function suspendGoalSpaceRequests(): void {
  state.requestSequence++;
  state.detailRequestSequence++;
  state.activationRequestSequence++;
  state.writeRequestSequence++;
  state.navigationSequence++;
  if (state.activation) state.activation.grantText = "";
  state.detailGoal = null;
  state.detailOrchestration = null;
  state.activation = null;
  state.activationRecoveryId = null;
  state.loading = false;
  state.activating = false;
  state.composerOpen = false;
  state.runComposerOpen = false;
  state.orchestrationComposerOpen = false;
  state.creatingRun = false;
  state.composingOrchestration = false;
  state.runCreateError = null;
  state.orchestrationComposeError = null;
  state.notice = "";
}

export async function renderGoalSpace(item: string | null = null): Promise<void> {
  const principal = appState.me?.user ?? null;
  if (!principal) {
    resetGoalSpaceState(state.principal);
    return;
  }
  if (state.principal && state.principal !== principal) resetGoalSpaceState(state.principal);
  state.principal = principal;
  const navigation = ++state.navigationSequence;
  state.detailRequestSequence++;
  state.detailGoal = null;
  state.detailOrchestration = null;
  if (item?.startsWith("orchestration:")) state.systemId = systemFromLocation() ?? state.systemId;
  await refreshLists(true);
  if (appState.currentView !== "goals" || navigation !== state.navigationSequence) return;
  if (item?.startsWith("orchestration:")) {
    if (state.systemId) await openOrchestration(item.slice("orchestration:".length), state.systemId, true, navigation);
    else orchestrationLinkWithoutSystem();
  } else if (item?.startsWith("activation:")) await recoverActivation(item.slice("activation:".length), true);
  else if (item) await openGoal(item, true, navigation);
  else {
    const recovery = readRecovery(principal);
    if (recovery) await resumeActivation(recovery);
    else draw();
  }
}

export function resetGoalSpaceState(principal: string | null = state.principal): void {
  if (state.activation) state.activation.grantText = "";
  clearRecovery(principal);
  state.requestSequence++;
  state.detailRequestSequence++;
  state.activationRequestSequence++;
  state.writeRequestSequence++;
  state.navigationSequence++;
  state.tab = "goals";
  state.goals = [];
  state.orchestrations = [];
  state.systemId = null;
  state.loading = false;
  state.listErrors = [];
  state.detailGoal = null;
  state.detailOrchestration = null;
  state.activation = null;
  state.activationRecoveryId = null;
  state.activating = false;
  state.composerOpen = false;
  state.runComposerOpen = false;
  state.orchestrationComposerOpen = false;
  state.creatingRun = false;
  state.composingOrchestration = false;
  state.runCreateError = null;
  state.orchestrationComposeError = null;
  state.notice = "";
  state.principal = null;
}
