#!/usr/bin/env node

// M4 product/operator-state proof for the existing ported /ai#new-session composer.
// The native seed submit remains a distinct Session-shaped act and never crosses the
// GoalRunActivation boundary. Durable goal truth requires the separately labelled, two-step
// daemon review/admission affordance. This verifier owns a fresh daemon + product-ui process.

import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import {
  sanitizedVerifierBaseEnv,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
const GOAL_RUN_CREATE_SCOPE = "scope:goal.run.create";
const POST_STALE_DAEMON_RESPONSE_TIMEOUT_MS = 60_000;
const checks = [];
const EXPECTED_CHECKS = 17;
const CLEAN_BASE_ENV = sanitizedVerifierBaseEnv();
const check = (name, pass, detail = "") =>
  checks.push({ name, pass: Boolean(pass), detail });

function familyCount(dataDir, family) {
  try {
    return readdirSync(join(dataDir, family)).filter((name) =>
      name.endsWith(".json"),
    ).length;
  } catch {
    return 0;
  }
}

async function json(base, method, path, body, headers = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    body: await response.json().catch(() => ({})),
  };
}

let plane = null;
let browser = null;
let authorityResolver = null;
let verifierPhase = "startup";
try {
  check(
    "SCOPE: no parallel apps/ioi-ai workspace was introduced",
    !existsSync(join(REPO, "apps", "ioi-ai")),
  );
  authorityResolver = await startRealWalletNetworkPrincipalAuthorityFixture({
    baseEnv: CLEAN_BASE_ENV,
  });
  plane = await startIsolatedPlane({
    serve: true,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...authorityResolver.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF,
    },
  });
  if (!plane) {
    console.error("BLOCKED: build target/debug/hypervisor-daemon first");
    process.exitCode = 2;
  } else {
    const exposedAnonymous = await json(
      plane.serveUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      {
        schema_version: "ioi.goal-run-activation-draft-request.v1",
        goal_text: "This exposed anonymous request must not create durable goal truth",
        constraints: [],
        project_ref: null,
        result_profile: "research",
        idempotency_key: "m4-shell-exposed-anonymous-refusal-v1",
      },
      { "x-ioi-forwarded": "m4-product-shell-proof" },
    );
    check(
      "IDENTITY: shell proxy preserves deployment posture and exposed anonymous activation fails closed",
      exposedAnonymous.status === 401 &&
        exposedAnonymous.body.error?.code ===
          "goal_run_activation_authentication_required" &&
        familyCount(plane.dataDir, "goal-run-activations") === 0,
      `${exposedAnonymous.status}/${exposedAnonymous.body.error?.code}`,
    );
    const exposedSessionCreate = await json(
      plane.serveUrl,
      "POST",
      "/v1/hypervisor/sessions",
      {
        session_ref: "session:m4-exposed-anonymous-refusal",
        initial_input: "must not persist",
      },
      { "x-ioi-forwarded": "m4-product-shell-proof" },
    );
    const exposedRegistryStatuses = await Promise.all(
      [
        "/v1/hypervisor/sessions",
        "/v1/goal-orchestration/goal-runs",
        "/v1/hypervisor/work-results",
        "/v1/hypervisor/outcome-deltas",
      ].map(async (path) => {
        const response = await fetch(`${plane.serveUrl}${path}`, {
          headers: { "x-ioi-forwarded": "m4-product-shell-proof" },
        });
        return response.status;
      }),
    );
    check(
      "IDENTITY: exposed anonymous callers cannot create Sessions or enumerate Session/GoalRun/result/delta owner registries",
      exposedSessionCreate.status === 401 &&
        exposedRegistryStatuses.every((status) => status === 401) &&
        familyCount(plane.dataDir, "sessions") === 0,
      `create=${exposedSessionCreate.status}/lists=${exposedRegistryStatuses.join(",")}`,
    );
    verifierPhase = "anonymous-goal-space-posture";
    const exposedProjection = await fetch(
      `${plane.serveUrl}/__ioi/goal-space?room=outcome-room%3A%2F%2Fmissing`,
      { headers: { "x-ioi-forwarded": "m4-product-shell-proof" } },
    );
    const exposedProjectionHtml = await exposedProjection.text();
    check(
      "IDENTITY: server-rendered Goal Space reads preserve exposed posture and never fall back to local-operator truth",
      exposedProjection.status === 401 &&
        exposedProjectionHtml.includes("HTTP 401") &&
        exposedProjectionHtml.includes("OutcomeRoom") &&
        !exposedProjectionHtml.includes("all projections match the room head"),
      `status=${exposedProjection.status}`,
    );
    browser = await chromium.launch();
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) =>
      pageErrors.push(String(error?.name || "page_error").slice(0, 80)),
    );

    // Native submit remains the ported seed lane, rebound in place to daemon Session truth. Prove
    // that it attaches the input and that neither activation nor GoalRun is minted as a side effect.
    const nativeRequests = [];
    page.on("request", (request) => nativeRequests.push(request.url()));
    await page.goto(`${plane.serveUrl}/ai#new-session`, {
      waitUntil: "networkidle",
    });
    const textarea = page.locator('[data-testid="prompt-input-textarea"]');
    await textarea.waitFor({ state: "visible", timeout: 20_000 });
    await page.locator("#ioi-goal-activation").waitFor({
      state: "visible",
      timeout: 10_000,
    });
    check(
      "SEED: the existing ported composer owns /ai#new-session",
      (await page.evaluate(() => location.pathname + location.hash)) ===
        "/ai#new-session" &&
        (await page.locator('[data-testid="ioi-ai-page"]').count()) === 1,
    );
    check(
      "SEED: Activate Goal is an augmentation of the composer, not a replacement shell",
      (await page.locator('[data-testid="prompt-input-submit-button"]').count()) === 1 &&
        (await page.locator("#ioi-goal-activation").count()) === 1 &&
        (await page.locator("#ioi-home-explorer").count()) <= 1,
    );

    await textarea.fill("Inspect the current bounded room projection as a Session");
    await page.waitForFunction(
      () =>
        document.querySelector('[data-testid="prompt-input-submit-button"]')
          ?.disabled === false,
      { timeout: 10_000 },
    );
    const nativeSessionResponse = page.waitForResponse(
      (response) =>
        response.url().endsWith("/v1/hypervisor/sessions") &&
        response.request().method() === "POST",
      { timeout: 30_000 },
    );
    // Enter is the highest-risk semantic alias: it must dispatch the exact native Session
    // action owned by the ported composer, never the adjacent explicit Goal activation act.
    await textarea.press("Enter");
    const nativeSession = await nativeSessionResponse;
    const nativeSessionPayload = await nativeSession.json().catch(() => ({}));
    await page
      .getByText("Session ready", { exact: true })
      .waitFor({ state: "visible", timeout: 20_000 });
    const afterNative = await json(
      plane.daemonUrl,
      "GET",
      "/v1/goal-orchestration/goal-runs",
    );
    const sessionsAfterNative = await json(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/sessions",
    );
    const sessionAfterNative = await json(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(nativeSessionPayload.session_ref)}`,
    );
    const exposedSessionRead = await fetch(
      `${plane.serveUrl}/v1/hypervisor/sessions/${encodeURIComponent(nativeSessionPayload.session_ref)}`,
      { headers: { "x-ioi-forwarded": "m4-product-shell-proof" } },
    );
    check(
      "SESSION DEFAULT: native seed Enter admits one bounded daemon Session",
        nativeSession.status() === 202 &&
        nativeSessionPayload.session_ref &&
        nativeSessionPayload.initial_input_projection?.disposition ===
          "session_only_non_goal" &&
        nativeSessionPayload.goal_run_activation_ref === null &&
        nativeSessionPayload.goal_run_ref === null &&
        (sessionsAfterNative.body.sessions || []).length === 1 &&
        sessionAfterNative.body.session?.initial_input_projection?.content ===
          "Inspect the current bounded room projection as a Session",
      `${nativeSession.status()}/${nativeSessionPayload.error?.code || nativeSessionPayload.session_ref}`,
    );
    check(
      "IDENTITY: exposed anonymous callers cannot read the persisted Session prompt by id",
      exposedSessionRead.status === 401,
      `status=${exposedSessionRead.status}`,
    );
    check(
      "DENIAL: native Enter cannot mint GoalRunActivation or GoalRun truth",
      familyCount(plane.dataDir, "goal-run-activations") === 0 &&
        familyCount(plane.dataDir, "goal-runs") === 0 &&
        (afterNative.body.goal_runs || []).length === 0 &&
        !nativeRequests.some((url) => url.includes("/goal-run-activations")) &&
        !nativeRequests.some((url) =>
          /\/api\/ioi[.]v1[.]AgentService\/(CreateAgentExecution|StartAgent)/u.test(
            url,
          ),
        ),
      `activations=${familyCount(plane.dataDir, "goal-run-activations")} goal_runs=${familyCount(plane.dataDir, "goal-runs")}`,
    );

    // Explicit activation is two-step. Drafting displays daemon-owned identity, authority,
    // non-grants, profile coordinates, source, and review posture before admission.
    await page.goto(`${plane.serveUrl}/ai#new-session`, {
      waitUntil: "networkidle",
    });
    const changedPrompt =
      "Compile one hosted OutcomeRoom and retain all negative evidence";
    await textarea.fill(changedPrompt);
    const firstDraftResponse = page.waitForResponse(
      (response) =>
        response.url().includes("/goal-run-activations") &&
        response.request().method() === "POST" &&
        !response.url().endsWith("/submit"),
      { timeout: 20_000 },
    );
    await page.locator("#ioi-goal-activation").click();
    const firstDraft = await firstDraftResponse;
    await page
      .getByText("Review durable Goal activation")
      .waitFor({ state: "visible", timeout: 20_000 });
    const reviewText =
      (await page.locator("#ioi-goal-activation-panel").textContent()) || "";
    check(
      "REVIEW: drafting alone admits no GoalRun",
      firstDraft.status() === 201 &&
        familyCount(plane.dataDir, "goal-run-activations") === 1 &&
        familyCount(plane.dataDir, "goal-runs") === 0,
      `${firstDraft.status()}/activations=${familyCount(plane.dataDir, "goal-run-activations")}/goal_runs=${familyCount(plane.dataDir, "goal-runs")}`,
    );
    const reviewMarkers = [
      "Intent",
      "Source",
      "Source kind",
      "Principal",
      "Profile",
      "Profile hash",
      "Authority",
      "Effects",
      "Review",
      "Activation hash",
      "explicit_user",
      "ioi_goal_draft",
    ];
    check(
      "REVIEW: required source, principal, profile, authority, effects, hash, and explicit review are visible",
      reviewMarkers.every((text) => reviewText.includes(text)),
      JSON.stringify({
        panel_text_bytes: Buffer.byteLength(reviewText),
        required_marker_count: reviewMarkers.length,
        present_marker_count: reviewMarkers.filter((text) =>
          reviewText.includes(text),
        ).length,
      }),
    );

    let submitCalls = 0;
    page.on("request", (request) => {
      if (request.url().endsWith("/submit")) submitCalls += 1;
    });
    await textarea.fill(`${changedPrompt} with a changed body`);
    await page.locator("#ioi-goal-activation-confirm").click();
    await page
      .getByText("Goal activation refused")
      .waitFor({ state: "visible", timeout: 10_000 });
    const staleText =
      (await page.locator("#ioi-goal-activation-panel").textContent()) || "";
    check(
      "STALE STATE: changing prompt after review refuses before daemon submission",
      submitCalls === 0 &&
        staleText.includes("goal_activation_review_stale") &&
        familyCount(plane.dataDir, "goal-runs") === 0,
      `submit_calls=${submitCalls} goal_runs=${familyCount(plane.dataDir, "goal-runs")}`,
    );

    // Re-review the changed bytes, then perform the explicit activation act.
    verifierPhase = "changed-prompt-second-draft";
    const secondDraftResponse = page.waitForResponse(
      (response) =>
        response.url().includes("/goal-run-activations") &&
        response.request().method() === "POST" &&
        !response.url().endsWith("/submit"),
      { timeout: POST_STALE_DAEMON_RESPONSE_TIMEOUT_MS },
    );
    await page.locator("#ioi-goal-activation").click();
    const secondDraft = await secondDraftResponse;
    verifierPhase = "changed-prompt-second-draft-render";
    await page
      .getByText("Review durable Goal activation")
      .waitFor({ state: "visible", timeout: 20_000 });
    verifierPhase = "explicit-activation-authority-request";
    const authorityResponse = page.waitForResponse(
      (response) =>
        response.url().endsWith("/submit") &&
        response.request().method() === "POST",
      { timeout: POST_STALE_DAEMON_RESPONSE_TIMEOUT_MS },
    );
    await page.locator("#ioi-goal-activation-confirm").click();
    const authorityRequired = await authorityResponse;
    const authorityPayload = await authorityRequired.json().catch(() => ({}));
    verifierPhase = "explicit-activation-authority-render";
    await page
      .getByText("Wallet authority required", { exact: true })
      .waitFor({ state: "visible", timeout: 20_000 });
    const authorityText =
      (await page.locator("#ioi-goal-activation-panel").textContent()) || "";
    check(
      "AUTHORITY: explicit review exposes the exact wallet scope and commitments without minting GoalRun truth",
      authorityRequired.status() === 403 &&
        authorityPayload.error?.code ===
          "goal_run_activation_authority_required" &&
        authorityPayload.error?.required_scope === GOAL_RUN_CREATE_SCOPE &&
        authorityPayload.error?.approval?.policy_hash &&
        authorityPayload.error?.approval?.request_hash &&
        authorityText.includes(GOAL_RUN_CREATE_SCOPE) &&
        authorityText.includes(authorityPayload.error.approval.policy_hash) &&
        authorityText.includes(authorityPayload.error.approval.request_hash) &&
        familyCount(plane.dataDir, "goal-runs") === 0,
      `${authorityRequired.status()}/${authorityPayload.error?.code}`,
    );
    verifierPhase = "wallet-authority-grant";
    const grant = await authorityResolver.mintRecorded(
      DEPLOYMENT_AUTHORITY_REF,
      authorityPayload.error.approval.policy_hash,
      authorityPayload.error.approval.request_hash,
      GOAL_RUN_CREATE_SCOPE,
    );
    await page.locator("#ioi-goal-activation-grant").fill(JSON.stringify(grant));
    verifierPhase = "explicit-activation-granted-submit";
    const submitResponse = page.waitForResponse(
      (response) =>
        response.url().endsWith("/submit") &&
        response.request().method() === "POST",
      { timeout: POST_STALE_DAEMON_RESPONSE_TIMEOUT_MS },
    );
    await page.locator("#ioi-goal-activation-authority-submit").click();
    const submitted = await submitResponse;
    const admittedPayload = await submitted.json().catch(() => ({}));
    verifierPhase = "explicit-activation-admitted-render";
    await page.waitForTimeout(1_000);
    const admittedText =
      (await page.locator("#ioi-goal-activation-panel").textContent()) || "";
    check(
      "ACTIVATION: explicit second act admits exactly one typed GoalRun",
      secondDraft.status() === 201 &&
        submitted.status() === 201 &&
        admittedPayload.activation?.status === "admitted" &&
        admittedPayload.goal_run?.schema_version === "ioi.goal-run.v1" &&
        familyCount(plane.dataDir, "goal-runs") === 1 &&
        admittedText.includes("Goal admitted"),
      JSON.stringify({
        draft_status: secondDraft.status(),
        submit_status: submitted.status(),
        error_code: admittedPayload.error?.code || null,
        goal_ref_present: Boolean(admittedPayload.goal_run?.goal_ref),
        admitted_label_present: admittedText.includes("Goal admitted"),
        panel_text_bytes: Buffer.byteLength(admittedText),
      }),
    );
    const admittedProjectionMarkers = [
      "GoalRun",
      "Authority decision",
      "Admitted root",
      "Lifecycle head",
      "Review receipt",
      "Admission receipt",
      "Activation receipt",
    ];
    check(
      "PRODUCT STATE: admitted projection exposes durable identity, head/root, and all receipts",
      admittedProjectionMarkers.every((text) => admittedText.includes(text)) &&
        /^agentgres:\/\/state-root\//u.test(
          admittedPayload.goal_run?.admitted_state_root_ref || "",
        ) &&
        /^sha256:[0-9a-f]{64}$/u.test(
          admittedPayload.goal_run?.lifecycle_head || "",
        ) &&
        admittedPayload.receipts?.review?.receipt_ref &&
        admittedPayload.receipts?.admission?.receipt_ref &&
        admittedPayload.receipts?.activation?.receipt_ref,
      JSON.stringify({
        panel_text_bytes: Buffer.byteLength(admittedText),
        required_marker_count: admittedProjectionMarkers.length,
        present_marker_count: admittedProjectionMarkers.filter((text) =>
          admittedText.includes(text),
        ).length,
        admitted_state_root_ref_present: Boolean(
          admittedPayload.goal_run?.admitted_state_root_ref,
        ),
        lifecycle_head_present: Boolean(admittedPayload.goal_run?.lifecycle_head),
        receipt_presence: {
          review: Boolean(admittedPayload.receipts?.review?.receipt_ref),
          admission: Boolean(admittedPayload.receipts?.admission?.receipt_ref),
          activation: Boolean(admittedPayload.receipts?.activation?.receipt_ref),
        },
      }),
    );
    const browserStorage = await page.evaluate(() => ({
      localKeys: Object.keys(localStorage).sort(),
      local: Object.values(localStorage),
      sessionKeys: Object.keys(sessionStorage).sort(),
      session: Object.values(sessionStorage),
      grantFieldPresent: Boolean(document.querySelector("#ioi-goal-activation-grant")),
    }));
    const forbiddenPatternPresent = [
      ...browserStorage.local,
      ...browserStorage.session,
    ].some((value) =>
      String(value).includes(String(grant.grant_id || "__no_grant_id__")),
    );
    check(
      "AUTHORITY CUSTODY: the one-use signed grant is absent from DOM and browser storage after admission",
      browserStorage.grantFieldPresent === false &&
        !forbiddenPatternPresent,
      JSON.stringify({
        local_key_count: browserStorage.localKeys.length,
        local_keys: browserStorage.localKeys
          .slice(0, 64)
          .map((key) => String(key).slice(0, 120)),
        session_key_count: browserStorage.sessionKeys.length,
        session_keys: browserStorage.sessionKeys
          .slice(0, 64)
          .map((key) => String(key).slice(0, 120)),
        key_list_truncated:
          browserStorage.localKeys.length > 64 || browserStorage.sessionKeys.length > 64,
        grant_field_present: browserStorage.grantFieldPresent,
        forbidden_pattern_present: forbiddenPatternPresent,
      }),
    );
    check(
      "UX SAFETY: the composer journey produced no uncaught page errors",
      pageErrors.length === 0,
      JSON.stringify({
        page_error_count: pageErrors.length,
        page_error_types: pageErrors.slice(0, 16),
        type_list_truncated: pageErrors.length > 16,
      }),
    );
    await context.close();
  }
} catch (error) {
  check(
    "verifier completed without an unhandled error",
    false,
    JSON.stringify({
      phase: verifierPhase,
      error_name: String(error?.name || "Error").slice(0, 80),
      error_code: error?.code ? String(error.code).slice(0, 120) : null,
      message_bytes: Buffer.byteLength(String(error?.message || error)),
    }),
  );
} finally {
  if (browser) await browser.close().catch(() => {});
  if (plane) await plane.stop().catch(() => {});
  if (authorityResolver) await authorityResolver.stop().catch(() => {});
}

if (process.exitCode === 2) process.exit(2);
const failures = checks.filter((result) => !result.pass);
for (const result of checks) {
  console.log(
    `${result.pass ? "PASS" : "FAIL"} ${result.name}${result.detail ? ` — ${result.detail}` : ""}`,
  );
}
console.log(
  `\nM4_PORTED_COMPOSER_GOAL_ACTIVATION=${checks.length - failures.length}/${checks.length}`,
);
if (checks.length !== EXPECTED_CHECKS) {
  console.error(`FAIL verifier coverage changed: expected ${EXPECTED_CHECKS}, got ${checks.length}`);
}
process.exit(failures.length || checks.length !== EXPECTED_CHECKS ? 1 : 0);
