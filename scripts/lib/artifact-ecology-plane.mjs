// M08.17 PLANE — the ecology surface driven against a real isolated daemon and the REAL
// wallet.network principal-authority fixture, with the composition it renders actually admitted.
//
// What this leg does, in order:
//   the bounded System is admitted and activated through its governed genesis;
//   an orchestration composes a collective-resolution receipt and THREE persistent executable lineages
//     that sit on the three different rungs — one reused (stored), one installed, one activated on a
//     kernel-owned delegation (running);
//   the serve is started AGAINST THAT DAEMON and the ecology page is fetched over HTTP;
//   every rendered rung is compared to the rung the DAEMON's own record supports, not to what the
//     surface's model said — the page is the artifact under test, so the page is what is read;
//   the running lineage is then STOPPED through the composer, the page is refetched, and the rung must
//     have fallen: a view that keeps rendering `running` after the runtime is gone is the defect this
//     unit exists to prevent, and a source pin cannot see it;
//   the page is fetched EMBEDDED and must resolve the same rungs;
//   and nothing the surface did wrote anything: the record count is taken before the first fetch and
//     after the last, because a read model that writes is not a read model.
//
// WHAT IT DOES NOT CLAIM, said here rather than implied: there is no ioi.ai Goal Space surface anywhere
// in this estate, so the cross-application parity the unit's acceptance names is proven between the DEEP
// and EMBEDDED renderings of the one view that exists. That absence is the gate's clause 12.

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "../../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "../../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "../../apps/hypervisor/scripts/verify-hypervisor-system-sequence-zero-materialization.mjs";

const SYSTEM_ID = "system://ioi/collective/m08-17-ecology";
const GENESIS_ID = "genesis://ioi/collective/m08-17-ecology/genesis";
const CONSTITUTION_REF = "constitution://ioi/collective/m08-17-ecology/v1";
const PACKAGE = "package://ioi/outcome-room";
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE = "app-scope://ioi-ai/orchestration/orc_m0817_ecology";
const SUBJECT = "goal://m0817_ecology";
const ROUTE = "/__ioi/missions/ecology";

const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); });
});

async function jsonCall(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = [];
      response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; } resolve({ status: response.statusCode, body: parsed, text: raw }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error(`HTTP timeout at ${method} ${path}`)), 900_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

async function getText(url, headers = {}) {
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(url), { method: "GET", headers }, (response) => {
      const chunks = [];
      response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); resolve({ status: response.statusCode, text: Buffer.concat(chunks).toString("utf8") }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error("page read timed out")), 120_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    request.end();
  });
}

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await getText(url); if (r.status && r.status < 500) return true; } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
};

function genesisBody() {
  const body = exactGenesisBody();
  body.release.package_id = PACKAGE;
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"5".repeat(64)}`;
  body.release.display_name = "Persistent artifact ecology M08.17 verifier package";
  body.release.description = "The collective composition the ecology surface renders.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/collective";
  recomputeReleaseHashes(body.release);
  // Every profile ref carries the SYSTEM'S OWN TAIL or genesis refuses it `profile_coordinate_mismatch`.
  const TAIL = SYSTEM_ID.slice("system://".length);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://${TAIL}/local/revision/sha256:${"a".repeat(64)}`,
    orderingProfileRef: `ordering-profile://${TAIL}/hosted`,
    oracleProfileRef: `oracle-evidence-profile://${TAIL}/fail-closed`,
    lifecycleProfileRef: `lifecycle-profile://${TAIL}/default`,
  });
}

const refused = async (fn) => {
  try { return { ok: true, value: await fn() }; } catch (error) {
    const daemon = error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
    return { ok: false, status: error?.status, code: daemon || error?.code, message: String(error?.message ?? "") };
  }
};

/** Every `data-ioi-lineage`/`data-ioi-rung` pair the page carries, read from the BYTES. */
const renderedRungs = (html) => Object.fromEntries(
  [...String(html).matchAll(/data-ioi-lineage="([^"]+)"[^>]*data-ioi-rung="([a-z]+)"/gu)].map((m) => [m[1], m[2]]),
);

export async function planeLeg({ ROOT, LIB }) {
  const started = Date.now();
  const findings = [];
  const observed = { rungs: {}, after_stop: {}, embedded: {}, writes: {} };
  const note = (what) => findings.push(what);
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m0817-ecology-"));
  const APP_DIR = join(ROOT, "apps", "hypervisor");
  const SERVE = join(APP_DIR, "scripts", "serve-product-ui.mjs");
  let resolver;
  let plane;
  let serve;
  try {
    const sdkPath = join(ROOT, "packages", "agent-sdk", "dist", "index.js");
    const composerPath = join(ROOT, "apps", "ioi-ai", "orchestration", "dist", "index.js");
    if (!existsSync(sdkPath)) return { blocked: true, findings: ["BLOCKED: build packages/agent-sdk first"], seconds: 0, observed };
    if (!existsSync(composerPath)) return { blocked: true, findings: ["BLOCKED: build apps/ioi-ai/orchestration first"], seconds: 0, observed };
    const { Orchestration, createRuntimeSubstrateClient } = await import(pathToFileURL(sdkPath).href);
    const { CollectiveResolutions, ContextCells, ContextLeases, ExecutableLineages, GoalRuns, collectiveReceiptId } = await import(pathToFileURL(composerPath).href);

    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: false });
    if (!plane) return { blocked: true, findings: ["BLOCKED: build target/debug/hypervisor-daemon first"], seconds: 0, observed };
    const DAEMON = plane.daemonUrl;

    const log = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = log.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1];
    if (!token) return { blocked: true, findings: ["BLOCKED: the isolated daemon exposed no bootstrap token"], seconds: 0, observed };
    const operator = await jsonCall(DAEMON, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "m0817-ecology-password", email: "m0817@ioi.local" });
    const sessionToken = operator.status === 200 && operator.body?.session_token;
    if (!sessionToken) return { blocked: true, findings: [`BLOCKED: operator bootstrap failed ${operator.status}`], seconds: 0, observed };
    const headers = { authorization: `Bearer ${sessionToken}` };
    const cookie = `ioi_session=${sessionToken}`;
    const call = (method, path, body) => jsonCall(DAEMON, method, path, body, headers);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${operator.body?.principal?.principal_id}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    const client = createRuntimeSubstrateClient({ endpoint: DAEMON, headers });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    if (!(active.status === "active" || active.source)) return { blocked: true, findings: [`BLOCKED: the System did not activate (${JSON.stringify(active).slice(0, 180)})`], seconds: 0, observed };

    // ---- the composition the surface will render -------------------------------------------------
    const orchestration = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE, objective: "M08.17: the ecology the surface renders" });
    const META = "docs/architecture/_meta/schemas";
    const rootOf = (invariantFile, ruleId, record) => {
      const rule = JSON.parse(readFileSync(join(ROOT, META, "invariants", invariantFile), "utf8")).rules.find((r) => r.rule_id === ruleId);
      const material = {};
      for (const [field, d] of Object.entries(rule.expression.material_fields)) {
        const v = d.path.replace(/^\$\./u, "").split(".").reduce((acc, k) => (acc == null ? undefined : acc[k]), record);
        if (v === undefined) throw new Error(`${ruleId}: ${d.path} absent`);
        material[field] = v;
      }
      const canonical = (value) => {
        if (value === null || typeof value !== "object") { const e = JSON.stringify(value); return e === undefined ? "" : e; }
        if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
        return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
      };
      return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
    };
    const profileFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "goal-run-profile-resolution-receipt-v1", "positive-minimal.json"), "utf8"));
    const profileReceipt = { ...profileFixture, receipt_id: "receipt://m0817/profile-resolution", goal_ref: SUBJECT };
    profileReceipt.receipt_root = rootOf("goal-run-profile-resolution-receipt.v1.invariants.json", "goal_run_profile_resolution_receipt.closure.recomputes", profileReceipt);
    await refused(() => orchestration.record({ contract_id: "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1", object_id: profileReceipt.receipt_id, record: profileReceipt, expected_head: null }));
    const runs = new GoalRuns(orchestration);
    const run = await refused(() => runs.admit({ goal_run_id: "gr_m0817", goal_ref: SUBJECT, owner_ref: OWNER, profile_resolution_receipt_ref: profileReceipt.receipt_id, origin_surface: "api", normalized_goal: "hold three lineages on three rungs", source_context_binding: { target_session_ref: null, project_ref: null }, receipt_obligations: [], admitted_state_root_ref: "artifact://m0817/admitted-state", authority_scope_refs: ["scope:goal.run.create"] }));
    const worker = await refused(() => orchestration.delegate({ prompt: "carry the running lineage", role: "worker" }));
    const subagentId = worker.value?.subagent_id ?? worker.value?.subagent?.subagent_id ?? (await orchestration.delegations()).subagents?.[0]?.subagent_id;
    const DELEGATION = `delegation://${orchestration.thread_id}/${subagentId}`;

    const project = await call("POST", "/v1/hypervisor/projects", { repository_url: "https://example.invalid/m0817/ecology.git", project_name: "m0817-ecology" });
    const projectId = project.body?.selected_project_id ?? project.body?.project?.project_id ?? project.body?.project_id ?? "";
    const automation = await call("POST", "/v1/hypervisor/automations", { project_ref: projectId, name: "m0817 ecology installation", steps: [] });
    const automationId = automation.body?.automation?.automation_id ?? automation.body?.automation?.id ?? "";
    const INSTALLATION = `automation-installation://${automationId}`;

    const owners = {
      async exists(ref) {
        if (ref.startsWith("automation-installation://")) { const r = await call("GET", `/v1/hypervisor/automations/${encodeURIComponent(ref.slice("automation-installation://".length))}`, undefined); return r.status === 200 && r.body?.ok !== false && Boolean(r.body?.automation ?? r.body?.automation_id); }
        if (ref.startsWith("delegation://")) { const [thread, sub] = ref.slice("delegation://".length).split("/"); if (thread !== orchestration.thread_id) return false; const listed = await orchestration.delegations(); return (listed.subagents ?? []).some((s) => s.subagent_id === sub); }
        return false;
      },
    };
    const actors = { async isAccountable(ref) { return ref.startsWith("delegation://") ? owners.exists(ref) : false; } };
    const resolutions = new CollectiveResolutions(orchestration, {
      owners,
      system: { async active() { return { system_release_ref: genesisBody().release.manifest_id, constitution_ref: CONSTITUTION_REF, active_profile_set_ref: genesisBody().proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref }; } },
    });
    const RECEIPT_ID = collectiveReceiptId("m0817/one");
    const receipt = await refused(() => resolutions.resolve({ receipt_id: RECEIPT_ID, goal_run_profile_revision_refs: [run.value?.record?.goal_run_profile_revision_ref], policy_refs: ["policy://ioi/orchestration/coordination/v1"], lease_policy_refs: ["policy://ioi/lease/context/v1"], artifact_lifecycle_policy_ref: "policy://ioi/artifact/reuse-fork-install-retire/v1", requirement_refs: ["requirement://verifier/path/v1"], resolved_owner_refs: [SCOPE, SUBJECT, DELEGATION] }));
    if (!receipt.ok) return { blocked: true, findings: [`BLOCKED: no collective-resolution receipt (${receipt.code}: ${receipt.message?.slice(0, 200)})`], seconds: Math.round((Date.now() - started) / 1000), observed };

    const cells = new ContextCells(orchestration);
    const leases = new ContextLeases(orchestration, { views: { async query() { throw Object.assign(new Error("no views"), { status: 404 }); } } });
    await refused(() => cells.admit({ context_cell_id: "context-cell://m0817/conductor", work_subject_ref: SUBJECT, role_topology_revision_ref: null, role_binding_id: "binding-conductor", accountable_actor_ref: "worker://m0817/conductor", role: "conductor", resolver_revision_ref: null, resolver_content_hash: null, model_route_ref: null, memory_projection_refs: [], information_flow_label_refs: [], active_runtime_assignment_ref: null, authority_scope_refs: ["authority://m0817/read"], compression_policy_ref: null, current_claim_ref: null, next_wake_condition_ref: null }));
    await refused(() => leases.issue({ context_lease_id: "context-lease://m0817/l1", issued_to_ref: "context-cell://m0817/conductor", lease_kind: "runtime", allowed_ref_patterns: ["worktree://m0817/*"], denied_ref_patterns: [], authority_scope_refs: ["authority://m0817/read"], budget_ref: null, ttl_seconds: 3600, receipt_required: false, leased_refs: [], information_flow_label_refs: [], permitted_recipient_roles: ["conductor", "implementer"] }));

    const lineages = new ExecutableLineages(orchestration, { owners, actors });
    const draft = (id, over = {}) => ({ lineage_id: id, resolution_receipt_ref: RECEIPT_ID, artifact_ref: `artifact://m0817/${id.split("/").pop()}`, artifact_sha256: `sha256:${createHash("sha256").update(id).digest("hex")}`, definition_ref: "automation-spec://m0817/etl/revision/1", accountable_subject_ref: "automation://m0817/etl", stop_policy_ref: "policy://m0817/stop", ...over });
    const STORED = "lineage://m0817/stored";
    const INSTALLED = "lineage://m0817/installed";
    const RUNNING = "lineage://m0817/running";
    await refused(() => lineages.reuse(draft(STORED)));
    await refused(() => lineages.reuse(draft(INSTALLED)));
    const inst = await refused(() => lineages.install(INSTALLED, { installation_ref: INSTALLATION }));
    await refused(() => lineages.reuse(draft(RUNNING)));
    await refused(() => lineages.install(RUNNING, { installation_ref: INSTALLATION }));
    const activated = await refused(() => lineages.activate(RUNNING, { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: ["context-lease://m0817/l1"], caretaker_ref: DELEGATION }));
    if (!inst.ok) note(`the installed lineage did not install (${inst.code})`);
    if (!activated.ok) return { blocked: true, findings: [`BLOCKED: the running lineage did not activate (${activated.code}: ${activated.message?.slice(0, 200)})`], seconds: Math.round((Date.now() - started) / 1000), observed };

    // ---- the serve, pointed at THIS daemon -------------------------------------------------------
    const servePort = await freePort();
    const productUiPort = await freePort();
    const SERVE_URL = `http://127.0.0.1:${servePort}`;
    serve = spawn(process.execPath, [SERVE], {
      cwd: APP_DIR,
      env: {
        ...sanitizedVerifierBaseEnv(process.env),
        PORT: String(servePort),
        PRODUCT_UI_PORT: String(productUiPort),
        IOI_PRODUCT_UI_PUBLIC: join(APP_DIR, "product-ui", "owned", "public"),
        IOI_HYPERVISOR_DAEMON_URL: DAEMON,
        // The seam read walks every authorized resource under the System and reads each record's full
        // stream; against a DEBUG daemon on a box also running the wallet fixture that genuinely
        // exceeds the 3s product default, and the surface then degrades honestly to a timeout notice.
        // The leg is testing the RENDERING, so it buys the read enough time to happen.
        IOI_SURFACE_PLANE_TIMEOUT_MS: "25000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let serveLog = "";
    serve.stdout.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-20000); });
    serve.stderr.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-20000); });
    if (!(await waitFor(`${SERVE_URL}/__ioi/login`, 90_000))) {
      return { blocked: true, findings: [`BLOCKED: the serve never came up — ${serveLog.slice(-300)}`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }

    const recordCount = async () => (await orchestration.records()).count;
    const before = await recordCount();

    // TIME THE SAME READS THE SURFACE MAKES, from here, with the leg's own authenticated transport.
    // Three rounds of this leg reported "the page does not render it" with three different causes, and
    // the third was a plane_timeout that could have been the route or the serve. Timing them here
    // separates those: a route that answers in milliseconds to the leg and times out to the surface is a
    // serve problem, and a route slow to both is the route.
    const timed = async (label, path) => {
      const at = Date.now();
      const r = await call("GET", path, undefined);
      const ms = Date.now() - at;
      observed.read_ms = { ...(observed.read_ms ?? {}), [label]: ms };
      if (r.status !== 200) note(`the ${label} read answered ${r.status} to the leg's own transport (${JSON.stringify(r.body).slice(0, 160)})`);
      return { ms, body: r.body };
    };
    await timed("systems_projection", "/v1/hypervisor/autonomous-systems/projection");
    await timed("lineage_records", `/v1/hypervisor/autonomous-systems/${encodeURIComponent(SYSTEM_ID)}/records?contract_id=${encodeURIComponent(LIB.CONTRACTS.lineage)}`);

    // ---- THE PAGE IS THE ARTIFACT UNDER TEST, so the page is what is read ------------------------
    const scoped = `${ROUTE}?system=${encodeURIComponent(SYSTEM_ID)}`;
    const page = await getText(`${SERVE_URL}${scoped}`, { cookie });
    if (page.status !== 200) return { blocked: true, findings: [`BLOCKED: the ecology page answered ${page.status}`], seconds: Math.round((Date.now() - started) / 1000), observed };
    observed.rungs = renderedRungs(page.text);
    if (Object.keys(observed.rungs).length === 0) {
      // A page that rendered no lineage is the hardest failure to diagnose from a finding alone, so the
      // evidence carries enough of it to say WHY. The first run of this leg spent a whole round on
      // "the page does not render it" before the cause turned out to be an unauthenticated seam read.
      observed.empty_page_excerpt = page.text.replace(/<style>[\s\S]*?<\/style>/u, "<style/>").slice(0, 1200);
      observed.plane_notice = /not treated as zero/u.test(page.text);
      observed.notice_code = /<code>([a-z_]+)<\/code>/u.exec(page.text)?.[1] ?? "";
    }

    // What the DAEMON's own records support, derived independently of the surface's model.
    const served = await call("GET", `/v1/hypervisor/autonomous-systems/${encodeURIComponent(SYSTEM_ID)}/records?contract_id=${encodeURIComponent(LIB.CONTRACTS.lineage)}`, undefined);
    const records = (served.body?.records ?? []).map((e) => e?.current).filter(Boolean);
    if (!records.length) note("the seam served no lineage records, so the page's rungs are compared to nothing");
    const expected = Object.fromEntries(records.map((r) => [String(r.lineage_id), LIB.rungOf(r)]));
    for (const [id, rung] of Object.entries(expected)) {
      if (observed.rungs[id] === undefined) note(`${id} is admitted and the page does not render it`);
      else if (observed.rungs[id] !== rung) note(`${id} renders as ${observed.rungs[id]} and the daemon's own record supports ${rung}`);
    }
    if (expected[RUNNING] !== "running") note(`the activated lineage's record supports ${expected[RUNNING]}, so this leg never had a running rung to test`);
    if (expected[STORED] !== "stored" || expected[INSTALLED] !== "installed") {
      note(`the three rungs were not distinct on the daemon's own records (${JSON.stringify(expected)})`);
    }

    // ---- THE RUNG MUST FALL WHEN THE RUNTIME GOES ------------------------------------------------
    // No source pin can see this: the page rendered `running` correctly a moment ago, and the question
    // is whether it keeps saying so once the composer has stopped the runtime.
    const stopped = await refused(() => lineages.stop(RUNNING, "policy"));
    if (!stopped.ok) note(`the running lineage did not stop (${stopped.code})`);
    const after = await getText(`${SERVE_URL}${scoped}`, { cookie });
    observed.after_stop = renderedRungs(after.text);
    if (observed.after_stop[RUNNING] === "running") {
      note("the page still renders the stopped lineage as running — a surface that keeps saying `running` after the runtime is gone is the whole defect this unit exists to prevent");
    }
    if (!observed.after_stop[RUNNING]) note("the stopped lineage vanished from the page instead of falling a rung");

    // ---- embedded resolves the same ----------------------------------------------------------------
    const embedded = await getText(`${SERVE_URL}${scoped}&embed=1`, { cookie });
    observed.embedded = renderedRungs(embedded.text);
    for (const [id, rung] of Object.entries(observed.after_stop)) {
      if (observed.embedded[id] !== rung) note(`${id} resolves as ${rung} deep and ${observed.embedded[id]} embedded`);
    }

    // ---- a read model does not write ---------------------------------------------------------------
    const afterCount = await recordCount();
    observed.writes = { records_before: before, records_after: afterCount, stop_admitted: stopped.ok };
    // The composer's stop mints a successor REVISION, not a new record, so the count must be unchanged.
    if (afterCount !== before) note(`the record count moved from ${before} to ${afterCount} across three page reads`);

    // the page claims no authority and offers no write control
    if (/<form|type="submit"/u.test(page.text)) note("the served page carries a write control");
    if (!/writes nothing|executed by their owners/u.test(page.text)) note("the served page does not say who executes the composition's verbs");
  } catch (error) {
    note(`the plane leg threw: ${String(error?.stack ?? error).slice(0, 500)}`);
  } finally {
    if (serve) { try { serve.kill("SIGTERM"); } catch { /* already gone */ } }
    if (plane) await plane.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
  return { blocked: false, findings, observed, seconds: Math.round((Date.now() - started) / 1000) };
}
