#!/usr/bin/env node
// M1.6/M1.7 PRODUCT journey verifier — m1-system-genesis-product-journey.
//
// Drives the four pulled surfaces (Studio package/genesis composition, Governance preview,
// Packages lifecycle, provisional System detail — all under /__ioi/systems/*) through the
// compact/advanced/restart/two-System operator state matrix against a THROWAWAY isolated
// daemon+serve plane and the REAL wallet.network principal-authority fixture. Every successful
// authority decision traverses the real wallet; every refusal must render verbatim on the
// surface; the serve layer must proxy, never mint.
//
// OPERATOR STATE MATRIX (states x lanes — the journey walked below):
//
//   lane \ state      | loading_or_pending        | honest_empty        | ready_or_proposed        | denied_or_revoked          | unavailable_or_degraded | stale_conflict_or_ambiguous  | recovery_or_rollback      | completed
//   ------------------+---------------------------+---------------------+--------------------------+----------------------------+-------------------------+------------------------------+---------------------------+----------------------------
//   compact composer  | (n/a — stateless form)    | fresh form          | challenge preview+hashes | blocker report / bad input | daemon down on submit   | (daemon-coded conflicts)     | resubmit with grant       | admission record+receipt
//   advanced composer | (n/a — stateless form)    | fresh form          | challenge preview+hashes | blocker report / bad input | daemon down on submit   | (daemon-coded conflicts)     | resubmit with grant       | admission record+receipt
//   governance preview| ladder rows pending       | honest_empty census | pending challenge preview| blocker preview            | daemon down             | census fail-closed           | census recovered          | (never — preview only)
//   packages census   | census withheld mid-ladder| honest_empty census | per-System rows          | (daemon-coded refusals)    | daemon down             | source-incomplete fail-closed| restored census           | active/dissolving rows
//   System detail     | pending ladder stages     | unknown key         | action challenge preview | premature activate refusal | daemon down             | cross-System head conflict   | post-restart reconstruction| active + receipts + status
//   restart lane      | —                         | —                   | —                        | —                          | killed daemon = degraded| —                            | byte-exact rebuild        | both Systems ready again
//   two-System lane   | second System mid-ladder  | —                   | both rows listed         | substitution refused       | —                       | head-conflict verbatim       | —                         | two active isolated Systems
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-system-genesis-product-journey.mjs
// Exit 0 pass · 1 fail · 2 blocked (daemon binary or wallet fixture unavailable).

import { createHash } from "node:crypto";
import http from "node:http";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "docs", "architecture", "_meta", "schemas", "fixtures");
const SURFACE_MODULE = join(HERE, "system-genesis-surfaces.mjs");
const BASE = "/__ioi/systems";
const GENESIS_API = "/v1/hypervisor/autonomous-systems";
const OWNER = "org://acme/research";
const GENESIS_SCOPE = "scope:autonomous_system.genesis_admit";
const MATERIALIZE_SCOPE = "scope:autonomous_system.genesis_materialize";
const INITIALIZE_SCOPE = "scope:autonomous_system.lifecycle.initialize";
const ACTIVATE_SCOPE = "scope:autonomous_system.lifecycle.activate";
const DISSOLUTION_SCOPE = "scope:autonomous_system.continuity.initiate_dissolution";
const RECORD_FAMILY = "autonomous-system-genesis-registry";

const results = [];
function ok(name, pass, detail = "") {
  results.push({ name, pass: Boolean(pass) });
  console.log(`${pass ? "PASS" : "FAIL"}: ${name}${detail ? ` - ${detail}` : ""}`);
}
function requireValue(value, message) {
  if (!value) throw new Error(message);
  return value;
}
const clone = (value) => structuredClone(value);
const fixture = (relative) => JSON.parse(readFileSync(join(FIXTURES, relative), "utf8"));
const progress = (message) => console.log(`journey progress: ${message}`);

// ---- exact JCS hashing (mirrors the M1 verifiers over ordinary-JSON fixtures) --------------
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
const domainHash = (domain, value) =>
  `sha256:${createHash("sha256").update(canonicalJson({ domain, value })).digest("hex")}`;
const artifactHash = (domain, artifact) =>
  `sha256:${createHash("sha256").update(canonicalJson({ domain, artifact })).digest("hex")}`;

function recomputeReleaseHashes(release) {
  const componentMaterial = clone(release.typed_components);
  delete componentMaterial.component_set_hash;
  release.typed_components.component_set_hash = domainHash(
    "ioi.autonomous-system-component-set-jcs-sha256.v1",
    componentMaterial,
  );
  const releaseMaterial = clone(release);
  delete releaseMaterial.release_root;
  delete releaseMaterial.registry_status;
  delete releaseMaterial.receipts.package_readiness_receipt_ref;
  delete releaseMaterial.release.publisher_signature_ref;
  delete releaseMaterial.release.registry_published_at;
  release.release_root = domainHash(
    "ioi.autonomous-system-manifest-release-root-jcs-sha256.v1",
    releaseMaterial,
  );
}

function exactGenesisBody(genesisId = null) {
  const release = fixture("autonomous-system-manifest-v1/positive-reusable-release.json");
  recomputeReleaseHashes(release);
  const candidate = fixture("autonomous-system-genesis-v1/positive-proposed.json");
  delete candidate.admitted_manifest_root;
  delete candidate.initial_profile_bundle_root;
  delete candidate.cryptographic_origin.genesis_operation_commitment;
  delete candidate.cryptographic_origin.genesis_transition_commitment_ref;
  if (genesisId) candidate.genesis_id = genesisId;
  candidate.initial_component_bindings.admitted_component_set_hash =
    release.typed_components.component_set_hash;
  return {
    release,
    proposed_instantiation: {
      schema_version: "ioi.autonomous-system-genesis-proposal-input.v1",
      candidate,
      template_bindings: {
        constitution_template_ref: release.constitution_template_ref,
        deployment_template_ref: release.required_profile_templates.deployment_template_ref,
        ordering_admission_finality_template_ref:
          release.required_profile_templates.ordering_admission_finality_template_ref,
        oracle_evidence_template_refs:
          release.required_profile_templates.oracle_evidence_template_refs,
        lifecycle_continuity_template_ref:
          release.required_profile_templates.lifecycle_continuity_template_ref,
        network_enrollment_constraint_ref:
          release.required_profile_templates.network_enrollment_constraint_ref,
      },
      constitution: fixture("autonomous-system-constitution-v1/positive-draft.json"),
      ordering_profile: fixture("ordering-admission-finality-profile-v1/positive-single-authority.json"),
      oracle_profiles: [fixture("oracle-evidence-profile-v1/positive-fail-closed.json")],
      lifecycle_profile: fixture("lifecycle-continuity-profile-v1/positive-successor-governed.json"),
      network_enrollment: null,
    },
  };
}

function rebindGenesisBodySystem(source, ids) {
  const body = clone(source);
  const proposed = body.proposed_instantiation;
  const candidate = proposed.candidate;
  candidate.system_id = ids.systemId;
  candidate.genesis_id = ids.genesisId;
  candidate.constitution_ref = ids.constitutionRef;
  candidate.initial_profile_refs.deployment_profile_ref = ids.deploymentProfileRef;
  candidate.initial_profile_refs.ordering_admission_finality_profile_ref = ids.orderingProfileRef;
  candidate.initial_profile_refs.oracle_evidence_profile_refs = [ids.oracleProfileRef];
  candidate.initial_profile_refs.lifecycle_continuity_profile_ref = ids.lifecycleProfileRef;
  proposed.constitution.system_id = ids.systemId;
  proposed.constitution.constitution_id = ids.constitutionRef;
  proposed.ordering_profile.system_id = ids.systemId;
  proposed.ordering_profile.constitution_ref = ids.constitutionRef;
  proposed.ordering_profile.ordering_profile_id = ids.orderingProfileRef;
  proposed.oracle_profiles[0].system_id = ids.systemId;
  proposed.oracle_profiles[0].oracle_evidence_profile_id = ids.oracleProfileRef;
  proposed.lifecycle_profile.system_id = ids.systemId;
  proposed.lifecycle_profile.constitution_ref = ids.constitutionRef;
  proposed.lifecycle_profile.lifecycle_profile_id = ids.lifecycleProfileRef;
  return body;
}

// Pin the deployment profile ref of a genesis candidate to its content-derived revision (the
// same pinning bootstrapActiveSystem performs; initialize later binds this exact revision).
function lifecycleDeploymentRevisionForGenesis(genesis) {
  const revision = fixture("autonomous-system-deployment-profile-revision-v1/positive-candidate.json");
  const deploymentProfileRef = genesis.initial_profile_refs.deployment_profile_ref;
  const identity = typeof deploymentProfileRef === "string"
    ? deploymentProfileRef.replace(/\/revision\/sha256:[0-9a-f]{64}$/, "")
    : null;
  requireValue(identity?.startsWith("deployment-profile://"), "genesis deployment profile lacks a canonical identity");
  revision.profile.deployment_profile_id = identity;
  revision.profile.system_id = genesis.system_id;
  revision.profile.constitution_ref = genesis.constitution_ref;
  revision.profile.manifest_ref = genesis.manifest_ref;
  revision.profile.ordering_admission_finality_profile_ref =
    genesis.initial_profile_refs.ordering_admission_finality_profile_ref;
  const root = `sha256:${createHash("sha256")
    .update(canonicalJson({
      domain: "ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1",
      profile: revision.profile,
    }))
    .digest("hex")}`;
  revision.deployment_profile_root = root;
  revision.deployment_profile_ref = `${revision.profile.deployment_profile_id}/revision/${root}`;
  return revision;
}

// ---- transport (node:http with a 15-minute ceiling — governed posts hold on the wallet) ----
function httpCall(baseUrl, method, path, { json, form } = {}) {
  const target = new URL(`${baseUrl}${path}`);
  let payload = null;
  let contentType = "application/json";
  if (json !== undefined) payload = JSON.stringify(json);
  if (form !== undefined) {
    payload = new URLSearchParams(form).toString();
    contentType = "application/x-www-form-urlencoded";
  }
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method,
        headers: {
          "content-type": contentType,
          ...(payload === null ? {} : { "content-length": Buffer.byteLength(payload) }),
        },
      },
      (response) => {
        let raw = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => { raw += chunk; });
        response.on("error", reject);
        response.on("end", () => {
          let parsed = null;
          try { parsed = JSON.parse(raw); } catch { parsed = null; }
          resolve({ status: response.statusCode, text: raw, json: parsed, headers: response.headers });
        });
      },
    );
    request.on("error", (error) => resolve({ status: 0, text: "", json: null, error: error.message }));
    request.setTimeout(900_000, () => request.destroy(new Error(`call timed out: ${method} ${path}`)));
    if (payload !== null) request.write(payload);
    request.end();
  });
}

// ---- evidence helpers ----------------------------------------------------------------------
function collectJsonFiles(root, current = root, output = []) {
  let entries;
  try { entries = readdirSync(current, { withFileTypes: true }); } catch { return output; }
  for (const entry of entries) {
    const absolute = join(current, entry.name);
    if (entry.isDirectory()) collectJsonFiles(root, absolute, output);
    else if (entry.isFile() && entry.name.endsWith(".json")) {
      output.push([absolute.slice(root.length + 1), readFileSync(absolute, "utf8")]);
    }
  }
  return output.sort(([left], [right]) => left.localeCompare(right));
}
const jsonSnapshot = (dataDir) => JSON.stringify(collectJsonFiles(dataDir));

const journeyState = (html, state) => html.includes(`data-journey-state="${state}"`);
const truthCode = (html, code) => html.includes(`data-truth-code="${code}"`);
function approvalFrom(html) {
  const grab = (key) => {
    const match = html.match(new RegExp(`data-approval="${key}">(sha256:[0-9a-f]{64})<`));
    return match ? match[1] : null;
  };
  return {
    policy_hash: grab("policy_hash"),
    request_hash: grab("request_hash"),
    effect_hash: grab("effect_hash"),
  };
}

async function main() {
  // Inherited IOI_* env must not leak into the isolated plane or the wallet fixture.
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("IOI_")),
  );

  progress("starting the real wallet.network principal-authority fixture (cargo test — first run may compile)");
  let resolver;
  try {
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv: cleanEnv });
  } catch (error) {
    console.error(`BLOCKED: wallet.network fixture unavailable: ${error.message}`);
    process.exit(2);
  }

  const dataDir = mkdtempSync(join(tmpdir(), "ioi-sysgen-product-journey-"));
  let plane = null;
  let plane2 = null;
  let exitCode = 1;
  try {
    progress("booting the isolated daemon + serve plane");
    plane = await startIsolatedPlane({
      serve: true,
      dataDir,
      env: resolver.env,
      baseEnv: cleanEnv,
    });
    if (!plane) {
      console.error("BLOCKED: target/debug/hypervisor-daemon is not built");
      process.exit(2);
    }
    let serveUrl = plane.serveUrl;
    const S = (path, options) => httpCall(serveUrl, "GET", path, options);
    const P = (path, form) => httpCall(serveUrl, "POST", path, { form });
    const daemonDirect = (method, path, json) => httpCall(plane.daemonUrl, method, path, json === undefined ? {} : { json });

    // Shared surface-step driver: POST a governed form WITHOUT a grant, read the daemon's
    // approval hashes off the rendered challenge, mint+record the real wallet approval, then
    // repost the SAME form WITH the grant and return the committed page.
    async function governedSurfaceStep(label, path, form, scope) {
      progress(`governed step: ${label} (challenge)`);
      const challengePage = await P(path, form);
      const approval = approvalFrom(challengePage.text);
      requireValue(
        journeyState(challengePage.text, "ready_or_proposed") && approval.policy_hash && approval.request_hash,
        `${label}: surface did not render the authority challenge (page ${challengePage.status})`,
      );
      const grant = resolver.mintForCapability(OWNER, approval.policy_hash, approval.request_hash);
      await resolver.recordApproval(OWNER, approval.policy_hash, approval.request_hash, grant, scope);
      progress(`governed step: ${label} (granted resubmission)`);
      let committed = await P(path, { ...form, wallet_approval_grant: JSON.stringify(grant) });
      for (let retry = 0; retry < 3 && truthCode(committed.text, "system_lifecycle_authority_resolver_unavailable"); retry += 1) {
        await new Promise((resolve) => setTimeout(resolve, 250));
        committed = await P(path, { ...form, wallet_approval_grant: JSON.stringify(grant) });
      }
      return { challengePage, committed, approval };
    }

    // ---- 1. MOUNT: launch-addressed only, no permanent Systems navigation ------------------
    const [applicationsPage, catalogJson, augmentation, systemsRedirect] = await Promise.all([
      S("/__ioi/applications"),
      S("/__ioi/api/applications"),
      S("/ioi-augmentation.js"),
      S(BASE),
    ]);
    const catalogRoutes = (catalogJson.json?.apps || []).map((app) => app.route || "");
    ok(
      "MOUNT: the four surfaces mount launch-addressed only — no permanent Systems navigation (suite page, app catalog, injected rail untouched)",
      applicationsPage.status === 200 &&
        !applicationsPage.text.includes(BASE) &&
        !catalogRoutes.some((route) => route.startsWith(BASE)) &&
        !augmentation.text.includes(BASE) &&
        systemsRedirect.status === 302 &&
        systemsRedirect.headers.location === `${BASE}/packages`,
      `catalog=${catalogRoutes.length} redirect=${systemsRedirect.status}→${systemsRedirect.headers.location || "none"}`,
    );

    // ---- 2. honest_empty + composer readiness ----------------------------------------------
    const [packagesEmpty, governanceEmpty, composeCompact, composeAdvanced, unknownDetail] = await Promise.all([
      S(`${BASE}/packages`),
      S(`${BASE}/governance`),
      S(`${BASE}/compose?lane=compact`),
      S(`${BASE}/compose?lane=advanced`),
      S(`${BASE}/${"asg_" + "0".repeat(64)}`),
    ]);
    ok(
      "HONEST EMPTY: packages + governance render the daemon's honest_empty census with zero fabricated rows",
      journeyState(packagesEmpty.text, "honest_empty") &&
        packagesEmpty.text.includes("honest_empty") &&
        !packagesEmpty.text.includes("data-system-id=") &&
        journeyState(governanceEmpty.text, "honest_empty") &&
        !governanceEmpty.text.includes("data-system-id="),
      "no data-system-id rows in either census",
    );
    ok(
      "COMPOSER READY: both lanes render their composition forms with the estate nonclaims banner",
      composeCompact.status === 200 &&
        composeCompact.text.includes('data-lane-tab="compact"') &&
        composeCompact.text.includes('name="system_id"') &&
        composeCompact.text.includes('data-sysgen-nonclaims="1"') &&
        composeAdvanced.status === 200 &&
        !composeAdvanced.text.includes('name="system_id"') &&
        composeAdvanced.text.includes('data-sysgen-nonclaims="1"'),
      "compact carries rebind fields; advanced is verbatim-only",
    );
    ok(
      "UNKNOWN SYSTEM: a canonical-but-unknown key renders the daemon's not-found honestly (nothing substituted)",
      journeyState(unknownDetail.text, "honest_empty") && truthCode(unknownDetail.text, "system_genesis_not_found"),
      "system_genesis_not_found rendered",
    );

    // ---- 3. browsing mints nothing ---------------------------------------------------------
    const browseBaseline = jsonSnapshot(dataDir);
    await Promise.all([
      S(`${BASE}/packages`), S(`${BASE}/governance`), S(`${BASE}/compose`),
      S(`${BASE}/${"asg_" + "1".repeat(64)}`),
    ]);
    ok(
      "NAVIGATION MINTS NOTHING: browsing all four surfaces leaves the daemon tree byte-identical",
      browseBaseline === jsonSnapshot(dataDir),
      "durable JSON snapshot unchanged",
    );

    // ---- 4. invalid proposal → rendered blocker report -------------------------------------
    const invalidBody = exactGenesisBody("genesis://acme/system-alpha/product-journey-invalid");
    invalidBody.release.system_binding.allowed_use = "upgrade_existing";
    recomputeReleaseHashes(invalidBody.release);
    const beforeInvalid = jsonSnapshot(dataDir);
    const invalidPage = await P(`${BASE}/compose`, { lane: "advanced", declaration: JSON.stringify(invalidBody) });
    ok(
      "INVALID PROPOSAL: the compiler blocker report renders verbatim (denied state, exact blocker code+path) with zero mutation",
      journeyState(invalidPage.text, "denied_or_revoked") &&
        truthCode(invalidPage.text, "system_genesis_proposal_invalid") &&
        invalidPage.text.includes("ioi.autonomous-system-genesis-blocker-report.v1") &&
        invalidPage.text.includes('data-blocker-code="new_system_instantiation_forbidden"') &&
        invalidPage.text.includes("$.release.system_binding.allowed_use") &&
        beforeInvalid === jsonSnapshot(dataDir),
      "new_system_instantiation_forbidden @ $.release.system_binding.allowed_use",
    );

    // ---- 5. governance preview: pending decision + grant stripping -------------------------
    const alphaCompactIds = {
      systemId: "system://acme/system-alpha-compact",
      genesisId: "genesis://acme/system-alpha-compact/zero",
      constitutionRef: "constitution://acme/system-alpha-compact/v1",
      deploymentProfileRef: `deployment-profile://acme/system-alpha-compact/local/revision/sha256:${"d".repeat(64)}`,
      orderingProfileRef: "ordering-profile://acme/system-alpha-compact/poa1",
      oracleProfileRef: "oracle-evidence-profile://acme/system-alpha-compact/public-records",
      lifecycleProfileRef: "lifecycle-profile://acme/system-alpha-compact/default",
    };
    const alphaExpected = rebindGenesisBodySystem(exactGenesisBody(), alphaCompactIds);
    const alphaRevision = lifecycleDeploymentRevisionForGenesis(alphaExpected.proposed_instantiation.candidate);
    alphaExpected.proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref =
      alphaRevision.deployment_profile_ref;

    const beforePreview = jsonSnapshot(dataDir);
    const previewPage = await P(`${BASE}/governance/preview`, { declaration: JSON.stringify(alphaExpected) });
    const previewApproval = approvalFrom(previewPage.text);
    ok(
      "GOVERNANCE PREVIEW: a valid declaration renders the exact pending authority challenge as preview-not-authority with zero mutation",
      journeyState(previewPage.text, "ready_or_proposed") &&
        truthCode(previewPage.text, "system_genesis_host_authority_required") &&
        Boolean(previewApproval.policy_hash && previewApproval.request_hash && previewApproval.effect_hash) &&
        previewPage.text.includes(GENESIS_SCOPE) &&
        previewPage.text.includes('data-sysgen-preview-nonclaim="1"') &&
        beforePreview === jsonSnapshot(dataDir),
      `scope+hashes rendered (${(previewApproval.request_hash || "").slice(0, 18)}…)`,
    );
    const smuggled = { ...clone(alphaExpected), wallet_approval_grant: { schema_version: 1, forged: true } };
    const strippedPage = await P(`${BASE}/governance/preview`, { declaration: JSON.stringify(smuggled) });
    ok(
      "GOVERNANCE PREVIEW STRIPS AUTHORITY: a pasted grant is stripped before submission and the pending challenge still renders",
      strippedPage.text.includes('data-grant-stripped="1"') &&
        journeyState(strippedPage.text, "ready_or_proposed") &&
        truthCode(strippedPage.text, "system_genesis_host_authority_required") &&
        beforePreview === jsonSnapshot(dataDir),
      "grant never traveled",
    );

    // ---- 6. COMPACT-LANE genesis: System alpha-compact -------------------------------------
    const compactForm = {
      lane: "compact",
      declaration: JSON.stringify(exactGenesisBody()),
      system_id: alphaCompactIds.systemId,
      genesis_id: alphaCompactIds.genesisId,
      constitution_ref: alphaCompactIds.constitutionRef,
      deployment_profile_ref: alphaRevision.deployment_profile_ref,
      ordering_profile_ref: alphaCompactIds.orderingProfileRef,
      oracle_profile_ref: alphaCompactIds.oracleProfileRef,
      lifecycle_profile_ref: alphaCompactIds.lifecycleProfileRef,
    };
    const alphaChallengePage = await P(`${BASE}/compose`, compactForm);
    const alphaApproval = approvalFrom(alphaChallengePage.text);
    ok(
      "COMPACT LANE CHALLENGE: composing System alpha in the compact lane surfaces the daemon's exact challenge (identity rebind composed, authority previewed)",
      journeyState(alphaChallengePage.text, "ready_or_proposed") &&
        truthCode(alphaChallengePage.text, "system_genesis_host_authority_required") &&
        alphaChallengePage.text.includes('data-composed-lane="compact"') &&
        Boolean(alphaApproval.policy_hash && alphaApproval.request_hash) &&
        alphaApproval.request_hash === previewApproval.request_hash,
      "compact-lane rebind composed the SAME request hash the governance preview showed for the full declaration",
    );
    const alphaGrant = resolver.mintForCapability(OWNER, alphaApproval.policy_hash, alphaApproval.request_hash);
    await resolver.recordApproval(OWNER, alphaApproval.policy_hash, alphaApproval.request_hash, alphaGrant, GENESIS_SCOPE);
    const alphaAdmitPage = await P(`${BASE}/compose`, { ...compactForm, wallet_approval_grant: JSON.stringify(alphaGrant) });
    const alphaTailMatch = alphaAdmitPage.text.match(/href="\/__ioi\/systems\/(asg_[0-9a-f]{64})"/);
    const alphaTail = alphaTailMatch ? alphaTailMatch[1] : null;
    const alphaRecordResponse = alphaTail ? await S(`${GENESIS_API}/${alphaTail}`) : { json: null };
    const alphaRecord = alphaRecordResponse.json?.autonomous_system_genesis_admission;
    ok(
      "COMPACT LANE ADMISSION: the wallet-granted resubmission commits ONE admission through the surface and the daemon record carries the rebound identity",
      journeyState(alphaAdmitPage.text, "completed") &&
        Boolean(alphaTail) &&
        alphaRecord?.system_id === alphaCompactIds.systemId &&
        alphaRecord?.genesis_ref === alphaCompactIds.genesisId &&
        alphaAdmitPage.text.includes(alphaRecord?.proposal_root || "__missing__"),
      `admission ${alphaTail || "none"} · ${alphaRecord?.system_id || "no-record"}`,
    );
    requireValue(alphaTail && alphaRecord, "alpha admission did not commit through the surface");
    const alphaReceipt = alphaRecordResponse.json.autonomous_system_genesis_receipt;

    // ---- 7. mid-ladder pending census + detail honesty -------------------------------------
    const packagesPending = await S(`${BASE}/packages`);
    ok(
      "PENDING CENSUS: mid-ladder the packages census withholds honestly (loading_or_pending, daemon code verbatim, no partial rows)",
      journeyState(packagesPending.text, "loading_or_pending") &&
        truthCode(packagesPending.text, "system_lifecycle_not_found") &&
        !packagesPending.text.includes("data-system-id="),
      "census withheld while alpha lacks its live chain",
    );
    const alphaDetailPending = await S(`${BASE}/${alphaTail}`);
    ok(
      "DETAIL LADDER HONESTY: the provisional detail renders admission admitted and every later stage pending from live daemon reads",
      alphaDetailPending.text.includes('data-provisional-detail="1"') &&
        alphaDetailPending.text.includes(`data-detail-system-id="${alphaCompactIds.systemId}"`) &&
        alphaDetailPending.text.includes('data-ladder-stage="admission" data-ladder-state="admitted"') &&
        alphaDetailPending.text.includes('data-ladder-stage="sequence_zero" data-ladder-state="pending"') &&
        alphaDetailPending.text.includes('data-ladder-stage="initialize" data-ladder-state="pending"') &&
        alphaDetailPending.text.includes('data-ladder-stage="activate" data-ladder-state="pending"'),
      "admission admitted · sequence_zero/initialize/activate pending",
    );
    const governanceLadder = await S(`${BASE}/governance?system=${alphaTail}`);
    ok(
      "GOVERNANCE LADDER: the per-System governed ladder mirrors the same live stage truth on the preview surface",
      governanceLadder.text.includes('data-ladder-stage="admission" data-ladder-state="admitted"') &&
        governanceLadder.text.includes('data-ladder-stage="activate" data-ladder-state="pending"'),
      "preview ladder agrees with detail",
    );

    // ---- 8. premature activation refused ----------------------------------------------------
    const prematureRequest = {
      expected_initialize_proposal_root: `sha256:${"a".repeat(64)}`,
      expected_initialize_decision_root: `sha256:${"a".repeat(64)}`,
      expected_initialize_state_root: `sha256:${"a".repeat(64)}`,
      expected_initialize_transition_root: `sha256:${"a".repeat(64)}`,
      expected_initialize_receipt_root: `sha256:${"a".repeat(64)}`,
    };
    const beforePremature = jsonSnapshot(dataDir);
    let prematurePage = await P(`${BASE}/${alphaTail}/activate`, { request: JSON.stringify(prematureRequest) });
    let prematureVia = "direct refusal";
    if (journeyState(prematurePage.text, "ready_or_proposed")) {
      // Authority is computed first: mint the real grant and prove the daemon still refuses
      // the premature activation before any effect.
      const approval = approvalFrom(prematurePage.text);
      const grant = resolver.mintForCapability(OWNER, approval.policy_hash, approval.request_hash);
      await resolver.recordApproval(OWNER, approval.policy_hash, approval.request_hash, grant, ACTIVATE_SCOPE);
      prematurePage = await P(`${BASE}/${alphaTail}/activate`, {
        request: JSON.stringify(prematureRequest),
        wallet_approval_grant: JSON.stringify(grant),
      });
      prematureVia = "granted attempt still refused";
    }
    const prematureCode = (prematurePage.text.match(/data-truth-code="([a-z0-9_]+)"/) || [])[1] || "";
    const activateStillRefused = (await S(`${GENESIS_API}/${alphaTail}/activate`)).status !== 200;
    const prematureZeroEffect = prematureVia === "direct refusal"
      ? beforePremature === jsonSnapshot(dataDir)
      : activateStillRefused;
    ok(
      "PREMATURE ACTIVATION REFUSED: activate before initialize surfaces the daemon refusal verbatim, never masked, with zero lifecycle effect",
      !journeyState(prematurePage.text, "completed") &&
        prematureCode.startsWith("system_") &&
        prematurePage.text.includes(prematureCode) &&
        activateStillRefused &&
        prematureZeroEffect,
      `${prematureVia}: ${prematureCode || "no-code"}`,
    );

    // ---- 9. the governed ladder through the DETAIL surface (alpha) --------------------------
    const alphaRecordRoot = domainHash("ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1", alphaRecord);
    const alphaReceiptRoot = domainHash("ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1", alphaReceipt);
    const alphaMaterialize = await governedSurfaceStep(
      "alpha materialize",
      `${BASE}/${alphaTail}/sequence-zero-materialization`,
      {
        request: JSON.stringify({
          expected_genesis_admission_record_root: alphaRecordRoot,
          expected_genesis_admission_receipt_root: alphaReceiptRoot,
        }),
      },
      MATERIALIZE_SCOPE,
    );
    ok(
      "MATERIALIZE VIA SURFACE: the M1.4 sequence-zero materialization challenges, commits, and renders completed through the detail form",
      journeyState(alphaMaterialize.committed.text, "completed"),
      "sequence-zero committed",
    );
    const alphaSeqZero = (await S(`${GENESIS_API}/${alphaTail}/sequence-zero-materialization`)).json;
    const alphaInitializeRequest = {
      expected_sequence_zero_materialization_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
        alphaSeqZero.autonomous_system_sequence_zero_materialization,
      ),
      expected_sequence_zero_materialization_receipt_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
        alphaSeqZero.autonomous_system_sequence_zero_materialization_receipt,
      ),
      deployment_profile_revision: lifecycleDeploymentRevisionForGenesis(alphaRecord.authorized_genesis),
    };
    const alphaInitialize = await governedSurfaceStep(
      "alpha initialize",
      `${BASE}/${alphaTail}/initialize`,
      { request: JSON.stringify(alphaInitializeRequest) },
      INITIALIZE_SCOPE,
    );
    ok(
      "INITIALIZE VIA SURFACE: sequence 1 challenges, commits, and renders completed through the detail form",
      journeyState(alphaInitialize.committed.text, "completed"),
      "initialize committed",
    );
    const alphaInitGraph = (await S(`${GENESIS_API}/${alphaTail}/initialize`)).json;
    const alphaState = alphaInitGraph.autonomous_system_activation_state;
    const alphaLifecycleReceipt = alphaInitGraph.lifecycle_receipt;
    const alphaActivate = await governedSurfaceStep(
      "alpha activate",
      `${BASE}/${alphaTail}/activate`,
      {
        request: JSON.stringify({
          expected_initialize_proposal_root: alphaLifecycleReceipt.bound_facts.proposal_root,
          expected_initialize_decision_root: alphaLifecycleReceipt.bound_facts.decision_root,
          expected_initialize_state_root: alphaState.activation_state_root,
          expected_initialize_transition_root: alphaState.transition_root,
          expected_initialize_receipt_root: alphaState.transition_receipt_root,
        }),
      },
      ACTIVATE_SCOPE,
    );
    ok(
      "ACTIVATE VIA SURFACE: sequence 2 challenges, commits, and the committed page carries the live chain status",
      journeyState(alphaActivate.committed.text, "completed") &&
        alphaActivate.committed.text.includes('data-lifecycle-status="active"'),
      "alpha active",
    );
    const alphaDetailActive = await S(`${BASE}/${alphaTail}`);
    ok(
      "DETAIL COMPLETED: the provisional detail shows the full admitted ladder, active status, and canonical roots from the compact projection",
      alphaDetailActive.text.includes('data-ladder-stage="activate" data-ladder-state="admitted"') &&
        alphaDetailActive.text.includes('data-lifecycle-status="active"') &&
        alphaDetailActive.text.includes("verified_owner_reconstruction"),
      "alpha detail ready",
    );

    // ---- 10. ADVANCED-LANE genesis: a SECOND System from the SAME package -------------------
    const betaIds = {
      systemId: "system://acme/system-beta",
      genesisId: "genesis://acme/system-beta/zero",
      constitutionRef: "constitution://acme/system-beta/v1",
      deploymentProfileRef: `deployment-profile://acme/system-beta/local/revision/sha256:${"d".repeat(64)}`,
      orderingProfileRef: "ordering-profile://acme/system-beta/poa1",
      oracleProfileRef: "oracle-evidence-profile://acme/system-beta/public-records",
      lifecycleProfileRef: "lifecycle-profile://acme/system-beta/default",
    };
    const betaBody = rebindGenesisBodySystem(exactGenesisBody(), betaIds);
    const betaRevision = lifecycleDeploymentRevisionForGenesis(betaBody.proposed_instantiation.candidate);
    betaBody.proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref =
      betaRevision.deployment_profile_ref;
    const betaAdmission = await governedSurfaceStep(
      "beta genesis (advanced lane)",
      `${BASE}/compose`,
      { lane: "advanced", declaration: JSON.stringify(betaBody) },
      GENESIS_SCOPE,
    );
    const betaTail = (betaAdmission.committed.text.match(/href="\/__ioi\/systems\/(asg_[0-9a-f]{64})"/) || [])[1];
    const betaRecordResponse = betaTail ? await S(`${GENESIS_API}/${betaTail}`) : { json: null };
    const betaRecord = betaRecordResponse.json?.autonomous_system_genesis_admission;
    ok(
      "ADVANCED LANE ADMISSION: System beta admits through the verbatim advanced declaration lane (second System, same package)",
      journeyState(betaAdmission.committed.text, "completed") &&
        Boolean(betaTail) &&
        betaRecord?.system_id === betaIds.systemId &&
        betaRecord?.package_id === alphaRecord.package_id &&
        betaTail !== alphaTail,
      `beta ${betaTail || "none"} shares package ${betaRecord?.package_id || "?"}`,
    );
    requireValue(betaTail && betaRecord, "beta admission did not commit through the surface");
    const betaReceipt = betaRecordResponse.json.autonomous_system_genesis_receipt;
    await governedSurfaceStep(
      "beta materialize",
      `${BASE}/${betaTail}/sequence-zero-materialization`,
      {
        request: JSON.stringify({
          expected_genesis_admission_record_root: domainHash("ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1", betaRecord),
          expected_genesis_admission_receipt_root: domainHash("ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1", betaReceipt),
        }),
      },
      MATERIALIZE_SCOPE,
    );
    const betaSeqZero = (await S(`${GENESIS_API}/${betaTail}/sequence-zero-materialization`)).json;
    await governedSurfaceStep(
      "beta initialize",
      `${BASE}/${betaTail}/initialize`,
      {
        request: JSON.stringify({
          expected_sequence_zero_materialization_root: artifactHash(
            "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
            betaSeqZero.autonomous_system_sequence_zero_materialization,
          ),
          expected_sequence_zero_materialization_receipt_root: artifactHash(
            "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
            betaSeqZero.autonomous_system_sequence_zero_materialization_receipt,
          ),
          deployment_profile_revision: lifecycleDeploymentRevisionForGenesis(betaRecord.authorized_genesis),
        }),
      },
      INITIALIZE_SCOPE,
    );
    const betaInitGraph = (await S(`${GENESIS_API}/${betaTail}/initialize`)).json;
    const betaActivate = await governedSurfaceStep(
      "beta activate",
      `${BASE}/${betaTail}/activate`,
      {
        request: JSON.stringify({
          expected_initialize_proposal_root: betaInitGraph.lifecycle_receipt.bound_facts.proposal_root,
          expected_initialize_decision_root: betaInitGraph.lifecycle_receipt.bound_facts.decision_root,
          expected_initialize_state_root: betaInitGraph.autonomous_system_activation_state.activation_state_root,
          expected_initialize_transition_root: betaInitGraph.autonomous_system_activation_state.transition_root,
          expected_initialize_receipt_root: betaInitGraph.autonomous_system_activation_state.transition_receipt_root,
        }),
      },
      ACTIVATE_SCOPE,
    );
    ok(
      "SECOND SYSTEM ACTIVE: beta reaches its live chain through the same surface ladder",
      journeyState(betaActivate.committed.text, "completed") &&
        betaActivate.committed.text.includes('data-lifecycle-status="active"'),
      "beta active",
    );

    // ---- 11. two-System isolation across the surfaces ---------------------------------------
    const projectionCompact = (await S(`${GENESIS_API}/projection?view=compact`)).json;
    const byId = new Map((projectionCompact?.systems || []).map((system) => [system.system_id, system]));
    const alphaProjected = byId.get(alphaCompactIds.systemId);
    const betaProjected = byId.get(betaIds.systemId);
    const packagesBoth = await S(`${BASE}/packages`);
    ok(
      "TWO-SYSTEM PACKAGES: one reusable package lists two distinct active Systems with distinct live roots",
      (packagesBoth.text.match(/data-package-id=/g) || []).length === 1 &&
        packagesBoth.text.includes(`data-system-id="${alphaCompactIds.systemId}"`) &&
        packagesBoth.text.includes(`data-system-id="${betaIds.systemId}"`) &&
        alphaProjected && betaProjected &&
        alphaProjected.canonical_roots.chain_root !== betaProjected.canonical_roots.chain_root &&
        alphaProjected.canonical_roots.latest_state_root !== betaProjected.canonical_roots.latest_state_root,
      "one package card, two Systems, distinct chain/state roots",
    );
    const [alphaDetailCompact, alphaDetailAdvanced, betaDetailCompact] = await Promise.all([
      S(`${BASE}/${alphaTail}?view=compact`),
      S(`${BASE}/${alphaTail}?view=advanced`),
      S(`${BASE}/${betaTail}?view=compact`),
    ]);
    ok(
      "NO CROSS-SYSTEM BLEED: each detail (compact AND advanced) renders only its own System's identity and roots",
      !alphaDetailCompact.text.includes(betaIds.systemId) &&
        !alphaDetailAdvanced.text.includes(betaIds.systemId) &&
        !alphaDetailAdvanced.text.includes(betaProjected.canonical_roots.chain_root) &&
        !betaDetailCompact.text.includes(alphaCompactIds.systemId) &&
        !betaDetailCompact.text.includes(alphaProjected.canonical_roots.chain_root) &&
        alphaDetailAdvanced.text.includes(alphaProjected.canonical_roots.chain_root),
      "alpha/beta ids and chain roots stay separate per detail",
    );
    const substitutionPage = await P(`${BASE}/${betaTail}/continuity`, {
      op: "migrate",
      request: JSON.stringify({
        expected_chain_head_root: alphaProjected.canonical_roots.chain_root,
        expected_predecessor_state_root: alphaProjected.canonical_roots.latest_state_root,
        trigger_evidence_refs: ["evidence://acme/cross-system/product-journey-substitution"],
        migration_destination_ack_ref: "migration-destination-acknowledgement://acme/system-beta/substituted",
        migration_destination_ack_root: `sha256:${"c".repeat(64)}`,
      }),
    });
    const projectionAfterSubstitution = (await S(`${GENESIS_API}/projection?view=compact`)).json;
    ok(
      "CROSS-SYSTEM SUBSTITUTION REFUSED: beta continuity under alpha's live roots refuses before authority and renders the head conflict verbatim",
      journeyState(substitutionPage.text, "stale_conflict_or_ambiguous") &&
        truthCode(substitutionPage.text, "system_lifecycle_head_conflict") &&
        JSON.stringify(projectionAfterSubstitution) === JSON.stringify(projectionCompact),
      "system_lifecycle_head_conflict, both chains unchanged",
    );

    // ---- 12. restart lane: degraded honesty, then byte-exact reconstruction -----------------
    const preRestartCompact = (await S(`${GENESIS_API}/projection?view=compact`)).text;
    const preRestartAdvanced = (await S(`${GENESIS_API}/projection?view=advanced`)).text;
    requireValue(preRestartCompact.includes("verified_owner_reconstruction"), "pre-restart projection capture failed");
    progress("killing the daemon (unavailable lane)");
    process.kill(plane.daemonPid, "SIGKILL");
    await new Promise((resolve) => setTimeout(resolve, 500));
    const [downPackages, downGovernance, downComposeSubmit, downDetail, downSpine] = await Promise.all([
      S(`${BASE}/packages`),
      S(`${BASE}/governance`),
      P(`${BASE}/compose`, { lane: "advanced", declaration: JSON.stringify(exactGenesisBody()) }),
      S(`${BASE}/${alphaTail}`),
      S(`${GENESIS_API}/projection?view=compact`),
    ]);
    ok(
      "UNAVAILABLE: with the daemon dead every surface renders the NAMED degraded state and fabricates nothing",
      journeyState(downPackages.text, "unavailable_or_degraded") &&
        !downPackages.text.includes("data-system-id=") &&
        journeyState(downGovernance.text, "unavailable_or_degraded") &&
        journeyState(downComposeSubmit.text, "unavailable_or_degraded") &&
        journeyState(downDetail.text, "unavailable_or_degraded") &&
        !downDetail.text.includes('data-lifecycle-status="active"') &&
        downSpine.status === 502,
      "all four surfaces degraded, /v1 spine 502, no cached Systems claimed",
    );
    progress("restarting the plane on the same durable state");
    await plane.stop();
    plane2 = await startIsolatedPlane({ serve: true, dataDir, env: resolver.env, baseEnv: cleanEnv });
    requireValue(plane2, "restart plane failed to boot");
    serveUrl = plane2.serveUrl;
    const postRestartCompact = (await S(`${GENESIS_API}/projection?view=compact`)).text;
    const postRestartAdvanced = (await S(`${GENESIS_API}/projection?view=advanced`)).text;
    ok(
      "RESTART BYTE-EXACT: both compact and advanced projections rebuild byte-identical from durable owners after a full daemon restart",
      postRestartCompact === preRestartCompact && postRestartAdvanced === preRestartAdvanced,
      `compact ${postRestartCompact.length}B, advanced ${postRestartAdvanced.length}B identical`,
    );
    const [restartPackages, restartAlphaDetail, restartBetaDetail] = await Promise.all([
      S(`${BASE}/packages`),
      S(`${BASE}/${alphaTail}`),
      S(`${BASE}/${betaTail}`),
    ]);
    ok(
      "RESTART SURFACES READY (recovery): packages and both provisional details render ready again from verified reconstruction",
      restartPackages.text.includes(`data-system-id="${alphaCompactIds.systemId}"`) &&
        restartPackages.text.includes(`data-system-id="${betaIds.systemId}"`) &&
        restartAlphaDetail.text.includes('data-ladder-stage="activate" data-ladder-state="admitted"') &&
        restartBetaDetail.text.includes('data-ladder-stage="activate" data-ladder-state="admitted"'),
      "both Systems ready on the restarted plane",
    );

    // ---- 13. stale/conflict fail-closed + recovery ------------------------------------------
    const alphaAdmissionPath = join(dataDir, RECORD_FAMILY, `${alphaTail}.json`);
    const heldPath = `${alphaAdmissionPath}.held-for-product-journey`;
    renameSync(alphaAdmissionPath, heldPath);
    let stalePackages;
    try {
      stalePackages = await S(`${BASE}/packages`);
    } finally {
      renameSync(heldPath, alphaAdmissionPath);
    }
    ok(
      "STALE FAIL-CLOSED: a local/Agentgres census divergence renders the projection's fail-closed stop — no partial or plausible list",
      journeyState(stalePackages.text, "stale_conflict_or_ambiguous") &&
        truthCode(stalePackages.text, "system_projection_source_incomplete") &&
        !stalePackages.text.includes(`data-system-id="${betaIds.systemId}"`),
      "system_projection_source_incomplete, beta withheld too",
    );
    const recoveredPackages = await S(`${BASE}/packages`);
    ok(
      "RECOVERY: restoring the admission owner returns the census to verified ready with both Systems intact",
      recoveredPackages.text.includes(`data-system-id="${alphaCompactIds.systemId}"`) &&
        recoveredPackages.text.includes(`data-system-id="${betaIds.systemId}"`) &&
        recoveredPackages.text.includes("verified_owner_reconstruction"),
      "census recovered",
    );

    // ---- 14. recover_or_dissolve: the continuity ladder status on the surfaces --------------
    const betaProjectedNow = ((await S(`${GENESIS_API}/projection?view=compact&system_id=${encodeURIComponent(betaIds.systemId)}`)).json?.systems || [])[0];
    const betaActivateGraph = (await S(`${GENESIS_API}/${betaTail}/activate`)).json;
    const betaLiveState = betaActivateGraph.autonomous_system_activation_state;
    const dissolution = await governedSurfaceStep(
      "beta initiate_dissolution",
      `${BASE}/${betaTail}/continuity`,
      {
        op: "initiate_dissolution",
        request: JSON.stringify({
          expected_chain_head_root: betaProjectedNow.canonical_roots.chain_root,
          expected_predecessor_state_root: betaLiveState.lifecycle_state_root || betaLiveState.activation_state_root,
          trigger_evidence_refs: ["evidence://acme/system-beta/product-journey-dissolution"],
        }),
      },
      DISSOLUTION_SCOPE,
    );
    const [betaDetailDissolving, packagesDissolving] = await Promise.all([
      S(`${BASE}/${betaTail}`),
      S(`${BASE}/packages`),
    ]);
    ok(
      "RECOVER-OR-DISSOLVE: initiate_dissolution commits through the detail surface and dissolution_pending renders from the chain head on detail AND packages",
      journeyState(dissolution.committed.text, "completed") &&
        dissolution.committed.text.includes('data-lifecycle-status="dissolution_pending"') &&
        betaDetailDissolving.text.includes('data-lifecycle-status="dissolution_pending"') &&
        packagesDissolving.text.includes('data-lifecycle-status="dissolution_pending"') &&
        betaDetailDissolving.text.includes("dissolution_pending") &&
        betaDetailDissolving.text.includes("dissolving") &&
        betaDetailDissolving.text.includes("dissolved"),
      "continuity ladder status live; full ladder vocabulary named on the detail",
    );

    // ---- 15. proxy discipline (no UI-derived truth at the source level) ---------------------
    const moduleSource = readFileSync(SURFACE_MODULE, "utf8");
    const forbidden = ["writeFileSync", "appendFileSync", "mkdirSync", "rmSync", "unlinkSync", "child_process", "setInterval", "globalThis."];
    ok(
      "PROXY DISCIPLINE: the surface module holds no state and derives no truth — no fs writes, no processes, daemon-parameterized calls only",
      forbidden.every((token) => !moduleSource.includes(token)) &&
        moduleSource.includes("daemonJson(daemonUrl") &&
        !moduleSource.includes("fetch("),
      "source scan clean (single node:http proxy to the injected daemon origin)",
    );

    exitCode = results.every((result) => result.pass) ? 0 : 1;
  } catch (error) {
    console.error(`verifier crashed: ${error.stack || error.message}`);
    exitCode = 1;
  } finally {
    try { if (plane) await plane.stop(); } catch (error) { console.error(`plane stop failed: ${error.message}`); }
    try { if (plane2) await plane2.stop(); } catch (error) { console.error(`restart plane stop failed: ${error.message}`); }
    try { await resolver.stop(); } catch (error) { console.error(`wallet fixture stop failed: ${error.message}`); }
    try { rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  const passed = results.filter((result) => result.pass).length;
  console.log(`\n${passed}/${results.length} passed`);
  if (exitCode === 0) console.log("system genesis product journey: OK");
  process.exit(exitCode);
}

main().catch((error) => {
  console.error(`verifier crashed: ${error.stack || error.message}`);
  process.exit(1);
});
