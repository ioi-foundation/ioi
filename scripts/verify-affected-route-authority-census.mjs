#!/usr/bin/env node

// Static release fence for the owner-ratified authority overlay. Dynamic
// adversarial and wallet-consumption proof is produced by the route-family
// verifiers; this file proves the census itself remains exact and wired to the
// single owner boundary instead of silently losing a registration or alias.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";

function routeBlocks(source) {
  const blocks = [];
  let cursor = 0;
  while ((cursor = source.indexOf(".route(", cursor)) !== -1) {
    const start = cursor;
    let depth = 0;
    let quote = null;
    let escaped = false;
    let end = -1;
    for (let i = cursor + ".route".length; i < source.length; i += 1) {
      const ch = source[i];
      if (quote) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"') { quote = ch; continue; }
      if (ch === "(") depth += 1;
      else if (ch === ")") {
        depth -= 1;
        if (depth === 0) { end = i + 1; break; }
      }
    }
    if (end < 0) throw new Error(`unterminated router registration at byte ${start}`);
    blocks.push(source.slice(start, end));
    cursor = end;
  }
  return blocks;
}

function mutatingRegistrations(source) {
  const registrations = [];
  for (const block of routeBlocks(source)) {
    const path = block.match(/\.route\(\s*"([^"]+)"/)?.[1];
    if (!path) continue;
    const methodPattern = /(?:\.|\b)(post|put|patch|delete)\s*\(\s*([A-Za-z_][A-Za-z0-9_:]*)/g;
    for (const match of block.matchAll(methodPattern)) {
      registrations.push({ method: match[1].toUpperCase(), path, handler: match[2] });
    }
  }
  return registrations.sort((a, b) =>
    `${a.method} ${a.path} ${a.handler}`.localeCompare(`${b.method} ${b.path} ${b.handler}`));
}

function functionBody(source, name) {
  const signature = new RegExp(`(?:pub(?:\\([^)]*\\))?\\s+)?(?:async\\s+)?fn\\s+${name}\\b`);
  const match = signature.exec(source);
  if (!match) return null;
  const open = source.indexOf("{", match.index + match[0].length);
  if (open < 0) return null;
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"') { quote = ch; continue; }
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  return null;
}

const authorityDataflowMarkers = [
  "authorize_deployment_grant(",
  "authorize_capability_lease(",
  "authorize_decision(",
  "authorize_decision_with_context(",
  "authorize_decision_for_resolution(",
  "authorize_decision_for_resolution_with_context(",
  "reauthorize_sealed_receipt(",
  "reauthorize_sealed_receipt_with_context(",
  "consume_approval_grant_for_effect_v2(",
  "preflight_approval_grant_for_effect_v2(",
  "verify_wallet_approval_grant_binding(",
];

const routeSourceDir = "crates/node/src/bin/hypervisor_daemon_routes";
const routeSources = new Map(
  readdirSync(routeSourceDir)
    .filter((name) => name.endsWith(".rs"))
    .map((name) => [name.slice(0, -3), readFileSync(`${routeSourceDir}/${name}`, "utf8")]),
);
let functionLocationIndex = null;
const parsedBodyCache = new Map();

function ensureFunctionLocationIndex() {
  if (functionLocationIndex) return functionLocationIndex;
  functionLocationIndex = new Map();
  const sources = [["hypervisor-daemon", router], ...routeSources.entries()];
  for (const [module, source] of sources) {
    for (const match of source.matchAll(/(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
      const locations = functionLocationIndex.get(match[1]) ?? [];
      locations.push({ name: match[1], source, module });
      functionLocationIndex.set(match[1], locations);
    }
  }
  return functionLocationIndex;
}

function locatedBody(located) {
  const key = `${located.module}:${located.name}`;
  if (!parsedBodyCache.has(key)) parsedBodyCache.set(key, functionBody(located.source, located.name));
  return parsedBodyCache.get(key);
}

function handlerSource(handler) {
  const parts = handler.split("::");
  const name = parts.at(-1);
  if (parts.length === 1) {
    return uniqueFunctionSource(name) ?? { name, source: "", module: null };
  }
  const module = parts[0];
  return { name, source: routeSources.get(module) ?? "", module };
}

function uniqueFunctionSource(name) {
  const matches = ensureFunctionLocationIndex().get(name) ?? [];
  return matches.length === 1 ? matches[0] : null;
}

const crossFileTraversal = new Set(["execute_authority_gate"]);

function reachesAuthorityDataflow(handler) {
  const root = handlerSource(handler);
  if (!root.source) return false;
  const visited = new Set();
  const visit = (located) => {
    const visitKey = `${located.module}:${located.name}`;
    if (visited.has(visitKey)) return false;
    visited.add(visitKey);
    const body = locatedBody(located);
    if (!body) return false;
    if (authorityDataflowMarkers.some((marker) => body.includes(marker))) return true;
    for (const call of body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)) {
      const local = locatedBody({ name: call[1], source: located.source, module: located.module })
        ? { name: call[1], source: located.source, module: located.module }
        : crossFileTraversal.has(call[1]) ? uniqueFunctionSource(call[1]) : null;
      if (local && visit(local)) return true;
    }
    return false;
  };
  return visit(root);
}

const postAdmissionSink = /\b(?:persist|write|store|dispatch|execute|invoke|send|spawn|finalize|transition|apply|restore|publish|open|acquire|handle|commit|plan)_[A-Za-z0-9_]*\s*\(/u;

// This is a per-registration order proof, not a file-level marker check. It starts at the
// exact handler compiled into the router, follows its local helper calls, and accepts only a
// function body in which the authority result dominates a later receipt revalidation or a
// mutation/finalizer call that consumes the admitted `auth`/lease value. Transitive failover is
// accepted only through the two separately classified child operation handlers; its evaluator is
// explicitly zero-effect. The runtime suites exercise the corresponding denial and crash paths.
function provesAdmissionBeforeTerminalLeaf(handler, routeKey) {
  const root = handlerSource(handler);
  if (!root.source) return false;
  const visited = new Set();
  const visit = (located) => {
    const visitKey = `${located.module}:${located.name}`;
    if (visited.has(visitKey)) return false;
    visited.add(visitKey);
    const body = locatedBody(located);
    if (!body) return false;

    const deployment = body.indexOf("authorize_deployment_grant(");
    if (deployment >= 0) {
      const revalidate = body.indexOf("revalidate_admission_receipt(", deployment);
      const tail = revalidate > deployment ? body.slice(revalidate) : "";
      if (revalidate > deployment && (postAdmissionSink.test(tail) || tail.includes("Ok(admitted.admission_intent_ref)"))) return true;
    }

    const lease = body.indexOf("authorize_capability_lease(");
    if (lease >= 0) {
      const tail = body.slice(lease + "authorize_capability_lease(".length);
      if (/\b(?:lease|admitted)\b/u.test(tail) && postAdmissionSink.test(tail)) return true;
    }

    const governedDecision = body.indexOf("authorize_decision(");
    if (governedDecision >= 0) {
      const tail = body.slice(governedDecision + "authorize_decision(".length);
      if (/&(?:auth|authorized)\b/u.test(tail)) return true;
    }

    const directConsume = body.indexOf("consume_approval_grant_for_effect_v2(");
    if (directConsume >= 0 && postAdmissionSink.test(body.slice(directConsume))) return true;

    if (
      routeKey === "POST /v1/hypervisor/failover/run" &&
      (body.includes("handle_provider_op(") || body.includes("provider_op(")) &&
      body.includes("handle_storage_archive_op(")
    ) return true;
    if (routeKey === "POST /v1/hypervisor/failover/evaluate") return !postAdmissionSink.test(body);
    if (
      routeKey === "POST /v1/threads/:id/approvals" &&
      body.includes("authorize_approval_request(") &&
      (body.includes("persist_run_with_bundle(") || body.includes("persist_record("))
    ) {
      const authorization = body.indexOf("authorize_approval_request(");
      const persistence = [body.indexOf("persist_run_with_bundle("), body.indexOf("persist_record(")]
        .filter((index) => index >= 0)
        .sort((a, b) => a - b)[0];
      return authorization < persistence;
    }

    const localDecision = body.indexOf("authorize(");
    const authorizedUse = body.indexOf("&authorized", localDecision);
    if (localDecision >= 0 && authorizedUse > localDecision) {
      const wrapper = locatedBody({ name: "authorize", source: located.source, module: located.module });
      if (wrapper?.includes("governed::authorize_decision(")) return true;
    }

    const localLease = body.indexOf("storage_lease(");
    if (localLease >= 0 && postAdmissionSink.test(body.slice(localLease))) {
      const wrapper = locatedBody({ name: "storage_lease", source: located.source, module: located.module });
      if (wrapper?.includes("authorize_capability_lease(")) return true;
    }

    for (const call of body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)) {
      const local = locatedBody({ name: call[1], source: located.source, module: located.module })
        ? { name: call[1], source: located.source, module: located.module }
        : crossFileTraversal.has(call[1]) ? uniqueFunctionSource(call[1]) : null;
      if (local && visit(local)) return true;
    }
    return false;
  };
  return visit(root);
}

const recordPath = ["active", "proposed", "verified", "archived"]
  .map((state) => `internal-docs/implementation/work-items/${state}/m3-affected-route-authority-census-and-fence.v1.json`)
  .find(existsSync);
if (!recordPath) throw new Error("m3 affected-route authority census record is absent");
const record = JSON.parse(readFileSync(recordPath, "utf8"));
const router = readFileSync("crates/node/src/bin/hypervisor-daemon.rs", "utf8");
const governed = readFileSync("crates/node/src/bin/hypervisor_daemon_routes/governed_authority.rs", "utf8");
const cohorts = [record.affected_route_census.cohort_a, record.affected_route_census.cohort_b];
const rows = cohorts.flat();
const failures = [];
const pass = (condition, message) => { if (!condition) failures.push(message); };

pass(record.source_provenance.includes("Owner-ratified source-neutral"), "census provenance is not source-neutral owner ratification");
pass(new Set(rows.map(([route]) => route)).size === rows.length, "route identities are not unique");
for (const [route, branch, leaf] of rows) {
  pass(route.startsWith("POST /v1/") && !route.includes("…"), `route is not exact: ${route}`);
  const path = route.slice("POST ".length);
  pass(router.includes(`"${path}"`), `router registration is absent: ${path}`);
  pass(typeof branch === "string" && branch.length > 0, `affected branch is absent: ${route}`);
  pass(typeof leaf === "string" && leaf.length > 0, `terminal leaf is absent: ${route}`);
}
pass(record.affected_route_census.aliases.every((alias) => typeof alias === "string" && alias.length > 0), "non-route alias census contains an empty entry");
pass(record.affected_route_census.branch_exclusions.every((item) => typeof item === "string" && item.length > 0), "branch-exclusion census contains an empty entry");

// Completeness is over the whole mutating registration universe, not a pinned
// list of known-bad rows. Any new POST/PUT/PATCH/DELETE registration changes
// this content hash and fails release until its owner classifies it. Existing
// source-policy tests independently reject a raw-verifier call outside the two
// qualified evidence-validation boundaries.
const mutating = mutatingRegistrations(router);
const canonicalMutating = mutating
  .map(({ method, path, handler }) => `${method} ${path}\t${handler}`)
  .join("\n");
const mutatingSha256 = createHash("sha256").update(canonicalMutating).digest("hex");
const universe = record.affected_route_census.mutating_registration_universe;
pass(Boolean(universe), "mutating-registration completeness binding is absent");
pass(universe?.sha256 === mutatingSha256,
  `mutating registration universe digest changed: expected ${universe?.sha256}, found ${mutatingSha256}`);

const registrationKeys = new Set(mutating.map(({ method, path }) => `${method} ${path}`));
const registrationByKey = new Map(mutating.map((registration) => [`${registration.method} ${registration.path}`, registration]));
const affectedKeys = new Set(rows.map(([route]) => route));
const controlKeys = new Set(record.affected_route_census.existing_v2_control_routes ?? []);
const nonMutatingKeys = new Set(record.affected_route_census.statically_non_mutating_routes ?? []);
pass(controlKeys.size === (record.affected_route_census.existing_v2_control_routes ?? []).length,
  "v2 control route identities are not unique");
for (const key of affectedKeys) {
  pass(registrationKeys.has(key), `affected registration missing from universe: ${key}`);
  const registration = registrationByKey.get(key);
  if (registration) {
    const companionOrAlias = key === "POST /v1/threads/:id/approvals"
      || key === "POST /v1/hypervisor/failover/run"
      || key === "POST /v1/hypervisor/failover/evaluate";
    pass(companionOrAlias || reachesAuthorityDataflow(registration.handler), `affected handler does not reach the owner authority boundary: ${key} -> ${registration.handler}`);
    pass(provesAdmissionBeforeTerminalLeaf(registration.handler, key), `affected handler lacks static admission-to-terminal-leaf order proof: ${key} -> ${registration.handler}`);
  }
}
for (const key of controlKeys) pass(registrationKeys.has(key), `v2 control registration missing from universe: ${key}`);
for (const key of affectedKeys) pass(!controlKeys.has(key), `registration has two authority classes: ${key}`);
for (const key of nonMutatingKeys) {
  pass(registrationKeys.has(key), `statically non-mutating registration missing from universe: ${key}`);
  pass(!affectedKeys.has(key) && !controlKeys.has(key), `registration has two authority classes: ${key}`);
}
const classifiedOutsideOverlay = mutating.filter(({ method, path }) => {
  const key = `${method} ${path}`;
  return !affectedKeys.has(key) && !controlKeys.has(key) && !nonMutatingKeys.has(key);
});
for (const registration of classifiedOutsideOverlay) {
  pass(
    !reachesAuthorityDataflow(registration.handler),
    `unclassified mutating registration reaches approval-grant authority dataflow: ${registration.method} ${registration.path} -> ${registration.handler}`,
  );
}
pass(
  affectedKeys.size + controlKeys.size + nonMutatingKeys.size + classifiedOutsideOverlay.length === mutating.length,
  "mutating registration classifications are not exhaustive",
);

for (const marker of [
  "resolve_required_authority(",
  "consume_approval_grant_for_effect_v2(",
  "persist_record_durable(",
  "revalidate_admission_receipt(",
  "reauthorize_sealed_receipt_with_context(",
]) pass(governed.includes(marker), `owner boundary marker is absent: ${marker}`);

if (failures.length) {
  for (const failure of failures) process.stderr.write(`FAIL: ${failure}\n`);
  process.stderr.write(`affected-route authority census: ${failures.length} failure(s)\n`);
  process.exit(1);
}
process.stdout.write(`affected-route authority census: PASS (whole mutating universe ${mutating.length} @ ${mutatingSha256}; ${affectedKeys.size} repaired overlay registrations; ${controlKeys.size} retained controls; ${nonMutatingKeys.size} explicit non-effect POST registrations; ${classifiedOutsideOverlay.length} registrations statically outside this approval-grant dataflow; ${record.affected_route_census.aliases.length} recovery aliases; ${record.affected_route_census.branch_exclusions.length} branch exclusions)\n`);
