import fs from "node:fs";
import path from "node:path";

const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "any"]);
const AUTHORITY_MARKERS = [
  "authorize_environment_owner",
  "authorize_environment_owner_identity",
  "authorize_environment_owner_request",
  "authorize_binding_owner",
  "authorize_conversation",
  "authorize_editor_service_owner",
  "lease_authorizes_env_ops",
  "preview_request_authorized",
  "x-ioi-internal-owner-ref",
  "ENVIRONMENT_SCOPE_KIND",
];

const DIRECT_ENVIRONMENT_SINKS = [
  /\.join\(\s*"environments"\s*\)/u,
  /read_record_dir\([\s\S]{0,160}?"environments"/u,
  /persist_record(?:_durable)?\([\s\S]{0,200}?"environments"/u,
  /remove_record\([\s\S]{0,160}?"environments"/u,
];
const AGGREGATE_ONLY_HANDLERS = new Set([
  "operability_routes::handle_operability_metrics",
  "orchestration_routes::handle_placement_metrics",
]);
const POLICY_CONTEXT_FUNCTION = "provider_routes::provider_workrun_guardrail_refusal";

function matching(source, start, open, close) {
  let depth = 0;
  let string = false;
  let rawStringHashes = null;
  let escaped = false;
  let lineComment = false;
  let blockDepth = 0;
  for (let index = start; index < source.length; index += 1) {
    const here = source[index];
    const next = source[index + 1] ?? "";
    if (lineComment) {
      if (here === "\n") lineComment = false;
      continue;
    }
    if (blockDepth > 0) {
      if (here === "/" && next === "*") { blockDepth += 1; index += 1; }
      else if (here === "*" && next === "/") { blockDepth -= 1; index += 1; }
      continue;
    }
    if (rawStringHashes !== null) {
      const terminator = `"${"#".repeat(rawStringHashes)}`;
      if (source.startsWith(terminator, index)) {
        index += terminator.length - 1;
        rawStringHashes = null;
      }
      continue;
    }
    if (string) {
      if (escaped) escaped = false;
      else if (here === "\\") escaped = true;
      else if (here === '"') string = false;
      continue;
    }
    if (here === "/" && next === "/") { lineComment = true; index += 1; continue; }
    if (here === "/" && next === "*") { blockDepth = 1; index += 1; continue; }
    // Rust raw strings (`r"…"`, `r#"…"#`, including the `r` within `br#"…"#`) may contain
    // arbitrary braces and quotes. Count their hashes and skip to the exact matching terminator.
    if (here === "r" && (next === '"' || next === "#")) {
      let cursor = index + 1;
      while (source[cursor] === "#") cursor += 1;
      if (source[cursor] === '"') {
        rawStringHashes = cursor - index - 1;
        index = cursor;
        continue;
      }
    }
    // A Rust char/byte-char literal can contain a quote or brace. Lifetimes (`'a`) do not close
    // with a second apostrophe, so only skip shapes that have an actual closing quote.
    if (here === "'") {
      const width = next === "\\" ? 3 : 2;
      if (source[index + width] === "'") { index += width; continue; }
    }
    if (here === '"') { string = true; continue; }
    if (here === open) depth += 1;
    else if (here === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function moduleName(file) {
  const base = path.basename(file, ".rs");
  return base === "hypervisor-daemon" ? "root" : base;
}

function withoutCfgTestModules(source) {
  const pattern = /#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{/gu;
  let cleaned = source;
  let searchFrom = 0;
  while (true) {
    pattern.lastIndex = searchFrom;
    const match = pattern.exec(cleaned);
    if (!match) break;
    const open = cleaned.indexOf("{", match.index);
    const close = matching(cleaned, open, "{", "}");
    if (close < 0) break;
    cleaned = `${cleaned.slice(0, match.index)}${" ".repeat(close + 1 - match.index)}${cleaned.slice(close + 1)}`;
    searchFrom = close + 1;
  }
  return cleaned;
}

function rustFunctions(file, source) {
  source = withoutCfgTestModules(source);
  const module = moduleName(file);
  const functions = [];
  const declaration = /\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:<[^>{}]*>)?\s*\(/gu;
  for (const match of source.matchAll(declaration)) {
    const signatureOpen = source.indexOf("(", match.index);
    const signatureClose = matching(source, signatureOpen, "(", ")");
    if (signatureClose < 0) continue;
    const bodyOpen = source.indexOf("{", signatureClose);
    if (bodyOpen < 0 || source.slice(signatureClose, bodyOpen).includes(";")) continue;
    const bodyClose = matching(source, bodyOpen, "{", "}");
    if (bodyClose < 0) continue;
    functions.push({
      key: `${module}::${match[1]}`,
      module,
      name: match[1],
      file,
      body: source.slice(bodyOpen + 1, bodyClose),
    });
  }
  const familyInvocation = /family_handlers!\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,/gu;
  for (const invocation of source.matchAll(familyInvocation)) {
    for (const [name, target] of [
      [invocation[1], "family_list"],
      [invocation[2], "family_create"],
      [invocation[3], "load"],
      [invocation[4], "family_patch"],
    ]) {
      functions.push({ key: `${module}::${name}`, module, name, file, body: `${target}()` });
    }
  }
  return functions;
}

function routeRegistrations(file, source) {
  const ownerModule = moduleName(file);
  const routes = [];
  let cursor = 0;
  while ((cursor = source.indexOf(".route(", cursor)) >= 0) {
    const open = source.indexOf("(", cursor);
    const close = matching(source, open, "(", ")");
    if (close < 0) break;
    const expression = source.slice(open + 1, close);
    const pathMatch = expression.match(/^\s*"([^"]+)"\s*,/u);
    if (pathMatch) {
      const handlerExpression = expression.slice(pathMatch[0].length);
      // Axum registrations appear in both chained form (`get(...).post(...)`) and fully qualified
      // form (`axum::routing::delete(...)`). Treating only the former as a route made the census
      // blind to the preview listener and every other qualified registration.
      const handlerPattern = /(?:^|\.)\s*(?:axum::routing::)?(get|post|put|patch|delete|any)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_:]*)/gu;
      for (const handler of handlerExpression.matchAll(handlerPattern)) {
        const raw = handler[2].replace(/^super::/u, "");
        const parts = raw.split("::");
        const key = parts.length === 1
          ? `${ownerModule}::${raw}`
          : parts[0] === "lifecycle_routes"
            ? `lifecycle_routes::${parts.at(-1)}`
            : `${parts.at(-2)}::${parts.at(-1)}`;
        routes.push({
          method: handler[1].toUpperCase(),
          path: pathMatch[1],
          handler: key,
          registration_file: file,
        });
      }
    }
    cursor = close + 1;
  }
  return routes;
}

function calledFunctions(fn, known) {
  const calls = new Set();
  const qualified = /\b(?:super::)?([a-zA-Z_][a-zA-Z0-9_]*)::([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/gu;
  for (const call of fn.body.matchAll(qualified)) {
    const key = `${call[1]}::${call[2]}`;
    if (known.has(key)) calls.add(key);
  }
  const local = /(?<![.:])\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/gu;
  for (const call of fn.body.matchAll(local)) {
    if (ROUTE_METHODS.has(call[1]) || call[1] === fn.name) continue;
    const key = `${fn.module}::${call[1]}`;
    if (known.has(key)) calls.add(key);
  }
  return calls;
}

function directSink(fn) {
  return DIRECT_ENVIRONMENT_SINKS.some((pattern) => pattern.test(fn.body))
    || (fn.module === "lifecycle_routes"
      && ["serve_preview_root", "serve_preview_path"].includes(fn.name)
      && fn.body.includes("serve_preview_file"));
}

export function deriveEnvironmentOwnerCensus(root) {
  const routeDir = path.join(root, "crates/node/src/bin/hypervisor_daemon_routes");
  const routeFiles = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const resolved = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(resolved);
      else if (entry.name.endsWith(".rs")) routeFiles.push(resolved);
    }
  };
  walk(routeDir);
  const central = path.join(root, "crates/node/src/bin/hypervisor-daemon.rs");
  const files = [central, ...routeFiles];
  const sources = new Map(files.map((file) => [file, fs.readFileSync(file, "utf8")]));
  const functions = files.flatMap((file) => rustFunctions(file, sources.get(file)));
  const byKey = new Map(functions.map((fn) => [fn.key, fn]));
  for (const fn of functions) fn.calls = calledFunctions(fn, byKey);

  const closure = (start) => {
    const seen = new Set();
    const pending = [start];
    while (pending.length) {
      const key = pending.pop();
      if (seen.has(key) || !byKey.has(key)) continue;
      seen.add(key);
      pending.push(...byKey.get(key).calls);
    }
    return [...seen].map((key) => byKey.get(key));
  };

  const registrations = [
    ...routeRegistrations(central, sources.get(central)),
    ...routeRegistrations(
      path.join(routeDir, "lifecycle_routes.rs"),
      sources.get(path.join(routeDir, "lifecycle_routes.rs")),
    ),
  ];
  const unresolved = registrations.filter((route) => !byKey.has(route.handler));
  const classified = registrations.map((route) => {
    const reached = closure(route.handler);
    const sinks = reached.filter(directSink).map((fn) => fn.key).sort();
    // Aggregate-only is an exact handler exception, never a transitive magic marker. Both allowed
    // handlers are simple count projections whose only environment sink is their own record scan;
    // if either starts returning workspace/id material or reaches another sink it becomes
    // unclassified and the gate is red.
    const handlerFn = byKey.get(route.handler);
    const aggregateOnly = AGGREGATE_ONLY_HANDLERS.has(route.handler)
      && sinks.length === 1 && sinks[0] === route.handler
      && handlerFn?.body.includes("ENVIRONMENT_OWNER_CENSUS: aggregate_only")
      && !handlerFn.body.includes("workspace_root")
      && !handlerFn.body.includes('["id"]')
      && !handlerFn.body.includes("environment_id")
      ? [route.handler]
      : [];
    const invalidAggregateMarker = reached.some((fn) => fn.body.includes("ENVIRONMENT_OWNER_CENSUS: aggregate_only"))
      && aggregateOnly.length === 0;
    // Provider workrun admission reads an environment projection only as INPUT to the shared
    // command-policy decision. It does not return the projection or touch workspace bytes. Keep
    // this exception structural: the closure must reach exactly the strict policy loader as its
    // sole environment sink, and the marked helper must neither inspect nor project workspace
    // coordinates. A second sink or a workspace-shaped field therefore goes red automatically.
    const policyContextFn = reached.find((fn) => fn.key === POLICY_CONTEXT_FUNCTION);
    const policyContextOnly = sinks.length === 1
      && sinks[0] === "environment_routes::load_env_guardrail_context"
      && policyContextFn?.body.includes("ENVIRONMENT_OWNER_CENSUS: policy_context_only")
      && policyContextFn.body.includes("load_env_guardrail_context")
      && policyContextFn.body.includes("guardrail_refusal_response")
      && !policyContextFn.body.includes("workspace_root")
      && !policyContextFn.body.includes("material_path")
      ? [POLICY_CONTEXT_FUNCTION]
      : [];
    const invalidPolicyContextMarker = reached.some((fn) => fn.body.includes("ENVIRONMENT_OWNER_CENSUS: policy_context_only"))
      && policyContextOnly.length === 0;
    const authorities = reached
      .filter((fn) => AUTHORITY_MARKERS.some((marker) => fn.body.includes(marker)))
      .map((fn) => fn.key)
      .sort();
    return {
      ...route,
      reaches_environment_workspace: sinks.length > 0 && aggregateOnly.length === 0 && policyContextOnly.length === 0,
      classification: invalidAggregateMarker || invalidPolicyContextMarker
        ? "unclassified"
        : sinks.length === 0
        ? "does_not_reach_environment_workspace"
        : aggregateOnly.length > 0
          ? "aggregate_only"
          : policyContextOnly.length > 0
            ? "policy_context_only"
          : authorities.length > 0
            ? "owner_authorized"
            : "unclassified",
      sinks,
      authorities,
      aggregate_only_markers: aggregateOnly,
      policy_context_only_markers: policyContextOnly,
    };
  });
  const environmentCandidates = classified.filter((route) => route.sinks.length > 0);
  const workspaceRoutes = environmentCandidates.filter((route) => route.reaches_environment_workspace);
  return {
    schema_version: "ioi.hypervisor.environment-owner-source-census.v1",
    derivation: "central router plus subsidiary preview router; transitive Rust function call graph; environment-record and workspace-byte sinks",
    registered_route_handlers: classified.length,
    workspace_route_handlers: workspaceRoutes.length,
    unresolved,
    routes: environmentCandidates,
    unclassified: environmentCandidates.filter((route) => route.classification === "unclassified"),
  };
}
