#!/usr/bin/env node
//
// Every path parameter in the daemon's router must be written in the syntax the
// PINNED axum version actually matches.
//
// This exists because one route was written in axum 0.8's brace syntax while the
// daemon is pinned to axum 0.7. Braces are not a parameter there, so
// `DELETE /v1/hypervisor/auth/passkeys/:id` matched nothing and passkey
// revocation — a security control — was unreachable through the API. Nothing
// caught it: the device-custody gate asserts revocation by grepping the handler
// for its refusal strings, and a handler can be perfectly correct and still be
// unroutable. A substring in a source file is not a reachable endpoint.
//
//   --mutation  prove the finding fails on its own
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const routerPath = join(repo, "crates/node/src/bin/hypervisor-daemon.rs");
const manifestPath = join(repo, "Cargo.toml");
const router = readFileSync(routerPath, "utf8");
const manifest = readFileSync(manifestPath, "utf8");

// The pinned major.minor decides the syntax. 0.7 uses `:name`; 0.8 uses `{name}`.
const declared = (manifest.match(/^axum\s*=\s*"([^"]+)"/mu) || [])[1] || "";
const BRACE_SYNTAX_FROM = 8;
const minor = Number.parseInt(declared.split(".")[1] ?? "", 10);
const bracesAreParameters = Number.isInteger(minor) && minor >= BRACE_SYNTAX_FROM;

function inspect(source, expectBraces) {
  const findings = [];
  const routes = [...source.matchAll(/"(\/v1\/[^"]*)"/gu)].map((match) => match[1]);
  for (const route of routes) {
    const hasBrace = /\{[A-Za-z_][A-Za-z0-9_]*\}/u.test(route);
    const hasColon = /(?:^|\/):[A-Za-z_][A-Za-z0-9_]*(?=$|\/)/u.test(route);
    if (!expectBraces && hasBrace) findings.push(`brace_param_unmatched_by_pinned_axum:${route}`);
    if (expectBraces && hasColon) findings.push(`colon_param_unmatched_by_pinned_axum:${route}`);
  }
  return [...new Set(findings)].sort();
}

const findings = inspect(router, bracesAreParameters);
if (findings.length > 0) {
  console.error(JSON.stringify({
    check: "check:router-path-params", verdict: "FAIL",
    axum_declared: declared,
    parameter_syntax: bracesAreParameters ? "{name}" : ":name",
    findings,
    detail: "a path parameter in the other version's syntax is a LITERAL segment: the route registers, the handler compiles, and nothing reaches it",
  }, null, 2));
  process.exit(1);
}

if (process.argv.includes("--mutation")) {
  const planted = bracesAreParameters
    ? router.replace('"/v1/hypervisor/auth/passkeys"', '"/v1/hypervisor/auth/passkeys/:credential_ref_id"')
    : router.replace('"/v1/hypervisor/auth/passkeys"', '"/v1/hypervisor/auth/passkeys/{credential_ref_id}"');
  if (planted === router) {
    console.error(JSON.stringify({ check: "mutate:router-path-params", verdict: "FAIL", detail: "mutation did not change the router" }, null, 2));
    process.exit(1);
  }
  const caught = inspect(planted, bracesAreParameters);
  if (caught.length === 0) {
    console.error(JSON.stringify({ check: "mutate:router-path-params", verdict: "FAIL", detail: "a wrong-syntax path parameter was not detected" }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    check: "mutate:router-path-params", verdict: "PASS",
    mutations: [{ mutation: "path parameter written in the other axum version's syntax", detected_by: caught[0] }],
  }, null, 2));
} else {
  const routes = [...router.matchAll(/"(\/v1\/[^"]*)"/gu)].map((m) => m[1]);
  console.log(JSON.stringify({
    check: "check:router-path-params", verdict: "PASS",
    axum_declared: declared,
    parameter_syntax: bracesAreParameters ? "{name}" : ":name",
    routes_scanned: routes.length,
    parameterised_routes: routes.filter((r) => /(?:^|\/):[A-Za-z_]/u.test(r)).length,
  }, null, 2));
}
