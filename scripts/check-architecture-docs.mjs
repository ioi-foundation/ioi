#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { checkArchitectureIntegrity } from "./lib/architecture-docs-integrity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const architectureRoot = path.join(root, "docs/architecture");
const internalDocsRoot = path.join(root, "internal-docs");
const failures = [];

function allMarkdownFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) return allMarkdownFiles(absolute);
    return entry.name.endsWith(".md") ? [absolute] : [];
  });
}

function allFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) return allFiles(absolute);
    return [absolute];
  });
}

function relative(file) {
  return path.relative(root, file);
}

function isImportedConsensusCorpus(file) {
  return relative(file).startsWith("internal-docs/architecture/protocols/aft/");
}

function isGeneratedArchitectureArtifact(file) {
  const rel = relative(file);
  return (
    rel.includes("/states/") ||
    /_TTrace_/.test(rel) ||
    /\.(st|fp|bin|aux|log|out|pdf)$/.test(rel)
  );
}

function fail(message) {
  failures.push(message);
}

function trackedFilesUnder(...paths) {
  const result = spawnSync("git", ["ls-files", ...paths], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(`Unable to inspect tracked docs/formal files: ${result.stderr || result.stdout}`);
    return [];
  }
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && fs.existsSync(path.join(root, line)));
}

const markdownFiles = allMarkdownFiles(architectureRoot);
const internalMarkdownFiles = fs.existsSync(internalDocsRoot)
  ? allMarkdownFiles(internalDocsRoot)
  : [];

for (const failure of checkArchitectureIntegrity({
  root,
  architectureRoot,
  markdownFiles,
})) {
  fail(failure);
}

for (const file of allFiles(architectureRoot)) {
  if (isGeneratedArchitectureArtifact(file)) {
    fail(`${relative(file)} is generated proof/evidence output and must live outside docs/architecture/.`);
  }
}

for (const file of trackedFilesUnder("docs/formal", "docs/formal-artifacts")) {
  fail(`${file} is tracked under public docs formal output; use internal-docs/ or .internal/formal-cache/.`);
}

for (const file of internalMarkdownFiles) {
  const content = fs.readFileSync(file, "utf8");
  if (/^Status:\s*canonical\b/im.test(content)) {
    fail(`${relative(file)} declares canonical status inside internal-docs/.`);
  }
  if (/^Canonical owner:/im.test(content)) {
    fail(`${relative(file)} declares a canonical owner inside internal-docs/.`);
  }
}
const rootMarkdownFiles = fs
  .readdirSync(architectureRoot, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
  .map((entry) => entry.name);
const allowedRootMarkdown = new Set(["README.md", "START_HERE.md"]);
for (const file of rootMarkdownFiles) {
  if (!allowedRootMarkdown.has(file)) {
    fail(`docs/architecture/${file} must live in a subject directory or be moved to README.md.`);
  }
}

for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  const firstLines = content.split(/\r?\n/).slice(0, 12).join("\n");
  if (!/^Status:/m.test(firstLines)) {
    fail(`${relative(file)} is missing a status block near the top.`);
  }
}

const markdownLinkPattern = /\[[^\]]+\]\(([^)\n]+)\)/g;
for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  for (const match of content.matchAll(markdownLinkPattern)) {
    const rawTarget = match[1].trim();
    if (
      rawTarget.startsWith("http://") ||
      rawTarget.startsWith("https://") ||
      rawTarget.startsWith("mailto:") ||
      rawTarget.startsWith("#")
    ) {
      continue;
    }
    const targetWithoutHash = rawTarget.split("#")[0];
    if (!targetWithoutHash) continue;
    const resolved = path.resolve(path.dirname(file), targetWithoutHash);
    if (!resolved.startsWith(root)) {
      fail(`${relative(file)} links outside the repository: ${rawTarget}`);
      continue;
    }
    if (!fs.existsSync(resolved)) {
      fail(`${relative(file)} has broken local link: ${rawTarget}`);
    }
  }
}

const staleLinePatterns = [
  { name: "legacy cap prefix", pattern: /\bcap:[A-Za-z0-9_.-]+/ },
  { name: "legacy capgrant", pattern: /\bcapgrant\b/ },
  { name: "legacy capability_grant", pattern: /\bcapability_grant\b/ },
  { name: "legacy capability_policy", pattern: /\bcapability_policy\b/ },
  { name: "legacy capabilities_required", pattern: /\bcapabilities_required\b/ },
  { name: "legacy wallet_capabilities_required", pattern: /\bwallet_capabilities_required\b/ },
  { name: "legacy CapabilityEnvelope", pattern: /\bCapabilityEnvelope\b/ },
  { name: "legacy capability grant phrase", pattern: /\bcapability grants?\b/i },
  { name: "legacy capability request phrase", pattern: /\bcapability request\b/i },
  { name: "legacy scoped capability phrase", pattern: /\bscoped capabilities\b/i },
];

function lineIsAllowedLegacyNote(file, line) {
  const rel = relative(file);
  if (rel.includes("_meta/changelog/")) {
    return true;
  }
  return /older|legacy|historical|supersedes|pre-split|watchlist/i.test(line);
}

for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  const lines = content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (const { name, pattern } of staleLinePatterns) {
      if (pattern.test(line) && !lineIsAllowedLegacyNote(file, line)) {
        fail(`${relative(file)}:${index + 1} contains ${name}: ${line.trim()}`);
      }
    }
  }
}

for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (!line.includes("Providers / Environments")) continue;
    const context = lines
      .slice(Math.max(0, index - 2), index + 3)
      .join(" ");
    if (
      !/\b(?:alias|older|legacy|maps? to|migration|compatib|retired|historical|family label)\b/i.test(
        context,
      )
    ) {
      fail(
        `${relative(file)}:${index + 1} restores Providers / Environments outside explicit alias or migration context; the product surface is Environments.`,
      );
    }
  }
}

const index = fs.readFileSync(path.join(architectureRoot, "README.md"), "utf8");
for (const required of [
  "_meta/source-of-truth-map.md",
  "../decisions/README.md",
  "_meta/doc-classes.md",
  "components/daemon-runtime/api.md",
  "components/agentgres/api-object-model.md",
  "components/daemon-runtime/events-receipts-delivery-bundles.md",
  "IOI daemon = hypervisor/control plane for autonomous execution",
  "Hypervisor App/Web/CLI-headless = first-class clients over Hypervisor Core",
  "Systems = stable context/read model for one admitted system_id, not system truth",
  "Work = policy-filtered projection over typed work objects, not work truth",
  "Developer Workspace / Automations / Foundry = owner applications over Hypervisor Core",
  "Packages = local package lifecycle owner; Marketplace = optional distribution mode",
  "publisher origin, creation method, distribution, availability, admission",
  "package disposition, enablement, capability depth, and",
  "IOI Authority Gateway = compatibility adapter profile",
  "physical-action-safety.md",
]) {
  if (!index.includes(required)) {
    fail(`README.md must link ${required}.`);
  }
}
if (
  /aiagent\.xyz\s*\|\s*Canonical Web4 marketplace for portable digital workers/.test(
    index,
  )
) {
  fail(
    "README.md must describe aiagent.xyz as ontology-bound digital and embodied workers, not portable digital workers only.",
  );
}

if (!index.includes("ontology-bound digital and embodied workers")) {
  fail("README.md must describe aiagent.xyz as ontology-bound digital and embodied workers.");
}

const sourceMap = fs.readFileSync(
  path.join(architectureRoot, "_meta/source-of-truth-map.md"),
  "utf8",
);
for (const required of [
  "`prim:*`",
  "`scope:*`",
  "Hypervisor App, Hypervisor Web, and Hypervisor CLI/headless are",
  "Developer Workspace is the live code, files,",
  "adapter targets, not",
  "Generic `HypervisorMission` is not a canonical truth object",
  "Systems and Work are policy-filtered core workspaces",
  "HypervisorRouteAliasRegistration",
  "package disposition, enablement state, capability depth, and operational state",
  "IOI Authority Gateway is the daemon sidecar/compatibility profile",
  "the daemon authorizes anything",
  "PhysicalActionPolicy",
  "ActuatorCommandReceipt",
  "SDK, CLI/headless, GUI, harness, benchmark, compositor, and agent-harness-adapter boundaries",
  "Smarter-agent runtime loop",
  "Decision History Policy",
]) {
  if (!sourceMap.includes(required)) {
    fail(`_meta/source-of-truth-map.md missing ${required}.`);
  }
}

const decisionsIndex = fs.readFileSync(path.join(root, "docs/decisions/README.md"), "utf8");
for (const required of [
  "ADR 0002",
  "ADR 0003",
  "ADR 0004",
  "ADR 0005",
  "ADR 0006",
  "ADR 0007",
  "ADR 0008",
  "ADR 0009",
  "ADR 0010",
  "ADR 0011",
  "ADR 0012",
  "ADR 0013",
  "ADR 0014",
  "ADR 0015",
  "ADR 0016",
]) {
  if (!decisionsIndex.includes(required)) {
    fail(`docs/decisions/README.md missing ${required}.`);
  }
}

const vocabulary = fs.readFileSync(
  path.join(architectureRoot, "_meta/vocabulary.md"),
  "utf8",
);
for (const required of [
  "`HypervisorSystems`",
  "`HypervisorWork`",
  "`HypervisorDeveloperWorkspace`",
  "`HypervisorApplicationSurfaceRegistration`",
  "`HypervisorRouteAliasRegistration`",
  "`HypervisorProductSurfaceProjection`",
  "`HypervisorSurfaceReleaseRecord`",
  "`HypervisorSurfaceInstallationBinding`",
  "`HypervisorSystemInterfaceBinding`",
  "`HypervisorSurfaceServingBinding`",
  "`surface_enablement_state`",
  "`IOIAuthorityGateway`",
  "`CompatibilityAdapter`",
  "`HypervisorAppShell`",
  "`GuestWorkload`",
  "`TrustAuditSubstrate`",
  "`PhysicalActionPolicy`",
  "`SafetyEnvelope`",
  "`EmergencyStopAuthority`",
  "`ActuatorCommandReceipt`",
  "`GoalRunProfile`",
  "`GoalKernel`",
  "`GoalRun`",
  "`WorkflowTemplate`",
  "`AutomationSpec`",
  "`AutomationInstallationBinding`",
  "`AutomationRun`",
  "`HarnessProfile`",
  "`AgentHarnessAdapter`",
  "`HarnessInvocation`",
  "`SkillManifest`",
  "`SkillEntry`",
  "`ActiveSkillSetSnapshot`",
  "`RuntimeToolContract`",
  "`WorkResult`",
  "`DataRecipe`",
  "`TransformationRun`",
]) {
  if (!vocabulary.includes(required)) {
    fail(`_meta/vocabulary.md missing ${required}.`);
  }
}

function normalizeContractText(content) {
  return content.replace(/[`*]/g, "").replace(/\s+/g, " ").trim();
}

function normalizeWhitespace(content) {
  return content.replace(/\s+/g, " ").trim();
}

function contractSection(content, startMarker, endMarker, rel) {
  const start = content.indexOf(startMarker);
  const end = content.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0 || end <= start) {
    fail(`${rel} is missing bounded contract section ${startMarker} -> ${endMarker}.`);
    return "";
  }
  return content.slice(start, end);
}

function hasMigrationContext(lines, index) {
  const context = lines
    .slice(Math.max(0, index - 2), Math.min(lines.length, index + 3))
    .join(" ");
  return /(compatib|legacy|retir|prohibit|must not|not (?:a )?canonical|no longer|stale)/i.test(context);
}

function requireMigrationContext(rel, content, term) {
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (!lines[index].includes(term)) continue;
    if (!hasMigrationContext(lines, index)) {
      fail(`${rel} uses ${term} outside an explicit compatibility, prohibition, or retirement context.`);
    }
  }
}

const canonicalEnums = fs.readFileSync(
  path.join(architectureRoot, "foundations/canonical-enums.md"),
  "utf8",
);
const coreSurfaces = fs.readFileSync(
  path.join(architectureRoot, "components/hypervisor/core-clients-surfaces.md"),
  "utf8",
);
const daemonApi = fs.readFileSync(
  path.join(architectureRoot, "components/daemon-runtime/api.md"),
  "utf8",
);
const commonObjects = fs.readFileSync(
  path.join(architectureRoot, "foundations/common-objects-and-envelopes.md"),
  "utf8",
);
const taxonomyAdr = fs.readFileSync(
  path.join(root, "docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md"),
  "utf8",
);
const pursuitTaxonomyAdr = fs.readFileSync(
  path.join(root, "docs/decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md"),
  "utf8",
);
const connectorContracts = fs.readFileSync(
  path.join(architectureRoot, "components/connectors-tools/contracts.md"),
  "utf8",
);
const connectorDoctrine = fs.readFileSync(
  path.join(architectureRoot, "components/connectors-tools/doctrine.md"),
  "utf8",
);
const receiptContracts = fs.readFileSync(
  path.join(architectureRoot, "components/daemon-runtime/events-receipts-delivery-bundles.md"),
  "utf8",
);
const defaultHarnessProfile = fs.readFileSync(
  path.join(architectureRoot, "components/daemon-runtime/default-harness-profile.md"),
  "utf8",
);
const collaborativeOutcomePattern = fs.readFileSync(
  path.join(architectureRoot, "domains/ioi-ai/collaborative-outcome-pattern.md"),
  "utf8",
);
const implementationMatrix = fs.readFileSync(
  path.join(architectureRoot, "_meta/implementation-matrix.md"),
  "utf8",
);
const canonToCodeDelta = fs.readFileSync(
  path.join(architectureRoot, "_meta/canon-to-code-delta.md"),
  "utf8",
);
const aiipDoctrine = fs.readFileSync(
  path.join(architectureRoot, "foundations/aiip.md"),
  "utf8",
);
const ioiL1Mainnet = fs.readFileSync(
  path.join(architectureRoot, "foundations/ioi-l1-mainnet.md"),
  "utf8",
);
const web4AndIoiStack = fs.readFileSync(
  path.join(architectureRoot, "foundations/web4-and-ioi-stack.md"),
  "utf8",
);
const architectureWhitepaper = fs.readFileSync(
  path.join(architectureRoot, "whitepaper.tex"),
  "utf8",
);
const daemonDoctrine = fs.readFileSync(
  path.join(architectureRoot, "components/daemon-runtime/doctrine.md"),
  "utf8",
);
const hypervisorKernelMigrationGuide = fs.readFileSync(
  path.join(
    architectureRoot,
    "_meta/hypervisor-kernel-substrate-unification-master-guide.md",
  ),
  "utf8",
);
const architectureDocClasses = fs.readFileSync(
  path.join(architectureRoot, "_meta/doc-classes.md"),
  "utf8",
);
const archivedHypervisorMigrationLedgers = [
  "_archive/change-ledgers/hypervisor-kernel-substrate-slice-ledger.md",
  "_archive/change-ledgers/hypervisor-kernel-substrate-migration-cut-log.md",
].map((rel) => [
  rel,
  fs.readFileSync(path.join(architectureRoot, rel), "utf8"),
]);
const hypervisorKernelMigrationMatrix = fs.readFileSync(
  path.join(
    architectureRoot,
    "_meta/hypervisor-kernel-substrate-migration-matrix.md",
  ),
  "utf8",
);
const hypervisorDaemonRoutes = fs.readFileSync(
  path.join(root, "crates/node/src/bin/hypervisor-daemon.rs"),
  "utf8",
);
const hypervisorLifecycleRoutes = fs.readFileSync(
  path.join(
    root,
    "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
  ),
  "utf8",
);
const harnessTerminalAttachAdmission = fs.readFileSync(
  path.join(
    root,
    "crates/services/src/agentic/runtime/kernel/runtime_harness_session_terminal_attach_admission.rs",
  ),
  "utf8",
);
const currentHarnessRustCorpus = allFiles(
  path.join(root, "crates/services/src/agentic/runtime"),
)
  .concat(allFiles(path.join(root, "crates/node/src/bin")))
  .filter((file) => file.endsWith(".rs"))
  .map((file) => fs.readFileSync(file, "utf8"))
  .join("\n");

const harnessMigrationRow = hypervisorKernelMigrationMatrix
  .split(/\r?\n/u)
  .find((line) => line.startsWith("| `runtime-harness` |"));
for (const [label, row, facts] of [[
  "_meta/hypervisor-kernel-substrate-migration-matrix.md runtime-harness",
  harnessMigrationRow,
  [
    "pure planners over caller-provided proof refs",
    "No typed `HarnessSessionLaunch` producer existed",
    "independently loaded a session",
    "Recipe -> Binding -> Launch -> Spawn -> Readiness -> TerminalAttach",
    "Rust did not author or durably admit",
  ],
]]) {
  if (!row) {
    fail(`${label} row is missing.`);
    continue;
  }
  for (const fact of facts) {
    if (!row.includes(fact)) {
      fail(`${label} must preserve source-audited harness fact: ${fact}.`);
    }
  }
}

const modelMountTerminalRow = hypervisorKernelMigrationMatrix
  .split(/\r?\n/u)
  .find((line) =>
    line.startsWith(
      "| `model-mounting/route-invocation-result-inventory-conversation` |",
    ),
  );
for (const fact of [
  "neither called `plan_route_control`",
  "not `admit_invocation`, `plan_invocation_authority`, or `admit_provider_result`",
  "accepted-receipt head/transition planners were uncalled",
  "inventory was hand-authored because the canonical inventory planner was incompatible",
  "Conversation state was directly persisted/read",
  "`plan_conversation_state` was uncalled",
]) {
  if (!modelMountTerminalRow?.includes(fact)) {
    fail(
      `_meta/hypervisor-kernel-substrate-migration-matrix.md must preserve source-audited model-mount terminal fact: ${fact}.`,
    );
  }
}

function matrixRow(prefix) {
  return implementationMatrix
    .split(/\r?\n/u)
    .find((line) => line.startsWith(`| \`${prefix}`));
}

function topLevelRustFunction(source, name) {
  const declaration = new RegExp(
    `^(?:pub(?:\\([^)]*\\))?\\s+)?(?:async\\s+)?fn\\s+${name}\\b`,
    "mu",
  );
  const match = declaration.exec(source);
  if (!match) {
    fail(`Current Rust source is missing expected handler ${name}.`);
    return "";
  }
  const tail = source.slice(match.index + match[0].length);
  const next = tail.search(
    /^\s*(?:(?:pub(?:\([^)]*\))?\s+)?async\s+fn|(?:pub(?:\([^)]*\))?\s+)?fn)\s+[A-Za-z0-9_]+\b/mu,
  );
  return next < 0 ? tail : tail.slice(0, next);
}

function requireMatrixRow(prefix) {
  const row = matrixRow(prefix);
  if (!row) {
    fail(`_meta/implementation-matrix.md missing stateless concept-owner row ${prefix}.`);
  }
  return row;
}

function mountedRouteMatches(source, routePath, handler) {
  const escapedPath = routePath.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(
    `\\.route\\(\\s*"${escapedPath}"[\\s\\S]{0,240}\\b${handler}\\b`,
    "u",
  ).test(source);
}

const criticalImplementationSourceAssertions = [
  {
    row: "RuntimeModelRouteSelection`",
    mounts: [
      ["/v1/model-mount/routes", "handle_routes_create"],
      ["/v1/model-mount/routes/:id/test", "handle_route_test"],
    ],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "handle_routes_create",
        required: ["authorize(", "persist_record(", '"model-routes"'],
        forbidden: [".plan_route_control("],
      },
      {
        source: hypervisorDaemonRoutes,
        name: "handle_route_test",
        required: ["route_selection(", "build_route_decision("],
        forbidden: [".plan_route_control(", "persist_record("],
      },
    ],
  },
  {
    row: "ModelRouteControl`",
    mounts: [
      ["/v1/model-mount/routes", "handle_routes_create"],
      ["/v1/model-mount/routes/:id/test", "handle_route_test"],
    ],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "handle_routes_create",
        required: ["persist_record(", '"model-routes"'],
        forbidden: [".plan_route_control("],
      },
      {
        source: hypervisorDaemonRoutes,
        name: "handle_route_test",
        required: ["route_selection(", "build_route_decision("],
        forbidden: [".plan_route_control("],
      },
    ],
  },
  {
    row: "ModelInvocationControl`",
    mounts: [["/v1/model-mount/native-local", "handle_native_local"]],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "invoke_native_local",
        required: [".admit_provider_execution(", ".invoke_provider("],
        forbidden: [".admit_invocation(", ".plan_invocation_authority("],
      },
    ],
  },
  {
    row: "ModelProviderResult`",
    mounts: [["/v1/model-mount/native-local", "handle_native_local"]],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "invoke_native_local",
        required: [".invoke_provider("],
        forbidden: [".admit_provider_result("],
      },
    ],
  },
  {
    row: "ModelProviderLifecycle`",
    mounts: [["/v1/model-mount/instances/load", "handle_instances_load"]],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "instance_real_load",
        required: [".plan_provider_lifecycle(", "persist_record("],
        forbidden: [],
      },
    ],
  },
  {
    row: "ModelLifecycleReceiptControl`",
    mounts: [["/v1/responses", "handle_responses"]],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "persist_invocation_receipt",
        required: ['"model_invocation"', 'persist_record(&st.data_dir, "receipts"'],
        forbidden: [
          ".plan_accepted_receipt_head(",
          ".plan_accepted_receipt_transition(",
        ],
      },
    ],
  },
  {
    row: "ModelProviderInventory`",
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "seed_catalog",
        required: [
          "Hand-author the native provider's model inventory",
          '"model-provider-inventory"',
          "persist_record(",
        ],
        forbidden: [".plan_provider_inventory("],
      },
    ],
  },
  {
    row: "ModelConversationStateControl`",
    mounts: [["/v1/responses", "handle_responses"]],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "store_conversation",
        required: ["persist_record(", '"model-conversations"'],
        forbidden: [".plan_conversation_state("],
      },
    ],
  },
  {
    row: "HypervisorSessionLaunchRecipe`",
    mounts: [
      [
        "/v1/hypervisor/session-launch-recipe-admissions",
        "handle_session_launch_recipe_admission",
      ],
      [
        "/v1/hypervisor/harness-session-binding-admissions",
        "handle_harness_session_binding_admission",
      ],
      ["/v1/hypervisor/sessions/:id/execute", "handle_session_execute"],
    ],
    functions: [
      {
        source: hypervisorLifecycleRoutes,
        name: "handle_session_launch_recipe_admission",
        required: ["admit_hypervisor_session_launch_recipe("],
        forbidden: ["persist_record(", "State("],
      },
      {
        source: hypervisorLifecycleRoutes,
        name: "handle_harness_session_binding_admission",
        required: ["admit_harness_session_binding("],
        forbidden: ["persist_record(", "State("],
      },
      {
        source: hypervisorLifecycleRoutes,
        name: "handle_session_execute",
        required: [
          "load_session_record(",
          "execute_authority_gate(",
          "run_host_spawn_lane(",
        ],
        forbidden: [
          "admit_hypervisor_session_launch_recipe(",
          "admit_harness_session_binding(",
          "HarnessSessionLaunch",
        ],
      },
    ],
  },
  {
    row: "HarnessSessionSpawn`",
    mounts: [
      [
        "/v1/hypervisor/harness-session-terminal-attachments",
        "handle_harness_session_terminal_attach_admission",
      ],
    ],
    functions: [
      {
        source: hypervisorLifecycleRoutes,
        name: "handle_harness_session_terminal_attach_admission",
        required: ["admit_harness_session_terminal_attach("],
        forbidden: ["persist_record(", "State("],
      },
    ],
  },
  {
    row: "RuntimeMcpControl`",
    mounts: [["/v1/model-mount/mcp/invoke", "handle_mcp_invoke"]],
    functions: [
      {
        source: hypervisorDaemonRoutes,
        name: "handle_mcp_invoke",
        required: [
          "authorize(",
          'persist_record(&st.data_dir, "receipts"',
          '"status": "executed"',
        ],
        forbidden: [
          "execute_runtime_mcp_live_backend",
          "McpLiveBackend",
          "tools/call",
        ],
      },
    ],
  },
];

for (const assertion of criticalImplementationSourceAssertions) {
  requireMatrixRow(assertion.row);
  for (const [routePath, handler] of assertion.mounts ?? []) {
    if (!mountedRouteMatches(hypervisorDaemonRoutes, routePath, handler)) {
      fail(
        `source audit for matrix concept ${assertion.row} expects ${routePath} to mount ${handler}.`,
      );
    }
  }
  for (const functionAssertion of assertion.functions ?? []) {
    const body = topLevelRustFunction(
      functionAssertion.source,
      functionAssertion.name,
    );
    for (const marker of functionAssertion.required) {
      if (!body.includes(marker)) {
        fail(
          `${functionAssertion.name} is missing critical implementation marker ${marker}.`,
        );
      }
    }
    for (const marker of functionAssertion.forbidden) {
      if (body.includes(marker)) {
        fail(
          `${functionAssertion.name} unexpectedly contains unmounted marker ${marker}.`,
        );
      }
    }
  }
}

for (const unmountedDaemonCall of [
  ".plan_route_control(",
  ".admit_invocation(",
  ".plan_invocation_authority(",
  ".admit_provider_result(",
  ".plan_accepted_receipt_head(",
  ".plan_accepted_receipt_transition(",
  ".plan_provider_inventory(",
  ".plan_conversation_state(",
]) {
  if (hypervisorDaemonRoutes.includes(unmountedDaemonCall)) {
    fail(
      `Critical model-mount source classification must be re-audited: hypervisor-daemon.rs now calls ${unmountedDaemonCall}.`,
    );
  }
}

function requireMountedModelRoute(routePath, handler) {
  const escapedPath = routePath.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const pattern = new RegExp(
    `\\.route\\(\\s*"${escapedPath}"[\\s\\S]{0,180}\\b${handler}\\b`,
    "u",
  );
  if (!pattern.test(hypervisorDaemonRoutes)) {
    fail(
      `crates/node/src/bin/hypervisor-daemon.rs must mount ${routePath} through ${handler} for the direct source audit.`,
    );
  }
}

for (const [routePath, handler] of [
  ["/v1/model-mount/tokens/tokenize", "handle_tokenize"],
  ["/v1/model-mount/tokens/count", "handle_token_count"],
  ["/v1/model-mount/context/fit", "handle_context_fit"],
  ["/v1/model-mount/providers", "handle_provider_set"],
  ["/v1/model-mount/artifacts/import", "handle_artifacts_import"],
  ["/v1/model-mount/artifacts/:id", "handle_artifact_delete"],
  ["/v1/model-mount/catalog/import-url", "handle_catalog_import_url"],
  ["/v1/model-mount/downloads", "handle_downloads"],
  ["/v1/model-mount/downloads/:id/cancel", "handle_download_cancel"],
  ["/v1/model-mount/storage/cleanup", "handle_storage_cleanup"],
  ["/v1/model-mount/vault/refs", "handle_vault_set"],
  ["/v1/model-mount/workflows/receipt-gate", "handle_receipt_gate"],
  ["/v1/model-mount/mcp/invoke", "handle_mcp_invoke"],
]) {
  requireMountedModelRoute(routePath, handler);
}

const tokenizerHandlers = [
  "handle_tokenize",
  "handle_token_count",
  "handle_context_fit",
].map((name) => topLevelRustFunction(hypervisorDaemonRoutes, name)).join("\n");
if (
  !tokenizerHandlers.includes("split_whitespace") ||
  !tokenizerHandlers.includes("authorize(") ||
  /plan_tokenizer/u.test(tokenizerHandlers)
) {
  fail(
    "Mounted tokenizer handlers must remain wallet-authorized direct whitespace behavior and must not be certified by the unbound tokenizer planner.",
  );
}
requireMatrixRow("ModelTokenizerControl`");

const providerHandler = topLevelRustFunction(
  hypervisorDaemonRoutes,
  "handle_provider_set",
);
if (
  !providerHandler.includes("authorize(") ||
  !providerHandler.includes(".plan_provider_control(") ||
  !providerHandler.includes("secret_ref_hash")
) {
  fail(
    "Mounted provider control must be backed by wallet authorization, plan_provider_control, and hash-only secret binding.",
  );
}
requireMatrixRow("ModelProviderControl`");

const artifactImportHandler = topLevelRustFunction(
  hypervisorDaemonRoutes,
  "handle_artifacts_import",
);
const artifactDeleteHandler = topLevelRustFunction(
  hypervisorDaemonRoutes,
  "handle_artifact_delete",
);
if (
  !artifactImportHandler.includes(".plan_artifact_endpoint(") ||
  /plan_storage_control/u.test(
    `${artifactImportHandler}\n${artifactDeleteHandler}`,
  )
) {
  fail(
    "Mounted artifact import/delete source behavior must distinguish the artifact-endpoint planner from the unbound storage-control planner.",
  );
}
requireMatrixRow("ModelArtifactStorageControl`");

const storageDownloadHandlers = [
  "handle_catalog_import_url",
  "handle_downloads",
  "handle_download_cancel",
  "handle_storage_cleanup",
  "handle_artifact_delete",
].map((name) => topLevelRustFunction(hypervisorDaemonRoutes, name)).join("\n");
if (
  !storageDownloadHandlers.includes("fixture") ||
  !storageDownloadHandlers.includes("authorize(") ||
  /plan_storage_control/u.test(storageDownloadHandlers)
) {
  fail(
    "Mounted catalog/download/storage handlers must remain source-classified as wallet-gated direct fixture/local behavior, not storage-control planner execution.",
  );
}
requireMatrixRow("ModelCatalogDownloadControl`");

if (
  hypervisorDaemonRoutes.includes("/v1/model-mount/catalog/providers") ||
  hypervisorDaemonRoutes.includes("plan_catalog_provider_control")
) {
  fail(
    "Catalog-provider control can no longer be classified as unmounted; update its source audit, crossing index, and conformance.",
  );
}
requireMatrixRow("ModelCatalogProviderControl`");

const receiptGateHandler = topLevelRustFunction(
  hypervisorDaemonRoutes,
  "handle_receipt_gate",
);
if (
  receiptGateHandler.includes("authorize(") ||
  receiptGateHandler.includes("plan_receipt_gate")
) {
  fail(
    "Receipt-gate source classification must be revised if the mounted handler gains authority or planner binding.",
  );
}
requireMatrixRow("ModelReceiptGateControl`");

const vaultHandlers = [
  "handle_vault_set",
  "handle_vault_list",
  "handle_vault_rm",
  "handle_vault_get_meta",
  "handle_vault_status",
  "handle_vault_health",
  "handle_vault_health_latest",
].map((name) => topLevelRustFunction(hypervisorDaemonRoutes, name)).join("\n");
if (
  !vaultHandlers.includes("authorize(") ||
  /plan_vault_control/u.test(vaultHandlers)
) {
  fail(
    "Mounted vault routes must remain source-classified as direct wallet-gated hash/in-memory behavior, not vault planner or cTEE custody.",
  );
}
requireMatrixRow("ModelVaultControl`");

const modelMountMcpInvoke = topLevelRustFunction(
  hypervisorDaemonRoutes,
  "handle_mcp_invoke",
);
if (
  !modelMountMcpInvoke.includes('\"status\": \"executed\"') ||
  !modelMountMcpInvoke.includes("persist_record(") ||
  !modelMountMcpInvoke.includes("authorize(") ||
  /execute_runtime_mcp_live_backend|McpLiveBackend|tools\/call/u.test(
    modelMountMcpInvoke,
  )
) {
  fail(
    "Model-mount MCP invoke honesty assertion no longer matches the mounted receipt-only handler; inspect behavior before changing canon.",
  );
}
requireMatrixRow("RuntimeMcpControl`");

requireMatrixRow("HarnessContainerLanePlan`");
if (
  !hypervisorDaemonRoutes.includes(
    '"/v1/hypervisor/harness-session-binding-admissions"',
  ) ||
  !hypervisorDaemonRoutes.includes(
    '"/v1/hypervisor/harness-session-terminal-attachments"',
  ) ||
  !hypervisorDaemonRoutes.includes('"/v1/hypervisor/sessions/:id/execute"') ||
  !hypervisorLifecycleRoutes.includes("run_host_spawn_lane(") ||
  !harnessTerminalAttachAdmission.includes(
    'request.get("session_spawn")',
  ) ||
  !harnessTerminalAttachAdmission.includes(
    'request.get("session_readiness")',
  ) ||
  currentHarnessRustCorpus.includes("HarnessSessionLaunch")
) {
  fail(
    "Harness source classification must remain bound to pure recipe/binding planners, the independent host-spawn path, caller-supplied terminal-attach records, and an absent typed HarnessSessionLaunch producer.",
  );
}
for (const absentType of [
  "HarnessContainerLanePlan",
  "HarnessContainerLaneReceipt",
]) {
  if (currentHarnessRustCorpus.includes(absentType)) {
    fail(
      `Harness matrix says ${absentType} is absent, but current Rust now names it; audit producer behavior and update status deliberately.`,
    );
  }
}

const mountedTopLevelMcpDiscoveryRoutes = [
  ["get", "/v1/mcp", "handle_mcp_discover_status"],
  ["get", "/v1/mcp/servers", "handle_mcp_discover_servers"],
  ["get", "/v1/mcp/tools", "handle_mcp_discover_tools"],
  ["get", "/v1/mcp/resources", "handle_mcp_discover_resources"],
  ["get", "/v1/mcp/prompts", "handle_mcp_discover_prompts"],
];
const mountedThreadMcpControlRoutes = [
  ["get", "/v1/threads/:id/mcp/tools/search", "handle_mcp_tool_search"],
  ["post", "/v1/threads/:id/mcp/import", "handle_mcp_import"],
  ["post", "/v1/threads/:id/mcp/servers", "handle_mcp_add"],
  [
    "delete",
    "/v1/threads/:id/mcp/servers/:server_id",
    "handle_mcp_remove",
  ],
  [
    "post",
    "/v1/threads/:id/mcp/servers/:server_id/enable",
    "handle_mcp_enable",
  ],
  [
    "post",
    "/v1/threads/:id/mcp/servers/:server_id/disable",
    "handle_mcp_disable",
  ],
  ["post", "/v1/threads/:id/mcp", "handle_mcp_status"],
  ["post", "/v1/threads/:id/mcp/status", "handle_mcp_status"],
  ["post", "/v1/threads/:id/mcp/validate", "handle_mcp_validate"],
];
const mountedLifecycleRoutes = [
  ...hypervisorDaemonRoutes.matchAll(
    /\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|patch|delete)\(lifecycle_routes::([A-Za-z0-9_]+)\)\s*,?\s*\)/g,
  ),
].map((match) => ({
  path: match[1],
  method: match[2],
  handler: match[3],
}));
const mountedRouteHandlers = new Map(
  mountedLifecycleRoutes.map(({ method, path: routePath, handler }) => [
    `${method} ${routePath}`,
    handler,
  ]),
);
const expectedMcpRouteKeys = new Set(
  [
    ...mountedTopLevelMcpDiscoveryRoutes,
    ...mountedThreadMcpControlRoutes,
  ].map(([method, routePath]) => `${method} ${routePath}`),
);
const actualMcpRoutes = mountedLifecycleRoutes.filter(
  ({ path: routePath }) =>
    routePath === "/v1/mcp" ||
    routePath.startsWith("/v1/mcp/") ||
    routePath === "/v1/threads/:id/mcp" ||
    routePath.startsWith("/v1/threads/:id/mcp/") ||
    routePath === "/api/v1/mcp" ||
    routePath.startsWith("/api/v1/mcp/"),
);
for (const { method, path: routePath, handler } of actualMcpRoutes) {
  const key = `${method} ${routePath}`;
  if (!expectedMcpRouteKeys.has(key)) {
    fail(
      `crates/node/src/bin/hypervisor-daemon.rs has an unexpected mounted MCP route ${key} -> ${handler}; update the source-backed inventory and implementation-status canon deliberately.`,
    );
  }
}
for (const [method, routePath, handler] of [
  ...mountedTopLevelMcpDiscoveryRoutes,
  ...mountedThreadMcpControlRoutes,
]) {
  if (mountedRouteHandlers.get(`${method} ${routePath}`) !== handler) {
    fail(
      `crates/node/src/bin/hypervisor-daemon.rs must keep the source-backed ${method.toUpperCase()} ${routePath} -> ${handler} MCP mount until its status assertions are deliberately revised.`,
    );
  }
  if (
    !new RegExp(
      `pub\\(crate\\)\\s+async\\s+fn\\s+${handler}\\b`,
      "u",
    ).test(hypervisorLifecycleRoutes)
  ) {
    fail(
      `crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs missing implemented MCP handler ${handler}.`,
    );
  }
}
for (const forbidden of [
  "/api/v1/mcp",
  "/v1/mcp/serve",
  "/v1/threads/:id/mcp/invoke",
  "/v1/threads/:id/mcp/serve",
]) {
  if (
    mountedLifecycleRoutes.some(
      ({ path: routePath }) =>
        routePath === forbidden || routePath.startsWith(`${forbidden}/`),
    )
  ) {
    fail(
      `crates/node/src/bin/hypervisor-daemon.rs unexpectedly remounted retired/absent MCP surface ${forbidden}.`,
    );
  }
}

const mcpStatusRows = [
  [
    "_meta/hypervisor-kernel-substrate-migration-matrix.md",
    hypervisorKernelMigrationMatrix
      .split(/\r?\n/)
      .find((line) => line.startsWith("| `runtime-mcp-control-discovery` |")),
  ],
];
for (const [rel, row] of mcpStatusRows) {
  if (!row) {
    fail(`${rel} missing the MCP implementation-status row.`);
    continue;
  }
  for (const [, routePath] of mountedTopLevelMcpDiscoveryRoutes) {
    if (!row.includes(`\`${routePath}\``)) {
      fail(`${rel} must acknowledge mounted current-master MCP route ${routePath}.`);
    }
  }
  if (!row.includes("remain mounted")) {
    fail(`${rel} must say the current-master top-level MCP discovery routes remain mounted.`);
  }
  if (
    /public\s+`?\/v1\/mcp\*`?\s+handlers[^|]{0,240}\b(?:are\s+)?(?:gone|retired)\b/i.test(
      row,
    ) ||
    /full top-level(?:\/legacy)? MCP route[^|]{0,160}\bretirement\b/i.test(
      row,
    ) ||
    /\b(?:all|every)\s+(?:public\s+)?(?:top-level\s+)?(?:MCP|`?\/v1\/mcp\*?`?)[^|]{0,100}\b(?:routes?|handlers?)[^|]{0,40}\b(?:are|were|have been|remain)\s+(?:gone|removed|retired|absent|deleted)\b/i.test(
      row,
    ) ||
    /\b(?:the\s+)?(?:entire|full|blanket)\s+(?:top-level\s+)?(?:MCP|`?\/v1\/mcp\*?`?)[^|]{0,100}\b(?:retirement|removal|deletion)\s+(?:is|was|has been)\s+(?:complete|completed|done|landed|merged)\b/i.test(
      row,
    )
  ) {
    fail(`${rel} falsely claims blanket top-level MCP route retirement.`);
  }
}

const modelMountMcpStatusRows = [
  [
    "_meta/hypervisor-kernel-substrate-migration-matrix.md",
    hypervisorKernelMigrationMatrix
      .split(/\r?\n/)
      .find((line) => line.startsWith("| `model-mounting/mcp-workflow` |")),
  ],
];
for (const [rel, row] of modelMountMcpStatusRows) {
  if (!row) {
    fail(`${rel} missing model-mount MCP workflow status.`);
    continue;
  }
  for (const required of [
    "no public model-mount mcp workflow route",
    "unmounted",
  ]) {
    if (!row.toLowerCase().includes(required)) {
      fail(`${rel} must classify model-mount MCP workflow as unmounted substrate: ${required}.`);
    }
  }
  for (const forbidden of [
    "contextPolicyCore.executeRuntimeMcpLiveBackend()",
    "returning public workflow truth",
    "returns public truth only after",
  ]) {
    if (row.includes(forbidden)) {
      fail(`${rel} falsely claims live model-mount MCP workflow execution: ${forbidden}.`);
    }
  }
}
for (const identifier of [
  "plan_model_mount_mcp_workflow",
  "execute_runtime_mcp_live_backend",
]) {
  if (hypervisorDaemonRoutes.includes(identifier) || hypervisorLifecycleRoutes.includes(identifier)) {
    fail(
      `The mounted Rust daemon unexpectedly calls unmounted model-mount MCP substrate ${identifier}; update implementation status and positive conformance before claiming a route.`,
    );
  }
}

for (const required of [
  "GoalRunProfile   immutable reusable specification",
  "AutomationInstallationBinding immutable successor-versioned",
  "AutomationRun    one activation freezing the exact WorkflowTemplate",
  "SkillEntry       immutable successor-versioned",
  "WorkResult       generic result seam with exact producer-component resolution",
  "DataRecipe       immutable transformation definition with an exact semantic-component set",
  "HarnessInvocation binds an underlying typed work subject and never becomes a",
  "MCP remains a replaceable transport",
]) {
  if (!pursuitTaxonomyAdr.includes(required)) {
    fail(`ADR 0017 missing stable taxonomy invariant: ${required}.`);
  }
}

const surfaceAxisContracts = [
  ["surface_class", "owner_application | substrate_application | tool_surface | extension_application"],
  ["surface_origin", "first_party | organization | external_publisher"],
  ["surface_creation_method", "hand_authored | studio_generated | developer_kit_generated | imported | adapted"],
  ["surface_distribution", "bundled | direct_package | organization_catalog | private_registry | marketplace"],
  ["surface_availability", "planned | preview | limited | available | deprecated | unavailable"],
  ["surface_admission_state", "not_applicable | candidate | under_review | admitted | rejected | revoked"],
  ["surface_installation_state", "not_applicable | not_installed | installing | installed | update_available | uninstalling | uninstalled"],
  ["surface_package_disposition", "not_applicable | active | deprecated | superseded | recalled"],
  ["surface_enablement_state", "not_applicable | enabled | disabled"],
  ["surface_capability_depth", "browse | inspect | propose | act | workflow_complete"],
  ["surface_operational_state", "inactive | starting | ready | serving | degraded | blocked | stopped | unavailable"],
];

for (const [rel, content] of [
  ["foundations/canonical-enums.md", canonicalEnums],
  ["components/hypervisor/core-clients-surfaces.md", coreSurfaces],
  ["../decisions/0016-hypervisor-systems-work-and-application-taxonomy.md", taxonomyAdr],
]) {
  const normalized = normalizeContractText(content);
  for (const [field, values] of surfaceAxisContracts) {
    if (!normalized.includes(field) || !normalized.includes(values)) {
      fail(`${rel} must preserve the canonical ${field} values: ${values}.`);
    }
  }
}

const applicationRegistrationSchema = coreSurfaces.slice(
  coreSurfaces.indexOf("HypervisorApplicationSurfaceRegistration:"),
  coreSurfaces.indexOf("HypervisorProductSurfaceProjection:"),
);
const stableApplicationRegistrationSchema = coreSurfaces.slice(
  coreSurfaces.indexOf("HypervisorApplicationSurfaceRegistration:"),
  coreSurfaces.indexOf("HypervisorSurfaceReleaseRecord:"),
);
for (const forbidden of [
  "origin",
  "creation_method",
  "distribution_channel",
  "availability",
  "admission_state",
  "installation_state",
  "package_disposition",
  "enablement_state",
  "capability_depth",
  "operational_state",
]) {
  if (new RegExp(`^\\s{2}${forbidden}:`, "m").test(applicationRegistrationSchema)) {
    fail(`core-clients-surfaces.md contains an unprefixed product-surface field: ${forbidden}.`);
  }
}

for (const forbidden of [
  "surface_distribution:",
  "surface_admission_state:",
  "surface_installation_state:",
  "surface_package_disposition:",
  "surface_enablement_state:",
  "surface_capability_depth:",
  "surface_operational_state:",
  "descriptor_ref:",
  "package_refs:",
  "release_refs:",
]) {
  if (stableApplicationRegistrationSchema.includes(forbidden)) {
    fail("stable HypervisorApplicationSurfaceRegistration must not absorb normalized owner field: " + forbidden + ".");
  }
}

for (const required of [
  "workspace_kind: home | systems | projects | applications | work",
  "workspace_id: hypervisor-workspace://...",
  "workspace_key: string",
  "publisher_ref:",
  "org://... | user://... | ioi://publisher/... | null",
  "release_ref: package://.../release/... | null",
  "system_binding_ref: package_binding://... | null",
  "system_ref: system://... | null",
  "work_queue |",
  "work_queue://...",
  "legacy_ref: mission://...",
  "OutcomeContract",
  "ServiceOrder",
  "HypervisorProductSurfaceProjection:",
  "HypervisorRouteAliasRegistration:",
  "HypervisorSurfaceReleaseRecord:",
  "HypervisorSurfaceInstallationBinding:",
  "HypervisorSystemInterfaceBinding:",
  "HypervisorSurfaceServingBinding:",
  "surface_id: surface://...",
  "surface_key: string",
  "route_alias_ref: route-alias://...",
  "tool_surface_contract:",
  "required_when: surface_class == tool_surface",
  "permanent_shell | applications_catalog",
  "descriptor_ref: surface-descriptor://... | artifact://...",
  "application_entries:",
  "selected_installation_enablement_state:",
  "selected_system_enablement_state:",
  "effective_enablement_state:",
  "resolved_launch_route: string | null",
  "effective_object_contract_refs:",
  "first_party_applications | tools_for_context",
  "### Canonical Target Routes And Compatibility Aliases",
]) {
  if (!coreSurfaces.includes(required)) {
    fail(`core-clients-surfaces.md missing taxonomy contract: ${required}.`);
  }
}

for (const [rel, content] of [
  ["_meta/implementation-matrix.md", fs.readFileSync(path.join(architectureRoot, "_meta/implementation-matrix.md"), "utf8")],
  ["_meta/canon-to-code-delta.md", fs.readFileSync(path.join(architectureRoot, "_meta/canon-to-code-delta.md"), "utf8")],
  ["_meta/vocabulary.md", vocabulary],
  ["components/hypervisor/core-clients-surfaces.md", coreSurfaces],
]) {
  if (content.includes("HypervisorProductSurfaceCatalogProjection")) {
    fail(`${rel} uses retired HypervisorProductSurfaceCatalogProjection; use HypervisorProductSurfaceProjection.`);
  }
}

if (/workspace_kind:[^\n]*automations/i.test(coreSurfaces)) {
  fail("core workspace registration must exclude Automations; it is a shell-placed owner application.");
}
const daemonTaxonomyPermanentShellCount =
  (daemonApi.match(/"permanent_shell"/g) ?? []).length;
if (daemonTaxonomyPermanentShellCount !== 1) {
  fail("daemon taxonomy v2 must reserve permanent_shell for exactly one Automations owner registration.");
}

for (const forbidden of [
  "hypervisor_session:...",
  "hypervisor_work_item:...",
  "hypervisor_work_run:...",
  "legacy_ref: mission:...",
  "Hypervisor Automation specification or run identity",
  "hypervisor_surface:...",
  "generated_or_installed_application",
]) {
  if (
    coreSurfaces.includes(forbidden) ||
    daemonApi.includes(forbidden) ||
    commonObjects.includes(forbidden) ||
    sourceMap.includes(forbidden) ||
    fs.readFileSync(path.join(architectureRoot, "foundations/domain-ontologies-and-data-recipes.md"), "utf8").includes(forbidden)
  ) {
    fail(`typed Work and Automation canon contains ambiguous or legacy identity form: ${forbidden}.`);
  }
}

for (const required of [
  "automation://...        Hypervisor AutomationSpec identity",
  "automation-run://...    one Hypervisor AutomationRun activation identity",
  "work_queue://...        Hypervisor work-queue identity",
  "surface-descriptor://... ontology-bound surface descriptor identity",
  "surface-serving://...   serving route/runtime binding",
  "hypervisor-workspace://... stable Hypervisor core-workspace registration identity",
  "route-alias://...       typed route-alias registration",
  "ui-primitive://...      reusable source-neutral Hypervisor UX primitive identity",
  "install://...           worker, service, package, application-surface, or System-interface install/license binding",
]) {
  if (!commonObjects.includes(required)) {
    fail(`common-objects-and-envelopes.md missing taxonomy identity: ${required}.`);
  }
}

for (const required of [
  "goal-run-profile://...",
  "workflow-template://...",
  "skill://...",
  "skill-entry://...",
  "active-skill-set://...",
  "harness-profile://...",
  "agent-harness-adapter://...",
  "development-environment-recipe://...",
  "session-launch-recipe://...",
  "mcp-gateway-requirement://...",
  "WorkflowTemplateEnvelope",
  "SkillManifestEnvelope",
  "SkillEntryEnvelope",
  "ActiveSkillSetSnapshotEnvelope",
  "GoalRunProfileEnvelope",
  "GoalRunProfilePatch",
]) {
  if (!commonObjects.includes(required)) {
    fail(`common-objects-and-envelopes.md missing pursuit/skill taxonomy contract: ${required}.`);
  }
}

const artifactBlock = contractSection(
  commonObjects,
  "## ArtifactEnvelope",
  "## DeliveryEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "artifact_role:",
  "lineage_commitment:",
  "editable_domain_object_revision_ref:",
  "source_snapshot_artifact_ref:",
  "derivation_run_ref:",
  "derivation_contract_ref:",
  "derivation_receipt_ref:",
  "For `immutable_source_snapshot`",
  "For `derived_export`",
  "output lineage commitment",
  "source -> snapshot -> derived",
]) {
  if (!artifactBlock.includes(required)) {
    fail(`ArtifactEnvelope missing source-snapshot-derived lineage contract: ${required}.`);
  }
}

const dataRecipeBlock = contractSection(
  commonObjects,
  "## DataRecipeEnvelope",
  "## ConnectorMappingEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "data_recipe_id: data-recipe://...",
  "revision_ref: data-recipe://.../revision/...",
  "predecessor_revision_ref:",
  "content_hash:",
  "semantic_component_set_snapshot_ref:",
  "semantic_component_set_hash:",
  "output_dataset_contract_refs:",
  "registry_lifecycle_ref:",
  "registry_status:",
  "contains no concrete dataset",
]) {
  if (!dataRecipeBlock.includes(required)) {
    fail(`DataRecipeEnvelope missing immutable definition boundary: ${required}.`);
  }
}
for (const forbidden of ["output_dataset_refs:", "output_distilled_dataset_refs:", "authority_grant_refs:", "receipt_refs:"]) {
  if (dataRecipeBlock.includes(forbidden)) {
    fail(`DataRecipeEnvelope carries concrete run/output state: ${forbidden}.`);
  }
}

const connectorMappingBlock = contractSection(
  commonObjects,
  "## ConnectorMappingEnvelope",
  "## LearningSourceRightsClaimEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "connector_mapping_id: mapping://...",
  "revision_ref: mapping://.../revision/...",
  "predecessor_revision_ref:",
  "content_hash:",
  "semantic_component_set_snapshot_ref:",
  "semantic_component_set_hash:",
  "registry_lifecycle_ref:",
  "registry_status:",
  "Any field, action,",
]) {
  if (!connectorMappingBlock.includes(required)) {
    fail(`ConnectorMappingEnvelope missing immutable semantic binding: ${required}.`);
  }
}

const transformationRunBlock = contractSection(
  commonObjects,
  "## TransformationRunEnvelope",
  "## DistilledOntologyDatasetEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "data_recipe_revision_ref:",
  "data_recipe_content_hash:",
  "resolved_semantic_component_set_snapshot_ref:",
  "resolved_semantic_component_set_hash:",
  "must exactly equal the tuple committed",
  "output_dataset_refs:",
  "receipt_refs:",
]) {
  if (!transformationRunBlock.includes(required)) {
    fail(`TransformationRunEnvelope missing exact recipe/output ownership field: ${required}.`);
  }
}

const workflowTemplateBlock = contractSection(
  commonObjects,
  "### WorkflowTemplateEnvelope",
  "### SkillManifestEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "revision_ref:",
  "content_hash:",
  "graph_hash:",
  "input_contract_refs:",
  "output_contract_refs:",
  "step_contract_refs:",
  "dependency_and_handoff_refs:",
  "acceptance_and_review_contract_refs:",
  "runtime_tool_contract_requirement_refs:",
  "authority_scope_requirement_refs:",
  "allowed_override_schema_ref:",
]) {
  if (!workflowTemplateBlock.includes(required)) {
    fail(`WorkflowTemplateEnvelope missing immutable directed-work field: ${required}.`);
  }
}
for (const forbidden of [
  "trigger_refs:",
  "schedule_refs:",
  "authority_grant_refs:",
  "authority_lease_refs:",
  "runtime_assignment_refs:",
  "automation_run_refs:",
]) {
  if (workflowTemplateBlock.includes(forbidden)) {
    fail(`WorkflowTemplateEnvelope carries standing activation or live state: ${forbidden}.`);
  }
}
const skillManifestBlock = contractSection(
  commonObjects,
  "### SkillManifestEnvelope",
  "### SkillEntryEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "skill_id:",
  "revision_ref:",
  "content_hash:",
  "instruction_entrypoint_ref:",
  "dependency_skill_revision_refs:",
  "runtime_tool_contract_requirement_refs:",
  "provenance_refs:",
  "source_rights_and_license_refs:",
  "evaluation_and_benchmark_refs:",
]) {
  if (!skillManifestBlock.includes(required)) {
    fail(`SkillManifestEnvelope missing immutable procedure field: ${required}.`);
  }
}
for (const forbidden of [
  "price:",
  "ranking:",
  "credential_refs:",
  "authority_grant_refs:",
  "executable_body:",
]) {
  if (skillManifestBlock.includes(forbidden)) {
    fail(`SkillManifestEnvelope carries listing, authority, or executable state: ${forbidden}.`);
  }
}

const skillEntryBlock = contractSection(
  commonObjects,
  "### SkillEntryEnvelope",
  "### ActiveSkillSetSnapshotEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "skill_entry_id:",
  "binding_revision_ref:",
  "predecessor_binding_revision_ref:",
  "binding_hash:",
  "skill_revision_ref:",
  "skill_manifest_content_hash:",
  "owner_scope_ref:",
  "configuration_ref:",
  "compatibility_decision_ref:",
  "admission_receipt_ref:",
  "registry_lifecycle_ref:",
  "registry_status:",
  "excluded from the hash",
]) {
  if (!skillEntryBlock.includes(required)) {
    fail(`SkillEntryEnvelope missing exact owner-scope binding field: ${required}.`);
  }
}
for (const forbidden of [
  "instruction_entrypoint_ref:",
  "procedure_and_reference_refs:",
  "credential_refs:",
  "authority_grant_refs:",
]) {
  if (skillEntryBlock.includes(forbidden)) {
    fail(`SkillEntryEnvelope copies procedure, credentials, or authority: ${forbidden}.`);
  }
}

const activeSkillSetBlock = contractSection(
  commonObjects,
  "### ActiveSkillSetSnapshotEnvelope",
  "### AutonomousSystemManifestEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "work_subject_ref:",
  "skill_entry_binding_revision_ref:",
  "skill_entry_binding_hash:",
  "skill_revision_ref:",
  "manifest_content_hash:",
  "active_set_hash:",
  "resolved_runtime_tool_contracts:",
  "revision_ref: tool://.../revision/...",
  "context_lease_refs:",
  "resolution_receipt_ref:",
  "registry_lifecycle_ref:",
  "registry_status:",
]) {
  if (!activeSkillSetBlock.includes(required)) {
    fail(`ActiveSkillSetSnapshotEnvelope missing exact run-selection field: ${required}.`);
  }
}
for (const forbidden of [
  "instruction_entrypoint_ref:",
  "configuration_ref:",
  "credential_refs:",
  "authority_grant_refs:",
]) {
  if (activeSkillSetBlock.includes(forbidden)) {
    fail(`ActiveSkillSetSnapshotEnvelope carries reusable or authority state: ${forbidden}.`);
  }
}
if (/work_subject_ref:[\s\S]*?harness_invocation:\/\/[\s\S]*?selected_skills:/.test(activeSkillSetBlock)) {
  fail("ActiveSkillSetSnapshotEnvelope makes HarnessInvocation a second work subject.");
}

const autonomousSystemManifestBlock = contractSection(
  commonObjects,
  "### AutonomousSystemManifestEnvelope",
  "### AutonomousSystemGenesisEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "component_set_snapshot_ref:",
  "component_set_hash:",
  "goal_run_profiles:",
  "workflow_templates:",
  "automation_specs:",
  "harness_profiles:",
  "agent_harness_adapters:",
  "skill_manifests:",
  "data_recipes:",
  "runtime_tool_contracts:",
  "mcp_gateway_requirements:",
  "revision_ref: tool://.../revision/...",
  "content_hash: hash",
  "worker_revision_ref:",
  "worker_content_hash:",
]) {
  if (!autonomousSystemManifestBlock.includes(required)) {
    fail(`AutonomousSystemManifestEnvelope missing immutable typed component requirement: ${required}.`);
  }
}
for (const forbidden of [
  "skill_entry_refs:",
  "active_skill_set_snapshot_refs:",
  "mcp_gateway_profile_refs:",
  "context_lease_refs:",
  "capability_lease_refs:",
  "authority_grant_refs:",
  "runtime_assignment_refs:",
  "automation_run_refs:",
  "latest_run_receipt_refs:",
  "latest_eval_receipt_refs:",
  "preview_or_public_endpoint_refs:",
  "readiness: ready",
  "enablement_state:",
  "subject_ref:",
  "session_refs:",
  "credential_refs:",
  "secret_refs:",
]) {
  if (autonomousSystemManifestBlock.includes(forbidden)) {
    fail(`AutonomousSystemManifestEnvelope carries admission-bound live state: ${forbidden}.`);
  }
}

const goalRunProfileBlock = contractSection(
  commonObjects,
  "## GoalRunProfileEnvelope",
  "## OrchestrationConstraintEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "goal_run_profile_id:",
  "revision_ref:",
  "predecessor_revision_ref:",
  "content_hash:",
  "applicable_goal_class_refs:",
  "orchestration_policy_ref:",
  "workflow_template_revision_refs:",
  "role_topology_requirement_refs:",
  "harness_requirement_refs:",
  "skill_requirement_refs:",
  "runtime_tool_contract_requirement_refs:",
  "allowed_override_schema_ref:",
  "acceptance_contract_refs:",
  "verifier_requirement_refs:",
  "stop_policy_ref:",
  "recovery_policy_ref:",
  "registry_lifecycle_ref:",
  "registry_status:",
  "not a workflow graph, executable, authority holder",
]) {
  if (!goalRunProfileBlock.includes(required)) {
    fail(`GoalRunProfileEnvelope missing immutable pursuit-spec field: ${required}.`);
  }
}
for (const forbidden of [
  "authority_grant_refs:",
  "authority_lease_refs:",
  "context_lease_refs:",
  "runtime_assignment_refs:",
  "active_skill_set_snapshot_ref:",
  "goal_run_status:",
]) {
  if (goalRunProfileBlock.includes(forbidden)) {
    fail(`GoalRunProfileEnvelope carries execution, authority, or live state: ${forbidden}.`);
  }
}

const goalRunBlock = contractSection(
  commonObjects,
  "## GoalRunEnvelope",
  "## GoalGroundingLoopEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "goal_run_profile_revision_ref:",
  "goal_run_profile_content_hash:",
  "admitted_override_set_ref:",
  "admitted_override_set_hash:",
  "resolved_component_set_snapshot_ref:",
  "resolved_component_set_hash:",
  "active_skill_set_snapshot_ref:",
  "active_skill_set_hash:",
  "initial_role_topology_revision_ref:",
  "initial_role_topology_content_hash:",
  "role_topology_ref:",
  "orchestration_plan_revision_refs:",
  "selected_orchestration_plan_revision_ref:",
  "selected_orchestration_plan_content_hash:",
  "orchestration_decision_receipt_ref:",
  "goal_run_profile_resolution_receipt_ref:",
]) {
  if (!goalRunBlock.includes(required)) {
    fail(`GoalRunEnvelope missing frozen GoalRunProfile resolution field: ${required}.`);
  }
}

const roleTopologyBlock = contractSection(
  commonObjects,
  "## RoleTopologyEnvelope",
  "## ContextCellEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "revision_ref:",
  "content_hash:",
  "work_subject_ref:",
  "role_bindings:",
  "accountable_actor_ref:",
  "selected_resolver_kind:",
  "selected_resolver_revision_ref:",
  "selected_resolver_content_hash:",
  "runtime_assignment_ref:",
]) {
  if (!roleTopologyBlock.includes(required)) {
    fail(`RoleTopologyEnvelope missing actor/resolver-separated binding: ${required}.`);
  }
}
for (const forbidden of ["applies_to: goal://... | automation://", "conductor_ref: harness-profile://"]) {
  if (roleTopologyBlock.includes(forbidden)) {
    fail(`RoleTopologyEnvelope restores spec-as-run or resolver-as-actor drift: ${forbidden}.`);
  }
}

const contextCellBlock = contractSection(
  commonObjects,
  "## ContextCellEnvelope",
  "## ContextLeaseEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "work_subject_ref:",
  "role_topology_revision_ref:",
  "role_binding_id:",
  "accountable_actor_ref:",
  "resolver_revision_ref:",
  "resolver_content_hash:",
  "convenience projections, not independent selection truth",
]) {
  if (!contextCellBlock.includes(required)) {
    fail(`ContextCellEnvelope missing exact work/role projection binding: ${required}.`);
  }
}

const contextLeaseBlock = contractSection(
  commonObjects,
  "## ContextLeaseEnvelope",
  "## ContextHandoffEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of ["work_subject_ref:", "issued_to_ref: context_cell://... | harness_invocation://..."]) {
  if (!contextLeaseBlock.includes(required)) {
    fail(`ContextLeaseEnvelope missing concrete work-subject lease binding: ${required}.`);
  }
}
for (const forbidden of ["issued_to:\n    harness-profile://", "issued_to:\n    agent-harness-adapter://"]) {
  if (contextLeaseBlock.includes(forbidden)) {
    fail(`ContextLeaseEnvelope issues authority/context to a reusable resolver: ${forbidden}.`);
  }
}
if (/work_subject_ref:[\s\S]*?harness_invocation:\/\/[\s\S]*?context_cell_ref:/.test(contextLeaseBlock)) {
  fail("ContextLeaseEnvelope makes HarnessInvocation a second work subject instead of a lease recipient.");
}

const harnessInvocationBlock = contractSection(
  commonObjects,
  "## HarnessInvocationEnvelope",
  "## HarnessAdapterEventEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "work_subject_ref:",
  "accountable_actor_ref:",
  "resolver_kind:",
  "resolver_revision_ref:",
  "resolver_content_hash:",
  "external_protocol_binding_ref:",
  "work_result_ref:",
  "profile_result_ref:",
  "A completed invocation requires `work_result_ref`",
]) {
  if (!harnessInvocationBlock.includes(required)) {
    fail(`HarnessInvocationEnvelope missing generic exact execution binding: ${required}.`);
  }
}

const workResultBlock = contractSection(
  commonObjects,
  "## WorkResultEnvelope and OutcomeDeltaEnvelope",
  "## GoalRunEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "WorkResultEnvelope:",
  "work_subject_ref:",
  "result_payload_ref:",
  "implementation_result://...",
  "producer_component_resolution:",
  "resolved_component_set_snapshot_ref:",
  "resolved_component_set_hash:",
  "component_resolution_receipt_ref:",
  "resolver_kind:",
  "resolver_revision_ref:",
  "resolver_content_hash:",
  "OutcomeDeltaEnvelope:",
]) {
  if (!workResultBlock.includes(required)) {
    fail(`Generic WorkResult/OutcomeDelta seam missing canonical field: ${required}.`);
  }
}
if (workResultBlock.includes("worker_harness_model_runtime_version_refs:")) {
  fail("WorkResultEnvelope restores loose mutable producer-component family refs.");
}
if (/WorkResultEnvelope:[\s\S]*?work_subject_ref:[\s\S]*?harness_invocation:\/\/[\s\S]*?goal_run_ref:/.test(workResultBlock)) {
  fail("WorkResultEnvelope makes HarnessInvocation a second work subject.");
}

const localAgentPairingBlock = contractSection(
  commonObjects,
  "## LocalAgentPairingSessionEnvelope",
  "## AIIP and Bounded Execution Domain Envelopes",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "resolver_kind: harness_profile | agent_harness_adapter | none",
  "resolver_revision_ref:",
  "resolver_content_hash:",
  "semantic_harness_profile_revision_ref:",
  "semantic_harness_profile_content_hash:",
  "concrete bridge never",
]) {
  if (!localAgentPairingBlock.includes(required)) {
    fail(`LocalAgentPairingSessionEnvelope conflates semantic profile and concrete adapter: ${required}.`);
  }
}
if (localAgentPairingBlock.includes("harness_adapter_ref:")) {
  fail("LocalAgentPairingSessionEnvelope restores an undiscriminated profile/adapter ref.");
}

const benchmarkBlock = contractSection(
  commonObjects,
  "## BenchmarkEnvelope",
  "## RoutingDecisionEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "resolver_kind: harness_profile | agent_harness_adapter | none",
  "resolver_revision_ref:",
  "resolver_content_hash:",
  "semantic_harness_profile_revision_ref:",
  "semantic_harness_profile_content_hash:",
  "score never treats an adapter family ref",
]) {
  if (!benchmarkBlock.includes(required)) {
    fail(`BenchmarkEnvelope conflates semantic profile and concrete adapter: ${required}.`);
  }
}
if (benchmarkBlock.includes("harness_ref:")) {
  fail("BenchmarkEnvelope restores an undiscriminated profile/adapter ref.");
}

const goalRunProfileResolutionReceiptBlock = contractSection(
  receiptContracts,
  "GoalRunProfileResolutionReceipt:",
  "## AutomationRun Resolution Receipts",
  "components/daemon-runtime/events-receipts-delivery-bundles.md",
);
for (const required of [
  "goal_run_profile_revision_ref:",
  "goal_run_profile_content_hash:",
  "admitted_override_set_hash:",
  "effective_constraint_envelope_hash:",
  "orchestration_policy_version_or_hash:",
  "workflow_template_resolutions:",
  "resolved_skill_bindings:",
  "skill_entry_binding_revision_ref:",
  "skill_entry_binding_hash:",
  "active_skill_set_snapshot_ref:",
  "active_skill_set_hash:",
  "resolved_harness_profile_revisions:",
  "resolved_runtime_tool_contracts:",
  "initial_role_topology_revision_ref:",
  "initial_role_topology_content_hash:",
  "initial_role_topology_decision_ref:",
  "unresolved_late_binding_requirement_refs:",
  "resolved_component_set_snapshot_ref:",
  "resolved_component_set_hash:",
]) {
  if (!goalRunProfileResolutionReceiptBlock.includes(required)) {
    fail(`GoalRunProfileResolutionReceipt missing frozen resolution fact: ${required}.`);
  }
}

const automationRunResolutionReceiptBlock = contractSection(
  receiptContracts,
  "AutomationRunResolutionReceipt:",
  "## Orchestration Decision Receipts",
  "components/daemon-runtime/events-receipts-delivery-bundles.md",
);
for (const required of [
  "automation_run_ref:",
  "automation_spec_revision_ref:",
  "automation_spec_content_hash:",
  "automation_installation_binding_revision_ref:",
  "automation_installation_binding_hash:",
  "workflow_template_revision_ref:",
  "workflow_template_content_hash:",
  "activation_kind:",
  "activation_event_ref:",
  "admitted_parameter_set_hash:",
  "admitted_activation_override_set_hash:",
  "goal_run_activation_resolutions:",
  "resolved_component_set_snapshot_ref:",
  "resolved_component_set_hash:",
]) {
  if (!automationRunResolutionReceiptBlock.includes(required)) {
    fail(`AutomationRunResolutionReceipt missing frozen admission fact: ${required}.`);
  }
}

const autonomousSystemChainBlock = contractSection(
  commonObjects,
  "AutonomousSystemChainEnvelope:",
  "## LocalAgentPairingSessionEnvelope",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "active_component_registry_ref:",
  "active_component_registry_root:",
]) {
  if (!autonomousSystemChainBlock.includes(required)) {
    fail(`AutonomousSystemChainEnvelope missing active component registry binding: ${required}.`);
  }
}

for (const [rel, content] of [
  ["_meta/vocabulary.md", vocabulary],
  ["foundations/common-objects-and-envelopes.md", commonObjects],
  ["_meta/implementation-matrix.md", implementationMatrix],
  ["_meta/canon-to-code-delta.md", canonToCodeDelta],
]) {
  requireMigrationContext(rel, content, "GoalMicroharness");
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (
      (/^#{1,6}\s+RecipeEnvelope\b/.test(line) || /^RecipeEnvelope:\s*$/.test(line)) &&
      !hasMigrationContext(lines, index)
    ) {
      fail(`${rel} defines a generic RecipeEnvelope; Recipe is only an owner-qualified product/package label.`);
    }
    if (
      /^\|\s*`?Harness`?\s*\|\s*Reusable workflow topology/i.test(line) &&
      !hasMigrationContext(lines, index)
    ) {
      fail(`${rel} restores the stale bare-Harness workflow-topology definition.`);
    }
  }
}

const solePursuitOwnerRows = [
  [
    "`GoalRunProfile`",
    "[`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)",
  ],
  [
    "`WorkflowTemplate`",
    "[`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)",
  ],
  [
    "`HarnessProfile`",
    "[`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)",
  ],
  [
    "`SkillManifest`, `SkillEntry`, `ActiveSkillSetSnapshot`",
    "[`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)",
  ],
  [
    "`RuntimeToolContract`",
    "[`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md)",
  ],
];
for (const [rel, content] of [
  ["_meta/implementation-matrix.md", implementationMatrix],
  ["_meta/canon-to-code-delta.md", canonToCodeDelta],
]) {
  const lines = content.split(/\r?\n/);
  for (const [subject, owner] of solePursuitOwnerRows) {
    if (!lines.some((line) => line.startsWith(`| ${subject} | ${owner} |`))) {
      fail(`${rel} must assign ${subject} solely to ${owner}.`);
    }
  }
}

const aiipChannelEnvelopeBlock = contractSection(
  commonObjects,
  "AIIPChannelEnvelope:",
  "AIIPEnvelope:",
  "foundations/common-objects-and-envelopes.md",
);
for (const required of [
  "system_id_to: system://... # required to differ from system_id_from",
  "endpoint_channel_enrollments:",
  "channel_enrollment_decision_ref:",
  "channel_enrollment_receipt_ref:",
  "profile: marketplace_worker | outcome_service | autonomous_system | collaborative_pursuit | enterprise",
  "transport: in_process | daemon_ipc | unix_socket | local_http",
  "use of the same transports inside one System is L0",
]) {
  if (!aiipChannelEnvelopeBlock.includes(required)) {
    fail(
      `AIIPChannelEnvelope must preserve the independently governed two-System/L0 boundary: ${required}.`,
    );
  }
}
if (
  /\bprofile:\s*[^\n]*(?:\blocal\b|\binstalled_worker\b)/u.test(
    aiipChannelEnvelopeBlock,
  )
) {
  fail(
    "AIIPChannelEnvelope must not restore same-System local or installed-worker routing as an AIIP profile.",
  );
}

const aiipProtocolProfilesBlock = contractSection(
  aiipDoctrine,
  "## Protocol Profiles",
  "## Multi-Party Collaboration",
  "foundations/aiip.md",
);
const normalizedAiipProtocolProfilesBlock = normalizeWhitespace(
  aiipProtocolProfilesBlock,
);
for (const required of [
  "Same-system HarnessInvocation and installed Worker routing belongs to native L0 contracts",
  "Installing a package or Worker under the same System identity does not create a second sovereign endpoint and remains L0.",
]) {
  if (!normalizedAiipProtocolProfilesBlock.includes(required)) {
    fail(`foundations/aiip.md must keep same-System routing at L0: ${required}.`);
  }
}
for (const forbidden of ["Local Profile", "Installed Worker Profile"]) {
  if (aiipProtocolProfilesBlock.includes(forbidden)) {
    fail(
      `foundations/aiip.md must not restore the same-System ${forbidden} as an AIIP protocol profile.`,
    );
  }
}
for (const [rel, content, required] of [
  [
    "foundations/aiip.md",
    aiipDoctrine,
    "distinct independently governed `system_id` values and each endpoint binds its",
  ],
  [
    "foundations/aiip.md",
    aiipDoctrine,
    "The same transports carry L0 when both endpoints belong to one System.",
  ],
  [
    "whitepaper.tex",
    architectureWhitepaper,
    "between distinct independently governed systems",
  ],
  [
    "whitepaper.tex",
    architectureWhitepaper,
    "same-system GoalRuns, HarnessInvocations, installed Workers",
  ],
  [
    "whitepaper.tex",
    architectureWhitepaper,
    "The same transports carry L0 when both endpoints belong to one System.",
  ],
]) {
  if (!normalizeWhitespace(content).includes(required)) {
    fail(`${rel} must preserve the ADR 0015 AIIP/L0 boundary: ${required}.`);
  }
}
for (const [rel, content, required] of [
  [
    "_meta/vocabulary.md",
    vocabulary,
    "Same-system local or installed-Worker routing is L0, not an AIIP profile.",
  ],
  [
    "_meta/vocabulary.md",
    vocabulary,
    "A local transport can carry the channel only under that two-System condition; the same transport within one System remains L0.",
  ],
  [
    "foundations/ioi-l1-mainnet.md",
    ioiL1Mainnet,
    "ordinary AIIP packets that do not invoke an IOI L1 service or commitment",
  ],
  [
    "foundations/web4-and-ioi-stack.md",
    web4AndIoiStack,
    "AIIP = semantic work interop between distinct independently governed systems; same-system handoffs remain native L0",
  ],
  [
    "whitepaper.tex",
    architectureWhitepaper,
    "An \\textbf{AIIPChannel} binds two distinct independently governed and bilaterally enrolled System identities",
  ],
]) {
  if (!normalizeWhitespace(content).includes(required)) {
    fail(`${rel} must preserve the canon-wide ADR 0015 AIIP/L0 boundary: ${required}.`);
  }
}
for (const [rel, content, forbidden] of [
  [
    "_meta/vocabulary.md",
    vocabulary,
    "AIIP mode such as local, installed worker",
  ],
  [
    "_meta/vocabulary.md",
    vocabulary,
    "registered or local channel binding two bounded execution domains",
  ],
  [
    "foundations/ioi-l1-mainnet.md",
    ioiL1Mainnet,
    "AIIP local-profile packets",
  ],
  [
    "foundations/web4-and-ioi-stack.md",
    web4AndIoiStack,
    "AIIP                      = semantic work interop for local and cross-system autonomous handoffs",
  ],
]) {
  if (content.includes(forbidden)) {
    fail(`${rel} restores same-System routing as AIIP: ${forbidden}.`);
  }
}
const aiipChannelImplementationRow = implementationMatrix
  .split(/\r?\n/)
  .find((line) => line.startsWith("| `AIIPChannel` |"));
for (const required of [
  "two distinct independently governed System identities",
  "same-System local/installed routing remains L0 even over a local transport",
  "reject equal endpoint System identities",
]) {
  if (!aiipChannelImplementationRow?.includes(required)) {
    fail(
      `_meta/implementation-matrix.md must preserve the cross-System AIIPChannel contract: ${required}.`,
    );
  }
}

const workProjectionRow = canonToCodeDelta
  .split(/\r?\n/)
  .find((line) =>
    line.startsWith(
      "| `HypervisorWorkSubjectProjection`, `HypervisorLegacyWorkSubjectAlias` |",
    ),
  );
if (!workProjectionRow) {
  fail("_meta/canon-to-code-delta.md missing the typed Work projection row.");
} else {
  for (const required of [
    "typed Work views across GoalRuns, WorkResults, OutcomeRooms, participants, frontier items and claims, Attempts, Findings, VerifierChallenges",
    "Work / Rooms with typed WorkResult, OutcomeRoom, participant, frontier/claim, Attempt, Finding, and VerifierChallenge views",
  ]) {
    if (!workProjectionRow.includes(required)) {
      fail(
        `_meta/canon-to-code-delta.md must keep Missions compatibility separate from typed Work owner projections: ${required}.`,
      );
    }
  }
  if (/\/__ioi\/missions[^|]{0,240}\bvisibly framed as Work\b/i.test(workProjectionRow)) {
    fail(
      "_meta/canon-to-code-delta.md must not claim the current /__ioi/missions compatibility route is visibly reframed as Work.",
    );
  }
}

const workClaimRow = canonToCodeDelta
  .split(/\r?\n/)
  .find((line) => line.startsWith("| `WorkClaimLease` |"));
if (
  !workClaimRow?.includes(
    "| reassignment admission plus acceptance, verdict, and federation at their canonical owner boundaries |",
  )
) {
  fail(
    "_meta/canon-to-code-delta.md must name only reassignment, acceptance/verdict, and federation as remaining WorkClaim owner-plane work.",
  );
}
if (workClaimRow && /\bland (?:Attempt|Finding)|then VerifierChallenge/i.test(workClaimRow)) {
  fail(
    "_meta/canon-to-code-delta.md must not restore merged Attempt/Finding/VerifierChallenge planes as WorkClaim next steps.",
  );
}

for (const required of [
  "Generic WorkResult admission is merged",
  "OutcomeRoom graph through participants, frontier/claims, offers, Attempts, Findings, OutcomeDelta, and VerifierChallenge is merged but partial",
  "federation, acceptance/verdict, and settlement remain planned",
]) {
  if (!normalizeWhitespace(architectureWhitepaper).includes(required)) {
    fail(`whitepaper.tex must keep merged versus planned Work status honest: ${required}.`);
  }
}
if (/generic result\s+profiles[^.]{0,160}\bplanned\b/i.test(architectureWhitepaper)) {
  fail("whitepaper.tex must not restore generic WorkResult profiles to planned status.");
}

if (
  !normalizeWhitespace(architectureDocClasses).includes(
    "The two `_meta` migration artifacts remain in place only as structurally bounded `archived terminal record / non-actionable` provenance",
  )
) {
  fail(
    "_meta/doc-classes.md must classify both retired sequencers as structurally bounded archived terminal records.",
  );
}
for (const [rel, content] of archivedHypervisorMigrationLedgers) {
  if (
    !content.includes(
      "Canonical owner: none; this file is history, not authority.",
    ) ||
    /\(live doctrine\)|Superseded by: the canonical owner doc/u.test(content)
  ) {
    fail(
      `${rel} must not restore either non-doctrinal Hypervisor migration artifact as live doctrine.`,
    );
  }
}
for (const required of [
  "## Step/Module Execution ABI",
  "The daemon owns the canonical Step/Module execution boundary.",
]) {
  if (!daemonDoctrine.includes(required)) {
    fail(`components/daemon-runtime/doctrine.md must own the Step/Module ABI: ${required}.`);
  }
}
for (const required of [
  "| Daemon Step/Module execution ABI, invocation/result binding, backend-neutral admission order, and no-peer-runtime boundary |",
  "| Archived Hypervisor kernel-substrate sequencing, cleanup, retirement, and terminal-conformance provenance |",
  "every statement below each archived record’s whole-document boundary is historical provenance and MUST NOT direct current work",
]) {
  if (!sourceMap.includes(required)) {
    fail(`_meta/source-of-truth-map.md must keep doctrine with subject owners: ${required}.`);
  }
}
for (const line of implementationMatrix.split(/\r?\n/)) {
  if (!line.startsWith("| ")) continue;
  const concept = line.split("|")[1]?.trim();
  const canonicalOwnerCell = line.split("|")[2] ?? "";
  for (const nonDoctrinalOwner of [
    "hypervisor-kernel-substrate-unification-master-guide.md",
    "hypervisor-kernel-substrate-migration-matrix.md",
  ]) {
    if (canonicalOwnerCell.includes(nonDoctrinalOwner)) {
      if (
        concept === "`HypervisorKernelSubstrateMigration`" &&
        line.includes("Canonical owner: none") &&
        line.includes("archived terminal provenance") &&
        line.includes("archived records may not direct work")
      ) {
        continue;
      }
      fail(
        `_meta/implementation-matrix.md must not use non-doctrinal migration evidence as a canonical owner: ${line.split("|")[1]?.trim()} -> ${nonDoctrinalOwner}.`,
      );
    }
  }
}
for (const [subject, owner] of [
  [
    "`StepModuleInvocation`",
    "[`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md)",
  ],
  [
    "`StepModuleResult`",
    "[`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md)",
  ],
  [
    "`StepModuleRouter`",
    "[`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md)",
  ],
  [
    "`ModelRouteControl`",
    "[`model-router-byok-run-to-idle.md`](../components/model-router/doctrine.md)",
  ],
  [
    "`RuntimeAgentgresStateCacheControl`",
    "[`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md)",
  ],
  [
    "`RuntimeRepositoryWorkflowProjectionControl`",
    "[`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)",
  ],
]) {
  if (
    !implementationMatrix
      .split(/\r?\n/)
      .some((line) => line.startsWith(`| ${subject} | ${owner} |`))
  ) {
    fail(`_meta/implementation-matrix.md must assign ${subject} to ${owner}.`);
  }
}

for (const required of [
  "`GoalRunProfile`",
  "`WorkflowTemplate`",
  "`HarnessProfile`",
  "`SkillManifest`, `SkillEntry`, `ActiveSkillSetSnapshot`",
  "`RuntimeToolContract`",
  "`MCPPrimitiveNormalization`, `HypervisorMCPGatewayRequirement`, `HypervisorMCPGatewayProfile`",
]) {
  if (!implementationMatrix.includes(required)) {
    fail(`_meta/implementation-matrix.md missing pursuit/skill/MCP concept-owner mapping: ${required}.`);
  }
}

for (const required of [
  "raw-tool admission",
  "resource-to-view/lease proof",
  "Task handle distinct from GoalRun identity/status",
  "package requirement/live-profile separation",
]) {
  if (!implementationMatrix.includes(required)) {
    fail(`_meta/implementation-matrix.md is missing pursuit/skill/MCP conformance doctrine: ${required}.`);
  }
}

for (const required of [
  "`GoalRunProfile`",
  "`WorkflowTemplate`",
  "`HarnessProfile`",
  "`SkillManifest`, `SkillEntry`, `ActiveSkillSetSnapshot`",
  "`RuntimeToolContract`",
  "`MCPPrimitiveNormalization`, `HypervisorMCPGatewayRequirement`, `HypervisorMCPGatewayProfile`",
]) {
  if (!canonToCodeDelta.includes(required)) {
    fail(`_meta/canon-to-code-delta.md missing pursuit/skill/MCP implementation drift: ${required}.`);
  }
}

for (const [rel, content, required] of [
  ["components/connectors-tools/contracts.md", connectorContracts, "## Hypervisor MCP Gateway Profile"],
  ["components/connectors-tools/doctrine.md", connectorDoctrine, "RuntimeToolContract"],
  ["foundations/common-objects-and-envelopes.md", commonObjects, "An MCP Task or another protocol-native asynchronous task remains an opaque"],
  ["components/hypervisor/core-clients-surfaces.md", coreSurfaces, "An imported MCP App is a sandboxed extension surface"],
]) {
  if (!content.includes(required)) {
    fail(`${rel} missing transport-subordinate MCP contract: ${required}.`);
  }
}

const runtimeToolContractBlock = contractSection(
  connectorContracts,
  "## RuntimeToolContract",
  "## MCP Gateway Requirement",
  "components/connectors-tools/contracts.md",
);
for (const required of [
  '"tool_id"',
  '"revision_ref"',
  '"predecessor_revision_ref"',
  '"content_hash"',
  '"input_schema"',
  '"output_schema"',
  '"risk_class"',
  '"effect_class"',
  '"primitive_capabilities_required"',
  '"authority_scopes_required"',
  '"evidence_required"',
  '"registry_lifecycle_ref"',
  '"registry_status"',
  "immutable",
  "content-addressed",
]) {
  if (!runtimeToolContractBlock.includes(required)) {
    fail(`RuntimeToolContract missing exact immutable capability field: ${required}.`);
  }
}

const harnessProfileBlock = contractSection(
  defaultHarnessProfile,
  "HarnessProfile:",
  "DefaultHarnessProfile:",
  "components/daemon-runtime/default-harness-profile.md",
);
for (const required of [
  "profile_id:",
  "revision_ref:",
  "predecessor_revision_ref:",
  "content_hash:",
  "supported_normalized_boundary_contracts:",
  "completed_invocation_terminal_minimum:",
  "conditional_contracts_follow_task_brief:",
  "registry_lifecycle_ref:",
  "registry_status:",
]) {
  if (!harnessProfileBlock.includes(required)) {
    fail(`HarnessProfile missing immutable resolver-contract field: ${required}.`);
  }
}
for (const forbidden of ["codex_adapter", "claude_code_adapter", "service_engine", "deterministic_only"]) {
  if (harnessProfileBlock.includes(forbidden)) {
    fail(`HarnessProfile conflates vendor adapter or direct execution family: ${forbidden}.`);
  }
}

const agentHarnessAdapterBlock = contractSection(
  defaultHarnessProfile,
  "## AgentHarnessAdapterEnvelope",
  "## Agent Operating Contract",
  "components/daemon-runtime/default-harness-profile.md",
);
for (const required of [
  "AgentHarnessAdapterEnvelope:",
  "revision_ref:",
  "content_hash:",
  "adapter_family:",
  "transport_kind:",
  "compatible_harness_profile_revision_refs:",
  "rendering_and_normalization_contract_refs:",
  "registry_lifecycle_ref:",
  "registry_status:",
]) {
  if (!agentHarnessAdapterBlock.includes(required)) {
    fail(`AgentHarnessAdapterEnvelope missing exact bridge field: ${required}.`);
  }
}

for (const required of [
  "MCPGatewayRequirementEnvelope:",
  "required_runtime_tool_contract_refs:",
  "resolved_requirement_set_hash",
  "exposure_manifest_hash",
  "profile_revision_ref",
  "profile_content_hash",
  "backing_contract_revision_ref",
  "backing_contract_content_hash",
  "| Tool | One admitted `RuntimeToolContract`",
  "| Resource | `PolicyBoundDataView`, `ArtifactRef`, or `MemoryProjection`",
  "| Prompt | User-selectable import input",
  "| Elicitation | Typed user-input",
  "| Task | Opaque external invocation handle",
  "| App | Sandboxed `extension_application` surface",
  "Widening tools, resources,",
]) {
  if (!connectorContracts.includes(required)) {
    fail(`components/connectors-tools/contracts.md missing MCP requirement/normalization contract: ${required}.`);
  }
}

for (const required of [
  "`POST /goal-runs` atomically revalidates, resolves, admits",
  '"goal_run_profile_revision_ref"',
  '"resolved_component_set_snapshot_ref"',
  '"goal_run_profile_resolution_receipt_ref"',
  "built-in generic-adaptive profile",
  "POST /v1/threads/{thread_id}/mcp/prompts/{prompt_id}/imports",
  "POST /v1/threads/{thread_id}/mcp/external-task-bindings",
  "GET  /v1/threads/{thread_id}/mcp/apps/search",
]) {
  if (!daemonApi.includes(required)) {
    fail(`components/daemon-runtime/api.md missing pursuit/MCP target API contract: ${required}.`);
  }
}

const automationProposalApiBlock = contractSection(
  daemonApi,
  "POST /v1/hypervisor/automation-runs/proposals",
  "GET /v1/hypervisor/model-infrastructure",
  "components/daemon-runtime/api.md",
);
for (const required of [
  '"proposal_ref": "proposal://automation-run/..."',
  '"operation_kind": "activate_occurrence"',
  '"automation_spec_revision_ref"',
  '"automation_spec_content_hash"',
  '"resolution_preview_ref"',
  "never emits an",
  "AutomationRunResolutionReceipt",
  "Package promotion remains",
]) {
  if (!automationProposalApiBlock.includes(required)) {
    fail(`AutomationRun proposal API missing proposal/admission separation: ${required}.`);
  }
}
for (const forbidden of [
  '"proposal_ref": "automation-run://',
  '"operation_kind": "run_now | schedule_run | promote_package"',
  '"resolution_receipt_ref"',
]) {
  if (automationProposalApiBlock.includes(forbidden)) {
    fail(`AutomationRun proposal API mints run truth or owns package promotion: ${forbidden}.`);
  }
}

for (const required of [
  "IoiAiGoalDraft:",
  "draft_intent_ref: intent://...",
  "IoiAiGoalProjection:",
  "goal_run_ref: goal://...",
  "IoiAiOutcomePlanProjection:",
  "orchestration_plan_revision_ref:",
  "orchestration_plan_content_hash:",
  "orchestration_decision_receipt_ref:",
  "read_model_only: true",
  "cannot mint `goal://` identity",
]) {
  if (!collaborativeOutcomePattern.includes(required)) {
    fail(`ioi.ai Goal Space missing draft/projection owner split: ${required}.`);
  }
}
for (const forbidden of ["\nIoiAiGoal:\n", "\nIoiAiOutcomePlan:\n", "selected_harnesses:", "selected_workers:"]) {
  if (collaborativeOutcomePattern.includes(forbidden)) {
    fail(`ioi.ai Goal Space restores a second goal/plan truth owner: ${forbidden.trim()}.`);
  }
}

const automationSpecBlock = contractSection(
  coreSurfaces,
  "HypervisorAutomationSpec:",
  "HypervisorAutomationInstallationBinding:",
  "components/hypervisor/core-clients-surfaces.md",
);
for (const required of [
  "automation_revision_ref:",
  "content_hash:",
  "owner_ref:",
  "workflow_template_revision_ref:",
  "workflow_template_content_hash:",
  "trigger_schedule_monitor_service_or_queue_contract_refs:",
  "delivery_contract_ref:",
  "goal_run_activation_contract_refs:",
  "allowed_activation_override_schema_ref:",
  "authority_requirement_refs:",
]) {
  if (!automationSpecBlock.includes(required)) {
    fail(`HypervisorAutomationSpec missing template/activation ownership field: ${required}.`);
  }
}
for (const forbidden of [
  "project_ref:",
  "system_ref:",
  "delivery_binding_ref:",
  "delivery://",
  "enablement_state:",
  "authority_grant_refs:",
  "authority_lease_refs:",
]) {
  if (automationSpecBlock.includes(forbidden)) {
    fail(`HypervisorAutomationSpec carries installation, delivery, or live state: ${forbidden}.`);
  }
}

const automationInstallationBindingBlock = contractSection(
  coreSurfaces,
  "HypervisorAutomationInstallationBinding:",
  "HypervisorAutomationRun:",
  "components/hypervisor/core-clients-surfaces.md",
);
for (const required of [
  "binding_revision_ref:",
  "predecessor_binding_revision_ref:",
  "binding_hash:",
  "automation_spec_revision_ref:",
  "automation_spec_content_hash:",
  "owner_scope_ref:",
  "enablement_state:",
  "policy_and_authority_overlay_refs:",
  "admission_receipt_ref:",
  "registry_lifecycle_ref:",
  "registry_status:",
]) {
  if (!automationInstallationBindingBlock.includes(required)) {
    fail(`HypervisorAutomationInstallationBinding missing exact local binding field: ${required}.`);
  }
}

const automationRunBlock = contractSection(
  coreSurfaces,
  "HypervisorAutomationRun:",
  "HypervisorCanvasView:",
  "components/hypervisor/core-clients-surfaces.md",
);
for (const required of [
  "automation_spec_revision_ref:",
  "automation_spec_content_hash:",
  "automation_installation_binding_revision_ref:",
  "automation_installation_binding_hash:",
  "workflow_template_revision_ref:",
  "workflow_template_content_hash:",
  "admitted_parameter_set_hash:",
  "admitted_activation_override_set_hash:",
  "resolution_receipt_ref:",
  "resolved_component_set_snapshot_ref:",
  "resolved_component_set_hash:",
  "authority_lease_refs:",
]) {
  if (!automationRunBlock.includes(required)) {
    fail(`HypervisorAutomationRun missing frozen activation field: ${required}.`);
  }
}

for (const required of [
  '"core_workspaces"',
  '"owner_applications"',
  '"substrate_applications"',
  '"surface_class": "owner_application"',
  '"surface_availability": "planned"',
  '"launchable": false',
  '"route_alias_registrations"',
  '"alias_route_pattern": "/missions/{legacy_subject_id?}"',
  '"alias_route_pattern": "/workbench"',
  '"workspace_ref": "hypervisor-workspace://work"',
  '"surface_ref": "surface://hypervisor/studio"',
  '"selected_release_ref"',
  '"selected_installation_enablement_state"',
  '"selected_system_enablement_state"',
  '"effective_enablement_state"',
  '"resolved_launch_route"',
  '"open_application_identity_and_back_stack": true',
  '"request_context_hash"',
  "match that principal and an admitted tenant-membership binding",
  '"canonical_route": "/studio"',
  '"canonical_route": "/developer-workspace"',
  '`WorkQueue`',
]) {
  if (!daemonApi.includes(required)) {
    fail(`components/daemon-runtime/api.md missing v2 taxonomy distinction: ${required}.`);
  }
}

const daemonTaxonomyBlock = daemonApi.slice(
  daemonApi.indexOf("GET /v1/hypervisor/core-taxonomy"),
  daemonApi.indexOf("POST /v1/hypervisor/session-launch-recipe-admissions"),
);
for (const forbidden of [
  '"conditional_applications"',
  '"compatibility_aliases"',
  '"admitted_package_install_surface_records"',
  '"surface_ref": "workspace:',
  '"surface_id": "developer-workspace"',
]) {
  if (daemonTaxonomyBlock.includes(forbidden)) {
    fail("components/daemon-runtime/api.md v2 taxonomy uses retired shape: " + forbidden + ".");
  }
}

const aiagentBroadLaborDocs = [
  {
    rel: "domains/aiagent/worker-marketplace.md",
    required: [
      "ontology-bound digital and embodied workers",
      "DigitalWorkerOntology",
      "VerticalOntologyPacks",
      "IntegrationSurfaces",
      "ManagedWorkerInstance",
    ],
  },
  {
    rel: "domains/aiagent/digital-worker-ontology.md",
    required: [
      "DigitalWorkerOntology",
      "VerticalOntologyPack",
      "IntegrationSurface",
      "ManagedWorkerInstance",
      "physical-action",
    ],
  },
  {
    rel: "domains/aiagent/vertical-ontology-packs.md",
    required: [
      "VerticalOntologyPack",
      "DigitalWorkerOntology",
      "safety envelopes",
      "forbidden actions",
      "receipt schemas",
    ],
  },
  {
    rel: "domains/aiagent/integration-surface-taxonomy.md",
    required: [
      "IntegrationSurface",
      "robotics_physical",
      "embodied_humanoid",
      "voice_sms",
      "authority scopes",
    ],
  },
  {
    rel: "domains/aiagent/managed-worker-instance-lifecycle.md",
    required: [
      "ManagedWorkerInstanceLifecycle",
      "payment",
      "archive",
      "restore",
      "Agentgres",
    ],
  },
  {
    rel: "domains/aiagent/managed-agent-console-contract.md",
    required: [
      "Managed Agent Console",
      "ManagedWorkerInstance",
      "projection",
      "wallet.network",
      "Agentgres",
    ],
  },
];

for (const { rel, required } of aiagentBroadLaborDocs) {
  const file = path.join(architectureRoot, rel);
  if (!fs.existsSync(file)) {
    fail(`aiagent broad-labor canon missing ${rel}.`);
    continue;
  }
  const content = fs.readFileSync(file, "utf8");
  for (const phrase of required) {
    if (!content.includes(phrase)) {
      fail(`${rel} missing aiagent broad-labor phrase: ${phrase}.`);
    }
  }
}

for (const [rel, content] of [
  ["_meta/source-of-truth-map.md", sourceMap],
  ["_meta/implementation-matrix.md", fs.readFileSync(path.join(architectureRoot, "_meta/implementation-matrix.md"), "utf8")],
  ["_meta/vocabulary.md", vocabulary],
]) {
  for (const phrase of [
    "DigitalWorkerOntology",
    "VerticalOntologyPack",
    "IntegrationSurface",
    "ManagedWorkerInstance",
  ]) {
    if (!content.includes(phrase)) {
      fail(`${rel} missing aiagent broad-labor concept: ${phrase}.`);
    }
  }
}

if (failures.length > 0) {
  console.error("Architecture documentation check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Architecture documentation check passed.");
