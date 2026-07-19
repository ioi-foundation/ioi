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

for (const required of [
  "`GoalRunProfile`, `WorkflowTemplate`",
  "`SkillManifest`, `SkillEntry`, `ActiveSkillSetSnapshot`",
  "`MCPPrimitiveNormalization`, `HypervisorMCPGatewayRequirement`, `HypervisorMCPGatewayProfile`",
  "raw-tool admission",
  "resource-to-view/lease proof",
  "Task handle distinct from GoalRun identity/status",
  "package requirement/live-profile separation",
]) {
  if (!implementationMatrix.includes(required)) {
    fail(`_meta/implementation-matrix.md missing pursuit/skill/MCP status contract: ${required}.`);
  }
}

for (const required of [
  "`GoalRunProfile`, `WorkflowTemplate`",
  "`SkillManifest`, `SkillEntry`, `ActiveSkillSetSnapshot`",
  "`MCPPrimitiveNormalization`, `HypervisorMCPGatewayRequirement`, `HypervisorMCPGatewayProfile`",
  "top-level `/v1/mcp`",
  "different protocol/session assumptions",
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
