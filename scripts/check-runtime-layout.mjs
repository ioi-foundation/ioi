#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const report = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
}

function allFiles(dir, predicate = () => true) {
  const absolute = path.join(root, dir);
  if (!fs.existsSync(absolute)) return [];
  return fs.readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => {
    const relative = path.join(dir, entry.name);
    if (entry.isDirectory()) return allFiles(relative, predicate);
    return predicate(relative) ? [relative] : [];
  });
}

function assert(id, condition, evidence, message) {
  report.push({ id, status: condition ? "passed" : "failed", evidence, message });
  if (!condition) failures.push(`${id}: ${message}`);
}

const packageJson = JSON.parse(read("package.json"));
const readme = read("README.md");
const developersDocs = read("apps/developers-ioi-ai/src/content/docs.tsx");
const refineArchitectureGuide = read("internal-docs/implementation/refine-architecture.md");
const hypervisorCoreClientsSurfacesDoc = read(
  "docs/architecture/components/hypervisor/core-clients-surfaces.md",
);
const hypervisorFleetDoc = read("docs/architecture/components/hypervisor/fleet.md");
const hypervisorProvidersEnvironmentsDoc = read(
  "docs/architecture/components/hypervisor/providers-and-environments.md",
);
const daemonRuntimeApiDoc = read("docs/architecture/components/daemon-runtime/api.md");
const architectureSourceOfTruthMap = read("docs/architecture/_meta/source-of-truth-map.md");
const architectureImplementationMatrix = read("docs/architecture/_meta/implementation-matrix.md");
const architectureVocabulary = read("docs/architecture/_meta/vocabulary.md");
const workbenchAdapterLauncher = read("scripts/launch-hypervisor-workbench-adapter-host.mjs");
const workbenchAdapterHostPaths = read("scripts/lib/hypervisor-workbench-adapter-host-paths.mjs");
const workbenchAdaptersReadme = read("workbench-adapters/README.md");
const workbenchShellManifest = read("workbench-adapters/shell.manifest.json");
const workbenchShellPatch = read("scripts/lib/hypervisor-workbench-shell-patch.mjs");
const rootGitignore = read(".gitignore");
const hypervisorShellNavigationSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
);
const hypervisorActivityBarSource = read(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLocalActivityBar.tsx",
);
const hypervisorHomeSource = [
  "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
  "apps/hypervisor/src/surfaces/Home/HomeWalkthroughDocument.tsx",
  "apps/hypervisor/src/surfaces/Home/homeOnboardingModel.ts",
  "apps/hypervisor/src/surfaces/Home/index.ts",
].map(read).join("\n");
const workspaceRepositoryGateSource = read(
  "apps/hypervisor/src/surfaces/Workspace/WorkspaceRepositoryGate.tsx",
);
const packageScriptNames = Object.keys(packageJson.scripts ?? {});
const retiredAutopilotPackageScripts = packageScriptNames.filter((scriptName) =>
  /^(?:goal|validate|test):autopilot/.test(scriptName),
);
const retiredDesktopLaunchScripts = packageScriptNames.filter((scriptName) =>
  /^(?:dev|probe|dryrun):desktop(?::|$)/.test(scriptName),
);
const activeHypervisorPackageScriptValues = [
  "validate:hypervisor-app-harness",
  "validate:hypervisor-app-harness:run",
  "test:hypervisor-app-harness",
  "goal:hypervisor-app-ux-readiness",
  "goal:hypervisor-app-ux-readiness:run",
].map((scriptName) => packageJson.scripts?.[scriptName] ?? "");
const daemonSource = read("packages/runtime-daemon/src/index.mjs");
const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
const sdkIndex = read("packages/agent-sdk/src/index.ts");
const workbenchRuntimeFiles = allFiles("packages/hypervisor-workbench/src/runtime", (file) =>
  /\.(ts|tsx)$/.test(file),
);
const activeTauriSrc = "apps/hypervisor/src-tauri/src";
const activeTauriRuntimeService = "apps/hypervisor/src/services/TauriRuntime.ts";
const activeTauriDesktopLauncher = "apps/hypervisor/scripts/dev-desktop.sh";
const legacyTauriArchive = "internal-docs/legacy/autopilot-tauri-src";
const rootIdeDir = "ide";
const retiredAgentIdePath = "packages/agent-ide";
const retiredAutopilotShellWindow = "apps/hypervisor/src/windows/AutopilotShellWindow";
const builtinFiles = allFiles("crates/services/src/agentic/runtime/tools/builtins", (file) =>
  file.endsWith(".rs"),
);
const runtimeServiceFiles = allFiles("crates/services/src/agentic/runtime/service", (file) =>
  /\.(rs|md)$/.test(file),
);
const hypervisorDesktopProbeFiles = allFiles("apps/hypervisor/scripts", (file) =>
  /^apps\/hypervisor\/scripts\/(?:desktop_.*_probe|dev_.*_probe)\.py$/.test(file) ||
  file === "apps/hypervisor/scripts/home_onboarding_condition_matrix.ts",
);
const activeRuntimeSwarmFiles = [
  ...allFiles("apps/hypervisor/src", (file) => /\.(ts|tsx|css)$/.test(file)),
  ...allFiles("crates/api/src", (file) => file.endsWith(".rs")),
  ...allFiles("crates/services/src/agentic/runtime", (file) => file.endsWith(".rs")),
  "crates/types/src/app/chat.rs",
].filter((file) => exists(file));
const allowedSwarmCompatibilityFiles = new Set([
  "apps/hypervisor/src/types/work-graph-compat.ts",
  "crates/api/src/chat/types.rs",
  "crates/services/src/agentic/runtime/service/memory/context.rs",
  "crates/services/src/agentic/runtime/types.rs",
  "crates/types/src/app/chat.rs",
]);
const generatedTs = read("packages/hypervisor-workbench/src/runtime/generated/action-schema.ts");
const generatedRust = read("crates/types/src/app/generated/runtime_action_schema.rs");
const actionSchema = JSON.parse(read("internal-docs/implementation/runtime-action-schema.json"));

assert(
  "daemon-promoted",
  exists("packages/runtime-daemon/src/index.mjs") && !exists("scripts/lib/local-runtime-daemon.mjs"),
  ["packages/runtime-daemon/src/index.mjs"],
  "daemon implementation must live outside scripts/lib",
);
assert(
  "daemon-product-names",
  daemonSource.includes("startRuntimeDaemonService") &&
    daemonSource.includes("AgentgresRuntimeStateStore") &&
    !daemonSource.includes("startLocalRuntimeDaemon") &&
    !daemonSource.includes("AgentgresRuntimeStore"),
  ["packages/runtime-daemon/src/index.mjs"],
  "daemon implementation must use product runtime names",
);
assert(
  "stable-conformance-scripts",
  exists("scripts/conformance/runtime-complete-plus.mjs") &&
    exists("scripts/evidence/runtime-complete-plus.mjs") &&
    packageJson.scripts["validate:runtime-complete-plus"] &&
    packageJson.scripts["evidence:runtime-complete-plus"],
  ["scripts/conformance/runtime-complete-plus.mjs", "scripts/evidence/runtime-complete-plus.mjs", "package.json"],
  "runtime conformance/evidence must have durable names",
);
assert(
  "roadmap-wrappers-retired",
  !exists("scripts/run-architectural-improvements-broad-validation.mjs") &&
    !exists("scripts/run-architectural-improvements-broad-evidence.mjs") &&
    !packageJson.scripts["validate:architectural-improvements-broad"] &&
    !packageJson.scripts["evidence:architectural-improvements-broad"],
  [
    "scripts/conformance/runtime-complete-plus.mjs",
    "scripts/evidence/runtime-complete-plus.mjs",
    "package.json",
  ],
  "roadmap-specific compatibility wrappers and package aliases must stay retired; use runtime-complete-plus commands",
);
assert(
  "autopilot-package-scripts-retired",
  retiredAutopilotPackageScripts.length === 0 &&
    activeHypervisorPackageScriptValues.every(
      (scriptValue) =>
        !/run-autopilot-|build-autopilot|custom-autopilot|autopilot-gui-harness/.test(
          scriptValue,
        ),
    ) &&
    packageJson.scripts["validate:hypervisor-app-harness"] &&
    packageJson.scripts["validate:hypervisor-app-harness:run"] &&
    packageJson.scripts["test:hypervisor-app-harness"] &&
    packageJson.scripts["goal:hypervisor-app-ux-readiness"] &&
    packageJson.scripts["goal:hypervisor-workflow-compositor-parity"] &&
    packageJson.scripts["goal:hypervisor-model-mounting"] &&
    packageJson.scripts["goal:hypervisor-workbench-mode-shell"] &&
    packageJson.scripts["build:hypervisor-workbench-composer"] &&
    !packageJson.scripts["build:ioi-workbench-composer"],
  ["package.json"],
  "root package scripts must expose Hypervisor command names, not retired Autopilot product aliases",
);
assert(
  "runtime-module-map",
  exists("internal-docs/implementation/runtime-module-map.md") &&
    read("internal-docs/implementation/runtime-module-map.md").includes("RuntimeSubstrate") &&
    read("internal-docs/implementation/runtime-package-boundaries.md").includes("runtime-module-map.md") &&
    read("internal-docs/implementation/runtime-module-map.md").includes("WorkbenchAdapterHost") &&
    read("internal-docs/implementation/runtime-module-map.md").includes("root `ide/` product path") &&
    read("internal-docs/implementation/runtime-module-map.md").includes("not an active proof home"),
  [
    "internal-docs/implementation/runtime-module-map.md",
    "internal-docs/implementation/runtime-package-boundaries.md",
  ],
  "runtime module map must identify canonical homes and be linked from boundary docs",
);
assert(
  "refine-architecture-ioi-reference-target",
  refineArchitectureGuide.includes("internal-docs/reverse-engineering/ioi") &&
    refineArchitectureGuide.includes("Primary IOI reference mirror") &&
    !/internal-docs\/reverse-engineering\/ona|ONA-like/.test(refineArchitectureGuide),
  ["internal-docs/implementation/refine-architecture.md"],
  "refine-architecture Phase 0A must use the IOI reverse-engineering mirror as the primary UX target, not ONA-era wording.",
);
assert(
  "hypervisor-shell-ioi-reference-contract",
  hypervisorShellNavigationSource.includes("HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS") &&
    hypervisorShellNavigationSource.includes('primaryReference: "internal-docs/reverse-engineering/ioi"') &&
    [
      '"home"',
      '"sessions"',
      '"projects"',
      '"missions"',
      '"workbench"',
      '"automations"',
      '"insights"',
      '"agents"',
      '"models"',
      '"privacy"',
      '"fleet"',
      '"foundry"',
      '"authority"',
      '"receipts"',
      '"settings"',
    ].every((surface) => hypervisorShellNavigationSource.includes(surface)) &&
    [
      '"left_nav"',
      '"new_session"',
      '"session_rail"',
      '"session_detail_tabs"',
      '"right_inspector"',
      '"bottom_inspector"',
    ].every((region) => hypervisorShellNavigationSource.includes(region)) &&
    hypervisorShellNavigationSource.includes('"editor_preference"') &&
    hypervisorShellNavigationSource.includes('"git_auth"') &&
    hypervisorShellNavigationSource.includes("Codex CLI") &&
    hypervisorShellNavigationSource.includes("Claude Code") &&
    hypervisorShellNavigationSource.includes("DeepSeek CLI") &&
    hypervisorActivityBarSource.includes("HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS") &&
    hypervisorActivityBarSource.includes(
      "HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS.leftNavSurfaceIds.slice(0, 9)",
    ) &&
    !/internal-docs\/reverse-engineering\/ona|Hypervisor IDE/.test(
      hypervisorShellNavigationSource,
    ),
  [
    "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts",
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLocalActivityBar.tsx",
  ],
  "Hypervisor shell must bind Phase 0A to the IOI reference cockpit contract and derive rail shortcuts from that contract.",
);
assert(
  "repo-facing-hypervisor-client-map",
  readme.includes("[`apps/hypervisor`](apps/hypervisor)") &&
    readme.includes("[`packages/hypervisor-workbench`](packages/hypervisor-workbench)") &&
    readme.includes("[`workbench-adapters`](workbench-adapters)") &&
    readme.includes("Hypervisor Workbench") &&
    !readme.includes("packages/agent-ide") &&
    !readme.includes("Hypervisor IDE"),
  ["README.md"],
  "README must present Hypervisor App/Web, Workbench, and adapter targets instead of retired Hypervisor IDE or packages/agent-ide language.",
);
assert(
  "active-product-copy-hypervisor-taxonomy",
  developersDocs.includes("Hypervisor exists today as a native operator client over Hypervisor Core") &&
    developersDocs.includes("'apps/hypervisor/src/windows/HypervisorShellWindow'") &&
    developersDocs.includes("routePath: '/hypervisor'") &&
    !developersDocs.includes("Autopilot exists today as a local Tauri desktop product") &&
    !developersDocs.includes("'apps/hypervisor/src/windows/AutopilotShellWindow'") &&
    !developersDocs.includes("daemon and Autopilot surfaces") &&
    workbenchAdapterLauncher.includes("hypervisor-workbench-configured-llama-cpp") &&
    !workbenchAdapterLauncher.includes("autopilot-ide-configured-llama-cpp"),
  [
    "apps/developers-ioi-ai/src/content/docs.tsx",
    "scripts/launch-hypervisor-workbench-adapter-host.mjs",
  ],
  "Active product docs and model preload identifiers must use Hypervisor client/Workbench taxonomy, not Autopilot IDE or Tauri product language.",
);
assert(
  "workbench-shell-patch-hypervisor-named",
  exists("scripts/lib/hypervisor-workbench-shell-patch.mjs") &&
    !exists("scripts/lib/autopilot-workbench-shell-patch.mjs") &&
    workbenchShellPatch.includes("applyHypervisorWorkbenchShellPatch") &&
    workbenchShellPatch.includes("ioi-hypervisor-native-shell") &&
    workbenchShellPatch.includes("ioi-hypervisor-workbench-quickinput") &&
    workbenchShellPatch.includes("ioi.hypervisor-workbench-shell-patch.v1") &&
    workbenchShellPatch.includes("ioi.hypervisor.shell.mode") &&
    workbenchShellPatch.includes("ioi.hypervisor.active.mode") &&
    workbenchShellPatch.includes("hypervisor-primary-rail") &&
    workbenchShellPatch.includes("code-rail-back-to-hypervisor") &&
    workbenchShellPatch.includes("secondaryHypervisorHeaderRemoved") &&
    workbenchShellPatch.includes("hypervisorModeMenuHiddenByCssAndSettings") &&
    !/applyAutopilotWorkbenchShellPatch|ioi-autopilot-native-shell|ioi-autopilot-fork-quickinput|ioi\.autopilot-workbench-shell-patch|ioi\.autopilot\.shell\.mode|ioi\.autopilot\.active\.mode|autopilot-primary-rail|code-rail-back-to-autopilot|activeAutopilotMode|secondaryAutopilotHeaderRemoved|autopilotModeMenuHiddenByCssAndSettings|Back to Autopilot/.test(
      workbenchShellPatch,
    ),
  [
    "scripts/lib/hypervisor-workbench-shell-patch.mjs",
    "scripts/lib/autopilot-workbench-shell-patch.mjs",
  ],
  "Workbench adapter shell patch helper must use Hypervisor naming; the retired Autopilot helper path/function/source ids must not return.",
);
assert(
  "workbench-adapter-fork-sync-target-only",
  /workbench-adapters\/vscode\/\n/.test(rootGitignore) &&
    /workbench-adapters\/builds\/\n/.test(rootGitignore) &&
    /"workbenchSource":\s*"workbench-adapters\/ioi-workbench"/.test(workbenchShellManifest) &&
    /"optionalForRuntimeLaunch":\s*true/.test(workbenchShellManifest) &&
    workbenchAdaptersReadme.includes("workbench-adapters/ioi-workbench") &&
    workbenchAdaptersReadme.includes("target optional local VS Code source") &&
    /const extensionSource = resolve\(\s*repoRoot,\s*"workbench-adapters\/ioi-workbench",\s*\);/.test(
      workbenchAdapterHostPaths,
    ) &&
    /const forkWorkbenchTarget = resolve\(forkRoot, "extensions\/ioi-workbench"\);/.test(
      workbenchAdapterHostPaths,
    ) &&
    /rmSync\(target\.path, \{ recursive: true, force: true \}\);\s*mkdirSync\(target\.path, \{ recursive: true \}\);\s*cpSync\(extensionSource, target\.path, \{ recursive: true, force: true \}\);/.test(
      workbenchAdapterHostPaths,
    ) &&
    !/const extensionSource = resolve\([\s\S]*workbench-adapters\/vscode/.test(
      workbenchAdapterHostPaths,
    ),
  [
    ".gitignore",
    "workbench-adapters/README.md",
    "workbench-adapters/shell.manifest.json",
    "scripts/lib/hypervisor-workbench-adapter-host-paths.mjs",
  ],
  "Ignored VS Code fork/build trees must stay sync targets copied from the canonical Workbench adapter source, not duplicate tracked JS truth paths.",
);
assert(
  "home-onboarding-hypervisor-taxonomy",
  hypervisorHomeSource.includes("HYPERVISOR_ONBOARDING_FAMILIES") &&
    hypervisorHomeSource.includes("HypervisorOnboardingStep") &&
    hypervisorHomeSource.includes("Get Started with Hypervisor") &&
    hypervisorHomeSource.includes("governed Workbench adapter") &&
    hypervisorHomeSource.includes("Workbench adapter") &&
    !/AUTOPILOT_ONBOARDING|AutopilotOnboarding|autopilot\.home\.onboarding|autopilot\.onboarding|OpenVSCode|contained OpenVSCode/.test(hypervisorHomeSource),
  [
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "apps/hypervisor/src/surfaces/Home/HomeWalkthroughDocument.tsx",
    "apps/hypervisor/src/surfaces/Home/homeOnboardingModel.ts",
    "apps/hypervisor/src/surfaces/Home/index.ts",
  ],
  "Home onboarding must use Hypervisor and Workbench adapter language instead of retired Autopilot/OpenVSCode product framing.",
);
assert(
  "workbench-landing-adapter-hub",
  workspaceRepositoryGateSource.includes('data-workbench-adapter-hub="true"') &&
    workspaceRepositoryGateSource.includes("<h1>Workbench</h1>") &&
    workspaceRepositoryGateSource.includes("Adapter targets") &&
    workspaceRepositoryGateSource.includes("Choose a governed adapter target") &&
    workspaceRepositoryGateSource.includes("adapter targets over Hypervisor Core") &&
    workspaceRepositoryGateSource.includes("not the parent product or runtime truth") &&
    workspaceRepositoryGateSource.includes("VS Code / OpenVSCode") &&
    workspaceRepositoryGateSource.includes("Cursor / Windsurf") &&
    workspaceRepositoryGateSource.includes("JetBrains / Terminal") &&
    workspaceRepositoryGateSource.includes("Browser / VM / Node") &&
    !/<h1>Code repositories<\/h1>|>Pull requests<|No pull requests created by you|Find pull requests/.test(
      workspaceRepositoryGateSource,
    ),
  ["apps/hypervisor/src/surfaces/Workspace/WorkspaceRepositoryGate.tsx"],
  "Workbench must open as a governed adapter hub over Hypervisor Core, not a code-repository or pull-request console.",
);
assert(
  "hypervisor-environment-ops-model",
  refineArchitectureGuide.includes("HypervisorEnvironmentOpsProfile") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentLifecycleState") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentClass") &&
    refineArchitectureGuide.includes("HypervisorSessionAccessLease") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentService") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentTask") &&
    refineArchitectureGuide.includes("HypervisorEnvironmentPort") &&
    refineArchitectureGuide.includes("HypervisorScmAuthRequirement") &&
    refineArchitectureGuide.includes("Environment-ops doctrine") &&
    refineArchitectureGuide.includes("create, create_from_project, start, stop, mark_active, archive,") &&
    refineArchitectureGuide.includes("access/log lease state, SCM auth requirements, ports/services, tasks, terminal/logs") &&
    !/\bGitpod\b|gitpod/i.test(refineArchitectureGuide),
  ["internal-docs/implementation/refine-architecture.md"],
  "Refine guide must model environment lifecycle, access/log leases, SCM auth, services, tasks, ports, and restore refs as Hypervisor-native objects without vendor-specific references.",
);
assert(
  "hypervisor-environment-ops-canon",
  [
    "HypervisorEnvironmentClass",
    "HypervisorEnvironmentOpsProfile",
    "HypervisorEnvironmentLifecycleState",
    "HypervisorEnvironmentActivitySignal",
    "HypervisorSessionAccessLease",
    "HypervisorEnvironmentService",
    "HypervisorEnvironmentTask",
    "HypervisorEnvironmentPort",
    "HypervisorScmAuthRequirement",
  ].every((term) =>
    [
      hypervisorCoreClientsSurfacesDoc,
      hypervisorProvidersEnvironmentsDoc,
      daemonRuntimeApiDoc,
      architectureSourceOfTruthMap,
      architectureImplementationMatrix,
      architectureVocabulary,
    ].every((doc) => doc.includes(term)),
  ) &&
    hypervisorCoreClientsSurfacesDoc.includes("encrypted blobs are restore material, not restore truth") &&
    hypervisorProvidersEnvironmentsDoc.includes("A blob can be necessary restore material without") &&
    daemonRuntimeApiDoc.includes("Provider lifecycle state may be evidence, but it is not") &&
    architectureVocabulary.includes("derived token material under a `HypervisorSessionAccessLease`") &&
    hypervisorFleetDoc.includes("Status: deprecated terminology stub") &&
    hypervisorFleetDoc.includes("`Hypervisor Fleet` is deprecated live canon") &&
    hypervisorProvidersEnvironmentsDoc.includes("There is no separate Fleet product") &&
    !/\bGitpod\b|gitpod/i.test(
      [
        hypervisorCoreClientsSurfacesDoc,
        hypervisorProvidersEnvironmentsDoc,
        hypervisorFleetDoc,
        daemonRuntimeApiDoc,
        architectureSourceOfTruthMap,
        architectureImplementationMatrix,
        architectureVocabulary,
      ].join("\n"),
    ),
  [
    "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    "docs/architecture/components/hypervisor/providers-and-environments.md",
    "docs/architecture/components/hypervisor/fleet.md",
    "docs/architecture/components/daemon-runtime/api.md",
    "docs/architecture/_meta/source-of-truth-map.md",
    "docs/architecture/_meta/implementation-matrix.md",
    "docs/architecture/_meta/vocabulary.md",
  ],
  "Canon docs must model Hypervisor environment lifecycle, access/log leases, SCM auth, services, tasks, ports, and restore refs without vendor-specific references.",
);
assert(
  "contract-family-modules",
  [
    "adapters",
    "agentgres",
    "authority",
    "cognition",
    "envelope",
    "events",
    "policy",
    "quality",
    "tools",
    "trace",
  ].every((name) => exists(`crates/types/src/app/runtime/${name}.rs`)) &&
    read("crates/types/src/app/mod.rs").includes("pub mod runtime;"),
  ["crates/types/src/app/runtime", "crates/types/src/app/mod.rs"],
  "runtime contract families must have concern-oriented module paths",
);
assert(
  "step-ownership-map",
  exists("crates/services/src/agentic/runtime/service/README.md") &&
    read("crates/services/src/agentic/runtime/service/README.md").includes("decision_loop") &&
    read("crates/services/src/agentic/runtime/service/README.md").includes("tool_execution") &&
    read("crates/services/src/agentic/runtime/service/decision_loop/README.md").includes("guarded service lane"),
  [
    "crates/services/src/agentic/runtime/service/README.md",
    "crates/services/src/agentic/runtime/service/decision_loop/README.md",
  ],
  "runtime service must have explicit lane ownership boundaries",
);
assert(
  "step-physical-split",
  !exists("crates/services/src/agentic/runtime/service/step") &&
    runtimeServiceFiles.every((file) => !read(file).includes("service::step")),
  ["crates/services/src/agentic/runtime/service"],
  "runtime service implementation must be physically split into named lanes with no service::step imports",
);
assert(
  "builtin-tool-family-names",
  builtinFiles.every((file) => {
    const base = path.basename(file);
    return (
      base === "tests.rs" ||
      /^[a-z][a-z0-9_]*\.rs$/.test(base) &&
        !base.includes("deterministic_system_tools_are_available") &&
        !base.includes("tier_1_deterministic") &&
        !base.includes("only_expose_screen")
    );
  }),
  builtinFiles,
  "built-in production tool files must use tool-family names",
);
assert(
  "proofs-isolated",
  !exists(activeTauriSrc) &&
  !exists(activeTauriRuntimeService) &&
  !exists(activeTauriDesktopLauncher) &&
  !exists(rootIdeDir) &&
    !exists(retiredAgentIdePath) &&
    !exists(retiredAutopilotShellWindow) &&
    !exists(legacyTauriArchive),
  [
    activeTauriSrc,
    activeTauriRuntimeService,
    activeTauriDesktopLauncher,
    rootIdeDir,
    retiredAgentIdePath,
    retiredAutopilotShellWindow,
    legacyTauriArchive,
  ],
  "Active Tauri Rust/launchers, root ide/, packages/agent-ide, old AutopilotShellWindow, and legacy Tauri archive paths must stay retired from active app paths.",
);
assert(
  "hypervisor-app-launcher-names",
  Boolean(packageJson.scripts?.["dev:hypervisor-app"]) &&
    Boolean(packageJson.scripts?.["dev:hypervisor-app:wayland"]) &&
    retiredDesktopLaunchScripts.length === 0,
  ["package.json", retiredDesktopLaunchScripts],
  "Active launch/probe scripts must use Hypervisor App naming; retired dev/probe/dryrun:desktop script keys must not return.",
);
assert(
  "desktop-probes-no-retired-tauri-workspace",
  hypervisorDesktopProbeFiles.every(
    (file) => !read(file).includes("apps/hypervisor/src-tauri"),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must use temporary/current workspaces, not the retired Tauri app path.",
);
assert(
  "desktop-probes-no-tauri-product-language",
  hypervisorDesktopProbeFiles.every(
    (file) => !/\bTauri\b|@tauri|tauri:\/\//.test(read(file)),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must target Hypervisor/App/Web/Workbench adapter hosts, not describe a Tauri app.",
);
assert(
  "desktop-probes-no-ide-product-marker",
  hypervisorDesktopProbeFiles.every(
    (file) => !/\[Workspace IDE\]|Workspace IDE/.test(read(file)),
  ),
  hypervisorDesktopProbeFiles,
  "Active Hypervisor desktop probes must target Workbench adapter hosts, not the retired Workspace IDE marker.",
);
assert(
  "sdk-no-gui-harness-imports",
  !/apps\/autopilot|hypervisor-workbench|scripts\/lib|benchmarks/.test(sdkSubstrate + sdkIndex),
  ["packages/agent-sdk/src"],
  "SDK must not import GUI, harness, benchmark, or script internals",
);
assert(
  "projection-adapter-names",
  exists("packages/hypervisor-workbench/src/runtime/runtime-projection-adapter.ts") &&
    !exists("packages/hypervisor-workbench/src/runtime/agent-execution-substrate.ts") &&
    !exists(`${activeTauriSrc}/runtime_projection.rs`) &&
    !exists(`${activeTauriSrc}/agent_runtime_substrate.rs`),
  [
    "packages/hypervisor-workbench/src/runtime/runtime-projection-adapter.ts",
    `${activeTauriSrc}/runtime_projection.rs`,
  ],
  "client projection adapters must not be named as canonical execution substrates, and Tauri Rust projection must stay retired",
);
assert(
  "workbench-projection-boundary",
  workbenchRuntimeFiles.every((file) => !read(file).includes("AgentgresRuntimeStateStore")) &&
    read("packages/hypervisor-workbench/src/runtime/workflow-composer-model.ts").includes("non-canonical"),
  ["packages/hypervisor-workbench/src/runtime"],
  "hypervisor-workbench runtime helpers must remain non-canonical projections",
);
assert(
  "capability-tiers",
  read("crates/types/src/app/runtime_contracts.rs").includes("primitive_capabilities: Vec<String>") &&
    read("crates/types/src/app/runtime_contracts.rs").includes("authority_scope_requirements: Vec<String>") &&
    read("crates/services/src/agentic/runtime/tools/contracts.rs").includes("authority_scopes_for") &&
    !read("crates/types/src/app/runtime_contracts.rs").includes("capability_lease_requirements"),
  ["crates/types/src/app/runtime_contracts.rs", "crates/services/src/agentic/runtime/tools/contracts.rs"],
  "primitive capabilities and authority scopes must stay separated",
);
assert(
  "action-schema-drift",
  actionSchema.actionKinds.every((kind) => generatedTs.includes(`"${kind}"`) && generatedRust.includes(`"${kind}"`)),
  [
    "internal-docs/implementation/runtime-action-schema.json",
    "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
    "crates/types/src/app/generated/runtime_action_schema.rs",
  ],
  "generated action schema projections must match shared runtime-action-schema.json",
);
assert(
  "public-swarm-boundary",
  !read("crates/types/src/app/chat.rs").includes('alias = "swarm"') &&
    !read("crates/types/src/app/chat.rs").includes("MicroSwarm") &&
    read("docs/architecture/_meta/vocabulary.md").includes("adaptive_work_graph") &&
    activeRuntimeSwarmFiles.every((file) => !read(file).includes("SWARM:")) &&
    activeRuntimeSwarmFiles.every((file) => {
      const content = read(file);
      if (!/\bswarm\b|Swarm|swarm[A-Z_]/.test(content)) return true;
      return allowedSwarmCompatibilityFiles.has(file);
    }),
  ["crates/types/src/app/chat.rs", "apps/hypervisor/src", "crates/services/src/agentic/runtime"],
  "active public runtime vocabulary must use adaptive work graph terminology; retired SWARM: decoding must stay absent",
);
assert(
  "retired-ioi-swarm-product",
  !exists("ioi-swarm") &&
    !exists("docs/ioi-swarm-release.md") &&
    (!exists("pyrightconfig.json") || !read("pyrightconfig.json").includes("ioi-swarm")),
  ["ioi-swarm", "docs/ioi-swarm-release.md", "pyrightconfig.json"],
  "retired ioi-swarm product package and release surface must not return",
);
assert(
  "debt-ledger-closed",
  !exists("docs/evidence/runtime-layout-refactor/remaining-debt.md") ||
    read("docs/evidence/runtime-layout-refactor/remaining-debt.md").includes(
      "No remaining runtime-layout refactor debt",
    ),
  ["docs/evidence/runtime-layout-refactor/remaining-debt.md"],
  "runtime-layout debt ledger must be closed before claiming completion when generated evidence is present",
);

const evidenceDir = path.join(root, "docs/evidence/runtime-layout-refactor");
fs.mkdirSync(evidenceDir, { recursive: true });
const summary = {
  schemaVersion: "ioi.runtime-layout-refactor.check.v1",
  generatedAt: new Date().toISOString(),
  status: failures.length ? "failed" : "passed",
  report,
  failures,
};
fs.writeFileSync(path.join(evidenceDir, "guardrail-report.json"), `${JSON.stringify(summary, null, 2)}\n`);

if (failures.length) {
  console.error("Runtime layout check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Runtime layout check passed.");
console.log(`Evidence: ${path.relative(root, path.join(evidenceDir, "guardrail-report.json"))}`);
