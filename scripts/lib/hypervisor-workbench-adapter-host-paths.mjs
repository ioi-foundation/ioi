import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../..");

function resolveEnvPath(name, fallback) {
  const value = process.env[name];
  return value ? resolve(value) : fallback;
}

function envFlag(name) {
  return ["1", "true", "yes"].includes(
    String(process.env[name] ?? "").toLowerCase(),
  );
}

const targetPackagedRoot = resolve(
  repoRoot,
  "workbench-adapters/builds/VSCode-linux-x64",
);
const targetForkRoot = resolve(repoRoot, "workbench-adapters/vscode");

const packagedRoot = resolveEnvPath(
  "HYPERVISOR_WORKBENCH_VSCODE_PACKAGED_ROOT",
  targetPackagedRoot,
);
const forkRoot = resolveEnvPath(
  "HYPERVISOR_WORKBENCH_VSCODE_FORK_ROOT",
  targetForkRoot,
);
const extensionSource = resolve(
  repoRoot,
  "workbench-adapters/ioi-code-editor-adapter",
);
const packagedWorkbenchTarget = resolve(
  packagedRoot,
  "resources/app/extensions/ioi-code-editor-adapter",
);
const forkWorkbenchTarget = resolve(forkRoot, "extensions/ioi-code-editor-adapter");
const binary = process.env.HYPERVISOR_WORKBENCH_VSCODE_FORK_BIN
  ? resolve(process.env.HYPERVISOR_WORKBENCH_VSCODE_FORK_BIN)
  : resolve(packagedRoot, "bin/hypervisor");

export const HYPERVISOR_WORKBENCH_ADAPTER_HOST = {
  repoRoot,
  packagedRoot,
  forkRoot,
  targetPackagedRoot,
  targetForkRoot,
  extensionSource,
  packagedWorkbenchTarget,
  forkWorkbenchTarget,
  binary,
};

export { envFlag };

function patchJsonFile(filePath, patch) {
  if (!existsSync(filePath)) return null;
  const before = JSON.parse(readFileSync(filePath, "utf8"));
  const after = patch({ ...before });
  writeFileSync(filePath, `${JSON.stringify(after, null, 2)}\n`, "utf8");
  return { filePath, changed: JSON.stringify(before) !== JSON.stringify(after) };
}

export function syncWorkbenchAdapterHostMetadata({
  root = packagedRoot,
} = {}) {
  const productJson = patchJsonFile(join(root, "resources/app/product.json"), (product) => ({
    ...product,
    nameShort: "Hypervisor",
    nameLong: "Hypervisor",
    applicationName: "hypervisor",
    dataFolderName: ".hypervisor",
    urlProtocol: "hypervisor",
  }));
  const packageJson = patchJsonFile(join(root, "resources/app/package.json"), (pkg) => ({
    ...pkg,
    name: "hypervisor",
  }));
  return {
    root,
    productJson,
    packageJson,
  };
}

export function syncWorkbenchExtensionTargets({
  includeForkIfPresent = true,
} = {}) {
  const copied = [];
  const skipped = [];
  const metadata = syncWorkbenchAdapterHostMetadata();
  const targets = [
    {
      kind: "packaged-app",
      path: packagedWorkbenchTarget,
      required: true,
    },
  ];

  if (includeForkIfPresent && existsSync(resolve(forkRoot, "extensions"))) {
    targets.push({
      kind: "source-fork",
      path: forkWorkbenchTarget,
      required: false,
    });
  } else {
    skipped.push({
      kind: "source-fork",
      path: forkWorkbenchTarget,
      reason: "source fork checkout is optional and not present",
    });
  }

  for (const target of targets) {
    rmSync(target.path, { recursive: true, force: true });
    mkdirSync(target.path, { recursive: true });
    cpSync(extensionSource, target.path, { recursive: true, force: true });
    copied.push(target);
  }

  return {
    source: extensionSource,
    copied,
    skipped,
    packagedRoot,
    forkRoot,
    forkOptional: true,
    metadata,
  };
}
