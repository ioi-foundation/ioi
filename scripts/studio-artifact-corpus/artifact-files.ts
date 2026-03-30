import { mkdtemp } from "node:fs/promises";
import {
  copyFile,
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { npmBinary } from "./config";
import { runCommand } from "./runtime";
import type {
  CaseSummary,
  CommandCapture,
  CorpusCase,
  GeneratedArtifactEvidence,
  WorkspaceBuildProof,
} from "./types";

export async function ensureCleanDirectory(target: string) {
  await rm(target, { recursive: true, force: true });
  await mkdir(target, { recursive: true });
}

export async function writeJson(target: string, value: unknown) {
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export async function writeText(target: string, value: string) {
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, value, "utf8");
}

export async function readJsonIfPresent<T>(target: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(target, "utf8")) as T;
  } catch {
    return null;
  }
}

export async function readTextIfPresent(target: string): Promise<string | null> {
  try {
    return await readFile(target, "utf8");
  } catch {
    return null;
  }
}

function extractSearchablePdfText(raw: string): string {
  const matches = [...raw.matchAll(/\(((?:\\.|[^()])*)\)\s*Tj/g)];
  if (matches.length === 0) {
    return raw;
  }

  return matches
    .map((match) =>
      match[1]
        .replace(/\\\\/g, "\\")
        .replace(/\\\(/g, "(")
        .replace(/\\\)/g, ")")
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t"),
    )
    .join("\n");
}

export async function fileExists(target: string): Promise<boolean> {
  try {
    await stat(target);
    return true;
  } catch {
    return false;
  }
}

export async function findFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await findFiles(fullPath)));
    } else {
      files.push(fullPath);
    }
  }
  return files.sort();
}

export function primaryFilePath(evidence: GeneratedArtifactEvidence): string | null {
  const primaryFile =
    evidence.manifest.files.find((file) => file.role === "primary") ??
    evidence.manifest.files.find((file) => file.renderable) ??
    evidence.manifest.files[0] ??
    null;
  return primaryFile?.path ?? null;
}

export async function collectArtifactText(
  evidence: GeneratedArtifactEvidence,
  artifactDir: string,
) {
  const parts: string[] = [];
  for (const file of evidence.manifest.files) {
    if (file.path === "artifact-manifest.json") {
      continue;
    }
    const fullPath = path.join(artifactDir, file.path);
    if (!(await fileExists(fullPath))) {
      continue;
    }
    const content = await readFile(fullPath, "utf8").catch(() => null);
    if (content) {
      parts.push(content);
    }
  }
  return parts.join("\n\n").toLowerCase();
}

export async function captureRendererOutput(
  caseConfig: CorpusCase,
  evidence: GeneratedArtifactEvidence,
  artifactDir: string,
  caseDir: string,
): Promise<{ capturePaths: string[]; workspaceBuild?: WorkspaceBuildProof }> {
  const capturesDir = path.join(caseDir, "captures");
  await mkdir(capturesDir, { recursive: true });
  const primaryRelativePath = primaryFilePath(evidence);
  const primaryAbsolutePath = primaryRelativePath
    ? path.join(artifactDir, primaryRelativePath)
    : null;
  const renderer = evidence.manifest.renderer;

  if (renderer === "workspace_surface") {
    const tempWorkspaceRoot = await mkdtemp(
      path.join(os.tmpdir(), `ioi-workspace-preview-${caseConfig.id}-`),
    );
    const tempWorkspace = path.join(tempWorkspaceRoot, "workspace");
    await cp(artifactDir, tempWorkspace, { recursive: true });
    const install = runCommand(npmBinary, ["install"], {
      cwd: tempWorkspace,
      allowFailure: true,
    });
    const build =
      install.status === 0
        ? runCommand(npmBinary, ["run", "build"], {
            cwd: tempWorkspace,
            allowFailure: true,
          })
        : null;
    const capturePath = path.join(capturesDir, "preview-capture.html");
    const distPath = path.join(tempWorkspace, "dist", "index.html");
    if (build?.status === 0 && (await fileExists(distPath))) {
      await copyFile(distPath, capturePath);
    } else if (primaryAbsolutePath) {
      await copyFile(primaryAbsolutePath, capturePath);
    }
    await writeText(
      path.join(caseDir, "workspace-install.log"),
      [install.stdout, install.stderr].filter(Boolean).join("\n"),
    );
    await writeText(
      path.join(caseDir, "workspace-build.log"),
      build ? [build.stdout, build.stderr].filter(Boolean).join("\n") : "build skipped",
    );
    return {
      capturePaths: [capturePath],
      workspaceBuild: {
        install,
        build,
        buildOk: install.status === 0 && build?.status === 0,
        capturePath,
      },
    };
  }

  if (!primaryAbsolutePath) {
    return { capturePaths: [] };
  }

  let capturePath = path.join(capturesDir, "render-capture.txt");
  if (renderer === "markdown") {
    capturePath = path.join(capturesDir, "render-capture.md");
    await copyFile(primaryAbsolutePath, capturePath);
  } else if (renderer === "html_iframe") {
    capturePath = path.join(capturesDir, "render-capture.html");
    await copyFile(primaryAbsolutePath, capturePath);
  } else if (renderer === "jsx_sandbox") {
    capturePath = path.join(capturesDir, "render-capture.jsx");
    await copyFile(primaryAbsolutePath, capturePath);
  } else if (renderer === "svg") {
    capturePath = path.join(capturesDir, "render-capture.svg");
    await copyFile(primaryAbsolutePath, capturePath);
  } else if (renderer === "mermaid") {
    capturePath = path.join(capturesDir, "render-capture.mermaid");
    await copyFile(primaryAbsolutePath, capturePath);
  } else if (renderer === "pdf_embed") {
    capturePath = path.join(capturesDir, "render-capture.txt");
    const pdfText = await readTextIfPresent(primaryAbsolutePath);
    await writeText(capturePath, pdfText ? extractSearchablePdfText(pdfText) : "");
  } else if (renderer === "download_card") {
    capturePath = path.join(capturesDir, "render-capture.html");
    const rows = evidence.manifest.files
      .filter((file) => file.downloadable)
      .map(
        (file) =>
          `<li><strong>${file.path}</strong><span>${file.mime}</span><span>${file.role}</span></li>`,
      )
      .join("\n");
    await writeText(
      capturePath,
      `<!doctype html><html><body><main><h1>${evidence.title}</h1><ul>${rows}</ul></main></body></html>`,
    );
  } else {
    await copyFile(primaryAbsolutePath, capturePath);
  }

  return { capturePaths: [capturePath] };
}

export async function loadGenerationEvidence(
  artifactDir: string,
): Promise<GeneratedArtifactEvidence> {
  return JSON.parse(await readFile(path.join(artifactDir, "generation.json"), "utf8"));
}

export async function diffArtifactFiles(
  baseDir: string,
  nextDir: string,
  options?: {
    ignorePaths?: Iterable<string>;
  },
): Promise<string[]> {
  const ignorePaths = new Set(["generation.json", ...(options?.ignorePaths ?? [])]);
  const baseFiles = await findFiles(baseDir);
  const nextFiles = await findFiles(nextDir);
  const relativePaths = Array.from(
    new Set(
      [...baseFiles, ...nextFiles]
        .map((file) => file.replace(`${baseDir}${path.sep}`, ""))
        .map((file) => file.replace(`${nextDir}${path.sep}`, "")),
    ),
  ).sort();

  const changed: string[] = [];
  for (const relativePath of relativePaths) {
    if (ignorePaths.has(relativePath)) {
      continue;
    }
    const left = path.join(baseDir, relativePath);
    const right = path.join(nextDir, relativePath);
    const leftContent = await readTextIfPresent(left);
    const rightContent = await readTextIfPresent(right);
    if (leftContent !== rightContent) {
      changed.push(relativePath);
    }
  }
  return changed;
}
