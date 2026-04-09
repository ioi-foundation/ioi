import { loader } from "@monaco-editor/react";

let configuredBasePath: string | null = null;
let configuredWorkerBaseUrl: string | null = null;
let monacoWorkerBootstrapUrl: string | null = null;

function ensureMonacoWorkerEnvironment(basePath: string) {
  if (typeof window === "undefined") {
    return;
  }

  const normalizedVsUrl = new URL(
    `${basePath.replace(/\/+$/, "")}/`,
    window.location.href,
  ).toString();
  const normalizedBaseUrl = new URL("../", normalizedVsUrl).toString();
  if (!monacoWorkerBootstrapUrl || configuredWorkerBaseUrl !== normalizedBaseUrl) {
    const workerBootstrap = [
      "self.MonacoEnvironment = self.MonacoEnvironment || {};",
      `self.MonacoEnvironment.baseUrl = ${JSON.stringify(normalizedBaseUrl)};`,
      `importScripts(${JSON.stringify(`${normalizedBaseUrl}vs/base/worker/workerMain.js`)});`,
    ].join("\n");
    monacoWorkerBootstrapUrl = URL.createObjectURL(
      new Blob([workerBootstrap], { type: "text/javascript" }),
    );
    configuredWorkerBaseUrl = normalizedBaseUrl;
  }

  const globalEnvironment = (globalThis as any).MonacoEnvironment ?? {};
  (globalThis as any).MonacoEnvironment = {
    ...globalEnvironment,
    baseUrl: normalizedBaseUrl,
    getWorkerUrl: () => monacoWorkerBootstrapUrl!,
    getWorker: (_moduleId: string, label: string) =>
      new Worker(monacoWorkerBootstrapUrl!, {
        name: `monaco-${label || "worker"}`,
      }),
  };
}

export function configureMonacoLoader(basePath: string) {
  if (!basePath || configuredBasePath === basePath) {
    return;
  }

  loader.config({
    paths: {
      vs: basePath,
    },
  });

  ensureMonacoWorkerEnvironment(basePath);
  configuredBasePath = basePath;
}
