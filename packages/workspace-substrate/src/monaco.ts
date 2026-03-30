import { loader } from "@monaco-editor/react";

let configuredBasePath: string | null = null;

export function configureMonacoLoader(basePath: string) {
  if (!basePath || configuredBasePath === basePath) {
    return;
  }

  loader.config({
    paths: {
      vs: basePath,
    },
  });

  configuredBasePath = basePath;
}
