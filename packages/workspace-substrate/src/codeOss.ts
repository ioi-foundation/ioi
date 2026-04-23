import {
  initialize,
  monaco,
  updateUserConfiguration,
} from "@codingame/monaco-editor-wrapper";
import type { editor as CodeOssEditorApi } from "monaco-editor";

let readyPromise: Promise<typeof monaco> | null = null;
let themeDefined = false;

function defineAutopilotTheme() {
  if (themeDefined) {
    return;
  }

  monaco.editor.defineTheme("autopilot-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [],
    colors: {
      "editor.background": "#0c0f13",
      "editor.foreground": "#e4e7ed",
      "editor.lineHighlightBackground": "#141922",
      "editorCursor.foreground": "#a8d0ff",
      "editor.selectionBackground": "#244260",
      "editor.selectionHighlightBackground": "#1a2f46",
      "editorIndentGuide.background1": "#1d2330",
      "editorIndentGuide.activeBackground1": "#37516f",
      "editorLineNumber.foreground": "#596273",
      "editorLineNumber.activeForeground": "#9eafc5",
      "editorWhitespace.foreground": "#2b3442",
      "editorGutter.background": "#0c0f13",
      "minimap.background": "#0f1318",
      "scrollbar.shadow": "#00000000",
      "diffEditor.insertedTextBackground": "#17331d",
      "diffEditor.removedTextBackground": "#3d171c",
      "diffEditor.insertedLineBackground": "#132817",
      "diffEditor.removedLineBackground": "#341419",
    },
  });

  monaco.editor.defineTheme("autopilot-light", {
    base: "vs",
    inherit: true,
    rules: [],
    colors: {
      "editor.background": "#ffffff",
      "editor.foreground": "#24292f",
      "editor.lineHighlightBackground": "#f6f8fa",
      "editorCursor.foreground": "#0969da",
      "editor.selectionBackground": "#cce5ff",
      "editor.selectionHighlightBackground": "#deecff",
      "editorIndentGuide.background1": "#e5e7eb",
      "editorIndentGuide.activeBackground1": "#c4c9d1",
      "editorLineNumber.foreground": "#8c959f",
      "editorLineNumber.activeForeground": "#57606a",
      "editorWhitespace.foreground": "#d0d7de",
      "editorGutter.background": "#ffffff",
      "minimap.background": "#ffffff",
      "scrollbar.shadow": "#00000000",
      "diffEditor.insertedTextBackground": "#dff3e4",
      "diffEditor.removedTextBackground": "#ffe4e8",
      "diffEditor.insertedLineBackground": "#edf9f0",
      "diffEditor.removedLineBackground": "#fff1f3",
    },
  });

  themeDefined = true;
}

export async function ensureCodeOssReady() {
  if (!readyPromise) {
    readyPromise = initialize({}, {
      registerAdditionalExtensions: false,
      waitForDefaultExtensions: false,
    }).then(async () => {
      defineAutopilotTheme();
      monaco.editor.setTheme("autopilot-dark");
      await updateUserConfiguration(
        JSON.stringify(
          {
            "editor.fontSize": 13,
            "editor.lineHeight": 21,
            "editor.smoothScrolling": true,
            "editor.minimap.enabled": true,
            "editor.stickyScroll.enabled": false,
            "workbench.colorTheme": "Default Dark Modern",
          },
          null,
          2,
        ),
      );
      return monaco;
    });
  }

  return readyPromise;
}

export function toCodeOssUri(path: string) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return monaco.Uri.file(normalizedPath);
}

export type CodeOssMonaco = typeof monaco;
export type CodeOssTextModel = CodeOssEditorApi.ITextModel;
export type CodeOssStandaloneEditor = CodeOssEditorApi.IStandaloneCodeEditor;
export { monaco as codeOssMonaco };
