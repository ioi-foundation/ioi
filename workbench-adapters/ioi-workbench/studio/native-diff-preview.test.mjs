import assert from "node:assert/strict";
import { test } from "node:test";
import nativeDiffPreviewModule from "./native-diff-preview.js";

const { createStudioNativeDiffPreview } = nativeDiffPreviewModule;

function createFakeVscode({ failDiff = false } = {}) {
  const executed = [];
  let provider = null;
  return {
    executed,
    vscode: {
      Uri: {
        parse(value) {
          return {
            value,
            toString() {
              return value;
            },
          };
        },
      },
      commands: {
        async executeCommand(...args) {
          executed.push(args);
          if (failDiff) {
            throw new Error("diff unavailable");
          }
        },
      },
      workspace: {
        registerTextDocumentContentProvider(_scheme, nextProvider) {
          provider = nextProvider;
          return { dispose() {} };
        },
      },
    },
    read(uri) {
      return provider.provideTextDocumentContent(uri);
    },
  };
}

test("native diff preview registers provider and opens sanitized diff URIs", async () => {
  const fake = createFakeVscode();
  const projection = { runtimeCockpit: { inlineDiffOverlayObserved: false } };
  const timeline = [];
  const { ensureStudioDiffProvider, openStudioNativeDiffPreview } = createStudioNativeDiffPreview({
    appendStudioTimeline: (...args) => timeline.push(args),
    crypto: { randomUUID: () => "uuid-1" },
    getStudioRuntimeProjection: () => projection,
    vscode: fake.vscode,
  });
  const context = { subscriptions: [] };

  ensureStudioDiffProvider(context);
  const opened = await openStudioNativeDiffPreview({
    file: "../unsafe file.md",
    beforeContent: "before",
    afterContent: "after",
  });

  assert.equal(opened, true);
  assert.equal(context.subscriptions.length, 1);
  assert.equal(fake.executed[0][0], "vscode.diff");
  assert.equal(fake.executed[0][1].toString(), "ioi-studio-diff:/..-unsafe-file.md.uuid-1.before.md");
  assert.equal(fake.executed[0][2].toString(), "ioi-studio-diff:/..-unsafe-file.md.uuid-1.after.md");
  assert.equal(fake.read(fake.executed[0][1]), "before");
  assert.equal(fake.read(fake.executed[0][2]), "after");
  assert.equal(projection.runtimeCockpit.inlineDiffOverlayObserved, true);
  assert.deepEqual(timeline[0], ["Native diff overlay opened", "..-unsafe-file.md", "completed"]);
});

test("native diff preview reports blocked diff without throwing", async () => {
  const fake = createFakeVscode({ failDiff: true });
  const projection = { runtimeCockpit: { inlineDiffOverlayObserved: false } };
  const timeline = [];
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  const { ensureStudioDiffProvider, openStudioNativeDiffPreview } = createStudioNativeDiffPreview({
    appendStudioTimeline: (...args) => timeline.push(args),
    crypto: { randomUUID: () => "uuid-2" },
    getStudioRuntimeProjection: () => projection,
    vscode: fake.vscode,
  });

  ensureStudioDiffProvider({ subscriptions: [] });
  const opened = await openStudioNativeDiffPreview({ file: "preview.md" }, output);

  assert.equal(opened, false);
  assert.equal(projection.runtimeCockpit.inlineDiffOverlayObserved, false);
  assert.deepEqual(timeline[0], ["Native diff overlay blocked", "diff unavailable", "blocked"]);
  assert.match(output.lines[0], /native diff overlay unavailable: diff unavailable/);
});
