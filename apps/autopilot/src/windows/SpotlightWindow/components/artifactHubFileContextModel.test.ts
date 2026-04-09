import assert from "node:assert/strict";
import type { SessionFileContext } from "../../../types";
import { buildFileContextPathOverview } from "./artifactHubFileContextModel";

function sampleContext(): SessionFileContext {
  return {
    session_id: "session-123",
    workspace_root: "/tmp/repo",
    pinned_files: [],
    recent_files: [],
    explicit_includes: [],
    explicit_excludes: [],
    updated_at_ms: 0,
  };
}

function directoryScopesUseFolderLabels(): void {
  const context = sampleContext();
  context.explicit_includes = ["docs"];

  const overview = buildFileContextPathOverview(context, "docs", "directory");

  assert.equal(overview.includeLabel, "Include folder");
  assert.equal(overview.excludeLabel, "Exclude folder");
  assert.equal(overview.canInclude, false);
  assert.equal(overview.canExclude, true);
  assert.equal(overview.canRemove, true);
  assert.deepEqual(
    overview.badges.map((badge) => badge.label),
    ["Folder", "Included scope"],
  );
}

function excludedFileCanBeRepinnedToResolveConflict(): void {
  const context = sampleContext();
  context.explicit_excludes = ["src/main.rs"];

  const overview = buildFileContextPathOverview(context, "src/main.rs", "file");

  assert.equal(overview.canPin, true);
  assert.equal(overview.canInclude, true);
  assert.equal(overview.canExclude, false);
  assert.equal(overview.canRemove, true);
  assert.deepEqual(
    overview.badges.map((badge) => badge.label),
    ["Excluded"],
  );
}

function conflictingPinnedAndExcludedPathShowsReviewPill(): void {
  const context = sampleContext();
  context.pinned_files = ["src/main.rs"];
  context.explicit_includes = ["src/main.rs"];
  context.explicit_excludes = ["src/main.rs"];
  context.recent_files = ["src/main.rs"];

  const overview = buildFileContextPathOverview(context, "src/main.rs", "file");

  assert.equal(overview.canPin, true);
  assert.equal(overview.canInclude, true);
  assert.equal(overview.canExclude, true);
  assert.deepEqual(
    overview.badges.map((badge) => badge.label),
    ["Needs review", "Pinned", "Included", "Excluded", "Recent"],
  );
}

function plainRecentPathOnlyOffersRemoval(): void {
  const context = sampleContext();
  context.recent_files = ["README.md"];

  const overview = buildFileContextPathOverview(context, "README.md", "file");

  assert.equal(overview.canPin, true);
  assert.equal(overview.canInclude, true);
  assert.equal(overview.canExclude, true);
  assert.equal(overview.canRemove, true);
  assert.equal(overview.removeLabel, "Remove");
  assert.deepEqual(
    overview.badges.map((badge) => badge.label),
    ["Recent"],
  );
}

directoryScopesUseFolderLabels();
excludedFileCanBeRepinnedToResolveConflict();
conflictingPinnedAndExcludedPathShowsReviewPill();
plainRecentPathOnlyOffersRemoval();
