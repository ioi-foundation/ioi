import assert from "node:assert/strict";
import test from "node:test";

import { computerUseContractsFromBrowserObservationArtifacts } from "./computer-use-browser-artifacts.mjs";

function buildContracts(artifacts) {
  return computerUseContractsFromBrowserObservationArtifacts({
    artifacts,
    leaseId: "lease-browser-artifact",
    observationRef: "observation-browser-artifact",
    targetIndexRef: "target-index-browser-artifact",
    affordanceGraphRef: "affordance-browser-artifact",
    retentionMode: "local_redacted_artifacts",
    sessionMode: "foreground_browser",
  });
}

test("browser observation artifacts project canonical artifact fields", () => {
  const result = buildContracts({
    page_title: "Canonical Browser Artifact Title",
    browser_use_selector_map_text: "[1] <button name=\"Submit\" target_id=\"target-submit\" />",
    browsergym_dom_text: "<button>Submit</button>",
    browsergym_axtree_text: "button Submit",
    browsergym_focused_bid: "bid-submit",
    screenshot_ref: "artifact:canonical:screenshot",
    som_ref: "artifact:canonical:som",
    redaction_report_ref: "artifact:canonical:redaction",
  });

  assert.ok(result);
  assert.equal(result.observationBundle.title, "Canonical Browser Artifact Title");
  assert.equal(result.observationBundle.screenshot_ref, "artifact:canonical:screenshot");
  assert.equal(result.observationBundle.som_ref, "artifact:canonical:som");
  assert.equal(result.observationBundle.redaction_report_ref, "artifact:canonical:redaction");
  assert.equal(result.observationBundle.dom_ref, "observation-browser-artifact:browsergym_dom");
  assert.equal(result.observationBundle.ax_ref, "observation-browser-artifact:browsergym_ax");
  assert.equal(result.observationBundle.selector_map_ref, "observation-browser-artifact:selector_map");
  assert.equal(result.targetIndex.targets[0].target_ref, "target:observation-browser-artifact:target-submit");
});

test("browser observation artifacts ignore retired camelCase aliases", () => {
  const result = buildContracts({
    pageTitle: "Retired Browser Artifact Title",
    browserUseSelectorMapText: "[99] <button name=\"Retired\" target_id=\"target-retired\" />",
    browsergymDomText: "<button>Retired</button>",
    browsergymAxtreeText: "button Retired",
    browsergymFocusedBid: "bid-retired",
    screenshotRef: "artifact:retired:screenshot",
    somRef: "artifact:retired:som",
    redactionReportRef: "artifact:retired:redaction",
  });

  assert.ok(result);
  assert.equal(result.observationBundle.title, null);
  assert.equal(result.observationBundle.screenshot_ref, null);
  assert.equal(result.observationBundle.som_ref, null);
  assert.equal(result.observationBundle.redaction_report_ref, null);
  assert.equal(result.observationBundle.dom_ref, null);
  assert.equal(result.observationBundle.ax_ref, null);
  assert.equal(result.observationBundle.selector_map_ref, null);
  assert.equal(result.targetIndex.targets.length, 1);
  assert.equal(result.targetIndex.targets[0].target_ref.endsWith(":document"), true);
  assert.deepEqual(result.targetIndex.targets[0].semantic_ids, ["document", "page-root"]);
});
