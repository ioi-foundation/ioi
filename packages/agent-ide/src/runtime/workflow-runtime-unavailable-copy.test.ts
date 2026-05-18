import assert from "node:assert/strict";
import test from "node:test";

import {
  createWorkflowRuntimeUnavailableFailure,
  workflowRuntimeCatalogFallbackCopy,
  workflowRuntimeUnavailableCopy,
} from "./workflow-composer-model";

test("runtime unavailable copy hides raw invoke exception from default message", () => {
  const copy = workflowRuntimeUnavailableCopy(
    new TypeError("Cannot read properties of undefined (reading 'invoke')"),
    "saved_workflow_bundle",
  );

  assert.equal(copy.code, "runtime_bridge_unavailable");
  assert.equal(copy.title, "Runtime bridge unavailable");
  assert.match(copy.message, /desktop\/runtime bridge/);
  assert.doesNotMatch(copy.message, /Cannot read properties|invoke/);
  assert.match(copy.technicalDetail, /Cannot read properties of undefined/);
});

test("runtime unavailable failure stores technical detail off the default message", () => {
  const result = createWorkflowRuntimeUnavailableFailure(
    "saved_workflow_bundle",
    new Error("Cannot read properties of undefined (reading 'invoke')"),
  );

  assert.equal(result.status, "blocked");
  assert.equal(result.errors[0]?.code, "runtime_bridge_unavailable");
  assert.doesNotMatch(result.errors[0]?.message ?? "", /Cannot read properties|invoke/);
  assert.match(result.errors[0]?.technicalDetail ?? "", /saved workflow bundle/);
  assert.match(result.errors[0]?.technicalDetail ?? "", /Cannot read properties/);
});

test("catalog fallback copy keeps catalog failures user-facing", () => {
  const tool = workflowRuntimeUnavailableCopy(
    new Error("Cannot read properties of undefined (reading 'invoke')"),
    "tool_catalog",
  );
  const connector = workflowRuntimeUnavailableCopy(
    new Error("Cannot read properties of undefined (reading 'invoke')"),
    "connector_catalog",
  );

  const fallback = workflowRuntimeCatalogFallbackCopy([tool, connector]);

  assert.ok(fallback);
  assert.match(fallback.message, /Runtime bridge unavailable/);
  assert.match(fallback.message, /offline presets/);
  assert.doesNotMatch(fallback.message, /Cannot read properties|invoke/);
  assert.match(fallback.technicalDetail ?? "", /tool catalog/);
  assert.match(fallback.technicalDetail ?? "", /connector catalog/);
});
