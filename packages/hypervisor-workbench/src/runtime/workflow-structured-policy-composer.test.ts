import assert from "node:assert/strict";
import test from "node:test";

import {
  compileWorkflowStructuredPolicy,
  type WorkflowStructuredModelRuleInput,
} from "./workflow-structured-policy-composer";

test("normalizes model policy rules with canonical hosted fallback field", () => {
  const compiled = compileWorkflowStructuredPolicy({
    modelRules: [{
      id: "model-local",
      privacy: "local_or_enterprise",
      allow_hosted_fallback: true,
    }],
  });

  assert.equal(compiled.status, "ready");
  assert.equal(compiled.modelRules[0].allow_hosted_fallback, true);
  assert.equal(
    Object.prototype.hasOwnProperty.call(compiled.modelRules[0], "allowHostedFallback"),
    false,
  );

  const retiredAliasRule = {
    id: "model-retired",
    privacy: "local_or_enterprise",
    allowHostedFallback: true,
  } as unknown as WorkflowStructuredModelRuleInput;
  const retiredAliasCompiled = compileWorkflowStructuredPolicy({
    modelRules: [retiredAliasRule],
  });

  assert.equal(retiredAliasCompiled.modelRules[0].allow_hosted_fallback, false);
});
