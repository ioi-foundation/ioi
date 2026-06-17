import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policyView = fs.readFileSync(
  new URL("./PolicyView.tsx", import.meta.url),
  "utf8",
);

test("policy view leads with authority profile projection before raw matrix", () => {
  assert.match(policyView, /buildAuthorityProfileProjection/);
  assert.match(policyView, /data-testid="shield-authority-profile"/);
  assert.match(policyView, /"allowed", authorityProfile\.allowedFamilies/);
  assert.match(policyView, /"gated", authorityProfile\.gatedFamilies/);
  assert.match(policyView, /"denied", authorityProfile\.deniedFamilies/);
  assert.match(policyView, /data-testid=\{`shield-authority-profile-\$\{posture\}`\}/);
  assert.match(policyView, /Advanced policy matrix/);
  assert.match(policyView, /shield-policy-matrix-details/);
});

console.log("policyViewWiring.test.ts: ok");
