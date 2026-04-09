import assert from "node:assert/strict";
import type { SessionHookSnapshot } from "../../../types";
import { buildAuthorityAutomationPlan } from "./authorityAutomationModel.ts";

function makeHookSnapshot(
  overrides: Partial<SessionHookSnapshot> = {},
): SessionHookSnapshot {
  return {
    generatedAtMs: Date.now(),
    sessionId: "authority-session",
    workspaceRoot: "/repo",
    activeHookCount: 0,
    disabledHookCount: 0,
    runtimeReceiptCount: 0,
    approvalReceiptCount: 0,
    hooks: [],
    recentReceipts: [],
    ...overrides,
  };
}

{
  const plan = buildAuthorityAutomationPlan({
    currentProfileId: "guided_default",
    hookSnapshot: makeHookSnapshot({
      activeHookCount: 1,
      approvalReceiptCount: 2,
    }),
    rememberedApprovals: {
      generatedAtMs: 1,
      activeDecisionCount: 1,
      recentReceiptCount: 1,
      decisions: [],
      recentReceipts: [],
    },
    governanceRequest: null,
    activeOverrideCount: 0,
  });

  assert.equal(plan.actionKind, "apply_profile");
  assert.equal(plan.recommendedProfileId, "safer_review");
}

{
  const plan = buildAuthorityAutomationPlan({
    currentProfileId: "safer_review",
    hookSnapshot: makeHookSnapshot({
      activeHookCount: 2,
      runtimeReceiptCount: 3,
    }),
    rememberedApprovals: {
      generatedAtMs: 1,
      activeDecisionCount: 2,
      recentReceiptCount: 1,
      decisions: [],
      recentReceipts: [],
    },
    governanceRequest: null,
    activeOverrideCount: 1,
  });

  assert.equal(plan.actionKind, "apply_profile");
  assert.equal(plan.recommendedProfileId, "guided_default");
}

{
  const plan = buildAuthorityAutomationPlan({
    currentProfileId: "guided_default",
    hookSnapshot: makeHookSnapshot({
      activeHookCount: 3,
      runtimeReceiptCount: 4,
    }),
    rememberedApprovals: {
      generatedAtMs: 1,
      activeDecisionCount: 4,
      recentReceiptCount: 3,
      decisions: [],
      recentReceipts: [],
    },
    governanceRequest: null,
    activeOverrideCount: 0,
  });

  assert.equal(plan.actionKind, "apply_profile");
  assert.equal(plan.recommendedProfileId, "autonomous");
}

{
  const plan = buildAuthorityAutomationPlan({
    currentProfileId: "autonomous",
    hookSnapshot: makeHookSnapshot({
      activeHookCount: 1,
      disabledHookCount: 1,
      runtimeReceiptCount: 1,
    }),
    rememberedApprovals: {
      generatedAtMs: 1,
      activeDecisionCount: 1,
      recentReceiptCount: 0,
      decisions: [],
      recentReceipts: [],
    },
    governanceRequest: null,
    activeOverrideCount: 0,
  });

  assert.equal(plan.actionKind, "review_hooks");
  assert.equal(plan.recommendedView, "hooks");
}
