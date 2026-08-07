import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const goalSpace = readFileSync(new URL("../src/goal-space.ts", import.meta.url), "utf8");
const shell = readFileSync(new URL("../src/shell.ts", import.meta.url), "utf8");

test("Goal Space tabs expose complete tab and tabpanel semantics", () => {
  assert.match(goalSpace, /role="tab"[\s\S]*?aria-controls="goal-panel-goals"[\s\S]*?@keydown=\$\{onGoalTabKeydown\}/);
  assert.match(goalSpace, /role="tab"[\s\S]*?aria-controls="goal-panel-rooms"[\s\S]*?@keydown=\$\{onGoalTabKeydown\}/);
  assert.match(goalSpace, /role="tabpanel"[\s\S]*?aria-labelledby=\$\{`goal-tab-\$\{state\.tab\}`\}/);
  assert.match(goalSpace, /tabindex=\$\{state\.tab === "goals" \? "0" : "-1"\}/);
});

test("Goal Space explicit transitions provide stable focus targets without refocusing after async reads", () => {
  for (const key of [
    "goal-text",
    "goal-review-heading",
    "goal-detail-heading",
    "room-detail-heading",
    "goal-tab-goals",
    "goal-tab-rooms",
  ]) {
    assert.match(goalSpace, new RegExp(`data-focus-key="${key}"`));
  }
  assert.doesNotMatch(goalSpace, /detail\.loading = false;\s*draw\("/);
  assert.match(goalSpace, /detail\.loading = false;\s*draw\(\)/);
});

test("detail reads are generation-bound and stale responses cannot replace newer navigation", () => {
  assert.match(goalSpace, /const sequence = \+\+state\.detailRequestSequence;/);
  assert.match(goalSpace, /navigation !== state\.navigationSequence/);
  assert.match(goalSpace, /state\.detailGoal !== detail/);
  assert.match(goalSpace, /state\.detailRoom !== detail/);
  assert.match(goalSpace, /const navigation = \+\+state\.navigationSequence;/);
  assert.match(shell, /if \(appState\.currentView === "goals"\) suspendGoalSpaceRequests\(\);/);
  assert.match(goalSpace, /sequence !== state\.activationRequestSequence[\s\S]*?appState\.currentView !== "goals"/);
});

test("Goal Space shows loading and endpoint-specific failures instead of false empty truth", () => {
  assert.match(goalSpace, /GoalRuns could not be loaded/);
  assert.match(goalSpace, /OutcomeRooms could not be loaded/);
  assert.match(goalSpace, /GoalRun events could not be loaded/);
  assert.match(goalSpace, /Loading GoalRun owner truth/);
  assert.match(goalSpace, /Loading OutcomeRoom projections/);
});

test("receipt and result evidence reads only the canonical GoalRun arrays", () => {
  assert.match(goalSpace, /canonicalRefs\(run, "receipt_refs", "receipt"\)/);
  assert.match(goalSpace, /canonicalRefs\(run, "work_result_refs", "work-result"\)/);
  assert.doesNotMatch(goalSpace, /collectNamedRefs/);
});

test("one principal recovery slot is resumed instead of overwritten", () => {
  assert.match(goalSpace, /const retained = readRecovery\(principal\);/);
  assert.match(goalSpace, /await resumeActivation\(retained\);/);
  assert.match(goalSpace, /already occupies this principal's recovery slot/);
});

test("signout and principal changes zeroize Goal Space state", () => {
  assert.match(shell, /clearPrincipalState\(principal\);[\s\S]*?appState\.me = null/);
  assert.match(shell, /appState\.me\.user !== nextMe\.user\)[\s\S]*?clearPrincipalState\(appState\.me\.user\)/);
  assert.match(
    shell,
    /if \(r\.status === 401\)[\s\S]*?clearPrincipalState\(appState\.me\?\.user \?\? null\);[\s\S]*?appState\.me = null/,
  );
  for (const reset of [
    "resetSessionsState",
    "resetCronsState",
    "resetFilesState",
    "resetDeploysState",
    "resetSkillsState",
    "resetMemoryState",
    "resetContextsState",
    "resetKeychainState",
    "resetGoalSpaceState",
  ])
    assert.match(shell, new RegExp(`${reset}\\(`));
  assert.match(shell, /advanceIdentityEpoch\(\)/);
  assert.match(shell, /clearAllDrafts\(\)/);
  assert.match(shell, /mainConversation\(\)\.resetChatState\(\)/);
  assert.match(goalSpace, /if \(state\.activation\) state\.activation\.grantText = "";/);
});

test("cross-view popstate routes the parsed target instead of requiring the current view to match", () => {
  assert.match(shell, /const target = isView\(view\) \? view : "chats";/);
  assert.match(shell, /switchView\(target, item, true\);/);
  assert.match(shell, /addEventListener\("popstate", \(\) => void routeShellHistory\(\)\)/);
  assert.match(shell, /switchView\(view, null, false, true\);/);
  assert.match(shell, /if \(push\) history\.pushState\(null, "", next\);/);
  assert.doesNotMatch(shell, /appState\.currentView === "goals" && view === "goals"/);
});

test("activation review renders the admitted execution ceiling rather than a local constant", () => {
  assert.match(goalSpace, /numberAt\(ceiling, "max_total_invocations"\)/);
  assert.match(goalSpace, /numberAt\(ceiling, "max_parallel_invocations"\)/);
  assert.doesNotMatch(goalSpace, /0 total · 0 parallel for the current Goal Chat profile/);
});

test("Goal Space exposes real daemon-owned GoalRun and OutcomeRoom mutations without fake completion", () => {
  for (const key of [
    "goal-run-create",
    "goal-start",
    "goal-reconcile",
    "outcome-room-create",
    "room-membership",
  ])
    assert.match(goalSpace, new RegExp(`data-focus-key=(?:"${key}"|\\$\\{[^}]*"${key}"[^}]*\\})`));
  assert.match(goalSpace, /validateGoalRunStart/);
  assert.match(goalSpace, /validateGoalRunReconcile/);
  assert.match(goalSpace, /validateOutcomeRoomCreate/);
  assert.match(goalSpace, /validateOutcomeRoomMembership/);
  assert.match(goalSpace, /outcome_room_v2_lifecycle_transition_unavailable/);
  assert.doesNotMatch(goalSpace, /HarnessInvocation route is not registered/);
  assert.match(goalSpace, /result is uncertain\. Reload owner truth before retrying/);
  assert.match(goalSpace, /Room membership result is uncertain\. Reload owner truth/);
  assert.match(goalSpace, /mutation\?\.uncertain === true/);
});
