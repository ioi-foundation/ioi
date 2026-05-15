# Browser Use Master Guide

Owner: agent runtime / browser driver / computer-use harness / Autopilot GUI

Status: active next-leg master guide

Created: 2026-05-07

Promoted: 2026-05-14

Related:

- `docs/plans/agent-runtime-harness-as-workflow-master-guide.md`
- `docs/plans/computer-use-browser-use-next-leg-meta-master-guide.md`
- `docs/plans/cua-parity-plus-computer-use-master-guide.md`
- `docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`
- `crates/drivers/README.md`
- `crates/drivers/src/browser/README.md`
- `crates/drivers/src/gui/README.md`
- `docs/plans/agent-tool-vocabulary-v2.md`
- `docs/computer-use-autonomy-prompt.md`

## Executive Verdict

IOI already has the core ingredients for a serious browser/computer-use harness:

- a native Rust browser driver built on Chrome DevTools Protocol via
  `chromiumoxide`;
- Browser-use and BrowserGym-style observations, including selector maps,
  DOM/AX snapshots, page metadata, pending requests, recent browser events,
  focused BrowserGym ids, markdown, HTML, and pagination context;
- screenshot plus Set-of-Marks visual grounding for both browser and desktop
  GUI control;
- browser runtime tools with grounded ids, ordered clicks, coordinate guards,
  scroll, type, key, select, upload, tabs, screenshots, wait, copy/paste, and
  find-text operations;
- desktop GUI fallback using screenshots, accessibility trees, and injected
  input.

The gap is not "we need browser control from scratch." The gap is that our
browser control is mostly shaped around an IOI-owned hermetic browser session.
The workflow we just used with an already-open authenticated Chrome instance
required manual glue: process discovery, CDP attach attempts, a controlled
Chrome relaunch with a non-default profile, user reauthentication, ad hoc
Playwright install, screenshot/evidence harvesting, and manual cleanup.

The target state is a first-class Browser Use Harness: a workflow-addressable
set of nodes that can choose between owned browser, CDP-attached browser,
controlled relaunch, and visual/OS fallback, while preserving consent,
grounding, receipts, redaction, and cleanup.

This guide is now the active first lane for the broader computer-use leg. The
browser lane ships first because IOI already has strong native CDP, DOM, AX,
BrowserGym, Browser-use, screenshot, and Set-of-Marks substrate. The same
contracts must later generalize to visual GUI and sandboxed/hosted computer
lanes without creating a second runtime.

## Active Next-Leg Scope

Browser use is the first concrete implementation lane inside a three-lane
computer-use harness family:

| Lane | Purpose | Default substrate |
| --- | --- | --- |
| Native Browser Use | Web automation, authenticated web app inspection, DOM/AX-rich workflows, browser benchmarks | Owned or attached Chromium through IOI's native CDP driver |
| Computer Use / Visual GUI | Arbitrary desktop apps, canvas apps, native apps, non-DOM browser surfaces, semantic fallback | Screenshot, accessibility tree, Set-of-Marks, coordinate-space guards |
| Sandboxed / Hosted Computer | Risk isolation, reproducible evals, training trajectories, team/hosted workers, mobile/device workflows | VM, container, hosted browser, hosted computer, or device adapter |

All three lanes must share IOI runtime truth:

- no second runtime;
- no React Flow shadow truth store;
- daemon/runtime contracts first;
- browser, GUI, sandbox, model, workflow, and Autopilot surfaces consume the
  same observations, target indexes, action proposals, actions, receipts,
  trajectories, policies, artifacts, and manifests.

## Current Implementation Snapshot

| Slice | Status | Regression guard |
| --- | --- | --- |
| Guide promotion | Done | `docs/plans/browser-use-master-guide.md` is active and linked to the meta/CUA guides. |
| Contract spine | Done | `cargo test -p ioi-types --lib` covers the Rust runtime contracts; `npm --prefix packages/agent-sdk test` covers SDK contract projection. |
| Owned browser adapter projection | Done | `cargo test -p ioi-drivers browser::computer_use --lib` covers owned-browser lease, adapter, and observation projection. |
| SDK/runtime trace projection | Done | `packages/agent-sdk/test/computer-use.test.mjs` asserts browser prompts emit environment selection, run state, observation, target index, affordance, action proposal, verification, receipt, and runtime event projections. |
| Daemon planner/executor | Pending | Next slice should move the SDK trace shape into daemon-owned planner and execution events. |
| Autopilot workbench | Pending | UI should consume the new runtime event payloads instead of inventing a separate trace channel. |

## Behavioral Control Layer

The browser lane must be more than a screenshot-to-click loop. The canonical
behavioral loop is:

```text
classify_intent
-> select_environment
-> acquire_lease
-> observe
-> build_target_index
-> build_affordance_graph
-> plan_next_step
-> propose_action
-> policy/risk_gate
-> execute_action
-> verify_postcondition
-> repair_or_continue
-> commit_or_handoff
-> write_trajectory
-> cleanup
```

The first implementation slice should establish these shared contracts:

- `ComputerUseLease`;
- `ComputerControlAdapterContract`;
- `ComputerUseObservationBundle`;
- `TargetIndex`;
- `AffordanceGraph`;
- `ActionProposal`;
- `ComputerAction`;
- `ActionReceipt`;
- `ComputerUseVerificationReceipt`;
- `ComputerUseTrajectoryBundle`;
- `CleanupReceipt`;
- `ComputerUseRunState`;
- `EnvironmentSelectionReceipt`;
- `RecoveryPolicy`;
- `HumanHandoffState`;
- `InterfacePatternIndex`;
- `OutcomeContract`;
- `CommitGate`;
- `ObservationRetentionMode`.

Provider/model outputs must become `ActionProposal` records before executable
`ComputerAction` records. Coordinates must be observation-bound. External-effect
final steps must pass through `CommitGate` when policy requires it.

## Why This Exists

The Palantir AIP exploration was useful because it was exactly the kind of
real-world browser task a user will expect:

1. Use the browser session the user already has open.
2. Preserve or recover authentication when possible.
3. Inspect a rich enterprise GUI, not a simple static page.
4. Move between screenshots, URL state, panels, right rails, tables, and graph
   views.
5. Capture evidence that can be turned into product requirements later.
6. Clean up temporary profiles, screenshots, helper scripts, and browser
   processes afterward.

That workflow should become normal substrate behavior, not a heroic one-off.

The lesson is simple: browser use must be a real harness lane, not just a tool
name. It needs discovery, consent, session brokerage, multimodal observation,
safe action execution, verification, evidence writing, and cleanup as explicit
runtime components.

## Current Repo Truth

### Native Browser Driver

The primary browser driver lives under `crates/drivers/src/browser`. It is
built on `chromiumoxide`, launches Chromium through CDP, and manages a browser
session, active page, retrieval page, profile directory, pointer state, recent
browser events, dialog handling, accessibility snapshots, and browser-use
artifacts.

Important current properties:

- launches a hermetic Chromium session by default;
- uses session-scoped profile directories under `ioi-data/browser_profiles`;
- supports a persistent profile with `IOI_BROWSER_PERSIST_PROFILE`;
- fetches and pins Chromium into `ioi-data/browser_cache`;
- exposes a debugger websocket URL for owned sessions;
- uses launch retries and headless fallback when headed startup fails;
- forces renderer accessibility and a stable viewport;
- attaches browser-use page watchdogs after navigation/page creation;
- cleans profile directories unless persistence is explicitly enabled.

This is the right foundation for deterministic benchmark and runtime work.
It is not yet a complete answer for taking over a user's currently open browser
window.

### Browser-use Observation Layer

The browser observation surface is already rich. `BrowserObservationArtifacts`
tracks:

- Browser-use state text;
- Browser-use selector map text;
- Browser-use HTML, eval, and markdown text;
- Browser-use pagination, tabs, page info, pending requests, recent events, and
  closed popup messages;
- BrowserGym extra properties;
- focused BrowserGym bid;
- BrowserGym DOM and AX tree text.

`browser__inspect` appends these sections to the accessibility XML when
available. That means the runtime already understands the browser as more than
pixels. It has DOM, AX, event, selector, page-state, and screenshot evidence in
one prompt-facing observation.

### BrowserGym / Set-of-Marks

The browser driver includes BrowserGym-style DOM marking:

- `bid` attributes for BrowserGym ids;
- visibility metadata;
- set-of-marks metadata;
- focused-bid extraction;
- DOM snapshot flattening;
- AX tree flattening;
- cleanup after marking.

Separately, the GUI driver has Set-of-Marks screenshot overlays. Interactive
elements are boxed and tagged with numeric ids, and the id-to-rectangle mapping
is registered so actions can resolve visual ids back into coordinates.

This means IOI already has both:

- semantic browser ids from DOM/AX/CDP;
- visual SoM ids from screenshots.

The ideal browser-use harness should fuse them instead of choosing one as the
only truth.

### Runtime Browser Tools

The V2 browser tool vocabulary is already mostly aligned with a browser-use
harness:

- `browser__inspect`;
- `browser__click`;
- `browser__click_at`;
- `browser__hover`;
- `browser__move_pointer`;
- `browser__pointer_down`;
- `browser__pointer_up`;
- `browser__scroll`;
- `browser__type`;
- `browser__select`;
- `browser__press_key`;
- `browser__copy`;
- `browser__paste`;
- `browser__find_text`;
- `browser__screenshot`;
- `browser__wait`;
- `browser__upload`;
- `browser__list_options`;
- `browser__select_option`;
- `browser__back`;
- `browser__list_tabs`;
- `browser__switch_tab`;
- `browser__close_tab`;
- `browser__subagent`.

The important design choice is already present: coordinate-style actions must
be grounded by observation refs, coordinate space ids, and semantic ids. The
harness explicitly rejects guessed raw coordinates.

The click path is also stronger than a naive "click selector" implementation.
It can try selector-grounded dispatch, safe inset geometry, postcondition
verification, fallback attempts, and structured failure receipts.

### Desktop Computer-use Layer

The GUI layer under `crates/drivers/src/gui` supplies the broader computer-use
substrate:

- screenshot capture;
- raw screen capture;
- accessibility tree capture;
- SoM overlays;
- sensitive-region redaction;
- input injection;
- element-center resolution;
- visual grounding cache.

The service runtime already distinguishes browser-semantic mode from broader
foreground/background visual modes. Browser semantic mode prefers
`browser__inspect` and browser ids; visual mode uses screenshot SoM as the
primary grounding surface.

### Playwright Today

Playwright is not the default live browser-control substrate in this repo.

Current truth:

- the main runtime browser driver is Rust CDP via `chromiumoxide`;
- the regular JS app dependencies do not include Playwright as a core runtime
  browser controller;
- `tools/browsergym/workarena_cdp_bridge.py` uses Python Playwright to connect
  over CDP to an existing BrowserDriver session for WorkArena setup and
  validation;
- one test fixture mentions a Playwright-flavored web backend string, but that
  is not the native browser harness.

In the Palantir pass, Playwright was installed outside the repo in `/tmp` as an
operator convenience. That was appropriate for exploration, but it should become
a productized adapter or remain an external debug tool. The core runtime should
not silently shift from `chromiumoxide` to Playwright without a typed adapter
boundary.

## What We Improvised

The live browser pass exposed the missing harness choreography:

1. Discovered the user's open Chrome instance and target page.
2. Tried CDP attach.
3. Hit Chrome's default-profile remote-debugging restriction.
4. Relaunched Chrome under a non-default controlled profile with CDP.
5. Recovered the target Palantir URL from local browser history.
6. Let the user reauthenticate when the copied/controlled profile could not
   preserve the session.
7. Attached a Playwright CDP client to inspect the page.
8. Captured screenshots and observations.
9. Converted the useful UI mechanics into guide evidence.
10. Deleted temporary screenshots, JSON, browser profile copies, and helper
    artifacts.
11. Closed the controlled browser process.

None of those steps are exotic. They are the expected path for real browser
computer use against authenticated enterprise tools. Today they require
operator judgment. The target harness should encode that judgment.

## Target Browser Use Harness

The target is a first-class harness that can run as workflow nodes and produce
receipted browser-control evidence.

### Core Principle

Browser use is a session lifecycle, not a single action primitive.

Every browser-use run should carry:

- user consent scope;
- target application or URL;
- session mode;
- profile provenance;
- observation bundle;
- action log;
- verification log;
- redaction policy;
- cleanup policy;
- retained evidence refs.

### Session Modes

The harness should support four modes:

| Mode | Purpose | Primary mechanism | Risk posture |
| --- | --- | --- | --- |
| Owned hermetic browser | Deterministic automation, tests, web tasks, benchmarks | IOI-launched Chromium via `chromiumoxide` CDP | Lowest ambiguity |
| Attached browser | Use an already-running browser that exposes CDP | CDP attach to discovered endpoint | Requires explicit consent and provenance |
| Controlled relaunch | Continue a user's flow when default Chrome cannot expose CDP | Relaunch with non-default profile, target URL recovery, user reauth handoff | Medium; must be transparent |
| Visual/OS fallback | Operate when DOM/CDP is unavailable or insufficient | screenshot, AX tree, SoM, OS input | Highest care; visual drift guards required |

Owned browser remains the default for autonomous web tasks. Attached or
controlled browser modes are user-assisted modes for tasks where authentication
or existing context matters.

### Component Nodes

Browser-use should become an explicit graph of workflow-addressable components:

| Component | Responsibility |
| --- | --- |
| Browser intent classifier | Decide whether the task needs browser use, web retrieval, visual GUI control, or direct answer. |
| Consent gate | Record whether the user allows attach, controlled relaunch, profile copy, credential-adjacent handling, or only read-only inspection. |
| Browser discovery | Enumerate visible browser windows, processes, tabs, URLs, CDP endpoints, profile paths, and browser family. |
| Target resolver | Match the user's requested site/app/page to an open tab, history entry, URL, or launch target. |
| Session strategy selector | Choose owned, attached, controlled relaunch, or visual fallback mode. |
| Profile broker | Create, copy, isolate, persist, or delete profile directories under policy. |
| Auth handoff | Detect auth walls and pause for the user to reauthenticate without harvesting credentials. |
| CDP connector | Attach to or launch a browser session and expose a normalized browser-control handle. |
| Observation capture | Produce screenshot, SoM overlay, AX tree, DOM snapshot, selector map, browser-use state, page info, tabs, pending requests, and recent events. |
| DOM/AX/SoM fusion | Map BrowserGym bids, semantic ids, selectors, AX nodes, screenshot marks, and coordinates into one target index. |
| Safe action executor | Execute click, hover, drag, scroll, type, key, upload, dropdown, tab, and wait actions with grounding checks. |
| Visual drift guard | Abort or reobserve when screenshot/DOM/AX changes invalidate the target. |
| Post-action verifier | Check URL, title, focus, DOM/AX, visible state, network quiescence, and expected postconditions. |
| Evidence writer | Persist redacted screenshots, observation text, action receipts, and summaries. |
| Cleanup manager | Stop controlled processes, delete temporary profiles, delete scratch screenshots, and record retained artifacts. |

These nodes should be usable directly in the default agent harness workflow and
projected through React Flow as configurable primitives, not as a parallel
runtime state store.

## Ideal Browser Control Workflow

### 1. Establish Scope

Before touching a user browser, the runtime should classify the request:

- read-only inspection;
- form filling;
- authenticated app navigation;
- file upload/download;
- account or billing action;
- admin/destructive action;
- credential or secret-adjacent page.

The harness should then choose the minimum authority and ask for user assistance
only when the action class requires it.

### 2. Discover Browser State

Discovery should collect:

- browser processes;
- active browser windows;
- browser family and packaging mode, such as Flatpak, system Chrome, Chromium,
  Brave, Edge, Safari, Firefox;
- CDP endpoints if already exposed;
- active tab URL/title when available;
- recent history entries when permitted;
- default-profile remote-debugging blockers;
- Wayland/X11/macOS/Windows accessibility availability.

Discovery must be read-only and receipted.

### 3. Choose Attach Strategy

The strategy selector should prefer:

1. Existing CDP endpoint if present and consented.
2. Owned hermetic browser for tasks that do not require user-authenticated
   state.
3. Controlled relaunch with a non-default profile when the user explicitly
   allows disruption and reauthentication.
4. Visual/OS fallback for apps or browser surfaces that cannot expose DOM/CDP.

The harness should surface why it chose a mode. For example:

```text
Chrome default profile refused remote debugging. Using controlled relaunch with
a new temporary profile and asking for user reauthentication.
```

### 4. Recover Target Context

If an existing browser cannot be attached directly, the harness should be able
to recover context without guesswork:

- current URL from tab metadata when available;
- recent history URL matching the user-visible page;
- copied address bar text only with user-approved OS interaction;
- screenshot OCR or AX tree title as a fallback;
- user-provided URL if recovery is blocked.

The recovery method should be in the receipt.

### 5. Capture Unified Observation

The observation bundle should include:

- raw screenshot;
- SoM screenshot;
- browser viewport and coordinate transform;
- accessibility XML;
- Browser-use selector map;
- Browser-use page info and pagination;
- Browser-use tabs;
- Browser-use pending requests;
- Browser-use recent events and popup messages;
- BrowserGym focused bid, DOM text, AX tree text, and extra properties;
- compact page markdown and/or visible text;
- redaction report.

The prompt-facing summary can be compact, but the evidence bundle should retain
the raw artifacts according to policy.

### 6. Act Through the Least Ambiguous Target

Target preference should be:

1. Browser semantic id or BrowserGym bid.
2. SoM id mapped to a semantic target.
3. Stable selector from the current observation.
4. Grounded coordinate with observation ref, coordinate space id, semantic id,
   and post-action reobserve.
5. OS-level input only when browser-level control is unavailable.

Raw coordinates without observation grounding should remain invalid.

### 7. Verify Every Material Action

Verification should be explicit after actions that change state:

- did focus move to the intended field?
- did the URL/title change?
- did the target disappear, expand, collapse, or become selected?
- did visible text or table rows change?
- did a pending request complete?
- did a modal appear?
- did the browser session remain healthy?
- did any challenge or auth wall appear?

The result should be a small postcondition receipt, not a wall of raw logs.

### 8. Preserve Evidence

Browser-use evidence should be saved as a small bundle:

```text
docs/evidence/browser-use/<run-id>/
  README.md
  observations/
  screenshots/
  receipts/
  cleanup.json
```

For user-private browser sessions, the default should be redacted summaries with
raw artifacts either omitted, locally retained, or explicitly user-approved.

### 9. Cleanup

Cleanup is part of the harness, not operator courtesy.

The cleanup manager should:

- close controlled browser processes;
- detach from CDP without closing user-owned browsers unless explicitly
  launched by the harness;
- delete temporary profiles and profile copies;
- delete scratch screenshots and JSON files;
- record retained evidence paths;
- report cleanup failures as warnings with paths and process ids.

## Gaps To Close

### Gap 1: User Browser Attach Is Not First-class

Current owned browser support is strong. What is missing is a formal
user-browser session lease that can attach to or safely relaunch a user's
already-open browser.

Needed:

- browser process/window inventory;
- CDP endpoint discovery;
- browser-family-specific attach guidance;
- consented relaunch;
- authenticated-session handoff;
- no-surprise close/detach behavior.

### Gap 2: Profile Brokerage Is Too Implicit

The browser driver already creates and cleans profile dirs. The future harness
needs a visible profile broker:

- temporary empty profile;
- persistent IOI profile;
- copied user profile;
- no-profile attach;
- retain/delete decision;
- provenance receipt.

Copied user profiles are credential-adjacent and must be exceptional,
consented, local-only, and aggressively cleaned unless the user opts otherwise.

### Gap 3: Playwright Exists Only As A Side Bridge

The repo has a WorkArena bridge that uses Python Playwright to connect over CDP,
but Playwright is not a general runtime browser-control adapter.

Recommendation:

- keep `chromiumoxide` as the native browser driver;
- introduce a `ComputerControlAdapterContract` boundary;
- allow a Playwright-backed adapter for benchmarks, external app exploration,
  and rapid dogfood where it adds leverage;
- require all adapters to emit the same observation, action, verification, and
  evidence contracts.

The question should not be "Playwright or Rust CDP?" It should be "which adapter
implements the same browser-use contract for this run?"

### Gap 4: Observation Fusion Needs A First-class Target Index

We have DOM ids, selectors, AX nodes, BrowserGym bids, SoM ids, and coordinates.
The harness needs one target index that can explain:

- what the element is;
- how it was observed;
- which ids point to it;
- which action paths are available;
- whether it moved or changed since observation;
- why a chosen action is safe.

### Gap 5: Enterprise GUI Mechanics Need Better Workbench Support

The AIP pass showed why browser-use is not just page automation. The target app
had:

- graph canvas;
- right rail;
- bottom table/workbench;
- mini graph;
- expandable groups;
- toolbar modes;
- warnings;
- read-only posture;
- output inventory;
- URL-addressable focus state.

The browser-use harness should know how to persist and inspect this shape:
canvas observation, right rail state, bottom workbench state, selected node,
expanded group path, and table preview state.

### Gap 6: Evidence Bundles Are Not Productized For Browser Sessions

We can write docs evidence manually, and runtime evidence exists elsewhere, but
browser session evidence should be a standard artifact family with redaction,
retention, and cleanup policy.

### Gap 7: Auth Handoff Is Manual

The harness needs an auth wall state:

```text
blocked: auth_required
user_action: reauthenticate in controlled browser
resume_condition: page url/title/body no longer matches login wall
```

The agent should not ask for credentials. It should pause, let the user operate
the browser, then resume after observation verifies that authentication
completed.

## Product UX Requirements

A browser-use run should be visible to users in Autopilot:

- current browser session mode;
- attached/owned/visual fallback badge;
- active tab title and domain;
- consent scope;
- read-only vs action-capable posture;
- observation freshness;
- selected target details;
- action receipts;
- cleanup state.

For complex browser apps, the GUI should expose:

- main screenshot/SoM view;
- DOM/AX/selector target list;
- right rail of page structure, outputs, receipts, warnings, and tabs;
- mini map or page-map for large canvases;
- bottom workbench for tables/forms/logs;
- evidence bundle link;
- "pause for user" and "resume after auth" controls.

This should feel like browser control, not hidden automation.

## Policy And Safety

Browser-use policy must be stricter than ordinary web read:

- no credential exfiltration;
- no hidden profile copying;
- no unsignaled relaunch of user browsers;
- no destructive admin/account/billing action without explicit approval;
- no raw coordinate action without observation grounding;
- no file upload/download without a file/path receipt;
- no persistence of private screenshots unless retention is explicit;
- no attempt to defeat bot, abuse, or access controls;
- no automated completion of sensitive auth steps.

When a site shows a human challenge or login wall, the harness should report the
state and pause for user assistance.

## Workflow Integration

The browser-use harness should eventually become a reusable subgraph inside the
default agent harness:

```text
intent -> browser consent gate -> session strategy -> observation capture
       -> target resolver -> action executor -> verifier -> evidence writer
       -> cleanup
```

This aligns with the harness-as-workflow master guide:

- every browser-use decision becomes a workflow-addressable node;
- every action has an evidence edge;
- users can fork browser-use strategy for their own workers;
- the default agent dogfoods the same browser-use substrate users can inspect.

This is now the active leg. The implementation should start with the shared
contract spine, then map the existing owned browser path into it without
changing browser behavior.

## Implementation Phases

### Phase 0: Promotion And Contract Spine

Goal: promote this guide, freeze current truth, and define the common
computer-use/browser-use contract spine.

Deliverables:

- active next-leg guide status;
- related meta and CUA parity-plus guide links;
- `ComputerUseLease` data model;
- `ComputerControlAdapterContract` boundary;
- lane and session mode enums;
- observation bundle schema;
- target index schema;
- affordance graph schema;
- action proposal schema;
- executable action and receipt schemas;
- verification receipt schema;
- trajectory bundle schema;
- cleanup receipt schema;
- run state, environment selection, recovery, handoff, outcome, commit, and
  retention contracts.

Acceptance:

- owned browser path can emit or be wrapped by the new schemas without behavior
  change;
- provider/model outputs pass through `ActionProposal` before execution;
- coordinates are invalid without observation grounding;
- commit gates exist for consequential external-effect actions;
- docs clearly say Playwright is optional adapter, not core replacement.

### Phase 1: Environment Planner And Run State

Goal: make lane/session selection explainable and replayable.

Deliverables:

- intent classifier;
- environment planner;
- `EnvironmentSelectionReceipt`;
- `ComputerUseRunState`;
- read-only vs action-capable posture;
- retention policy selection;
- structured rejected-option reasons.

Acceptance:

- runs can explain selected and rejected lane/session modes;
- missing sandbox or hosted providers fail closed;
- user browser attach/relaunch never happens without explicit authority.

### Phase 2: User Browser Discovery

Goal: make discovery first-class and read-only.

Deliverables:

- browser window/process inventory;
- CDP endpoint detection;
- target tab/title/domain detection where available;
- browser-family and packaging metadata;
- default-profile CDP refusal detection;
- discovery receipt.

Acceptance:

- discovery never mutates browser state;
- Linux Flatpak/system Chrome differences are recorded;
- no credentials or cookies are copied.

### Phase 3: Attach And Controlled Relaunch

Goal: productize the workflow we used manually.

Deliverables:

- attach to existing CDP endpoint;
- controlled relaunch with non-default profile;
- target URL recovery from consented sources;
- user auth handoff state;
- controlled process cleanup.

Acceptance:

- default-profile Chrome remote-debugging refusal becomes a structured branch;
- user can reauthenticate and the harness resumes;
- cleanup removes temporary profiles and reports retained evidence.

### Phase 4: Unified Observation Bundle

Goal: fuse browser and visual observations.

Deliverables:

- screenshot plus SoM;
- DOM/AX/BrowserGym capture;
- selector map;
- page info;
- tabs;
- pending requests;
- recent events;
- right-rail/bottom-workbench/canvas hints when detectable;
- redaction summary.

Acceptance:

- one observation ref can ground semantic ids, SoM ids, and coordinates;
- prompt-facing observation stays compact;
- raw evidence follows retention policy.

### Phase 5: Target Index And Affordance Graph

Goal: make action choice explainable before execution.

Deliverables:

- DOM/AX/BrowserGym/SoM target index;
- interface pattern hints;
- affordance graph;
- action confidence;
- action preconditions;
- expected transitions;
- risk class;
- fallback action paths.

Acceptance:

- the runtime can explain what each target is and what can safely be done with
  it;
- action proposals cite target refs and expected postconditions;
- stale observations invalidate affected affordances.

### Phase 6: Safe Action Executor

Goal: normalize action execution across adapters.

Deliverables:

- selector/BID/SoM/coordinate target dispatch;
- drag and hover flows;
- table/canvas-safe actions;
- action preconditions;
- post-action verification;
- structured no-effect and target-not-found failures.

Acceptance:

- no guessed raw coordinates;
- visible-control follow-ups require reobservation when geometry changed;
- failed actions explain what was tried and what to do next.

### Phase 7: Recovery, Handoff, Outcome, And Commit Gates

Goal: turn failures and sensitive final steps into structured runtime states.

Deliverables:

- `RecoveryPolicy`;
- failure classes for perception, grounding, planning, policy, execution,
  verification, and environment;
- `HumanHandoffState`;
- auth/challenge/user-correction resume states;
- `OutcomeContract`;
- `CommitGate`.

Acceptance:

- auth walls pause for user action and resume only after observation;
- no-effect actions reobserve before retry;
- external-effect final actions can be staged before commit.

### Phase 8: Browser-use GUI Workbench

Goal: make browser-control state legible in Autopilot.

Deliverables:

- session mode badge;
- active tab/domain;
- consent scope;
- target index inspector;
- screenshot/SoM viewer;
- DOM/AX/selector tabs;
- evidence/receipt rail;
- auth handoff controls;
- cleanup status.

Acceptance:

- users can understand what browser the agent controls;
- users can pause/resume auth handoff;
- screenshots and target ids map visibly to actions.

### Phase 9: Harness Graph Dogfood

Goal: run browser-use as workflow nodes.

Deliverables:

- browser-use subgraph package;
- retained browser-control scenarios;
- attach/relaunch/fallback fixtures;
- evidence bundle comparison;
- forkable browser-use worker template.

Acceptance:

- a worker can fork the browser-use subgraph;
- default agent browser tasks produce node-addressed receipts;
- attached browser mode and owned browser mode share the same action contract.

### Phase 10: Trajectory Learning And Regression

Goal: use browser-use trajectories to improve the harness without benchmark
overfitting.

Deliverables:

- trajectory bundle writer;
- failure taxonomy summaries;
- shadow replay fixtures;
- held-out eval promotion gate;
- regression tests for model action adapters.

Acceptance:

- trajectory evidence supports debugging and improvement proposals;
- accepted harness changes require held-out validation;
- generated evidence remains ignored or policy-retained.

## Test Matrix

Minimum test coverage:

| Area | Scenario |
| --- | --- |
| Owned browser | Launch, inspect, click, type, scroll, wait, screenshot, close. |
| CDP attach | Connect to existing debug endpoint and inspect open tab. |
| Default-profile refusal | Detect Chrome refusal and branch to controlled relaunch guidance. |
| Controlled relaunch | Launch non-default profile, restore URL, pause for auth, resume. |
| Profile cleanup | Temporary profile and scratch artifacts are removed. |
| BrowserGym | Bids appear in DOM/AX observations and clean up after capture. |
| SoM fusion | Screenshot ids map to semantic targets and coordinate transforms. |
| Visual fallback | Browser unavailable path uses screen/AX/SoM safely. |
| No guessed coords | Raw coordinate browser actions require observation grounding. |
| Auth handoff | Login wall pauses without asking for secrets. |
| Evidence | Observation, action, verification, and cleanup receipts are written. |
| Enterprise GUI | Graph canvas, rail, bottom panel, table, and expanded group states remain inspectable. |

Existing tests already cover pieces of this under browser runtime, reliability,
and computer-use suites. The new work should add attach/relaunch and evidence
bundle tests rather than duplicating the owned-browser smoke tests.

## Later Decisions

Open decisions for this browser-use leg:

- Should Playwright be a production adapter, a benchmark-only adapter, or a
  developer debug adapter?
- How much browser history discovery is acceptable by default?
- Should controlled relaunch ever copy a user profile, or should it always use
  empty temporary profiles plus user reauth?
- How should we expose browser session consent in the Autopilot UI?
- What raw artifacts are retained by default for private browser sessions?
- Which enterprise GUI patterns deserve first-class inspectors: graph, table,
  right rail, modal stack, canvas, iframe, or shadow DOM?

## Definition Of Done

The browser-use harness leg is complete when:

- browser sessions are leased, not improvised;
- attach, owned, controlled relaunch, and visual fallback modes share one
  observation/action/evidence contract;
- durable run state, environment selection receipts, target indexes,
  affordance graphs, action proposals, recovery policies, handoff states,
  outcome contracts, commit gates, and retention modes exist in the canonical
  runtime contract spine;
- user authentication handoff is explicit and credential-safe;
- screenshots, SoM, DOM, AX, BrowserGym ids, selectors, and coordinates resolve
  through one target index;
- every material action has a postcondition receipt;
- temporary profiles and scratch artifacts are cleaned automatically;
- Autopilot shows users which browser/session is controlled and why;
- the default agent can run browser-use through workflow nodes that users can
  inspect, fork, and modify.

The north star is not "use Playwright" or "use screenshots." The north star is a
browser-control harness that can fluidly choose the right mechanism while
remaining grounded, visible, receipted, and forkable.
