# developers.ioi.ai Ship-Shape Master Guide

Owner: developer experience / docs / Autopilot / SDK / daemon runtime / product surfaces

Status: planning guide for live-readiness implementation

Created: 2026-05-16

## Executive Verdict

`developers.ioi.ai` should ship as the curated builder front door for IOI. It
should not become the canonical protocol reference, the node/operator manual, or
the place where generated markdown reference from the repo is duplicated.

The site should answer:

> What can I build with IOI, what can I run today, and where do I go next?

The app can and should preserve future product shapes, but every future-facing
claim needs status framing. Current repo-backed surfaces should be prominent:
runtime daemon, `@ioi/agent-sdk`, Autopilot, CLI, model mounting, MCP/tools,
memory, subagents, usage/telemetry, benchmarks, and the product preview paths
for `sas.xyz` and `aiagent.xyz`.

The practical live-readiness move is:

> Replace canonical-reference-heavy docs IA with builder-job IA, keep a small
> canonical-docs handoff, make current-vs-preview status explicit, and support
> real visual documentation with retained Autopilot GUI screenshots.

## Current Implementation Read

The current app is a useful docs shell, but it is still scaffold-shaped.

Observed implementation facts:

- `apps/developers-ioi-ai/src/content/docs.tsx` owns the page catalog, status
  labels, sources, canonical links, and body content.
- `apps/developers-ioi-ai/src/App.tsx` routes by hash fragment, not durable
  product paths such as `/quickstart` or `/sdks`.
- `apps/developers-ioi-ai/src/components/Header.tsx` builds the top nav from
  `DOC_SECTIONS`, shows the first three pages per section, and includes a
  standalone `Canonical docs` outbound link.
- `apps/developers-ioi-ai/src/components/Sidebar.tsx` is docs-navigation
  oriented and includes a canonical protocol docs handoff.
- `apps/developers-ioi-ai/README.md` already states the correct separation of
  concerns: this app is curated DX; `docs.ioi.network` owns canonical technical
  reference.
- The repo has a substantial daemon and SDK implementation, but also many
  future/product-preview surfaces. The developer app needs to show both without
  flattening their maturity.

Strong current repo-backed surfaces:

- `packages/runtime-daemon`: local runtime daemon, Agentgres v0 store, public
  runtime API, model mounting, OpenAI-compatible endpoints, memory, MCP,
  subagents, usage telemetry, computer-use, workspace restore, and receipts.
- `packages/agent-sdk`: daemon-backed default client, explicit mock/testing
  client, typed agents/runs/threads/tools/memory/MCP/subagent/computer-use
  helpers.
- `crates/cli`: project scaffolding, node/devnet, model mounting, routes,
  vault, receipts, agent, trace, verify, policy, MCP, PII, and developer tools.
- `crates/services/src/agentic/runtime`: Rust runtime service with durable
  session lifecycle, policy, PII, execution, queue, tool execution, recovery,
  visual loop, lifecycle, memory, and worker-result lanes.
- `apps/autopilot`: real Tauri app shell with local runtime, workflow,
  model-mounting, gate, workspace, and proof/probe scripts.
- `apps/benchmarks`: generated benchmark data, scorecard UI, preview fixtures,
  and validation scripts.

Preview or concept surfaces:

- `apps/sas-xyz`: product-facing service marketplace prototype with local demo
  state and static catalog/provider data.
- `apps/aiagent-xyz`: product-facing worker/procurement marketplace prototype
  with static products/jobs and wallet/deployment modal UI.
- worker training, MoW routing, Filecoin/CAS public settlement, IOI L1
  commitments, and full sovereign-domain flows are architecture-shaped and
  roadmap-shaped. They belong in the app as status-framed future paths, not as
  current product quickstarts.

## Canonical Sources

Use these as the source map for this work:

- `apps/developers-ioi-ai/README.md`
- `apps/developers-ioi-ai/src/content/docs.tsx`
- `apps/developers-ioi-ai/src/App.tsx`
- `apps/developers-ioi-ai/src/components/Header.tsx`
- `apps/developers-ioi-ai/src/components/Sidebar.tsx`
- `packages/runtime-daemon/src/index.mjs`
- `packages/agent-sdk/src/substrate-client.ts`
- `packages/agent-sdk/examples/quickstart-local.ts`
- `crates/cli/src/main.rs`
- `crates/services/src/agentic/runtime/README.md`
- `apps/autopilot/README.md`
- `apps/autopilot/package.json`
- `apps/benchmarks/package.json`
- `apps/sas-xyz/package.json`
- `apps/aiagent-xyz/package.json`
- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/architecture/_meta/vocabulary.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/daemon-runtime/api.md`
- `docs/architecture/components/connectors-tools/doctrine.md`
- `docs/architecture/products/autopilot/local-app-workflow-canvas.md`
- `internal-docs/implementation/runtime-package-boundaries.md`
- `internal-docs/implementation/runtime-module-map.md`

If this guide conflicts with canonical architecture docs, update the canonical
docs first, then reconcile this guide.

## Doctrine

- `developers.ioi.ai` teaches builders how to start, build, run, and ship.
- `docs.ioi.network` owns canonical protocol, kernel, consensus, operator,
  low-level schema, and generated markdown reference.
- Future shapes are allowed in the developer app when they help builders orient,
  but they must carry maturity labels and clear "what exists today" language.
- Current repo-backed details should not be hidden just because they are local,
  v0, or still maturing.
- Do not make a "Coming Soon" canonical reference mega-menu a primary surface.
  Keep canonical reference as a concise handoff link.
- Product-facing API docs should be curated: runtime daemon API, SDK, model
  mounting, CLI, tools/MCP, and local-compatible endpoints.
- Low-level reference material should be linked, not forked.
- Screenshots are product documentation assets. They need provenance, capture
  date, source commit, privacy review, and reproducible capture notes.
- Autopilot screenshots should show real current UI where possible. Do not use
  mockups to document runnable repo-backed product surfaces.
- Screenshot tooling must not become a second runtime authority. It is docs
  evidence unless explicitly promoted through runtime contracts.

## Status Semantics

The existing `DocStatus` enum is valuable. Make it public and unambiguous.

| Status | Meaning | Required page behavior |
| --- | --- | --- |
| Current | Repo-backed and runnable or inspectable today, possibly with local prerequisites. | Include commands, exact package paths, expected outputs, and validation status. |
| Preview | Product direction and some UI/code exist, but contracts, hosted availability, or UX may move. | Include "what exists today" and "what is still preview" sections. |
| Concept | Architecture, doctrine, or future product shape, not a ready builder path. | Keep short, route deep detail to canonical docs, and avoid quickstart promises. |

Recommended extra metadata in `DocPage`:

```ts
type Maturity = 'repo_current' | 'local_current' | 'preview' | 'concept';

interface DocPage {
  // existing fields...
  routePath: string;
  maturity: Maturity;
  repoBacked: boolean;
  runnableToday: boolean;
  sourceFreshness: 'current_repo' | 'architecture' | 'product_preview';
  primaryAudience: 'new_builder' | 'sdk_builder' | 'operator' | 'product_builder' | 'marketplace_builder';
}
```

This does not replace `Current / Preview / Concept`; it gives implementation and
UI enough precision to render badges honestly.

## Target Information Architecture

The live site should use builder-job navigation, not protocol-reference
navigation.

### Top-Level Navigation

| Nav group | Job | Pages |
| --- | --- | --- |
| Get Started | Get a builder to a successful first action quickly. | Quickstart, API Reference, Local Setup |
| Build | Build against official surfaces. | SDKs and Libraries, Examples and Templates, Tutorials, CLI |
| Run | Operate local/runtime surfaces. | Autopilot, Runtime Daemon, Model Mounting, MCP and Tools, Benchmarks |
| Ship | Move from local work to product/service shape. | Service Candidate, sas.xyz, aiagent.xyz, Sovereign Domain Flows |
| Canonical Docs | Hand off to low-level reference. | Single outbound link to `docs.ioi.network` |

### Slug Map

Move toward stable path routes before live. Keep hash compatibility as a
redirect/alias layer for existing links.

| Public path | Page id | Status |
| --- | --- | --- |
| `/` | `start-here` | Current |
| `/quickstart` | `quickstart` | Current |
| `/api` | `api-reference` | Current |
| `/setup` | `local-setup` | Current |
| `/sdks` | `sdks-and-libraries` | Current |
| `/examples` | `examples-and-templates` | Current |
| `/tutorials` | `tutorials` | Preview until real tutorials exist |
| `/cli` | `ioi-cli` | Current |
| `/autopilot` | `autopilot` | Current |
| `/runtime` | `runtime-daemon` | Current |
| `/model-mounting` | `model-mounting` | Current |
| `/mcp-tools` | `mcp-tools` | Current |
| `/benchmarks` | `benchmarks` | Current or Preview, depending on copy |
| `/ship/service-candidate` | `service-candidate` | Preview |
| `/ship/sas` | `sas-xyz` | Preview |
| `/ship/aiagent` | `aiagent-xyz` | Preview |
| `/ship/sovereign-domain` | `sovereign-domain-flows` | Preview |

The existing hash ids can remain as legacy anchors:

- `#choose-the-right-surface` -> `/`
- `#build-your-first-agent-with-ioi-agent-sdk` -> `/sdks`
- `#run-autopilot-locally` -> `/autopilot`
- `#ioi-cli-overview` -> `/cli`
- `#from-autopilot-to-service-candidate` -> `/ship/service-candidate`

## Content Inventory And Page Requirements

### Start Here

Goal: orient a new builder without protocol overload.

Required content:

- "Build with IOI" framing.
- One table or chooser: SDK, Autopilot, CLI, Runtime API, Product previews.
- Clear status key.
- One sentence canonical-docs handoff.

Do not include:

- canonical protocol mega-menu;
- deep L1, Filecoin/CAS, consensus, or node-operator explanation.

### Quickstart

Goal: get to a first successful local action.

Recommended quickstart path:

1. Clone repo and install dependencies.
2. Build SDK or run docs app.
3. Run explicit mock SDK quickstart.
4. Start daemon-backed path when `IOI_DAEMON_ENDPOINT` is configured.
5. Inspect receipts/trace output.

Important correction:

- `packages/agent-sdk/examples/quickstart-local.ts` currently uses
  `createMockRuntimeSubstrateClient`.
- The docs should not present that as the canonical live runtime path.
- Create two boxes:
  - "Fast local smoke test: explicit mock substrate"
  - "Daemon-backed local runtime: `IOI_DAEMON_ENDPOINT`"

### API Reference

Goal: curated product-facing API index.

Sections:

- Runtime daemon API:
  - agents, runs, threads, events, trace, usage;
  - tasks, jobs, checklist;
  - tools, skills, hooks;
  - memory;
  - MCP;
  - repository/GitHub context and review gates.
- Model mounting API:
  - `/api/v1/models`;
  - catalog import/search;
  - mount/load/unload;
  - providers;
  - vault refs;
  - routes;
  - chat/responses/embeddings/rerank/tokenization;
  - receipts and projections.
- OpenAI-compatible local endpoints:
  - `/v1/models`;
  - `/v1/chat/completions`;
  - `/v1/responses`;
  - `/v1/embeddings`;
  - `/v1/completions`;
  - `/v1/messages`.
- SDK:
  - `Agent`;
  - `Run`;
  - `Thread`;
  - `createRuntimeSubstrateClient`;
  - testing mock;
  - memory/MCP/tool/subagent helpers.
- CLI command families.

Rule: link to canonical docs and source for details. Do not paste full
low-level schemas unless curated and stable.

### SDKs And Libraries

Goal: give builders a truthful SDK path.

Required content:

- Install/build status.
- `@ioi/agent-sdk` daemon-backed default behavior.
- `IOI_DAEMON_ENDPOINT` requirement.
- Explicit mock testing path.
- Thread/run/event/trace examples.
- Memory, MCP/tools, subagents, and computer-use as discoverable subsections.
- Common failure modes:
  - no daemon endpoint;
  - hosted/self-hosted endpoints missing;
  - mock used in production path;
  - model route unavailable.

### Examples And Templates

Goal: route to concrete repo examples.

Initial examples:

- SDK explicit mock quickstart.
- Daemon-backed HTTP example.
- Runtime daemon event stream example.
- CLI model mounting flow.
- Autopilot workflow screenshot-backed walkthrough.
- Benchmark scorecard walkthrough.

### Tutorials

Goal: practical step-by-step build guides.

Initial tutorial candidates:

- Build a local agent with the SDK.
- Add memory to an agent run.
- Inspect runtime events and receipts.
- Mount or route a local model.
- Add an MCP server and invoke a governed tool.
- Use Autopilot to inspect a workflow and capture a receipt.
- Promote a local workflow to a service candidate.

### CLI

Goal: make the current command families scannable.

Required command families:

- `init`;
- `scaffold`;
- `artifact`;
- `node`;
- `test`;
- `keys`;
- `config`;
- `query`;
- `models`;
- `backends`;
- `routes`;
- `server`;
- `tokens`;
- `vault`;
- `receipts`;
- `agent`;
- `trace`;
- `verify`;
- `policy`;
- `mcp`;
- `pii`;
- `ghost`;
- `dev`.

Include "current repo invocation" examples and avoid claiming hosted CLI
services when the path is local/devnet.

### Autopilot

Goal: show the real local runtime product surface.

Required content:

- What Autopilot is today:
  - Tauri app;
  - local/private runtime shell;
  - workspace/workflow/gate surfaces;
  - model mounting workbench;
  - receipts/proofs/probes.
- How to run:
  - repo-level desktop helper;
  - web-only UI path;
  - direct app workspace launch.
- Current caveats:
  - local prerequisites;
  - Linux WebKit/X11 capture quirks;
  - local runtime/provider configuration;
  - screenshots may come from retained evidence or docs capture pass.

This page is the best candidate for Playwright or existing desktop-probe
screenshots.

### Runtime Daemon

Goal: explain the daemon as the developer API substrate.

Required content:

- `@ioi/runtime-daemon` description.
- `startRuntimeDaemonService`.
- Agentgres v0 local store language.
- Public `/v1` runtime API.
- `/api/v1` model mounting/admin API.
- OpenAI-compatible endpoints.
- SDK relationship.
- What it is not yet:
  - full distributed Agentgres deployment;
  - IOI L1 settlement;
  - Filecoin/CAS public artifact plane.

### Model Mounting

Goal: document one of the strongest current runtime lanes.

Required content:

- Model import/mount/load/unload lifecycle.
- Runtime engine survey/select.
- Provider/vault refs.
- Route decisions and receipts.
- CLI and GUI entry points.
- Live-provider gates are explicit and opt-in.

### MCP And Tools

Goal: expose governed tool integration without protocol sprawl.

Required content:

- MCP server discovery/import.
- Tool search/get/invoke.
- Resource and prompt catalogs.
- Validation.
- Thread-scoped MCP serve.
- Tool contracts: primitive capabilities versus authority scopes.
- Receipts and failure behavior.

### Benchmarks

Goal: show current scorecard product without overclaiming a hosted benchmark
market.

Required content:

- Generated benchmark-data pipeline.
- Scorecard UI.
- Preview fixture mode.
- Agent/model matrix data source.
- Candidate/deployment views.
- How to run validation.

### Service Candidate

Goal: preserve the future shape from Autopilot to productized worker delivery.

Status: Preview.

Required content:

- Autopilot stabilizes local work.
- Service candidate packages repeatable outcomes.
- Do not claim marketplace liquidity or production worker training as current.
- Link to `sas.xyz` and `aiagent.xyz` preview pages.

### sas.xyz

Goal: explain service/outcome marketplace direction without pretending the app
is backed by live marketplace contracts.

Status: Preview.

Required content:

- What exists today:
  - product UI prototype;
  - local demo state;
  - catalog/provider data;
  - contract/inbox/ledger/productization UX.
- What is future:
  - live service contracts;
  - settlement;
  - provider marketplace state;
  - disputes/payouts as canonical network flows.

### aiagent.xyz

Goal: explain discovery/procurement direction without hiding that the current
app is prototype-heavy.

Status: Preview.

Required content:

- What exists today:
  - product listing UI;
  - job/freelance UI;
  - sell/deploy/dashboard flows;
  - static products/jobs and modal behavior.
- What is future:
  - live worker marketplace;
  - routing and procurement;
  - install and deployment backed by runtime contracts.

### Sovereign Domain Flows

Goal: keep the domain/kernel future path visible while making clear it belongs
to heavier architecture and canonical docs.

Status: Preview or Concept.

Required content:

- CLI-led local project scaffolding.
- Local node/devnet path.
- When to leave product-DX docs for canonical domain/kernel reference.
- Link to generated canonical docs when available.

## Navigation And Menu Requirements

### Header

Replace section-derived mini menus with explicit product IA.

Recommended menu columns:

```ts
const NAV_GROUPS = [
  {
    label: 'Get Started',
    items: [
      { label: 'Quickstart', href: '/quickstart', description: 'Launch your first IOI integration fast.' },
      { label: 'API Reference', href: '/api', description: 'Browse product-facing IOI APIs.' },
      { label: 'Local Setup', href: '/setup', description: 'Prepare the monorepo and local runtime tools.' },
    ],
  },
  {
    label: 'Build',
    items: [
      { label: 'SDKs and Libraries', href: '/sdks', description: 'Official SDKs and helper libraries.' },
      { label: 'Examples and Templates', href: '/examples', description: 'Start from repo-backed examples.' },
      { label: 'Tutorials', href: '/tutorials', description: 'Follow practical step-by-step build guides.' },
      { label: 'CLI', href: '/cli', description: 'Use the kernel-adjacent command surface.' },
    ],
  },
  {
    label: 'Run',
    items: [
      { label: 'Autopilot', href: '/autopilot', description: 'Run the local desktop runtime surface.' },
      { label: 'Runtime Daemon', href: '/runtime', description: 'Develop against the daemon substrate API.' },
      { label: 'Model Mounting', href: '/model-mounting', description: 'Mount, route, and invoke model backends.' },
      { label: 'MCP and Tools', href: '/mcp-tools', description: 'Connect governed tools and MCP servers.' },
      { label: 'Benchmarks', href: '/benchmarks', description: 'Inspect scorecards and model/run evidence.' },
    ],
  },
  {
    label: 'Ship',
    items: [
      { label: 'Service Candidate', href: '/ship/service-candidate', description: 'Package a repeatable local workflow.' },
      { label: 'sas.xyz', href: '/ship/sas', description: 'Preview service/outcome productization.' },
      { label: 'aiagent.xyz', href: '/ship/aiagent', description: 'Preview discovery and procurement.' },
      { label: 'Sovereign Domains', href: '/ship/sovereign-domain', description: 'Know when to use heavier domain flows.' },
    ],
  },
];
```

Keep `Canonical docs` as one outbound item:

```ts
{ label: 'Canonical docs', href: 'https://docs.ioi.network', external: true }
```

Do not add a primary mega-menu column of canonical "Coming Soon" items.

### Sidebar

The sidebar should support deep reading after the user chooses a page, not
replace the primary IA.

Required sidebar behavior:

- group by the new nav groups;
- show status/maturity badge for each page;
- support search;
- keep one compact canonical-docs handoff;
- avoid surfacing every future concept page at the same weight as current
  quickstarts.

### Search

Search should prefer current runnable docs, then preview, then concept.

Recommended ranking:

1. Exact title or path match.
2. Current pages.
3. Repo-backed pages.
4. Preview pages.
5. Concept pages.

## Screenshot And Media Strategy

Screenshots are useful and should be captured, but only after the IA and content
truth are aligned.

### Screenshot Doctrine

- Use real repo UI for current Autopilot documentation where possible.
- Store raw evidence separately from curated public assets.
- Public assets must be reviewed for secrets, local paths, user data, and noisy
  development artifacts.
- Every public screenshot should carry:
  - capture date;
  - source command;
  - source commit;
  - target route/window;
  - viewport size;
  - redaction status;
  - owning docs page.
- Avoid screenshots of canonical markdown/reference unless the docs page is
  specifically about the docs UX.

### Existing Capture Assets

There is already evidence under:

- `docs/evidence/autopilot-gui-harness-validation/*/*.png`
- `docs/evidence/autopilot-gui-harness-validation/*/result.json`
- `apps/autopilot/scripts/desktop_workspace_probe.py`
- `apps/autopilot/scripts/desktop_workspace_panel_probe.py`
- `apps/autopilot/scripts/desktop_model_mounts_probe.py`
- `apps/autopilot/scripts/desktop_workflow_scratch_probe.py`
- `apps/autopilot/scripts/desktop_workflow_usability_probe.py`
- `scripts/run-autopilot-gui-harness-validation.mjs`
- `scripts/run-model-mounts-gui-validation.mjs`

Use these first for proof and methodology. Curated docs assets should be copied
or regenerated into a public docs asset path only after review.

Recommended public asset path:

```text
apps/developers-ioi-ai/public/media/screenshots/autopilot/
apps/developers-ioi-ai/public/media/screenshots/runtime/
apps/developers-ioi-ai/public/media/screenshots/benchmarks/
```

Recommended raw capture path:

```text
docs/evidence/developers-ioi-ai-media/<timestamp>/
```

### Playwright Capture Lane

Playwright is a good candidate for docs-asset capture when the target is a web
route or when Autopilot exposes an equivalent web route through Vite. It should
not replace the existing Tauri desktop probes for native-window evidence unless
that lane is explicitly upgraded.

Recommended docs capture command shape:

```bash
npm run dev:web
node scripts/capture-developers-docs-media.mjs --target autopilot --viewport desktop
node scripts/capture-developers-docs-media.mjs --target autopilot --viewport mobile
```

If implemented, `scripts/capture-developers-docs-media.mjs` should:

- start or reuse the target dev server;
- create an isolated browser context;
- capture desktop and mobile screenshots;
- write a manifest JSON;
- fail when screenshots are blank, too small, or missing expected landmarks;
- redact or block screenshots when sensitive selectors or local path patterns
  are detected;
- write raw output under `docs/evidence/developers-ioi-ai-media/<timestamp>`;
- optionally copy approved images into
  `apps/developers-ioi-ai/public/media/screenshots/...`.

Playwright should capture:

| Page | Target | Capture type | Priority |
| --- | --- | --- | --- |
| Autopilot | Home or shell route | web route screenshot if representative | High |
| Autopilot | Workspace surface | existing desktop probe plus web fallback | High |
| Autopilot | Workflow canvas | existing desktop probe or Playwright web route | High |
| Autopilot | Model mounting | existing model-mounts GUI validation | High |
| Autopilot | Gate/approval | existing Tauri probe or deterministic fixture route | Medium |
| Benchmarks | scorecard app | Playwright web route | Medium |
| Runtime daemon | API docs | no screenshot required; use code/API cards | Low |
| SDK | code examples | no screenshot required | Low |
| CLI | terminal snippets | no screenshot unless using asciinema-like artifact later | Low |
| sas.xyz | product preview | static screenshot optional with Preview badge | Medium |
| aiagent.xyz | product preview | static screenshot optional with Preview badge | Medium |

### Screenshot Manifest Shape

```json
{
  "schema_version": "ioi.developers.media-capture.v1",
  "captured_at": "2026-05-16T00:00:00.000Z",
  "source_commit": "git sha",
  "capture_command": "node scripts/capture-developers-docs-media.mjs --target autopilot",
  "target": "autopilot.workspace",
  "target_url": "http://127.0.0.1:5173/?view=workspace",
  "viewport": { "width": 1440, "height": 1000, "device_scale_factor": 1 },
  "raw_screenshot": "docs/evidence/developers-ioi-ai-media/.../workspace-desktop.png",
  "public_asset": "apps/developers-ioi-ai/public/media/screenshots/autopilot/workspace-desktop.png",
  "redaction_status": "reviewed",
  "expected_landmarks": ["Workspace", "Run", "Receipts"],
  "blank_check": { "passed": true, "mean_luma": 0.42 },
  "notes": []
}
```

## Design And UX Requirements

The current docs shell is functional, but live public developer docs need a
more productized first impression.

### First View

The first page should be a working developer entry, not a protocol essay.

Required first-view content:

- brand: `IOI Developers`;
- concise promise: "Build, run, and ship bounded autonomous software";
- primary CTA: `Start quickstart`;
- secondary CTA: `Browse API`;
- utility CTA: `Open GitHub`;
- small status row:
  - SDK;
  - Runtime daemon;
  - Autopilot;
  - CLI;
  - Model mounting.

Avoid:

- oversized canonical-reference grid;
- "Coming Soon" as the dominant first impression;
- marketing-only hero with no path to running code.

### Cards And Density

This is an operational docs/product surface. Use cards for repeated page links,
API families, and examples only. Avoid nested cards and decorative section
containers.

### Badges

Recommended badges:

- Current;
- Local;
- Preview;
- Concept;
- Requires daemon;
- Requires provider;
- Requires desktop;
- Canonical handoff.

### Copy Rules

- Lead with builder actions.
- Say "local runtime daemon" when the path is local.
- Say "Agentgres v0 local store" when relevant; do not claim production
  Agentgres unless the page is architecture-only.
- Say "explicit mock" for SDK testing examples.
- Say "preview product surface" for `sas.xyz` and `aiagent.xyz`.
- Use "canonical docs" for protocol depth, not "coming soon" placeholders.

## Implementation Workstreams

### Workstream 1: IA And Routing

Goal: make the public routes match the developer mental model.

Tasks:

- Add explicit `routePath` to every `DocPage`.
- Replace hash-only routing with path-aware SPA routing.
- Preserve hash compatibility with redirects or alias resolution.
- Replace `DOC_SECTIONS` with nav groups or add a separate `NAV_GROUPS`.
- Update Header mega-menu to use explicit nav groups.
- Keep canonical docs as utility handoff.
- Update Sidebar to respect nav group weighting and status.

Done when:

- `/quickstart`, `/api`, `/sdks`, `/autopilot`, `/runtime`,
  `/model-mounting`, `/benchmarks`, and ship routes render directly.
- Existing hash links still land on the expected page.
- No primary nav menu shows canonical protocol docs as "Coming Soon" items.

### Workstream 2: Status And Source Metadata

Goal: make maturity hard to misunderstand.

Tasks:

- Extend `DocPage` metadata with `routePath`, `maturity`, `repoBacked`,
  `runnableToday`, and `sourceFreshness`.
- Render status badges near page title and in nav/search results.
- Add "What exists today" blocks to every Preview page.
- Add "Canonical depth" links only where needed.
- Add a status legend page or compact component.

Done when:

- a reader can tell current local runtime docs from product preview docs in
  less than five seconds;
- search and nav do not rank concept pages above current quickstarts.

### Workstream 3: Quickstart And SDK Truth Pass

Goal: fix the most important trust gap before live.

Tasks:

- Split SDK quickstart into explicit mock and daemon-backed paths.
- Add `IOI_DAEMON_ENDPOINT` setup guidance.
- Add expected fail-closed error for missing daemon endpoint.
- Add `createMockRuntimeSubstrateClient` language only under testing/examples.
- Add a daemon-backed minimal example if not already present.
- Link to package tests as proof of behavior.

Done when:

- the docs never imply the explicit mock is the canonical runtime;
- the docs never imply the default SDK runs without daemon transport;
- local smoke-test and daemon-backed paths are both useful.

### Workstream 4: API Reference Curation

Goal: create a product-facing API page without forking canonical reference.

Tasks:

- Inventory runtime daemon routes from `packages/runtime-daemon/src/index.mjs`.
- Group routes by developer job.
- Create concise endpoint tables.
- Add source links and canonical links.
- Add "local/v0" caveats for Agentgres local store.
- Add OpenAI-compatible endpoints as a clear subsection.
- Add model mounting admin API subsection.

Done when:

- API Reference is useful without becoming the low-level generated reference;
- every endpoint family links to source or canonical docs for depth.

### Workstream 5: Autopilot Documentation And Screenshots

Goal: make Autopilot docs visual and current.

Tasks:

- Identify 4 to 6 screenshots:
  - home/shell;
  - workspace;
  - workflow canvas;
  - model mounting;
  - approval/gate;
  - receipts/trace or benchmark/harness view.
- Prefer existing retained evidence when current and clean.
- Add a docs-media capture script if screenshots need to be regenerated.
- Consider Playwright for Vite/web-route captures.
- Use existing desktop probes for native Tauri evidence.
- Add screenshot manifests.
- Add public assets only after review.
- Add image components with captions and status badges.

Done when:

- Autopilot page has real current UI imagery;
- every public image has provenance;
- no screenshot leaks local paths, tokens, secrets, or private user data.

### Workstream 6: Examples, Tutorials, And Benchmarks

Goal: make repo-backed learning paths feel alive.

Tasks:

- Add examples index page.
- Add tutorial shells with status badges.
- Add benchmark scorecard page.
- Link commands:
  - `npm run build:agent-sdk`;
  - `npm run test:agent-sdk`;
  - `npm run dev:benchmarks`;
  - `npm run verify:benchmarks`;
  - `npm run test:daemon-runtime-api`;
  - `npm run test:model-mounting`.
- Distinguish preview fixture mode in benchmarks.

Done when:

- current benchmark and example assets are represented;
- there is no claim of hosted benchmark marketplace unless explicitly marked
  future.

### Workstream 7: Product Preview Pages

Goal: keep future shape without overclaiming.

Tasks:

- Rewrite `sas.xyz` as Preview:
  - current UI prototype;
  - future marketplace/settlement path;
  - link to service candidate workflow.
- Rewrite `aiagent.xyz` as Preview:
  - current UI prototype;
  - future discovery/procurement path;
  - link to worker/marketplace canonical docs.
- Keep worker training and MoW as concept/architecture handoffs unless there is
  a current API or runnable product path.

Done when:

- preview pages are inspiring but honest;
- no static prototype is documented as a live marketplace.

### Workstream 8: Visual Polish And Accessibility

Goal: make the site feel shippable and durable.

Tasks:

- Review header at desktop, tablet, and mobile.
- Ensure menu text fits and tap targets are stable.
- Remove overly rounded, nested card feel where it makes docs dense and noisy.
- Add keyboard navigation for menus and search.
- Add `aria-current` for active nav/page.
- Add route-aware page titles and descriptions.
- Ensure code blocks wrap/scroll cleanly on mobile.
- Validate dark/light mode contrast.
- Add image alt text and captions.

Done when:

- Lighthouse/accessibility pass is clean enough for live launch;
- mobile docs navigation is usable without covering content awkwardly.

### Workstream 9: Validation And Release Gate

Goal: make live readiness repeatable.

Tasks:

- Add a focused docs validation command, for example:

```bash
npm run build --workspace=apps/developers-ioi-ai
npm run lint --workspace=apps/developers-ioi-ai
```

- Add a route smoke test if path routing is introduced.
- Add a link checker for internal routes and external docs links.
- Add a content guard that fails when:
  - "Coming Soon" canonical reference appears in primary nav;
  - mock SDK quickstart is not labeled explicit mock;
  - Preview pages lack "what exists today";
  - screenshot manifests are missing for public screenshot assets.
- Add Playwright visual smoke tests for:
  - home;
  - quickstart;
  - API reference;
  - SDKs;
  - Autopilot.

Done when:

- one command can validate build, lint, routes, links, and high-risk content
  claims before pushing live.

## Launch Acceptance Criteria

The app is ship-shape when all of these are true:

- Top navigation is builder-job oriented.
- Canonical docs are a utility handoff, not a primary coming-soon reference
  column.
- Stable public paths exist for key pages.
- Hash links are preserved or redirected.
- Current repo-backed surfaces are easy to find.
- Future product shapes remain visible but status-framed.
- SDK quickstart separates explicit mock from daemon-backed runtime.
- API Reference is product-facing and curated.
- Autopilot page includes real UI imagery or a tracked task explaining why
  screenshots were deferred.
- Any public screenshots have manifests and privacy review.
- Preview pages include "what exists today" and "what is still preview".
- No page claims full distributed Agentgres, IOI L1 settlement, Filecoin/CAS,
  worker marketplace liquidity, or worker training runtime as current unless
  backed by implementation and validation.
- Build and lint pass for `apps/developers-ioi-ai`.
- Route/link/content checks pass.

## Suggested Implementation Order

1. IA and route model.
2. Status metadata and badges.
3. Quickstart and SDK truth pass.
4. API Reference page.
5. Autopilot page and screenshot plan.
6. Runtime/model mounting/MCP pages.
7. Benchmarks page.
8. Product preview pages.
9. Visual/accessibility polish.
10. Validation guard and launch checklist.

## Risks

| Risk | Mitigation |
| --- | --- |
| Site overclaims future architecture as current product. | Status metadata, "what exists today" sections, and content guardrails. |
| Site hides real current repo details to look cleaner. | Current repo-backed pages are first-class in nav and search. |
| Canonical docs and developer docs fork low-level truth. | Keep only curated summaries and link to canonical docs for depth. |
| SDK examples confuse explicit mock with daemon runtime. | Split examples and enforce labels. |
| Screenshots get stale or leak private data. | Capture manifests, review step, and source commit binding. |
| Playwright becomes shadow runtime authority. | Scope Playwright to docs-media capture unless promoted by runtime contracts. |
| Hash-only routing feels unprofessional live. | Add stable path routing with legacy hash aliases. |
| Product preview apps look live. | Preview badges and "what exists today" blocks. |

## Open Questions

- Should `developers.ioi.ai` be a single-page docs app with path-aware routing,
  or should it be migrated to a docs framework later?
- Which public route will own "API Reference" if generated OpenAPI or markdown
  reference later exists on `docs.ioi.network`?
- Should screenshot assets be committed into the app repo, or generated during
  release from evidence bundles?
- Should the Autopilot page show desktop-native screenshots only, or combine
  desktop-native and web-route screenshots?
- Should `sas.xyz` and `aiagent.xyz` screenshots live on their own product
  sites and be embedded/linked, or should developers.ioi.ai carry curated
  previews?

## First Implementation Patch Set

Recommended first PR:

- Add `routePath`, `maturity`, `repoBacked`, `runnableToday`, and
  `sourceFreshness` to `DocPage`.
- Add explicit nav groups.
- Rename first page to `Start Here`.
- Add route aliases for existing hash ids.
- Replace header mega-menu content.
- Add status badges to page header and sidebar.
- Rewrite SDK page into explicit mock and daemon-backed sections.
- Add API Reference page skeleton.
- Add Autopilot screenshot requirements section without adding final images yet.
- Add a content guard test for the highest-risk claims.

Recommended second PR:

- Add Playwright or existing-probe-backed docs media capture workflow.
- Generate/review Autopilot screenshots.
- Add image components and captions.
- Add route/link smoke tests.
- Polish mobile nav and search ranking.
