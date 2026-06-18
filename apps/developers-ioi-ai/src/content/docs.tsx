import type { ReactNode } from 'react';
import {
  Callout,
  CodeBlock,
  ScreenshotFigure,
  StepList,
  Table,
} from '../components/UIComponents';

export type DocStatus = 'Current' | 'Preview' | 'Concept';
export type DocMaturity = 'repo_current' | 'local_current' | 'preview' | 'concept';
export type SourceFreshness = 'current_repo' | 'architecture' | 'product_preview';
export type PrimaryAudience =
  | 'new_builder'
  | 'sdk_builder'
  | 'operator'
  | 'product_builder'
  | 'marketplace_builder';
export type DocSectionId = 'get-started' | 'build' | 'run' | 'ship';

export interface DocSectionMeta {
  id: DocSectionId;
  label: string;
  description: string;
}

export interface NavGroup extends DocSectionMeta {
  pageIds: string[];
}

export interface DocLink {
  label: string;
  href: string;
  description?: string;
  external?: boolean;
}

export interface DocPageSection {
  id: string;
  title: string;
  render: (isDark: boolean) => ReactNode;
}

export interface DocPage {
  id: string;
  title: string;
  eyebrow: string;
  summary: string;
  section: DocSectionId;
  status: DocStatus;
  maturity: DocMaturity;
  repoBacked: boolean;
  runnableToday: boolean;
  sourceFreshness: SourceFreshness;
  primaryAudience: PrimaryAudience;
  routePath: string;
  legacyHashes: string[];
  lastVerified: string;
  keywords: string[];
  sources: string[];
  canonicalLinks: DocLink[];
  nextSteps: DocLink[];
  sections: DocPageSection[];
}

const LAST_VERIFIED = '2026-05-16';

const bodyClass = (isDark: boolean) =>
  isDark ? 'space-y-4 text-[15px] leading-7 text-stone-300/88' : 'space-y-4 text-[15px] leading-7 text-stone-700';

const listClass = (isDark: boolean) =>
  isDark
    ? 'list-disc space-y-3 pl-5 text-stone-300/88 marker:text-[#5a8cec]/80'
    : 'list-disc space-y-3 pl-5 text-stone-700 marker:text-[#3b5eda]';

const linkClass = (isDark: boolean) =>
  isDark
    ? 'text-[#93bef8] underline decoration-[#5a8cec]/45 underline-offset-4 hover:text-[#c8dcfd]'
    : 'text-[#2740a8] underline decoration-[#3b5eda]/35 underline-offset-4 hover:text-[#1c2d78]';

const code = String.raw;

const canonicalDocsLink: DocLink = {
  label: 'Canonical architecture and protocol docs',
  href: 'https://docs.ioi.network',
  description: 'Use docs.ioi.network for durable protocol, kernel, runtime, and operator depth.',
  external: true,
};

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'get-started',
    label: 'Get Started',
    description: 'Choose a path, run a truthful quickstart, and understand the public API surface.',
    pageIds: ['start-here', 'quickstart', 'api-reference', 'local-setup'],
  },
  {
    id: 'build',
    label: 'Build',
    description: 'Use SDKs, examples, tutorials, and CLI families with the local runtime as the default path.',
    pageIds: ['sdks-and-libraries', 'examples-and-templates', 'tutorials', 'ioi-cli'],
  },
  {
    id: 'run',
    label: 'Run',
    description: 'Operate Autopilot, daemon-backed runtime APIs, model mounts, MCP tools, and benchmarks.',
    pageIds: ['autopilot', 'runtime-daemon', 'model-mounting', 'mcp-tools', 'benchmarks'],
  },
  {
    id: 'ship',
    label: 'Ship',
    description: 'Package worker services and understand the preview marketplace and sovereign-domain paths.',
    pageIds: [
      'service-candidate',
      'sas-xyz',
      'aiagent-xyz',
      'sovereign-domain-flows',
      'worker-training-mow',
    ],
  },
];

export const DOC_SECTIONS: DocSectionMeta[] = NAV_GROUPS.map(({ pageIds: _pageIds, ...section }) => section);

export const DEFAULT_PAGE_ID = 'start-here';

export const DOC_PAGES: DocPage[] = [
  {
    id: 'start-here',
    title: 'Start Here',
    eyebrow: 'Builder front door',
    summary:
      'developers.ioi.ai is the product-facing builder guide: start fast, build against current APIs, run local workers, and route deeper protocol questions to canonical docs.',
    section: 'get-started',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'new_builder',
    routePath: '/',
    legacyHashes: ['choose-the-right-surface', 'introduction-to-ioi', 'overview'],
    lastVerified: LAST_VERIFIED,
    keywords: ['start', 'overview', 'builder jobs', 'canonical docs', 'current preview concept'],
    sources: [
      '.internal/plans/developers-ioi-ai-ship-shape-master-guide.md',
      'README.md',
      'docs/architecture/foundations/web4-and-ioi-stack.md',
    ],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Run the Quickstart', href: '#quickstart', description: 'Connect the SDK to the local daemon first.' },
      { label: 'Browse API Reference', href: '#api-reference', description: 'Product-facing route families and SDK entrypoints.' },
      { label: 'Run Autopilot', href: '#autopilot', description: 'See what exists today in the local desktop surface.' },
    ],
    sections: [
      {
        id: 'builder-jobs',
        title: 'Builder Jobs',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              This app is intentionally not the canonical protocol manual. It is the builder path:
              what to run, what to import, what is stable enough to build against, and where to go
              when a detail becomes protocol or operator depth.
            </p>
            <Table
              isDark={isDark}
              headers={['Job', 'Use developers.ioi.ai for', 'Canonical handoff']}
              rows={[
                ['Get Started', 'Quickstart, API map, local setup, and route selection.', 'Link out when the question becomes protocol semantics.'],
                ['Build', 'SDK usage, examples, tutorials, and CLI families.', 'Link out for formal object/envelope definitions.'],
                ['Run', 'Autopilot, runtime daemon, model mounting, MCP, memory, traces, and benchmarks.', 'Link out for kernel/runtime internals.'],
                ['Ship', 'Service candidate packaging, sas.xyz, aiagent.xyz, sovereign-domain, and worker-training/MoW previews.', 'Link out for marketplace, domain, and governance architecture.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'maturity-language',
        title: "Know What's Real",
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Future shapes stay visible because builders need the road signs. The labels keep a
              static preview, local proof, or concept from reading like a live production
              marketplace.
            </p>
            <Table
              isDark={isDark}
              headers={['Label', 'Meaning', 'Public-doc rule']}
              rows={[
                ['Current', 'Repo-backed implementation or local flow that can be used or inspected today.', 'Give runnable commands and current API names.'],
                ['Preview', 'Product direction with partial implementation, static preview, or local proof evidence.', 'Start with "What Exists Today" and state the missing production parts.'],
                ['Concept', 'Architecture or future-shape guidance that is not a live product surface.', 'Use mental-model language and hand off to canonical docs for depth.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'canonical-handoff',
        title: 'When To Use Canonical Docs',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="current" title="Small utility link, not a primary nav column">
              <p>
                Protocol docs, kernel/runtime internals, and node/operator reference belong in the
                markdown-backed canonical docs rendered by <code>docs.ioi.network</code>. This app
                links there instead of carrying primary navigation for unfinished canonical columns.
              </p>
            </Callout>
            <p>
              Keep this boundary crisp: developers.ioi.ai teaches product-facing builder jobs;
              docs.ioi.network owns durable protocol truth.
            </p>
          </div>
        ),
      },
    ],
  },
  {
    id: 'quickstart',
    title: 'Quickstart',
    eyebrow: 'Get Started',
    summary:
      'Connect the SDK to the daemon-backed local runtime through IOI_DAEMON_ENDPOINT. Use the offline fixture only when you are writing tests or examples without a daemon.',
    section: 'get-started',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'new_builder',
    routePath: '/quickstart',
    legacyHashes: ['local-setup', 'build-your-first-agent-with-ioi-agent-sdk', 'quickstart-local'],
    lastVerified: LAST_VERIFIED,
    keywords: ['quickstart', 'test fixture', 'daemon', 'IOI_DAEMON_ENDPOINT', 'SDK', 'runtime'],
    sources: [
      'packages/agent-sdk/src/substrate-client.ts',
      'packages/agent-sdk/examples/quickstart-local.ts',
      'packages/runtime-daemon/src/index.mjs',
    ],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'SDKs & Libraries', href: '#sdks-and-libraries', description: 'Understand the SDK boundary and fail-closed defaults.' },
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'Inspect the product-facing daemon route families.' },
      { label: 'API Reference', href: '#api-reference', description: 'Map SDK calls to daemon APIs.' },
    ],
    sections: [
      {
        id: 'connect-local-runtime',
        title: 'Connect To The Local Runtime',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              This is the path most builders should take. It uses the same daemon-backed substrate
              that Autopilot, probes, and product-facing runtime APIs use locally.
            </p>
            <p>
              Start the daemon in one terminal, then copy the printed
              <code> IOI_DAEMON_ENDPOINT</code> into the terminal where you run SDK code.
            </p>
            <CodeBlock
              isDark={isDark}
              label="Command"
              code={code`node --input-type=module <<'EOF'
import { startRuntimeDaemonService } from "./packages/runtime-daemon/src/index.mjs";

const service = await startRuntimeDaemonService({
  cwd: process.cwd(),
  port: 8787,
});

console.log("IOI_DAEMON_ENDPOINT=" + service.endpoint);
console.log("Leave this process running while you use the SDK.");

process.on("SIGINT", async () => {
  await service.close();
  process.exit(0);
});
EOF`}
            />
            <CodeBlock
              isDark={isDark}
              label="Code"
              code={code`import { Agent, createRuntimeSubstrateClient } from "@ioi/agent-sdk";

const substrateClient = createRuntimeSubstrateClient();

const agent = await Agent.create({
  model: { id: "local:auto" },
  local: { cwd: process.cwd() },
  substrateClient,
});

const run = await agent.send("Inspect the current workspace state");
await run.wait();`}
            />
          </div>
        ),
      },
      {
        id: 'what-to-use-when',
        title: 'What To Use When',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['You want to', 'Start here', 'Why']}
              rows={[
                ['Build against the real local runtime', 'Daemon-backed SDK quickstart', 'Uses IOI_DAEMON_ENDPOINT and fails closed when runtime config is missing.'],
                ['Use the product GUI', 'Autopilot desktop', 'Local workbench over chat, artifacts, workflow canvas, model mounts, MCP, and governed execution.'],
                ['Write tests without booting a daemon', 'Offline SDK fixture', 'Fast deterministic fixture for tests and examples; not the canonical live runtime.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'fail-closed-default',
        title: 'Fail-Closed Default',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="current" title="SDK truthfulness rule">
              <p>
                If <code>IOI_DAEMON_ENDPOINT</code> is absent, the default SDK client raises a
                configuration error. Tests and examples must opt into the explicit testing fixture
                instead of implying that fixture behavior is the live runtime.
              </p>
            </Callout>
          </div>
        ),
      },
      {
        id: 'offline-sdk-fixture',
        title: 'Offline SDK Fixture For Tests',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="preview" title="Testing-only fixture">
              <p>
                This path intentionally uses <code>createMockRuntimeSubstrateClient</code> from
                <code> @ioi/agent-sdk/testing</code>. It is for examples and tests that cannot
                start a daemon. It is not the canonical live runtime substrate.
              </p>
            </Callout>
            <CodeBlock
              isDark={isDark}
              code={code`import { Agent } from "@ioi/agent-sdk";
import { createMockRuntimeSubstrateClient } from "@ioi/agent-sdk/testing";

const agent = await Agent.create({
  model: { id: "local:auto" },
  local: { cwd: process.cwd() },
  substrateClient: createMockRuntimeSubstrateClient({
    cwd: process.cwd(),
  }),
});

const run = await agent.send("Summarize this repository");
for await (const event of run.stream()) {
  console.log(event.type, event.summary);
}`}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'api-reference',
    title: 'API Reference',
    eyebrow: 'Product-facing APIs',
    summary:
      'A builder-level map of daemon APIs, SDK entrypoints, model mounting, OpenAI-compatible local endpoints, MCP/tools, memory, events, traces, and CLI families.',
    section: 'get-started',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'sdk_builder',
    routePath: '/api',
    legacyHashes: ['api', 'reference', 'api-reference', 'runtime-api'],
    lastVerified: LAST_VERIFIED,
    keywords: ['api', 'daemon', 'sdk', 'models', 'mcp', 'memory', 'events', 'traces', 'cli'],
    sources: [
      'docs/architecture/components/daemon-runtime/api.md',
      'packages/runtime-daemon/src/index.mjs',
      'packages/agent-sdk/src/substrate-client.ts',
      'apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx',
      'crates/cli',
    ],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'Operational detail for the daemon-backed local runtime.' },
      { label: 'Model Mounting', href: '#model-mounting', description: 'Model catalog, mount, load, unload, and compatibility endpoints.' },
      { label: 'MCP Tools', href: '#mcp-tools', description: 'Tool discovery, import, validation, and invocation.' },
    ],
    sections: [
      {
        id: 'runtime-daemon-api',
        title: 'Runtime Daemon API',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The daemon API is the product-facing local runtime boundary. Use it for managed
              worker instances, runs, events, artifacts, receipts, approvals, replay, traces, and
              scorecards. Protocol internals remain in canonical docs.
            </p>
            <Table
              isDark={isDark}
              headers={['Family', 'Representative routes', 'Builder job']}
              rows={[
                ['Agents', <code>POST /v1/agents, GET /v1/agents, GET /v1/agents/{'{agent_id}'}</code>, 'Create and inspect managed worker instances.'],
                ['Runs', <code>POST /v1/agents/{'{agent_id}'}/runs, GET /v1/runs/{'{run_id}'}/status</code>, 'Launch and monitor runtime work.'],
                ['Events', <code>GET /v1/runs/{'{run_id}'}/events?mode=replay-and-tail</code>, 'Tail streamable runtime progress.'],
                ['Artifacts and receipts', <code>GET /v1/runs/{'{run_id}'}/artifacts, GET /v1/runs/{'{run_id}'}/receipts</code>, 'Inspect outputs and authority/effect evidence.'],
                ['Traces and scorecards', <code>GET /v1/runs/{'{run_id}'}/trace, GET /v1/runs/{'{run_id}'}/scorecard</code>, 'Debug execution quality and replayability.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'sdk-api',
        title: 'SDK API',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The SDK wraps the daemon substrate. <code>createRuntimeSubstrateClient()</code> reads
              <code> IOI_DAEMON_ENDPOINT</code> and fails closed by default. The offline fixture
              lives under testing for examples and tests that cannot start a daemon.
            </p>
            <Table
              isDark={isDark}
              headers={['SDK surface', 'Current meaning']}
              rows={[
                ['Agent.create', 'Creates an SDK-level agent projection over the selected substrate client.'],
                ['agent.send / run.stream / run.wait', 'Launches a task and consumes runtime events until the stop condition resolves.'],
                ['createRuntimeSubstrateClient', 'Daemon-backed default client; requires IOI_DAEMON_ENDPOINT.'],
                ['@ioi/agent-sdk/testing#createMockRuntimeSubstrateClient', 'Offline fixture for tests and examples; not the live runtime.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'models-and-openai',
        title: 'Model Mounting And OpenAI Compatibility',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Model mounting is current in the repo as a local/admin surface used by Autopilot and
              daemon probes. The OpenAI-compatible route is a compatibility lane, not the whole
              worker API.
            </p>
            <Table
              isDark={isDark}
              headers={['Family', 'Representative routes']}
              rows={[
                ['Catalog and inventory', <code>GET /v1/model-mount/snapshot, GET /v1/models/catalog/search</code>],
                ['Download and storage', <code>POST /v1/model-mount/downloads, POST /v1/model-mount/storage/cleanup</code>],
                ['Import and mount', <code>POST /v1/model-mount/artifacts/import, POST /v1/model-mount/endpoints</code>],
                ['Load and unload', <code>POST /v1/model-mount/instances/load, POST /v1/model-mount/instances/unload, GET /v1/model-mount/instances/loaded</code>],
                ['Compatibility', <code>POST /v1/chat/completions</code>],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'mcp-memory-events-cli',
        title: 'MCP, Memory, Events, Traces, CLI',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Area', 'Product-facing surface']}
              rows={[
                ['MCP/tools', <code>GET /v1/mcp/tools, GET /v1/mcp/tools/search, POST /v1/mcp/tools/{'{tool_id}'}/invoke, POST /v1/mcp/import</code>],
                ['Memory', <code>GET /v1/memory, GET /v1/memory/records, POST /v1/memory/validate</code>],
                ['Events', <code>GET /v1/runs/{'{run_id}'}/events</code>],
                ['Traces', <code>GET /v1/runs/{'{run_id}'}/trace, GET /v1/runs/{'{run_id}'}/inspect</code>],
                ['CLI families', 'Daemon/runtime probes, benchmark harnesses, computer-use suites, model mount probes, and Autopilot desktop harness commands in the repo.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'local-setup',
    title: 'Local Setup',
    eyebrow: 'Get Started',
    summary:
      'Prepare a local workspace for SDK, daemon, and Autopilot flows while keeping endpoint and authority configuration explicit.',
    section: 'get-started',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'new_builder',
    routePath: '/setup',
    legacyHashes: ['local-setup', 'setup'],
    lastVerified: LAST_VERIFIED,
    keywords: ['setup', 'local', 'workspace', 'daemon endpoint'],
    sources: ['package.json', 'packages/runtime-daemon/package.json', 'apps/hypervisor/package.json'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Quickstart', href: '#quickstart', description: 'Connect to the daemon-backed local runtime.' },
      { label: 'Autopilot', href: '#autopilot', description: 'Understand the GUI surface before running it.' },
    ],
    sections: [
      {
        id: 'workspace-setup',
        title: 'Workspace Setup',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <StepList
              isDark={isDark}
              steps={[
                {
                  title: 'Install dependencies at the repo root',
                  body: 'Use the repo package manager lockfiles and workspace scripts already present in the monorepo.',
                  code: 'npm install',
                },
                {
                  title: 'Set the daemon endpoint for live SDK calls',
                  body: 'The SDK will not silently fall back to an offline fixture when the endpoint is missing.',
                  code: 'export IOI_DAEMON_ENDPOINT="http://127.0.0.1:8787"',
                },
                {
                  title: 'Use the offline fixture only for examples or tests',
                  body: 'Import createMockRuntimeSubstrateClient from @ioi/agent-sdk/testing only when you deliberately want a fixture without a daemon.',
                },
              ]}
            />
          </div>
        ),
      },
      {
        id: 'authority-boundary',
        title: 'Authority Boundary',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="current" title="Local-first does not mean ambient authority">
              <p>
                Treat endpoints, tokens, model mounts, MCP servers, and connector credentials as
                explicit runtime configuration. Do not put private local paths or secrets into
                public docs, screenshots, or example manifests.
              </p>
            </Callout>
          </div>
        ),
      },
    ],
  },
  {
    id: 'sdks-and-libraries',
    title: 'SDKs & Libraries',
    eyebrow: 'Build',
    summary:
      'Use @ioi/agent-sdk as the builder SDK for daemon-backed agents, with a separate offline fixture for tests and current model/MCP/memory helpers.',
    section: 'build',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'sdk_builder',
    routePath: '/sdks',
    legacyHashes: ['sdks', 'sdks-and-libraries', 'build-your-first-agent-with-ioi-agent-sdk'],
    lastVerified: LAST_VERIFIED,
    keywords: ['sdk', '@ioi/agent-sdk', 'testing', 'mock', 'daemon'],
    sources: ['packages/agent-sdk/src/index.ts', 'packages/agent-sdk/src/substrate-client.ts', 'packages/agent-sdk/src/testing.ts'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Quickstart', href: '#quickstart', description: 'Start with the daemon-backed local runtime.' },
      { label: 'API Reference', href: '#api-reference', description: 'Map SDK calls to daemon route families.' },
      { label: 'MCP Tools', href: '#mcp-tools', description: 'Build governed tool flows.' },
    ],
    sections: [
      {
        id: 'sdk-defaults',
        title: 'SDK Defaults',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Need', 'Use', 'Truthfulness note']}
              rows={[
                ['Live/local runtime', <code>createRuntimeSubstrateClient()</code>, 'Requires IOI_DAEMON_ENDPOINT; fails closed if missing.'],
                ['Offline test fixture', <code>createMockRuntimeSubstrateClient()</code>, 'Only import from @ioi/agent-sdk/testing when you need a no-daemon fixture.'],
                ['Agent loop', <code>Agent.create, agent.send, run.stream, run.wait</code>, 'Use with the substrate that matches your track.'],
                ['Model/MCP/memory helpers', 'SDK substrate methods and typed events', 'Use daemon-backed routes for current runtime behavior.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'daemon-backed-pattern',
        title: 'Daemon-Backed Pattern',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={code`import { Agent, createRuntimeSubstrateClient } from "@ioi/agent-sdk";

const agent = await Agent.create({
  model: { id: "local:auto" },
  local: { cwd: process.cwd() },
  substrateClient: createRuntimeSubstrateClient({
    endpoint: process.env.IOI_DAEMON_ENDPOINT,
  }),
});

const run = await agent.send("Build a repo-grounded implementation plan");
for await (const event of run.stream()) {
  console.log(event.cursor, event.type, event.summary);
}`}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'examples-and-templates',
    title: 'Examples & Templates',
    eyebrow: 'Build',
    summary:
      'Repo-backed examples exist today, but the public template gallery is a preview until examples are curated, named, and validated as launch assets.',
    section: 'build',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'sdk_builder',
    routePath: '/examples',
    legacyHashes: ['examples', 'templates', 'build-your-first-chat-artifact'],
    lastVerified: LAST_VERIFIED,
    keywords: ['examples', 'templates', 'quickstart-local', 'gallery'],
    sources: ['packages/agent-sdk/examples/quickstart-local.ts', 'packages/agent-sdk/test/sdk.test.mjs', 'apps/hypervisor/scripts'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Tutorials', href: '#tutorials', description: 'Follow practical build-guide tracks.' },
      { label: 'SDKs & Libraries', href: '#sdks-and-libraries', description: 'Understand what each example imports.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The repo includes SDK examples, tests, daemon probes, model-mount probes, benchmark
              fixtures, and Autopilot desktop harness scripts. The public examples gallery is not
              yet a polished marketplace of templates.
            </p>
            <Table
              isDark={isDark}
              headers={['Example type', 'Current source', 'Public framing']}
              rows={[
                ['SDK test fixture', <code>packages/agent-sdk/examples/quickstart-local.ts</code>, 'Offline fixture for no-daemon examples and tests.'],
                ['Daemon-backed tests', <code>packages/agent-sdk/test/sdk.test.mjs</code>, 'Evidence for route coverage and SDK behavior.'],
                ['Autopilot probes', <code>apps/hypervisor/scripts/*probe*</code>, 'Local GUI/runtime evidence, not a hosted examples product.'],
                ['Benchmark fixtures', <code>apps/benchmarks</code>, 'Current evidence surface for evaluation routes.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'launch-template-rule',
        title: 'Launch Template Rule',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="preview" title="Do not overstate templates">
              <p>
                A template becomes public-current only when it has a stable route, a runnable
                command, validation output, and a clear distinction between fixture, local daemon,
                and production deployment.
              </p>
            </Callout>
          </div>
        ),
      },
    ],
  },
  {
    id: 'tutorials',
    title: 'Tutorials',
    eyebrow: 'Build',
    summary:
      'Tutorial tracks are ready to organize around builder jobs, but should stay preview until each guide has runnable commands and validation evidence.',
    section: 'build',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: false,
    sourceFreshness: 'product_preview',
    primaryAudience: 'new_builder',
    routePath: '/tutorials',
    legacyHashes: ['tutorials', 'guides'],
    lastVerified: LAST_VERIFIED,
    keywords: ['tutorials', 'guides', 'step by step'],
    sources: ['.internal/plans/developers-ioi-ai-ship-shape-master-guide.md', 'packages/agent-sdk/examples/quickstart-local.ts'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Quickstart', href: '#quickstart', description: 'Use the launch-ready onboarding path first.' },
      { label: 'Examples & Templates', href: '#examples-and-templates', description: 'See what exists today in repo-backed examples.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Tutorials are a public IA lane, not yet a complete tutorial library. The right launch
              posture is to show the lane, link to current quickstarts/examples, and mark deeper
              build guides as preview until each one is runnable and validated.
            </p>
            <Table
              isDark={isDark}
              headers={['Track', 'Launch framing']}
              rows={[
                ['Build an SDK agent', 'Current once the daemon-backed command and expected output are validated.'],
                ['Mount a local model', 'Current for local/admin model API; tutorial copy should warn about local resource requirements.'],
                ['Import MCP tools', 'Current for daemon endpoints; tutorial should include validation and authority notes.'],
                ['Package a worker service', 'Preview until service candidate packaging has public release gates.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'ioi-cli',
    title: 'IOI CLI',
    eyebrow: 'Build',
    summary:
      'CLI and harness commands are current repo surfaces for daemon/runtime work, benchmarking, computer-use suites, and local probes; public command docs should stay builder-level.',
    section: 'build',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'operator',
    routePath: '/cli',
    legacyHashes: ['ioi-cli-overview', 'cli', 'tui'],
    lastVerified: LAST_VERIFIED,
    keywords: ['cli', 'tui', 'harness', 'benchmark', 'daemon'],
    sources: ['crates/cli', 'apps/hypervisor/scripts', 'packages/runtime-daemon/package.json'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'Understand what CLI commands inspect or drive.' },
      { label: 'Benchmarks', href: '#benchmarks', description: 'See benchmark and visual smoke evidence lanes.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The repo contains Rust CLI code, benchmark targets, computer-use suite outputs,
              runtime daemon scripts, and Autopilot desktop probes. This page is a command-family
              map until public command names are frozen.
            </p>
            <Table
              isDark={isDark}
              headers={['Family', 'Use it for']}
              rows={[
                ['Runtime/daemon', 'Start or probe the local daemon and inspect route families.'],
                ['Benchmark/computer-use', 'Run browser/computer-use suites and collect trace bundles.'],
                ['Model mounts', 'Exercise catalog, download, import, load, unload, and local compatibility routes.'],
                ['Autopilot desktop probes', 'Launch and validate local GUI behavior with screenshots and runtime artifacts.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'autopilot',
    title: 'Autopilot',
    eyebrow: 'Run',
    summary:
      'Autopilot is the current local desktop workbench over chat, artifacts, workflow canvas, model mounting, MCP, policy, and harness evidence.',
    section: 'run',
    status: 'Current',
    maturity: 'local_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'operator',
    routePath: '/hypervisor',
    legacyHashes: ['run-autopilot-locally', 'autopilot', 'autopilot-desktop'],
    lastVerified: LAST_VERIFIED,
    keywords: ['hypervisor', 'desktop', 'GUI', 'screenshots', 'workflow canvas', 'chat', 'harness'],
    sources: [
      'apps/hypervisor',
      'apps/hypervisor/src/windows/HypervisorShellWindow',
      'apps/hypervisor/src/windows/ChatShellWindow',
      'apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx',
      'docs/evidence/autopilot-gui-harness-validation/2026-05-15T11-10-45-852Z/result.json',
      'docs/evidence/autopilot-gui-harness-validation/2026-05-15T11-10-45-852Z/workflow-terminal-coding-loop-run-button-proof.json',
      'docs/evidence/autopilot-gui-harness-validation/2026-05-15T11-10-45-852Z/workflow-telemetry-budget-chain-run-inspector-proof.json',
      'docs/evidence/autopilot-gui-harness-validation/2026-05-15T11-10-45-852Z/promotion-transition-gui-behavior-proof.json',
    ],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'See the daemon route families Autopilot projects.' },
      { label: 'Model Mounting', href: '#model-mounting', description: 'Manage local model catalog and compatibility routes.' },
      { label: 'MCP Tools', href: '#mcp-tools', description: 'Import, validate, discover, and invoke tools.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Hypervisor exists today as a native operator client over Hypervisor Core and
              the IOI daemon. The current repo includes chat and artifact surfaces,
              workflow composer/runtime wiring, local model mount UI, MCP import
              surfaces, policy/settings views, generated contracts, and GUI harness evidence.
            </p>
            <Table
              isDark={isDark}
              headers={['Surface', 'Current status']}
              rows={[
                ['Chat workbench', 'Current local GUI with answer-first transcript, sources, artifacts, approvals, and runtime disclosures.'],
                ['Workflow canvas', 'Current local workflow composition and harness proof path, with active preview areas for packaging/import review.'],
                ['Model mounts', 'Current local/admin UI over /v1/model-mount/snapshot and /v1/chat/completions compatibility.'],
                ['MCP tools', 'Current import/discovery/invocation paths in daemon and Hypervisor surfaces.'],
                ['Evidence harness', 'Current desktop probes capture screenshots, runtime artifacts, receipts, and logs.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'workflow-snapshots',
        title: 'Workflow Snapshots',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              These snapshots are not decorative harness artifacts. They show useful Autopilot
              workflows with the proof files that back the UI behavior. The manifest under
              <code> public/media/screenshots/autopilot/manifest.json</code> records source paths,
              capture time, review notes, and redaction status.
            </p>
            <div className="grid gap-5 lg:grid-cols-2">
              <ScreenshotFigure
                isDark={isDark}
                src="/media/screenshots/autopilot/workflow-canvas.png"
                alt="Autopilot workflow canvas with local GUI interaction evidence"
                caption="Workflow compositor: default agent harness topology with fork/use-template controls and promotion gates."
              />
              <ScreenshotFigure
                isDark={isDark}
                src="/media/screenshots/autopilot/source-grounded-workflow.png"
                alt="Autopilot source-grounded chat workflow with cited repo evidence"
                caption="Source-grounded chat workflow: answer-first response with cited repo files and compact runtime steps."
              />
              <ScreenshotFigure
                isDark={isDark}
                src="/media/screenshots/autopilot/safety-boundary.png"
                alt="Autopilot safety boundary refusing destructive codebase deletion without governed approval"
                caption="Safety-boundary workflow: destructive repository deletion is blocked without an explicit governed approval path."
              />
            </div>
          </div>
        ),
      },
      {
        id: 'compositor-workflows',
        title: 'Compositor Workflows',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The workflow compositor is the most mature Autopilot workflow surface today. The
              public docs should show the workflows builders can reason about, then point to proof
              files instead of asking readers to trust screenshots alone.
            </p>
            <Table
              isDark={isDark}
              headers={['Workflow', 'What the GUI shows', 'Proof file']}
              rows={[
                [
                  'Terminal coding loop',
                  'Workspace status, git diff, file inspect, patch dry-run, approval-gated patch apply, tests, LSP diagnostics, artifact read, and result retrieval.',
                  <code>workflow-terminal-coding-loop-run-button-proof.json</code>,
                ],
                [
                  'Telemetry budget chain',
                  'Usage meter, context budget, compaction policy, and coding budget gate wired into a runtime-readiness chain.',
                  <code>workflow-telemetry-budget-chain-run-inspector-proof.json</code>,
                ],
                [
                  'Promotion to gated/live',
                  'Cluster promotion controls that block missing receipts/replay/canary/rollback evidence, then allow gated and live promotion when proof exists.',
                  <code>promotion-transition-gui-behavior-proof.json</code>,
                ],
                [
                  'Rollback and restore canary',
                  'Activation gates, package evidence manifest, replay drill, rollback receipt selection, and restoration proof surfaces.',
                  <code>rollback-restore-canary-ui-proof.json</code>,
                ],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'capture-lane',
        title: 'Docs Media Capture Lane',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Prefer current Hypervisor App evidence for product screenshots because it exercises the
              active Code editor adapter-host path. For web-applicable docs routes, use the developers app visual smoke
              lane after the Vite preview server is running:
            </p>
            <CodeBlock
              isDark={isDark}
              code="npm run smoke:routes --workspace=apps/developers-ioi-ai"
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'runtime-daemon',
    title: 'Runtime Daemon',
    eyebrow: 'Run',
    summary:
      'The runtime daemon is the current local product API for agents, runs, events, traces, MCP, memory, model mounting, and Agentgres v0 local store projection.',
    section: 'run',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'operator',
    routePath: '/runtime',
    legacyHashes: ['runtime-daemon', 'policies-approvals-and-receipts', 'runtime'],
    lastVerified: LAST_VERIFIED,
    keywords: ['runtime', 'daemon', 'Agentgres', 'events', 'traces', 'receipts'],
    sources: ['packages/runtime-daemon/src/index.mjs', 'docs/architecture/components/daemon-runtime/api.md', 'internal-docs/implementation/runtime-module-map.md'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'API Reference', href: '#api-reference', description: 'Browse the route-family map.' },
      { label: 'Model Mounting', href: '#model-mounting', description: 'Manage local models through daemon/admin routes.' },
      { label: 'MCP Tools', href: '#mcp-tools', description: 'Connect external tools under runtime governance.' },
    ],
    sections: [
      {
        id: 'current-boundary',
        title: 'Current Boundary',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The daemon is the local runtime boundary that SDKs, CLI/headless clients, Workbench
              adapter hosts, Hypervisor App/Web, benchmarks, and probes should target. The current implementation includes an
              <code> AgentgresRuntimeStateStore</code> as the Agentgres v0 local store proof for
              runs, tasks, artifacts, receipts, policy decisions, traces, and projections.
            </p>
            <Callout isDark={isDark} tone="current" title="Agentgres v0 local store">
              <p>
                Agentgres v0 is local/current here: enough state substrate for daemon-backed
                runtime proof, not the final multi-domain Agentgres production deployment.
              </p>
            </Callout>
          </div>
        ),
      },
      {
        id: 'route-families',
        title: 'Route Families',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Area', 'Routes']}
              rows={[
                ['Agents/runs', <code>/v1/agents, /v1/runs/{'{run_id}'}/events, /v1/runs/{'{run_id}'}/trace</code>],
                ['MCP', <code>/v1/mcp, /v1/mcp/tools, /v1/mcp/import, /v1/mcp/serve</code>],
                ['Memory', <code>/v1/memory, /v1/memory/records, /v1/memory/validate</code>],
                ['Models', <code>/v1/model-mount/snapshot, /v1/model-mount/instances/load, /v1/chat/completions</code>],
                ['Artifacts/receipts', <code>/v1/runs/{'{run_id}'}/artifacts, /v1/runs/{'{run_id}'}/receipts</code>],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'model-mounting',
    title: 'Model Mounting',
    eyebrow: 'Run',
    summary:
      'Local model mounting is a current daemon/admin and Autopilot surface for catalog search, download, import, mount, load, unload, and OpenAI-compatible chat.',
    section: 'run',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'operator',
    routePath: '/model-mounting',
    legacyHashes: ['model-mounting', 'models', 'local-models'],
    lastVerified: LAST_VERIFIED,
    keywords: ['model mounting', 'models', 'OpenAI compatible', 'LM Studio', 'Ollama'],
    sources: ['packages/runtime-daemon/src/model-mounting.mjs', 'apps/hypervisor/src/surfaces/MissionControl/MissionControlMountsView.tsx', 'packages/agent-sdk/src/model-mounts.ts'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'See the daemon boundary behind model routes.' },
      { label: 'API Reference', href: '#api-reference', description: 'Browse representative route families.' },
    ],
    sections: [
      {
        id: 'current-api',
        title: 'Current API',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Task', 'Route']}
              rows={[
                ['List models', <code>GET /v1/model-mount/snapshot</code>],
                ['Search catalog', <code>GET /v1/models/catalog/search</code>],
                ['Download', <code>POST /v1/model-mount/downloads</code>],
                ['Import local artifact', <code>POST /v1/model-mount/artifacts/import</code>],
                ['Mount or unmount', <code>POST /v1/model-mount/endpoints, DELETE /v1/model-mount/endpoints/:id</code>],
                ['Load or unload', <code>POST /v1/model-mount/instances/load, POST /v1/model-mount/instances/unload</code>],
                ['Use compatibility chat', <code>POST /v1/chat/completions</code>],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'compatibility-boundary',
        title: 'Compatibility Boundary',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="current" title="A model endpoint is not the worker API">
              <p>
                <code>/v1/chat/completions</code> is useful for OpenAI-compatible local inference.
                Persistent workers, policy, memory, traces, receipts, and marketplace packaging
                belong in the runtime/agent route families.
              </p>
            </Callout>
          </div>
        ),
      },
    ],
  },
  {
    id: 'mcp-tools',
    title: 'MCP Tools',
    eyebrow: 'Run',
    summary:
      'MCP/tool support is current in the daemon and SDK: validate servers, import tools, search capabilities, and invoke tools through governed runtime routes.',
    section: 'run',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'operator',
    routePath: '/mcp-tools',
    legacyHashes: ['mcp-tools', 'tools', 'mcp'],
    lastVerified: LAST_VERIFIED,
    keywords: ['mcp', 'tools', 'invoke', 'server', 'resources', 'prompts'],
    sources: ['packages/runtime-daemon/src/mcp-manager.mjs', 'packages/agent-sdk/src/substrate-client.ts', 'docs/architecture/components/daemon-runtime/api.md'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'API Reference', href: '#api-reference', description: 'See MCP in the product-facing API map.' },
      { label: 'Autopilot', href: '#autopilot', description: 'See how the desktop surface uses tool discovery.' },
    ],
    sections: [
      {
        id: 'current-routes',
        title: 'Current Routes',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Task', 'Route']}
              rows={[
                ['Status', <code>GET /v1/mcp</code>],
                ['Servers', <code>GET /v1/mcp/servers, POST /v1/mcp/servers</code>],
                ['Tools', <code>GET /v1/mcp/tools, GET /v1/mcp/tools/search, GET /v1/mcp/tools/{'{tool_id}'}</code>],
                ['Invocation', <code>POST /v1/mcp/tools/{'{tool_id}'}/invoke</code>],
                ['Resources/prompts', <code>GET /v1/mcp/resources, GET /v1/mcp/prompts</code>],
                ['Validation/import/serve', <code>POST /v1/mcp/validate, POST /v1/mcp/import, POST /v1/mcp/serve</code>],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'governance',
        title: 'Governance',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              MCP endpoints do not bypass runtime tool contracts, primitive capability
              requirements, authority scopes, approvals, receipts, or trace expectations.
            </p>
          </div>
        ),
      },
    ],
  },
  {
    id: 'benchmarks',
    title: 'Benchmarks',
    eyebrow: 'Run',
    summary:
      'Benchmarks and visual smoke tests are current evidence lanes for runtime behavior, computer-use traces, route health, and public docs route rendering.',
    section: 'run',
    status: 'Current',
    maturity: 'repo_current',
    repoBacked: true,
    runnableToday: true,
    sourceFreshness: 'current_repo',
    primaryAudience: 'operator',
    routePath: '/benchmarks',
    legacyHashes: ['benchmarks', 'evals', 'visual-smoke'],
    lastVerified: LAST_VERIFIED,
    keywords: ['benchmarks', 'evals', 'visual smoke', 'Playwright', 'screenshots'],
    sources: ['apps/benchmarks', 'apps/hypervisor/scripts', 'docs/evidence', 'apps/developers-ioi-ai/scripts/smoke-routes.mjs'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Autopilot', href: '#autopilot', description: 'Use current GUI evidence and public screenshot manifests.' },
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'Validate route families behind benchmark runs.' },
    ],
    sections: [
      {
        id: 'evidence-lanes',
        title: 'Evidence Lanes',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Lane', 'What it proves']}
              rows={[
                ['Autopilot GUI harness', 'Desktop chat, workflow, safety, sources, and runtime evidence.'],
                ['Computer-use suites', 'Browser/control traces, receipts, diagnostics, and replay assets.'],
                ['Model mount probes', 'Catalog, download, load/unload, and compatibility-route behavior.'],
                ['Developers route smoke', 'Public docs routes render and key text is visible in browser automation.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'docs-visual-smoke',
        title: 'Docs Visual Smoke',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The developers app includes a route-smoke command that starts a local preview server
              and verifies major routes with Playwright when the dependency is available.
            </p>
            <CodeBlock
              isDark={isDark}
              code="npm run smoke:routes --workspace=apps/developers-ioi-ai"
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'service-candidate',
    title: 'Service Candidate Packaging',
    eyebrow: 'Ship',
    summary:
      'Service candidate packaging is the preview path for turning a local worker into a governed, portable service candidate before any production marketplace claim.',
    section: 'ship',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: false,
    sourceFreshness: 'product_preview',
    primaryAudience: 'marketplace_builder',
    routePath: '/ship/service-candidate',
    legacyHashes: ['package-a-service-candidate', 'service-candidate', 'ship'],
    lastVerified: LAST_VERIFIED,
    keywords: ['service candidate', 'package', 'worker', 'ship'],
    sources: ['docs/architecture/domains/sas/service-marketplace.md', 'docs/architecture/foundations/common-objects-and-envelopes.md', 'apps/hypervisor/src/windows/ChatShellWindow/components/ArtifactHubPackagingViews.tsx'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'sas.xyz', href: '#sas-xyz', description: 'Understand the provider marketplace preview.' },
      { label: 'aiagent.xyz', href: '#aiagent-xyz', description: 'Understand the discovery and procurement preview.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The repo has architecture, package/evidence concepts, Autopilot packaging UI code,
              and GUI proof assets. Treat service candidates as preview until packaging manifests,
              validation gates, import review, and release workflows are public-current.
            </p>
          </div>
        ),
      },
      {
        id: 'ship-checklist',
        title: 'Ship Checklist',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <ul className={listClass(isDark)}>
              <li>Bind worker identity, version, owner, runtime assignment, and authority scope.</li>
              <li>Attach evidence: tests, benchmark traces, receipts, model/tool requirements, and screenshots if UI-facing.</li>
              <li>State deployment maturity: local proof, private pilot, provider preview, or production candidate.</li>
              <li>Hand off protocol object depth to canonical docs instead of reproducing low-level specs here.</li>
            </ul>
          </div>
        ),
      },
    ],
  },
  {
    id: 'sas-xyz',
    title: 'sas.xyz',
    eyebrow: 'Ship',
    summary:
      'sas.xyz remains visible as the provider/service marketplace shape, but it is preview framing here rather than a claim of a live production marketplace.',
    section: 'ship',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: false,
    sourceFreshness: 'architecture',
    primaryAudience: 'marketplace_builder',
    routePath: '/ship/sas',
    legacyHashes: ['sas-xyz-provider-path', 'sas', 'sas-xyz'],
    lastVerified: LAST_VERIFIED,
    keywords: ['sas.xyz', 'service marketplace', 'provider', 'ship'],
    sources: ['docs/architecture/domains/sas/service-marketplace.md', 'docs/architecture/foundations/web4-and-ioi-stack.md'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Service Candidate Packaging', href: '#service-candidate', description: 'Package before presenting a service.' },
      { label: 'aiagent.xyz', href: '#aiagent-xyz', description: 'Compare provider and discovery paths.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              sas.xyz exists in the current architecture as the provider-side service marketplace
              direction. Public docs should describe the shape and prerequisites, not imply that
              listings, procurement, billing, ranking, or provider onboarding are production-live.
            </p>
          </div>
        ),
      },
      {
        id: 'provider-shape',
        title: 'Provider Shape',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Concern', 'Preview framing']}
              rows={[
                ['Service listing', 'A packaged worker/service candidate with evidence, scope, and terms.'],
                ['Provider trust', 'Receipts, benchmarks, versioning, and authority declarations.'],
                ['Delivery', 'Local, hosted, or sovereign-domain runtime depending on the service shape.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'aiagent-xyz',
    title: 'aiagent.xyz',
    eyebrow: 'Ship',
    summary:
      'aiagent.xyz remains the preview discovery/procurement path for portable workers, framed as future marketplace shape instead of live production inventory.',
    section: 'ship',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: false,
    sourceFreshness: 'architecture',
    primaryAudience: 'marketplace_builder',
    routePath: '/ship/aiagent',
    legacyHashes: ['aiagent-xyz-distribution-path', 'aiagent', 'aiagent-xyz'],
    lastVerified: LAST_VERIFIED,
    keywords: ['aiagent.xyz', 'worker marketplace', 'discovery', 'procurement'],
    sources: ['docs/architecture/domains/aiagent/worker-marketplace.md', 'docs/architecture/domains/aiagent/worker-endpoints.md'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Service Candidate Packaging', href: '#service-candidate', description: 'Understand the package boundary first.' },
      { label: 'Worker Training / MoW', href: '#worker-training-mow', description: 'See the concept lane for worker improvement.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              aiagent.xyz exists in architecture and endpoint design as the worker discovery and
              procurement direction. It should not be documented as a live production inventory,
              ranking system, billing layer, or procurement marketplace yet.
            </p>
          </div>
        ),
      },
      {
        id: 'worker-shape',
        title: 'Worker Shape',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Concern', 'Preview framing']}
              rows={[
                ['Discovery', 'Find workers by capability, evidence, compatibility, and deployment mode.'],
                ['Install/procure', 'Bind a worker to local Autopilot, daemon, hosted runtime, or sovereign domain.'],
                ['Compatibility', 'Worker value lives above /v1/chat/completions in agent, worker, and interagent routes.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'sovereign-domain-flows',
    title: 'Sovereign Domain Flows',
    eyebrow: 'Ship',
    summary:
      'Sovereign-domain flows stay visible as a preview deployment shape for customer-controlled kernels and Agentgres-backed domains.',
    section: 'ship',
    status: 'Preview',
    maturity: 'preview',
    repoBacked: true,
    runnableToday: false,
    sourceFreshness: 'architecture',
    primaryAudience: 'marketplace_builder',
    routePath: '/ship/sovereign-domain',
    legacyHashes: ['sovereign-domain', 'domain-kernels'],
    lastVerified: LAST_VERIFIED,
    keywords: ['sovereign domain', 'domain kernel', 'Agentgres', 'deployment'],
    sources: ['docs/architecture/foundations/domain-kernels.md', 'docs/architecture/foundations/web4-and-ioi-stack.md'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'Runtime Daemon', href: '#runtime-daemon', description: 'Start with local runtime boundaries.' },
      { label: 'sas.xyz', href: '#sas-xyz', description: 'Understand provider-side service packaging.' },
    ],
    sections: [
      {
        id: 'what-exists-today',
        title: 'What Exists Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Domain kernels and sovereign deployments are documented architecture, not a public
              self-serve deployment product in developers.ioi.ai. Use this page to orient builders
              toward the future shape while handing implementation depth to canonical docs.
            </p>
          </div>
        ),
      },
      {
        id: 'deployment-shape',
        title: 'Deployment Shape',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <ul className={listClass(isDark)}>
              <li>Local Autopilot or daemon domain for individual/private work.</li>
              <li>Provider-hosted service domain for packaged service candidates.</li>
              <li>Enterprise-private sovereign domain with customer-controlled kernel and Agentgres state.</li>
            </ul>
          </div>
        ),
      },
    ],
  },
  {
    id: 'worker-training-mow',
    title: 'Worker Training / MoW',
    eyebrow: 'Ship',
    summary:
      'Worker Training and MoW are concept-stage public shapes for improving workers from retained evidence, recipes, evaluation, and governed training loops.',
    section: 'ship',
    status: 'Concept',
    maturity: 'concept',
    repoBacked: true,
    runnableToday: false,
    sourceFreshness: 'architecture',
    primaryAudience: 'marketplace_builder',
    routePath: '/ship/worker-training-mow',
    legacyHashes: ['worker-training', 'mow', 'worker-training-mow', 'autopilot-foundry'],
    lastVerified: LAST_VERIFIED,
    keywords: ['worker training', 'MoW', 'Autopilot Foundry', 'data recipes', 'evaluation'],
    sources: ['docs/decisions/0004-worker-mow-and-training-doctrine.md', 'docs/architecture/foundations/domain-ontologies-and-data-recipes.md', 'internal-docs/implementation/roadmap-and-dependencies.md'],
    canonicalLinks: [canonicalDocsLink],
    nextSteps: [
      { label: 'aiagent.xyz', href: '#aiagent-xyz', description: 'See the worker discovery preview.' },
      { label: 'Service Candidate Packaging', href: '#service-candidate', description: 'Understand the package/evidence boundary.' },
    ],
    sections: [
      {
        id: 'concept-framing',
        title: 'Concept Framing',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="concept" title="Concept, not a live training marketplace">
              <p>
                Worker Training, MoW, and Autopilot Foundry describe a future improvement loop:
                retain governed evidence, define recipes, evaluate workers, and promote better
                versions. Public docs should not present this as a live marketplace or production
                training product yet.
              </p>
            </Callout>
          </div>
        ),
      },
      {
        id: 'current-building-blocks',
        title: 'Current Building Blocks',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Building block', 'Current maturity']}
              rows={[
                ['Autopilot evidence and artifacts', 'Current local GUI/runtime evidence.'],
                ['Benchmarks and traces', 'Current repo-backed evaluation assets.'],
                ['Domain ontologies and data recipes', 'Architecture/current docs, not fully productized.'],
                ['Worker promotion and marketplace packaging', 'Preview/concept depending on target surface.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
];

export function getDocPage(pageId: string): DocPage | undefined {
  return DOC_PAGES.find((page) => page.id === pageId);
}

export function firstPageForSection(sectionId: DocSectionId): DocPage | undefined {
  const group = NAV_GROUPS.find((section) => section.id === sectionId);
  return group?.pageIds.map(getDocPage).find(Boolean);
}

export function docPageByRoutePath(pathname: string): DocPage | undefined {
  const normalizedPath = normalizeRoutePath(pathname);
  return DOC_PAGES.find((page) => normalizeRoutePath(page.routePath) === normalizedPath);
}

export function docPageByLegacyHash(hash: string): DocPage | undefined {
  const normalizedHash = hash.replace(/^#/, '').trim();
  if (!normalizedHash) {
    return undefined;
  }

  return DOC_PAGES.find(
    (page) => page.id === normalizedHash || page.legacyHashes.includes(normalizedHash),
  );
}

export function routeForPageId(pageId: string): string {
  return getDocPage(pageId)?.routePath ?? getDocPage(DEFAULT_PAGE_ID)!.routePath;
}

export function sectionLabel(sectionId: DocSectionId): string {
  return NAV_GROUPS.find((section) => section.id === sectionId)?.label ?? sectionId;
}

export function matchesDocSearch(page: DocPage, query: string): boolean {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return true;
  }

  return [
    page.title,
    page.eyebrow,
    page.summary,
    page.section,
    page.status,
    page.maturity,
    page.routePath,
    ...page.keywords,
    ...page.sources,
  ]
    .join(' ')
    .toLowerCase()
    .includes(normalizedQuery);
}

export function statusDescription(page: DocPage): string {
  if (page.status === 'Current') {
    return page.runnableToday
      ? 'Ready to use against current repo behavior.'
      : 'Current repo-backed reference, but not a one-command flow.';
  }

  if (page.status === 'Preview') {
    return 'Preview: useful direction with a clear “what works today” boundary.';
  }

  return 'Concept: useful orientation, not a live production surface.';
}

function normalizeRoutePath(pathname: string): string {
  const withoutQuery = pathname.split('?')[0]?.split('#')[0] ?? '/';
  const trimmed = withoutQuery.replace(/\/+$/, '');
  return trimmed === '' ? '/' : trimmed;
}
