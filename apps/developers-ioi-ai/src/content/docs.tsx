import type { ReactNode } from 'react';
import { Callout, CodeBlock, StepList, Table } from '../components/UIComponents';

export type DocStatus = 'Current' | 'Preview' | 'Concept';
export type DocSectionId = 'overview' | 'get-started' | 'build' | 'ship' | 'reference';

export interface DocSectionMeta {
  id: DocSectionId;
  label: string;
  description: string;
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
  lastVerified: string;
  keywords: string[];
  sources: string[];
  canonicalLinks: DocLink[];
  nextSteps: DocLink[];
  sections: DocPageSection[];
}

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

export const DOC_SECTIONS: DocSectionMeta[] = [
  {
    id: 'overview',
    label: 'Overview',
    description: 'Mental models, boundaries, and the product surface map.',
  },
  {
    id: 'get-started',
    label: 'Get Started',
    description: 'The fastest trustworthy paths to running something real.',
  },
  {
    id: 'build',
    label: 'Build',
    description: 'Builder surfaces for CLI, Studio, SDKs, and governed execution.',
  },
  {
    id: 'ship',
    label: 'Ship',
    description: 'How stable local work becomes a service, listing, or sovereign domain.',
  },
  {
    id: 'reference',
    label: 'Reference',
    description: 'Current command families and durable quick-reference material.',
  },
];

export const DEFAULT_PAGE_ID = 'choose-the-right-surface';

export const DOC_PAGES: DocPage[] = [
  {
    id: 'choose-the-right-surface',
    title: 'Choose the Right Surface',
    eyebrow: 'Orientation',
    summary:
      'Use this page to decide whether you should start in Autopilot, IOI CLI, ioi-swarm, sas.xyz, aiagent.xyz, or the canonical docs layer.',
    section: 'overview',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['surface map', 'developers', 'docs', 'autopilot', 'cli', 'swarm', 'sas', 'aiagent', 'forge'],
    sources: [
      'apps/developers-ioi-ai/README.md',
      'docs/specs/ioi-cli.md',
      'docs/specs/autopilot/internal_product_spec.md',
      'docs/specs/sas_xyz.md',
      'docs/specs/aiagent_xyz.md',
    ],
    canonicalLinks: [
      {
        label: 'Need protocol and canonical reference docs?',
        href: 'https://docs.ioi.network',
        external: true,
      },
    ],
    nextSteps: [
      { label: 'Introduction to IOI', href: '#introduction-to-ioi' },
      { label: 'Local Setup', href: '#local-setup' },
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
    ],
    sections: [
      {
        id: 'surface-map',
        title: 'Surface Map',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The cleanest split in the current IOI ecosystem is altitude.{' '}
              <code>developers.ioi.ai</code> is the curated builder front door.{' '}
              <code>docs.ioi.network</code> is the canonical technical reference. The rest of the
              surfaces fit beneath that developer journey based on the job you are trying to do.
            </p>
            <Table
              isDark={isDark}
              headers={['Surface', 'Best for', 'Use it when']}
              rows={[
                ['developers.ioi.ai', 'Curated DX', 'You need onboarding, quickstarts, workflow guidance, and product-oriented docs.'],
                ['docs.ioi.network', 'Canonical reference', 'You need low-level specs, internals, operator docs, or formal protocol material.'],
                ['Autopilot', 'Private/local runtime', 'You want to run workers locally, supervise execution, work with Spotlight or Studio, and stay inside your trust boundary.'],
                ['IOI CLI', 'Kernel-adjacent toolchain', 'You want to scaffold projects, run local nodes, inspect artifacts, query state, and work close to the repo and runtime.'],
                ['ioi-swarm', 'Python SDK', 'You want to build agent logic in Python and connect it to runtime, policy, and receipted action flows.'],
                ['sas.xyz', 'Provider path', 'You want to package and productize repeatable worker delivery as a service.'],
                ['aiagent.xyz', 'Discovery and procurement', 'You want to distribute, compare, buy, install, or procure worker services.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'separation-of-concerns',
        title: 'Separation of Concerns',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="current" title="Front door vs source of truth">
              <p>
                <code>developers.ioi.ai</code> should summarize, teach, and route. It should not
                fork canonical protocol truth. When a topic becomes low-level or durable, link
                into <code>docs.ioi.network</code> rather than reproducing it here.
              </p>
            </Callout>
            <ul className={listClass(isDark)}>
              <li>
                Start with <code>developers.ioi.ai</code> for quickstarts, APIs, SDKs, tutorials,
                and surface selection.
              </li>
              <li>
                Go to <code>docs.ioi.network</code> for protocol, consensus, kernel/runtime,
                receipts, and operator reference.
              </li>
              <li>
                Treat preview product docs as orientation, not as the final source of public API
                contract truth.
              </li>
            </ul>
          </div>
        ),
      },
      {
        id: 'practical-starting-points',
        title: 'Practical Starting Points',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>Use the following shortcuts if you do not want the full ecosystem story first.</p>
            <ul className={listClass(isDark)}>
              <li>
                Want to generate or inspect artifacts? Start with{' '}
                <a className={linkClass(isDark)} href="#build-your-first-studio-artifact">
                  Build Your First Studio Artifact
                </a>
                .
              </li>
              <li>
                Want to understand the command line surface? Start with{' '}
                <a className={linkClass(isDark)} href="#ioi-cli-overview">
                  IOI CLI Overview
                </a>
                .
              </li>
              <li>
                Want to operate workers locally? Start with{' '}
                <a className={linkClass(isDark)} href="#run-autopilot-locally">
                  Run Autopilot Locally
                </a>
                .
              </li>
              <li>
                Want Python-first agent development? Start with{' '}
                <a className={linkClass(isDark)} href="#build-your-first-agent-with-ioi-swarm">
                  Build Your First Agent with ioi-swarm
                </a>
                .
              </li>
            </ul>
          </div>
        ),
      },
    ],
  },
  {
    id: 'introduction-to-ioi',
    title: 'Introduction to IOI',
    eyebrow: 'Mental model',
    summary:
      'IOI is a local-first, proof-oriented stack for running bounded autonomous software with explicit authority, policy gates, and receipt-bearing effects.',
    section: 'overview',
    status: 'Concept',
    lastVerified: '2026-03-31',
    keywords: ['introduction', 'bounded agency', 'ioi', 'overview', 'mental model'],
    sources: ['README.md', 'docs/specs/verifiable_bounded_agency.md'],
    canonicalLinks: [
      {
        label: 'Deep protocol and architecture reference',
        href: 'https://docs.ioi.network',
        external: true,
      },
    ],
    nextSteps: [
      { label: 'Choose the Right Surface', href: '#choose-the-right-surface' },
      { label: 'Policies, Approvals, and Receipts', href: '#policies-approvals-and-receipts' },
      { label: 'Run Autopilot Locally', href: '#run-autopilot-locally' },
    ],
    sections: [
      {
        id: 'core-thesis',
        title: 'Core Thesis',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="concept" title="This page is for orientation">
              <p>
                Use this page to get the developer mental model. For protocol claims, formal
                semantics, and lower-level internals, jump to <code>docs.ioi.network</code>.
              </p>
            </Callout>
            <p>
              IOI starts from a simple claim: models can be probabilistic, but authority cannot be.
              The runtime may plan, synthesize, and explore. Real-world effects must still cross
              explicit policy, capability, approval, and evidence boundaries before they execute.
            </p>
            <ul className={listClass(isDark)}>
              <li>Workers should not inherit ambient authority.</li>
              <li>Risk should be reduced by architecture, not just prompt advice.</li>
              <li>Important effects should be receipted, inspectable, and challengeable.</li>
              <li>
                Builders should be able to work locally first, then move toward service or sovereign
                network surfaces as needed.
              </li>
            </ul>
          </div>
        ),
      },
      {
        id: 'repo-today',
        title: 'What Exists In The Repo Today',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              This monorepo already contains multiple real builder surfaces. They are not all at
              the same maturity, but they are enough to support a serious first-pass docs site now.
            </p>
            <ul className={listClass(isDark)}>
              <li>
                <strong>IOI CLI:</strong> a kernel-adjacent toolchain for project scaffolding,
                local nodes, artifact workflows, query, trace, verify, policy, and dev tooling.
              </li>
              <li>
                <strong>Autopilot:</strong> a Tauri-based private/local runtime with Spotlight,
                Studio, gates, receipts, and a growing operator shell.
              </li>
              <li>
                <strong>Studio artifact pipeline:</strong> shared planning, generation,
                validation, and materialization helpers in the API and CLI layers.
              </li>
              <li>
                <strong>ioi-swarm:</strong> a Python SDK for agent construction with policy and
                receipted execution in view.
              </li>
              <li>
                <strong>Provider/discovery surfaces:</strong> <code>sas.xyz</code> and{' '}
                <code>aiagent.xyz</code> are documented enough to explain their role, even where
                UX and contracts are still evolving.
              </li>
            </ul>
          </div>
        ),
      },
      {
        id: 'developer-rule-of-thumb',
        title: 'Developer Rule Of Thumb',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The most useful shorthand for this docs surface is:
            </p>
            <CodeBlock
              isDark={isDark}
              code={`developers.ioi.ai = how to build with IOI
docs.ioi.network = how IOI works`}
            />
            <p>
              If a page is helping you choose a workflow, run a tool, or understand a product
              surface, it belongs here. If a page needs to become canonical technical truth, it
              should probably live on <code>docs.ioi.network</code>.
            </p>
          </div>
        ),
      },
    ],
  },
  {
    id: 'local-setup',
    title: 'Local Setup',
    eyebrow: 'Get started',
    summary:
      'Set up the monorepo for the developers docs app, Autopilot, and current builder surfaces without guessing at package or workspace structure.',
    section: 'get-started',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['setup', 'installation', 'monorepo', 'npm', 'rust', 'tauri'],
    sources: ['package.json', 'apps/developers-ioi-ai/README.md', 'apps/autopilot/README.md'],
    canonicalLinks: [],
    nextSteps: [
      { label: 'Build Your First Studio Artifact', href: '#build-your-first-studio-artifact' },
      { label: 'Run Autopilot Locally', href: '#run-autopilot-locally' },
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
    ],
    sections: [
      {
        id: 'prerequisites',
        title: 'Prerequisites',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Tooling', 'Needed for', 'Notes']}
              rows={[
                ['Node.js', 'Workspace apps', 'Required for the docs app and frontend surfaces. Node 20+ is a safe target.'],
                ['Rust', 'CLI and native runtime', 'Required for crates and the native desktop stack.'],
                ['Tauri CLI', 'Autopilot native shell', 'Only needed when you want the desktop runtime rather than web-only UI.'],
                ['Python 3.10+', 'ioi-swarm SDK', 'Required if you are following the Python agent path.'],
              ]}
            />
            <Callout isDark={isDark} tone="current" title="Current workspace shape">
              <p>
                The root <code>package.json</code> is a workspace file. Install once from the repo
                root, then use <code>--workspace</code> commands for app-specific flows.
              </p>
            </Callout>
          </div>
        ),
      },
      {
        id: 'monorepo-bootstrap',
        title: 'Monorepo Bootstrap',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <StepList
              isDark={isDark}
              steps={[
                {
                  title: 'Install workspace dependencies',
                  body: 'Run this once from the monorepo root.',
                  code: 'npm install',
                },
                {
                  title: 'Run the developers docs app',
                  body: 'This launches the docs shell on port 3000.',
                  code: 'npm run dev --workspace=apps/developers-ioi-ai',
                },
                {
                  title: 'Build the docs app',
                  body: 'Use this before publishing or validating the shell.',
                  code: 'npm run build --workspace=apps/developers-ioi-ai',
                },
              ]}
            />
          </div>
        ),
      },
      {
        id: 'common-next-commands',
        title: 'Common Next Commands',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={`# Agent Studio web shell
npm run dev:web

# Benchmarks app
npm run dev:benchmarks

# Docs app typecheck
npm run lint --workspace=apps/developers-ioi-ai`}
            />
            <p>
              If you are heading into the native runtime path, continue with the Autopilot page for
              Tauri dependencies and launch modes.
            </p>
          </div>
        ),
      },
    ],
  },
  {
    id: 'build-your-first-studio-artifact',
    title: 'Build Your First Studio Artifact',
    eyebrow: 'Get started',
    summary:
      'Generate a Studio artifact bundle through the shared CLI and API path using the mock runtime first, then graduate to a local inference runtime later.',
    section: 'get-started',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['studio', 'artifact', 'generate', 'validation', 'mock', 'cli'],
    sources: ['crates/cli/src/commands/artifact.rs', 'crates/api/src/studio.rs'],
    canonicalLinks: [],
    nextSteps: [
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
      { label: 'CLI Command Reference', href: '#cli-command-reference' },
      { label: 'Policies, Approvals, and Receipts', href: '#policies-approvals-and-receipts' },
    ],
    sections: [
      {
        id: 'why-this-path',
        title: 'Why Start Here',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The artifact path is one of the most implementation-backed builder flows in the repo
              today. It has a real CLI surface, a shared planning/generation/validation module, and a
              mock mode that lets you learn the workflow without immediately wiring a local model.
            </p>
            <Callout isDark={isDark} tone="current" title="Best first-run posture">
              <p>
                Use <code>--mock</code> for your first pass. Once the flow makes sense, move to{' '}
                <code>--local</code> with your inference endpoint, API URL, and model name.
              </p>
            </Callout>
          </div>
        ),
      },
      {
        id: 'artifact-quickstart',
        title: 'Quickstart',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <StepList
              isDark={isDark}
              steps={[
                {
                  title: 'Generate an artifact bundle in mock mode',
                  body: 'This uses the CLI binary from the workspace and writes a bundle to a local output directory.',
                  code: 'cargo run -p ioi-cli --bin cli -- artifact generate "Create a markdown release checklist for an IOI app launch." --output outputs/release-checklist --mock --force',
                },
                {
                  title: 'Inspect the typed validation result',
                  body: 'The validation command accepts the output directory or a direct path to generation.json.',
                  code: 'cargo run -p ioi-cli --bin cli -- artifact validation outputs/release-checklist --json',
                },
                {
                  title: 'Route a prompt without generating a full bundle',
                  body: 'Use route/query mode when you only want the shared planning contract.',
                  code: 'cargo run -p ioi-cli --bin cli -- artifact route "Build a pricing configurator page for a provider service." --mock --json',
                },
              ]}
            />
          </div>
        ),
      },
      {
        id: 'local-runtime-upgrade',
        title: 'Move From Mock To Local Runtime',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={`cargo run -p ioi-cli --bin cli -- artifact generate \\
  "Create a product landing page for a worker service." \\
  --output outputs/landing-page \\
  --local \\
  --api-url http://127.0.0.1:11434/v1 \\
  --model-name your-local-model \\
  --force`}
            />
            <p>
              The exact inference endpoint and model will depend on your local setup. The CLI also
              exposes acceptance validation parameters when you want a separate runtime for the proof or
              validation lane.
            </p>
          </div>
        ),
      },
    ],
  },
  {
    id: 'run-autopilot-locally',
    title: 'Run Autopilot Locally',
    eyebrow: 'Get started',
    summary:
      'Autopilot is the private/local runtime surface. Use it when you want a desktop-first operator shell with Spotlight, Studio, gates, and receipts.',
    section: 'get-started',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['autopilot', 'tauri', 'desktop', 'spotlight', 'studio', 'runtime'],
    sources: [
      'apps/autopilot/README.md',
      'apps/autopilot/package.json',
      'docs/specs/autopilot/internal_product_spec.md',
    ],
    canonicalLinks: [],
    nextSteps: [
      { label: 'Policies, Approvals, and Receipts', href: '#policies-approvals-and-receipts' },
      { label: 'Choose the Right Surface', href: '#choose-the-right-surface' },
      { label: 'Build Your First Studio Artifact', href: '#build-your-first-studio-artifact' },
    ],
    sections: [
      {
        id: 'runtime-shape',
        title: 'Runtime Shape',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Autopilot is not just a chat surface. In the repo today it is a native Tauri runtime
              with multiple windows, cross-window state sync, a gate model for risky actions, and a
              growing Studio path for artifacts and orchestration.
            </p>
            <ul className={listClass(isDark)}>
              <li>Spotlight window for intent intake.</li>
              <li>Pill window for non-blocking task progress.</li>
              <li>Gate window for approvals.</li>
              <li>Studio window for builder and artifact-oriented workflows.</li>
            </ul>
          </div>
        ),
      },
      {
        id: 'launch-modes',
        title: 'Launch Modes',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <StepList
              isDark={isDark}
              steps={[
                {
                  title: 'Web-only UI for quick inspection',
                  body: 'This is useful if you only need the frontend shell and not the native runtime.',
                  code: 'npm run dev --workspace=apps/autopilot',
                },
                {
                  title: 'Repo-level desktop helper',
                  body: 'The workspace exposes desktop helper scripts at the root.',
                  code: 'npm run dev:desktop',
                },
                {
                  title: 'Direct native launch from the app workspace',
                  body: 'Use this when you are working directly inside the Autopilot app.',
                  code: 'cd apps/autopilot && npm run tauri dev',
                },
              ]}
            />
          </div>
        ),
      },
      {
        id: 'system-dependencies',
        title: 'System Dependencies',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The README already includes the Ubuntu/Pop!_OS packages required by Tauri. Keep those
              instructions as the source of truth for Linux desktop prerequisites.
            </p>
            <CodeBlock
              isDark={isDark}
              code={`sudo apt update
sudo apt install -y \\
  build-essential \\
  pkg-config \\
  libssl-dev \\
  libgtk-3-dev \\
  libayatana-appindicator3-dev \\
  librsvg2-dev \\
  libsoup-3.0-dev \\
  libwebkit2gtk-4.1-dev`}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'build-your-first-agent-with-ioi-swarm',
    title: 'Build Your First Agent with ioi-swarm',
    eyebrow: 'Get started',
    summary:
      'Use the Python SDK when you want a lightweight path to agent construction while keeping IOI memory, policy, and receipt concepts in scope.',
    section: 'get-started',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['python', 'sdk', 'swarm', 'agent', 'quickstart'],
    sources: ['ioi-swarm/python/README.md', 'ioi-swarm/python/pyproject.toml'],
    canonicalLinks: [
      {
        label: 'Protocol-level swarm docs',
        href: 'https://docs.ioi.network',
        external: true,
      },
    ],
    nextSteps: [
      { label: 'Policies, Approvals, and Receipts', href: '#policies-approvals-and-receipts' },
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
    ],
    sections: [
      {
        id: 'install-sdk',
        title: 'Install The SDK',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock isDark={isDark} code="pip install ioi-swarm" />
            <p>
              The current package metadata requires Python 3.10+ and ships as the{' '}
              <code>ioi-swarm</code> package from <code>ioi-swarm/python</code>.
            </p>
          </div>
        ),
      },
      {
        id: 'minimal-agent',
        title: 'Minimal Agent',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={`from ioi_swarm import Agent, tool, ActionTarget

agent = Agent(name="Autopilot", policy_id="finance-restricted")

@tool(name="get_balance", target=ActionTarget.FS_READ)
def check_vault_balance(vault_id: str):
    return 100.0

agent.register_tool(check_vault_balance)
agent.run("Check my vault balance and alert me if it's below 50")`}
            />
            <p>
              This quickstart is intentionally narrow. The useful part is the shape: define an
              agent, bind a tool to an action target, register it, then run inside a policy-aware
              path.
            </p>
          </div>
        ),
      },
      {
        id: 'what-to-expect',
        title: 'What To Expect',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <ul className={listClass(isDark)}>
              <li>
                The SDK is framed around sovereign/autonomous agents rather than generic prompt
                wrappers.
              </li>
              <li>
                Full verification and settlement capabilities expect a running IOI node in the
                broader stack.
              </li>
              <li>
                Ghost Mode is already documented as a practical path for synthesizing least-privilege
                policy from observed traces.
              </li>
            </ul>
          </div>
        ),
      },
    ],
  },
  {
    id: 'ioi-cli-overview',
    title: 'IOI CLI Overview',
    eyebrow: 'Build',
    summary:
      'The CLI is the kernel-adjacent builder surface. It is the best current entry point for scaffolding, local nodes, artifacts, query, trace, verify, and policy workflows.',
    section: 'build',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['cli', 'command line', 'artifact', 'node', 'query', 'verify', 'policy'],
    sources: ['crates/cli/src/main.rs', 'docs/specs/ioi-cli.md', 'crates/cli/Cargo.toml'],
    canonicalLinks: [],
    nextSteps: [
      { label: 'CLI Command Reference', href: '#cli-command-reference' },
      { label: 'Build Your First Studio Artifact', href: '#build-your-first-studio-artifact' },
      { label: 'Policies, Approvals, and Receipts', href: '#policies-approvals-and-receipts' },
    ],
    sections: [
      {
        id: 'what-it-is',
        title: 'What It Is',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              In the codebase today, the CLI crate is named <code>ioi-cli</code> and exposes a
              binary named <code>cli</code>. The long-term product naming direction in the spec is
              "IOI CLI", with <code>forge</code> treated as an important namespace rather than the
              entire top-level brand.
            </p>
            <Callout isDark={isDark} tone="current" title="Safe way to invoke it from the repo">
              <p>
                Use <code>cargo run -p ioi-cli --bin cli -- &lt;command&gt;</code> while the CLI
                surface is evolving. That keeps the workspace package and binary names explicit.
              </p>
            </Callout>
          </div>
        ),
      },
      {
        id: 'starter-workflows',
        title: 'Starter Workflows',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Workflow', 'Command family', 'Best first use']}
              rows={[
                ['Scaffold a project', 'init / scaffold', 'Create a new IOI project shape or add services/contracts to a workspace.'],
                ['Generate artifacts', 'artifact', 'Run route/generate/validate/materialize flows through the shared Studio path.'],
                ['Run a local node', 'node / query', 'Bring up a local validator and inspect state or chain status.'],
                ['Inspect execution', 'trace / verify', 'Understand traces and determinism evidence after a run.'],
                ['Synthesize policy', 'policy / ghost', 'Turn recorded traces into a first-pass least-privilege policy.'],
                ['Developer utilities', 'dev', 'Use injection/debug/export helpers while the platform is still rapidly evolving.'],
              ]}
            />
          </div>
        ),
      },
      {
        id: 'first-commands',
        title: 'First Commands',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={`# Show the top-level command surface
cargo run -p ioi-cli --bin cli -- --help

# Generate a mock artifact bundle
cargo run -p ioi-cli --bin cli -- artifact generate "Draft a launch checklist." --output outputs/launch-checklist --mock --force

# Start a local node
cargo run -p ioi-cli --bin cli -- node

# Query chain status
cargo run -p ioi-cli --bin cli -- query status`}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'policies-approvals-and-receipts',
    title: 'Policies, Approvals, and Receipts',
    eyebrow: 'Build',
    summary:
      'This is the bounded-execution layer for developers: use policy synthesis, explicit approvals, and verification flows to keep actions inspectable and authority narrow.',
    section: 'build',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['policy', 'receipt', 'verify', 'ghost', 'approval', 'determinism'],
    sources: [
      'docs/specs/verifiable_bounded_agency.md',
      'crates/cli/src/commands/policy.rs',
      'crates/cli/src/commands/verify.rs',
      'crates/cli/src/commands/ghost.rs',
      'crates/services/src/agentic/runtime/README.md',
    ],
    canonicalLinks: [
      {
        label: 'Canonical technical reference for protocol and evidence semantics',
        href: 'https://docs.ioi.network',
        external: true,
      },
    ],
    nextSteps: [
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
      { label: 'Run Autopilot Locally', href: '#run-autopilot-locally' },
      { label: 'Build Your First Agent with ioi-swarm', href: '#build-your-first-agent-with-ioi-swarm' },
    ],
    sections: [
      {
        id: 'bounded-authority',
        title: 'Bounded Authority',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The repo's security posture is consistent across the conceptual docs and the runtime
              code: models can propose actions, but they should not silently inherit broad power.
              Authority is narrowed by policy, approvals, scopes, leases, and evidence-bearing
              execution.
            </p>
            <ul className={listClass(isDark)}>
              <li>Use policies to define what a worker may do.</li>
              <li>Use approvals when a step crosses a higher-risk threshold.</li>
              <li>Use receipts and verification to inspect what actually happened.</li>
            </ul>
          </div>
        ),
      },
      {
        id: 'practical-commands',
        title: 'Practical Commands',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <StepList
              isDark={isDark}
              steps={[
                {
                  title: 'Generate a policy from a session trace',
                  body: 'This pulls step traces from the local node and synthesizes a JSON policy.',
                  code: 'cargo run -p ioi-cli --bin cli -- policy generate <session-id-hex> --policy-id auto-policy-v1 --output policy.json',
                },
                {
                  title: 'Distill a policy with Ghost Mode',
                  body: 'Ghost Mode emphasizes the same idea from a distinct command family.',
                  code: 'cargo run -p ioi-cli --bin cli -- ghost distill <session-id-hex> --output policy.json',
                },
                {
                  title: 'Verify determinism-boundary evidence',
                  body: 'Use this when you want to inspect a specific session step and evidence bundle.',
                  code: 'cargo run -p ioi-cli --bin cli -- verify determinism <session-id-hex> --step 0 --rpc 127.0.0.1:8555',
                },
              ]}
            />
          </div>
        ),
      },
      {
        id: 'where-approvals-show-up',
        title: 'Where Approvals Show Up',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              In the desktop runtime, approvals are a lived UX surface rather than an abstract
              policy idea. The current service lifecycle already describes paused sessions waiting on
              signed approval tokens before an agent resumes a blocked action.
            </p>
            <Callout isDark={isDark} tone="current" title="Practical split">
              <p>
                Use Autopilot when you want the operator-facing approval UX. Use the CLI when you
                want trace, synthesis, verification, and lower-level evidence workflows.
              </p>
            </Callout>
          </div>
        ),
      },
    ],
  },
  {
    id: 'from-autopilot-to-service-candidate',
    title: 'From Autopilot to Service Candidate',
    eyebrow: 'Ship',
    summary:
      'Autopilot is the place to stabilize private/local work. Once a workflow becomes repeatable, the product path branches toward service packaging or heavier sovereign domain flows.',
    section: 'ship',
    status: 'Preview',
    lastVerified: '2026-03-31',
    keywords: ['promotion path', 'service candidate', 'autopilot', 'sas', 'forge'],
    sources: [
      'docs/specs/autopilot/internal_product_spec.md',
      'docs/specs/sas_xyz.md',
      'docs/specs/ioi-cli.md',
    ],
    canonicalLinks: [],
    nextSteps: [
      { label: 'Using sas.xyz to Productize Worker Delivery', href: '#using-sas-xyz-to-productize-worker-delivery' },
      { label: 'When to Use Forge or Sovereign Domain Flows', href: '#when-to-use-forge-or-sovereign-domain-flows' },
    ],
    sections: [
      {
        id: 'promotion-doctrine',
        title: 'Promotion Doctrine',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Callout isDark={isDark} tone="preview" title="Current doctrine">
              <p>
                The most stable current product distinction is: Autopilot stabilizes work,{' '}
                <code>sas.xyz</code> productizes it, and Forge or IOI CLI own the heavier sovereign
                domain path.
              </p>
            </Callout>
            <ul className={listClass(isDark)}>
              <li>Keep early experimentation and supervision in Autopilot.</li>
              <li>
                Promote repeatable delivery into a service candidate when the workflow can be
                versioned, bounded, and reused.
              </li>
              <li>
                Move toward the sovereign domain path only when durable policy, delegation,
                publication, or execution-economy semantics really matter.
              </li>
            </ul>
          </div>
        ),
      },
      {
        id: 'practical-branching',
        title: 'Practical Branching',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['If your work has become...', 'Next likely surface', 'Why']}
              rows={[
                ['A stable private operator workflow', 'Autopilot', 'Keep refining and supervising it locally.'],
                ['A reusable provider-facing service', 'sas.xyz', 'You need manifests, contracts, deployment posture, and productization.'],
                ['A demand-facing listing or install path', 'aiagent.xyz', 'You need discovery, comparison, routing, or procurement.'],
                ['A sovereign execution domain', 'IOI CLI / Forge direction', 'You need domain roots, policy permanence, and heavier lifecycle semantics.'],
              ]}
            />
          </div>
        ),
      },
    ],
  },
  {
    id: 'using-sas-xyz-to-productize-worker-delivery',
    title: 'Using sas.xyz to Productize Worker Delivery',
    eyebrow: 'Ship',
    summary:
      'sas.xyz is the provider operating path. Use it when stable worker delivery needs manifests, contracts, deployment posture, tenant controls, and commercialization.',
    section: 'ship',
    status: 'Preview',
    lastVerified: '2026-03-31',
    keywords: ['sas.xyz', 'provider', 'service as software', 'deploy', 'productize'],
    sources: ['apps/sas-xyz/README.md', 'docs/specs/sas_xyz.md'],
    canonicalLinks: [],
    nextSteps: [
      { label: 'From Autopilot to Service Candidate', href: '#from-autopilot-to-service-candidate' },
      { label: 'Using aiagent.xyz for Discovery and Procurement', href: '#using-aiagent-xyz-for-discovery-and-procurement' },
    ],
    sections: [
      {
        id: 'what-sas-owns',
        title: 'What sas.xyz Owns',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              The current product story for <code>sas.xyz</code> is consistent: providers use it to
              package and operate repeatable worker delivery as a service.
            </p>
            <ul className={listClass(isDark)}>
              <li>Service manifests and contracts.</li>
              <li>Capability requirements and operating envelopes.</li>
              <li>Deployment presets across local, hosted, BYOK, or customer boundaries.</li>
              <li>Billing, tenant controls, and distribution posture.</li>
            </ul>
          </div>
        ),
      },
      {
        id: 'what-sas-does-not-own',
        title: 'What It Does Not Own',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <ul className={listClass(isDark)}>
              <li>It is not the private/local operator shell. That remains Autopilot.</li>
              <li>
                It is not the canonical domain-instantiation surface. That remains the IOI CLI /
                Forge direction.
              </li>
              <li>
                It is not the discovery marketplace. That role belongs to <code>aiagent.xyz</code>.
              </li>
            </ul>
          </div>
        ),
      },
    ],
  },
  {
    id: 'using-aiagent-xyz-for-discovery-and-procurement',
    title: 'Using aiagent.xyz for Discovery and Procurement',
    eyebrow: 'Ship',
    summary:
      'aiagent.xyz is the demand-side market layer. Use it to route buyers toward published worker services or bespoke procurement, not as a provider console.',
    section: 'ship',
    status: 'Preview',
    lastVerified: '2026-03-31',
    keywords: ['aiagent.xyz', 'marketplace', 'discovery', 'procurement', 'listing'],
    sources: ['apps/aiagent-xyz/README.md', 'docs/specs/aiagent_xyz.md'],
    canonicalLinks: [],
    nextSteps: [
      { label: 'Using sas.xyz to Productize Worker Delivery', href: '#using-sas-xyz-to-productize-worker-delivery' },
      { label: 'Choose the Right Surface', href: '#choose-the-right-surface' },
    ],
    sections: [
      {
        id: 'two-market-loops',
        title: 'Two Market Loops',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <Table
              isDark={isDark}
              headers={['Loop', 'Object type', 'Typical buyer action']}
              rows={[
                ['Productized service loop', 'Published service object', 'Compare, buy, install, run, or route to an API/provider path.'],
                ['Bespoke procurement loop', 'Procurement request object', 'Post a need, compare providers, and procure custom delivery.'],
              ]}
            />
            <p>
              The important rule is not to collapse those two objects into one confusing marketplace
              story.
            </p>
          </div>
        ),
      },
      {
        id: 'routing-role',
        title: 'Routing Role',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              <code>aiagent.xyz</code> should route demand toward the right next surface rather than
              absorb every downstream job itself.
            </p>
            <ul className={listClass(isDark)}>
              <li>Run now through a hosted demand UX.</li>
              <li>Install into a private/local runtime.</li>
              <li>Call a provider API.</li>
              <li>Contact a provider for an enterprise or bespoke path.</li>
            </ul>
          </div>
        ),
      },
    ],
  },
  {
    id: 'when-to-use-forge-or-sovereign-domain-flows',
    title: 'When to Use Forge or Sovereign Domain Flows',
    eyebrow: 'Ship',
    summary:
      'Reach for the sovereign domain path when a system needs durable policy roots, publication semantics, or execution-economy behavior that is heavier than a single reusable service.',
    section: 'ship',
    status: 'Preview',
    lastVerified: '2026-03-31',
    keywords: ['forge', 'sovereign domain', 'ioi cli', 'init', 'scaffold', 'node'],
    sources: [
      'docs/specs/ioi-cli.md',
      'crates/cli/src/commands/init.rs',
      'crates/cli/src/commands/scaffold.rs',
      'crates/cli/src/commands/node.rs',
    ],
    canonicalLinks: [
      {
        label: 'Canonical protocol and domain reference',
        href: 'https://docs.ioi.network',
        external: true,
      },
    ],
    nextSteps: [
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
      { label: 'CLI Command Reference', href: '#cli-command-reference' },
    ],
    sections: [
      {
        id: 'use-it-when',
        title: 'Use It When',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <ul className={listClass(isDark)}>
              <li>Durable sovereign state matters.</li>
              <li>Policy roots and authority structure need to be explicit and durable.</li>
              <li>Publication and continuity are part of the product, not an implementation detail.</li>
              <li>
                The system is becoming an execution domain or protocolized economy rather than only
                a service package.
              </li>
            </ul>
          </div>
        ),
      },
      {
        id: 'today-in-the-cli',
        title: 'What Exists Today In The CLI',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={`# Initialize a new project shape
cargo run -p ioi-cli --bin cli -- init my-ioi-project

# Scaffold a native service module
cargo run -p ioi-cli --bin cli -- scaffold service payments

# Scaffold a contract module
cargo run -p ioi-cli --bin cli -- scaffold contract receipts

# Bring up a local node
cargo run -p ioi-cli --bin cli -- node`}
            />
            <p>
              The command surface already exists. The broader product story around "Forge" remains
              directionally useful, but it should still be treated as evolving.
            </p>
          </div>
        ),
      },
    ],
  },
  {
    id: 'cli-command-reference',
    title: 'CLI Command Reference',
    eyebrow: 'Reference',
    summary:
      'Current command families exposed by the CLI binary, with the repo-safe invocation pattern and the primary use for each family.',
    section: 'reference',
    status: 'Current',
    lastVerified: '2026-03-31',
    keywords: ['reference', 'commands', 'help', 'cli', 'query', 'node', 'artifact'],
    sources: ['crates/cli/src/main.rs', 'crates/cli/src/commands/*.rs'],
    canonicalLinks: [],
    nextSteps: [
      { label: 'IOI CLI Overview', href: '#ioi-cli-overview' },
      { label: 'Build Your First Studio Artifact', href: '#build-your-first-studio-artifact' },
    ],
    sections: [
      {
        id: 'how-to-use-this-page',
        title: 'How To Use This Page',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <p>
              Treat this as a current command-family map, not as exhaustive man pages. For the
              latest flag details, use the binary help surface directly from the workspace:
            </p>
            <CodeBlock isDark={isDark} code="cargo run -p ioi-cli --bin cli -- --help" />
          </div>
        ),
      },
      {
        id: 'command-families',
        title: 'Command Families',
        render: (isDark) => (
          <Table
            isDark={isDark}
            headers={['Command', 'Primary job', 'Notes']}
            rows={[
              ['init', 'Initialize a new IOI project structure', 'Creates a starter project shape with services, contracts, and config directories.'],
              ['scaffold', 'Add services or contracts', 'Scaffolds native service modules or WASM contract modules.'],
              ['artifact', 'Plan, generate, inspect, validate, materialize', 'One of the strongest implementation-backed workflows in the repo today.'],
              ['node', 'Run a local chain or validator flow', 'Use this when you need a local state/rpc surface.'],
              ['test', 'Run the project test suite', 'Builder and devnet validation path.'],
              ['keys', 'Manage identities and connector keys', 'Includes generation and inspection paths.'],
              ['config', 'Generate and validate configs', 'Useful when shaping orchestration or workload configs.'],
              ['query', 'Inspect node state or tx status', 'Companion to local node workflows.'],
              ['agent', 'Interact with the local desktop agent', 'Natural-language runtime entry point from the CLI side.'],
              ['trace', 'Visualize or inspect execution traces', 'Helpful after runs that need postmortem or audit review.'],
              ['verify', 'Verify determinism-boundary evidence', 'Evidence-oriented verification surface.'],
              ['policy', 'Generate a security policy from traces', 'Focused synthesis workflow.'],
              ['pii', 'PII review actions', 'Deterministic approval/review flow for PII decisions.'],
              ['ghost', 'Ghost Mode policy distillation', 'Alternative command family for trace-to-policy synthesis.'],
              ['dev', 'Developer/debug helpers', 'Includes skill injection/export and wallet bootstrap helpers.'],
            ]}
          />
        ),
      },
      {
        id: 'best-next-help-commands',
        title: 'Best Next Help Commands',
        render: (isDark) => (
          <div className={bodyClass(isDark)}>
            <CodeBlock
              isDark={isDark}
              code={`cargo run -p ioi-cli --bin cli -- artifact --help
cargo run -p ioi-cli --bin cli -- node --help
cargo run -p ioi-cli --bin cli -- query --help
cargo run -p ioi-cli --bin cli -- verify --help
cargo run -p ioi-cli --bin cli -- dev --help`}
            />
          </div>
        ),
      },
    ],
  },
];

export const DOC_PAGE_BY_ID = new Map(DOC_PAGES.map((page) => [page.id, page]));

export function getDocPage(id: string): DocPage | undefined {
  return DOC_PAGE_BY_ID.get(id);
}

export function matchesDocSearch(page: DocPage, query: string): boolean {
  if (!query.trim()) {
    return true;
  }

  const haystack = [page.title, page.summary, page.eyebrow, ...page.keywords]
    .join(' ')
    .toLowerCase();

  return haystack.includes(query.trim().toLowerCase());
}

export function firstPageForSection(sectionId: DocSectionId): DocPage | undefined {
  return DOC_PAGES.find((page) => page.section === sectionId);
}
