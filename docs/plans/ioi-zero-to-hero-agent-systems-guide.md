# IOI Zero-to-Hero Agent Systems Guide

Last updated: 2026-03-31
Owner: Autopilot kernel / Desktop agent runtime / Studio / Spotlight shell
Status: draft

Companion execution tracker:

- `docs/plans/ioi-zero-to-hero-agent-systems-rolling-plan.md`

## Why this guide exists

IOI already has more real architecture than most agent products:

- Studio has a typed artifact pipeline with blueprinting, judging, verification,
  and presentation gating in
  `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`.
- Desktop agent execution already has explicit step, planner, perception,
  action, browser completion, and anti-loop modules in
  `crates/services/src/agentic/desktop/service/step/`.
- Skills already exist as a real registry with lifecycle, reliability, and
  discovery weighting in `crates/services/src/agentic/skill_registry.rs`.
- Workspace artifacts already have supervised install, build, preview, and
  receipt capture in
  `apps/autopilot/src-tauri/src/kernel/studio/workspace_build.rs`.

The gap is no longer "do we have agent infrastructure?" The gap is:

1. model tiering is still too primitive for the current workload spread
2. the planner/executor/verifier hierarchy is only partially expressed across
   product surfaces
3. the same architectural truth is not surfaced with a confident user
   experience
4. local and remote model strategy is not yet benchmark-first enough
5. the thinking and swarm views still feel like debug surfaces instead of a
   state-of-the-art operator interface

This guide turns that into a practical gameplan that stays inside current local
hardware limits while materially leveling up IOI across:

- web research
- computer use
- coding
- Studio artifacts
- Spotlight chat and swarm UX

## Assumptions

This guide assumes the local target is still roughly a single consumer GPU in
the 16 GB to 24 GB VRAM band, plus CPU and normal developer workstation
resources. If the team has a 32 GB to 80 GB GPU tier available, later phases
can be widened, but the baseline plan should not require it.

## Governing constraints

This guide is subordinate to:

- `docs/specs/CIRC.md`
- `docs/specs/CEC.md`
- `docs/specs/autopilot/internal_product_spec.md`
- `docs/plans/close-the-parity-gap-with-artifacts.md`

That means:

- no lexical routing hacks
- no domain-bucket fallbacks
- no post-execution heuristic thrashing
- no product theater that hides verification truth
- no "swarm" that is really just an unbounded cloud of agents with unclear
  authority

The system should grow by typed roles, typed evidence, typed budgets, and
benchmark-backed promotion.

## Current architecture review

### 1. Studio already has the right shape

Studio is the most mature pipeline in the repo today.

Evidence:

- typed stage progression in
  `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`
- skill-backed planning context in
  `apps/autopilot/src-tauri/src/kernel/studio/skills.rs`
- workspace build supervision in
  `apps/autopilot/src-tauri/src/kernel/studio/workspace_build.rs`

Assessment:

- Strong: typed blueprint, IR, verification, candidate handling, presentation
  gating
- Weak: default model lineup is still too weak for consistently strong output
  quality in the local lane, especially for HTML and coding-heavy artifacts

### 2. Desktop agent runtime already contains the skeleton of a real hierarchy

Evidence:

- top-level service split in
  `crates/services/src/agentic/desktop/service/mod.rs`
- step pipeline in
  `crates/services/src/agentic/desktop/service/step/mod.rs`
- planner validation and boundedness in
  `crates/services/src/agentic/desktop/service/step/planner.rs`
- web research normalization in
  `crates/services/src/agentic/desktop/service/handler/web_research.rs`
- browser completion checks in
  `crates/services/src/agentic/desktop/service/step/browser_completion.rs`

Assessment:

- Strong: there is already explicit planning, intent resolution, tool gating,
  browser verification, and bounded retry logic
- Weak: the role hierarchy is still uneven across workloads, with some paths
  behaving like disciplined planner/executor flows and others behaving like a
  single generalized agent with tool adapters

### 3. Skills are real, but they are not yet the universal leverage point

Evidence:

- registry lifecycle and reliability scoring in
  `crates/services/src/agentic/skill_registry.rs`
- Studio skill matching in
  `apps/autopilot/src-tauri/src/kernel/studio/skills.rs`

Assessment:

- Strong: skills are registry-backed rather than prompt-only
- Weak: skill surfacing is still much stronger in Studio than in the wider
  desktop, research, and coding lanes

### 4. Spotlight still exposes too much mechanism and too little meaning

Evidence:

- current thinking entrypoint is a single pill in
  `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
- thought summaries compress to generic notes like `Agent 1`, `Agent 2` in
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
- reasoning classification still relies on coarse signals in
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.classification.ts`
- legacy thought rendering still groups raw chains in
  `apps/autopilot/src/windows/SpotlightWindow/hooks/useLegacyPresentation.tsx`
- Studio artifact evidence is thorough but dense in
  `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactEvidencePanel.tsx`
- Swarm visualization still reads like a debug console in
  `apps/autopilot/src/components/SwarmViz.tsx`

Assessment:

- Strong: the product already captures meaningful activity, receipts, thought
  traces, and evidence
- Weak: the presentation model is still "open the worklog" instead of "see the
  system think, route, verify, and finish with confidence"

### 5. Local model defaults are still too baseline-oriented

Evidence:

- local GPU dev still defaults to `llama3.2:3b` through the `ollama-openai`
  preset in
  `apps/autopilot/src-tauri/src/kernel/local_engine/mod.rs`
- overrides already exist in
  `apps/autopilot/src-tauri/src/kernel/local_engine/bootstrap.rs`

Assessment:

- Strong: the override hooks already exist, so evaluation can happen without
  destabilizing the default
- Weak: the shipped testing path undershoots the workloads where IOI most needs
  stronger local reasoning and execution continuity

## The target architecture

The disciplined end-state for IOI should be:

`Router -> Planner -> Specialists -> Verifier -> Human Gate -> Commit/Synthesize`

That is the compact golden shape.

The expanded operating shape should be:

1. Intake / Router
2. Planner / Supervisor
3. Specialist workers
4. Verifier / Evaluator
5. Human approval gate
6. Final synthesizer / committer
7. Optional memory worker
8. Optional recovery worker
9. Optional compliance worker

### What each role owns

#### Intake / Router

Responsibilities:

- normalize the request
- classify workload family
- set risk and latency budget
- decide single-agent vs multi-agent
- choose the minimal hierarchy required

It should not:

- directly decide tool details based on lexical shortcuts
- directly choose providers from query strings

#### Planner / Supervisor

Responsibilities:

- decompose the task
- spawn the minimal required specialists
- allocate time, token, and tool budgets
- keep shared state and progress truthful
- merge intermediate outputs

It should be the planner of record, not the fastest model of record.

#### Specialist workers

Specialize by workload or tool cluster, not by personality.

Primary specialist families for IOI:

- research worker
- browser/computer-use worker
- coding worker
- artifact/UI worker
- retrieval/context worker
- transformation/data worker

#### Verifier / Evaluator

Responsibilities:

- check citations, postconditions, tests, schema validity, render quality,
  safety, and policy
- distinguish "incomplete" from "wrong" from "unsafe"
- stop low-confidence completions from surfacing as polished lies

This role is more important than adding yet another specialist.

#### Human gate

Responsibilities:

- approve high-risk actions
- approve external side effects
- handle credentials, policy exceptions, and non-obvious commitments

#### Commit / Synthesize

Responsibilities:

- convert successful worker outputs into one final artifact, reply, patch set,
  or action report
- preserve receipts and evidence
- avoid leaking raw internal traces as user-facing final output

## First operational move

Do not swap the default model blindly.

The first step should be:

`add an experimental model matrix and benchmark it before promoting anything`

This is the highest-leverage, lowest-regret move.

### Why this is first

The current local default is still `llama3.2:3b`, which is fine as a lowest-bar
smoke-test lane but underpowered for:

- artifact quality
- long tool loops
- planner continuity
- coding autonomy
- verifier depth

The repo already supports env-based runtime overrides, so IOI can evaluate
stronger local and remote lanes without destabilizing the baseline.

### Recommended matrix

#### Lane A: baseline local

Purpose:

- fast smoke tests
- intent classification
- low-cost dev sanity runs

Candidate:

- current `llama3.2:3b`

Do not remove this lane. Keep it as the floor.

#### Lane B: local planner-grade OSS

Purpose:

- task decomposition
- longer-horizon planning
- verifier and judge passes
- general reasoning-heavy work

Candidates:

- `gpt-oss-20b`
- `Qwen3.5-27B-Claude-4.6-Opus-Reasoning-Distilled`

Why these fit:

- OpenAI states `gpt-oss-20b` is an open-weight reasoning model for low-latency
  and local use, with 21B total parameters, 3.6B active parameters, and the
  smaller checkpoint able to run on systems with as little as 16 GB memory.
- The Jackrong community model card claims the Qwen3.5 27B distilled model can
  run around the 16.5 GB VRAM class with Q4 quantization and is materially
  better in coding-agent environments than the base line.

Promotion rule:

- do not trust marketing or social media
- trust benchmark wins inside IOI

#### Lane C: local coding executor

Purpose:

- patching
- test repair
- long shell loops
- repo-grounded coding execution

Candidates:

- `Qwen3.5-27B-Claude-4.6-Opus-Reasoning-Distilled`
- a Qwen3-Coder-class open model if hardware permits and it wins local evals
- a future Codex-like OSS model only if it is real, benchmarked, and fits the
  same executor slot

Architecture note:

- keep the role generic: `coding_executor`
- do not couple the architecture to a single brand name

#### Lane D: remote multimodal / voice / interruption lane

Purpose:

- voice-first chat
- low-latency multimodal interaction
- screen plus audio grounding
- interruption-safe conversations

Candidates:

- `qwen3-omni-flash`
- `Qwen3.5-Plus`

Why:

- Alibaba Cloud currently positions Qwen3.5-Plus and Qwen3.5-Flash as the
  flagship balanced and fast model tiers, and its model docs also expose
  omni-modal and real-time multimodal families.
- Qwen-Agent documentation currently lists `qwen3-omni-flash` as a supported
  model name for omni configurations.

### Exact implementation of the first move

1. Keep the default local preset unchanged.
2. Add named experimental presets.
3. Wire those presets into the benchmark app and internal benchmark corpus.
4. Add workload-specific scorecards.
5. Promote only if a preset wins repeatedly.

### Metrics the first move must capture

- malformed tool call rate
- no-op stall rate
- time-to-first-useful-action
- mean step count to completion
- repair-loop iterations
- verifier pass rate
- coding test pass rate
- artifact judge score
- browser/computer-use postcondition pass rate
- latency
- VRAM and memory pressure
- interruption recovery quality

## Best next moves after the matrix

### 1. Make the hierarchy explicit across all workloads

The system should not use the same topology for every task.

Routing policy:

- single strong agent for narrow, tightly coupled tasks
- planner plus specialist for multi-tool or multi-domain tasks
- planner plus specialist plus verifier for anything expensive, high-risk, or
  high-visibility

This should be explicit in the route contract and visible in Spotlight.

### 2. Promote the verifier to a first-class role everywhere

Today verification is strongest in Studio and patchier elsewhere.

IOI should standardize verifier roles for:

- web research citation integrity
- browser/computer-use postconditions
- coding test and diff correctness
- artifact render quality
- policy and approval completeness

### 3. Extend skill discovery beyond Studio

The Studio lane already has the right instinct:

- derive typed needs
- retrieve skills from the registry
- use reliability-weighted discovery

That same pattern should be generalized to:

- coding tasks that need repo-specific execution styles
- research tasks that need evidence-pack or synthesis skills
- UX/art-direction tasks that need frontend guidance
- browser workflows that need stable playbooks

Skill selection should remain discovery-backed and registry-backed, not
skill-name routed.

### 4. Introduce a real context-prep worker

A dedicated context worker should:

- select the right files
- compress tool history
- prepare retrieval bundles
- summarize prior failed attempts
- avoid dragging the full transcript into every worker

This will improve:

- coding
- long research sessions
- swarm coherence
- latency and token efficiency

### 5. Add a recovery worker instead of free-form retries

The recovery worker should only activate when:

- a verifier fails
- a worker stalls
- a tool path is blocked

Its job:

- propose one alternate route
- preserve all existing receipts
- stay inside bounded retry budgets

This is much better than letting the main worker improvise forever.

### 6. Make the planner the authority and the workers replaceable

This is already close to the repo's design intent, and it should stay that way.

Good principle:

- the kernel remains planner-of-record, receipt authority, and policy boundary
- workers are replaceable
- models are replaceable
- providers are replaceable
- evidence and contracts are not replaceable

## Workload-specific analysis and recommendations

## Web research

### Current state

Strengths:

- web research intent normalization already exists in
  `crates/services/src/agentic/desktop/service/handler/web_research.rs`
- query contracts and retrieval contracts already exist
- there is meaningful discipline against brittle search behavior

Weaknesses:

- research can still feel like a specialized path inside a generalized agent,
  instead of an explicit planner plus researcher plus citation verifier flow
- source quality, synthesis quality, and comparison integrity should be made
  more visible in the product

### Recommended target pipeline

`router -> research planner -> search/read worker(s) -> citation verifier -> synthesis worker -> final answer`

### Tactical next steps

1. Add a dedicated research worker template as the default for
   `IntentScopeProfile::WebResearch`.
2. Add a citation verifier that checks:
   - source count
   - source independence
   - freshness
   - quote grounding
3. Separate source collection from answer synthesis in the UX.
4. Add benchmark cases for:
   - current-events queries
   - comparative research
   - local entity discovery
   - long-form source synthesis

## Computer use

### Current state

Strengths:

- the desktop service already has explicit perception, planning, action,
  browser, and verification modules
- browser snapshot completion already checks postconditions structurally in
  `browser_completion.rs`
- execution modules are receipt-driven and bounded

Weaknesses:

- the user-facing explanation of what the system is doing is still weaker than
  the internal structure
- failure recovery and alternate-route selection should be made more legible
- a stronger planner/verifier split would improve resilience

### Recommended target pipeline

`router -> computer-use planner -> perception/context worker -> ui/browser executor -> postcondition verifier -> recovery worker if needed -> completion gate`

### Tactical next steps

1. Make the perception step visible in Spotlight as "what the system thinks the
   UI is" rather than a hidden precondition.
2. Show postconditions separately from raw tool logs.
3. Add recovery receipts that explain why a fallback path was chosen.
4. Route high-risk side effects through an explicit approval card, not a generic
   pause message.
5. Evaluate multimodal models for voice-and-screen workflows, but keep the
   verifier in a typed local/kernel lane.

## Coding

### Current state

Strengths:

- Studio workspace artifacts already supervise install/build/preview
- the repo already carries strong evidence and benchmark habits
- the desktop stack already supports shell, filesystem, browser, and skills

Weaknesses:

- coding autonomy is still limited by default local model quality
- the coding lane needs a cleaner planner -> executor -> test verifier -> patch
  synthesizer shape
- repo-specific skill surfacing is not yet a universal part of coding flows

### Recommended target pipeline

`router -> coding planner -> context worker -> coding executor -> test verifier -> patch synthesizer -> final diff`

### Tactical next steps

1. Add explicit coding presets to the benchmark matrix.
2. Promote repo-specific coding skills through the registry instead of burying
   them in prompt context.
3. Add an autonomous but bounded test verifier lane:
   - run targeted tests first
   - widen only if needed
   - stop on clear regressions
4. Add a patch synthesizer that can merge worker diffs into one coherent final
   patch with verification receipts.
5. Treat open-weight coding models as executor candidates, not planner-of-record
   candidates, until they prove stability.

## Studio artifacts

### Current state

Studio is the most advanced lane, but still the best example of why better
models plus stronger role separation matter.

### Recommended target pipeline

`router -> artifact planner -> skill/context worker -> generator worker(s) -> render/static verifier -> judge -> repair worker -> presentation gate`

### Tactical next steps

1. Keep executing the parity plan in
   `docs/plans/close-the-parity-gap-with-artifacts.md`.
2. Use the new experimental model matrix to split:
   - planner
   - generator
   - judge
3. Treat frontend/UX guidance as a skill-backed need, not a prompt flourish.
4. Add frontier pairwise arena comparisons for the strongest artifact cases.

## Recommended model-role assignments

These are slots, not dogma.

Practical naming note:

- if the team says "ChatGPT OSS planner," map that to the current `gpt-oss`
  planner-grade slot rather than inventing a separate product category
- if the team says "Codex OSS executor," treat that as a coding-specialist slot
  that any qualified open-weight coding model can fill once it wins evals
- the architecture should stay role-first and benchmark-first, not brand-first

## Tier 0: cheap local baseline

Use for:

- routing
- smoke tests
- low-risk summarization
- always-on local fallback

Candidate:

- `llama3.2:3b`

## Tier 1: planner-grade local OSS

Use for:

- decomposition
- verifier passes
- mid-depth reasoning
- plan repair

Primary candidate:

- `gpt-oss-20b`

Secondary candidate:

- `Qwen3.5-27B-Claude-4.6-Opus-Reasoning-Distilled`

## Tier 2: coding executor local

Use for:

- shell/tool loops
- repo patching
- longer autonomous execution

Primary candidate:

- `Qwen3.5-27B-Claude-4.6-Opus-Reasoning-Distilled`

Optional candidate:

- Qwen3-Coder-class model if it fits hardware and wins evals

## Tier 3: multimodal remote

Use for:

- voice
- realtime chat
- audio interruption
- multimodal perception

Candidates:

- `qwen3-omni-flash`
- `Qwen3.5-Plus`

## Tier 4: premium judge or planner

Use only where the quality lift clearly justifies cost.

Use for:

- benchmark oracle runs
- difficult artifact judging
- hard planning cases

Rule:

- benchmark first
- promote learnings back into the cheaper default path

## Swarm mechanics: what to add and what not to add

## What to add

- a real supervisor role
- specialist workers by workload/tool cluster
- a verifier role
- a context-prep worker
- a bounded recovery worker
- human gates for risky actions

## What not to add

- a giant personality zoo
- unbounded recursive delegation
- many agents doing nearly the same thing
- opaque "team mode" that hides which agent owns what
- planner drift where the worker becomes the planner by accident

The best swarm is still small, typed, and auditable.

## Spotlight and chat UX: from debug surface to state-of-the-art operator surface

The current experience is too close to:

- one live "Working..." pill
- one artifact drawer
- one dump of thoughts, events, and logs

That is not enough.

The system already has richer structure than the UI admits.

## UX target principles

### 1. Show the system's shape, not just its noise

Users should immediately see:

- what route was chosen
- whether the task is single-agent or multi-agent
- which worker is active
- what is being verified
- whether the system is blocked, waiting, or finishing

### 2. Default to summary, not raw trace

Raw traces should remain available, but the default surface should summarize:

- intent
- active plan
- worker responsibilities
- verifier findings
- approvals
- final result

### 3. Turn thought history into execution narrative

Instead of generic "Agent 1" notes, show:

- Research worker: gathered 4 independent sources
- Coding worker: patched 2 files and started targeted tests
- Verifier: 1 test still failing in auth/session
- Recovery worker: switched from browser click to accessibility selector

### 4. Make pauses legible

If the system pauses, say exactly why:

- awaiting approval
- missing credential
- verifier blocked completion
- planner needs clarification

### 5. Separate truth surfaces

The UI should visually distinguish:

- plan
- execution
- evidence
- verification
- final synthesis

## Recommended Spotlight information architecture

### Primary chat lane

Show:

- user message
- answer draft or final answer
- compact execution card inline

### Inline execution card

Fields:

- selected route
- current stage
- active worker
- verifier state
- source/test/receipt counts
- one-line explanation of progress

### Expandable execution drawer

Tabs:

- Plan
- Workers
- Evidence
- Verification
- Raw trace

### Worker cards

Each worker card should show:

- role
- objective
- current action
- budget usage
- outputs produced
- verifier status if applicable

### Verifier card

This should be first-class, not buried.

Show:

- pass / blocked / warning
- what was checked
- what failed
- what is still missing

### History model

The conversation history should preserve:

- final answers
- execution summaries
- approval and pause moments
- branch points

It should not default to replaying raw chain fragments as the history of record.

## Concrete UX fixes from the current repo state

1. Replace the single `spot-thinking-pill` entrypoint in
   `ConversationTimeline.tsx` with an inline execution card that stays visible
   during work.
2. Replace `Agent 1`, `Agent 2` labels from
   `contentPipeline.summaries.ts` with role labels sourced from worker metadata.
3. Stop relying on coarse keyword reasoning classification where possible in
   `contentPipeline.classification.ts`; route from typed events first.
4. Keep `StudioArtifactEvidencePanel.tsx`, but add a summary tier above it so
   the first view is "what happened and why it is trustworthy" rather than the
   full evidence dump.
5. Evolve `SwarmViz.tsx` from terminal-log aesthetic toward operator cards plus
   branch and verifier visualization.

## Validation plan

Every promoted architectural move should be tested in four planes.

### 1. Benchmark plane

Use the benchmark app as the central living capability board.

Evaluate:

- artifacts
- research
- computer use
- coding
- voice or multimodal flows

### 2. Conformance plane

Verify:

- CIRC invariants
- CEC invariants
- no lexical routing
- no post-execution heuristic fallback

### 3. UX plane

Evaluate:

- time to user understanding
- ability to explain why the system paused
- ability to locate verifier findings quickly
- ability to reconstruct what happened after the fact

### 4. Hardware plane

Track:

- VRAM
- RAM
- latency
- cost
- concurrency limits

## Phased rollout

## Phase 0: baseline and matrix

Deliver:

- experimental preset matrix
- benchmark hooks
- workload scorecards
- no default swap yet

## Phase 1: hierarchy normalization

Deliver:

- explicit single-agent vs multi-agent route choice
- planner-of-record semantics everywhere
- verifier role standardization

## Phase 2: skill-first leverage

Deliver:

- skill discovery in coding, research, and UX lanes
- reliability-gated promotion of high-performing skills

## Phase 3: workload-specialized topologies

Deliver:

- research pipeline
- computer-use pipeline
- coding pipeline
- artifact pipeline refinements

## Phase 4: Spotlight overhaul

Deliver:

- inline execution card
- worker cards
- verifier-first surfacing
- branch and pause history

## Phase 5: promotion and ratcheting

Deliver:

- promote winning presets
- keep baseline fallback
- distill best behaviors back into the default path

## Near-term recommendations

If IOI only does five things in the next cycle, do these:

1. Add the experimental model matrix and benchmark it before touching defaults.
2. Standardize the planner -> specialist -> verifier hierarchy across research,
   coding, computer use, and artifacts.
3. Extend registry-backed skill discovery beyond Studio.
4. Treat Spotlight execution UX as a product surface, not a debug surface.
5. Promote only what wins on benchmarks, conformance, and operator
   comprehensibility.

## Sources

- OpenAI, "A practical guide to building agents":
  `https://cdn.openai.com/business-guides-and-resources/a-practical-guide-to-building-agents.pdf`
- OpenAI, "Introducing gpt-oss":
  `https://openai.com/index/introducing-gpt-oss`
- OpenAI, `gpt-oss-20b` model docs:
  `https://developers.openai.com/api/docs/models/gpt-oss-20b`
- OpenAI, `gpt-oss` model card:
  `https://openai.com/research/gpt-oss-model-card/`
- Alibaba Cloud Model Studio model list:
  `https://www.alibabacloud.com/help/en/model-studio/models`
- Qwen-Agent configuration docs:
  `https://qwenlm.github.io/Qwen-Agent/en/guide/get_started/configuration/`
- Qwen-Agent features docs:
  `https://qwenlm.github.io/Qwen-Agent/en/guide/get_started/features/`
- Qwen Code subagents docs:
  `https://qwenlm.github.io/qwen-code-docs/en/subagents/`
- Qwen3-Coder blog:
  `https://qwenlm.github.io/blog/qwen3-coder/`
- Jackrong community model card:
  `https://huggingface.co/Jackrong/Qwen3.5-27B-Claude-4.6-Opus-Reasoning-Distilled`

## Bottom line

IOI does not need a huge swarm.

It needs:

- better model tiering
- clearer planner authority
- stronger verifier roles
- broader skill discovery
- workload-specific specialist topologies
- a much better execution UX

That is the path from zero to hero without blowing past current local hardware
or violating CIRC and CEC.
