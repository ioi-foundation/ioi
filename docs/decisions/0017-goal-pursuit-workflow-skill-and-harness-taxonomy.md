# ADR 0017: Separate Goal Pursuit, Directed Work, Skills, Harnesses, And Tools

- Status: Accepted
- Date: 2026-07-15
- Owners: Hypervisor / Goal Kernel / Workflow Compositor / Automations / Packages / daemon runtime / Agentgres
- Refines: ADR 0015 and ADR 0016

## Context

IOI already distinguished durable GoalRuns, Workflow Compositor graphs,
AutomationSpecs, HarnessProfiles, tools, packages, and persistent workspace
intelligence. It lacked one reusable object that declared how a class of adaptive
goals should converge. “Harness” and “microharness” had consequently been used
for high-level pursuit, directed workflows, step resolvers, helper scripts, and
provider runtimes despite those concerns having different state and authority
owners.

That overload obscured replay, admission, improvement, packaging, and the
boundary between reusable definitions and live work.

## Decision

IOI adopts the following stable taxonomy:

```text
GoalRunProfile   immutable reusable specification of how a goal class converges
GoalRun          durable state of one admitted pursuit
GoalKernel       behavior that operates the bounded pursue-verify-course-correct loop
WorkflowTemplate immutable reusable directed graph and step-contract shape
AutomationSpec   standing trigger, schedule, service, monitor, or approval behavior
AutomationInstallationBinding immutable successor-versioned scope enablement/narrowing for one exact AutomationSpec
AutomationRun    one activation freezing the exact WorkflowTemplate, AutomationSpec, and InstallationBinding
HarnessProfile   resolver contract for one scoped assigned step
AgentHarnessAdapter versioned concrete bridge to an external or embedded agent harness
HarnessInvocation daemon-mediated execution through an exact HarnessProfile or AgentHarnessAdapter revision that emits normalized events and results
SkillManifest    immutable procedure, references, examples, and support assets
SkillEntry       immutable successor-versioned owner-scope binding to one exact SkillManifest revision
ActiveSkillSetSnapshot exact run-scoped selection of admitted skill revisions
RuntimeToolContract typed callable capability, effects, risk, authority requirements, and receipts
WorkResult       generic result seam with exact producer-component resolution
DataRecipe       immutable transformation definition with an exact semantic-component set
TransformationRun concrete execution and output state for one exact DataRecipe revision
MCPGatewayRequirement immutable package-safe MCP compatibility/exposure requirement
HypervisorMCPGatewayProfile admitted subject-scoped live MCP exposure
Package          versioned distribution of typed components without ownership transfer
Domain object    artifact, fleet, institution, campaign, business, or system lifecycle state
```

A released `GoalRunProfile` revision is immutable and content-addressed. It may
declare goal and output contracts, orchestration and constraint-derivation
policy, optional WorkflowTemplate revisions, topology and verifier requirements,
skills, harness and tool requirements, stop/recovery/escalation policy,
compatibility, and allowed overrides. Every newly admitted GoalRun binds exactly
one selected profile revision; direct ad hoc work resolves the built-in
generic-adaptive profile instead of creating a profileless exception.
Hypervisor Core and the daemon record the exact profile revision reference and
content hash, admitted override-set reference and hash, effective constraint
envelope, resolved-component snapshot reference and hash, and
GoalRunProfileResolutionReceipt. The Goal Kernel interprets that frozen
resolution; it does not create authoritative state, hold authority, or execute
effects outside daemon admission.

A WorkflowTemplate owns graph shape, not triggers or run history. An
AutomationSpec binds an exact template revision to standing activation behavior;
an immutable successor-versioned AutomationInstallationBinding owns local
scope enablement and policy overlay, and an AutomationRun freezes both plus one
activation. A SkillManifest supplies context and procedure but is not an
executable capability. Immutable successor-versioned SkillEntry binding
revisions declare local installation/enablement while the mutable registry
projection owns current lifecycle status; ActiveSkillSetSnapshot freezes one
run's exact selection; agent-callable effects cross a RuntimeToolContract. A HarnessProfile
defines how one scoped step is resolved; a daemon-mediated HarnessInvocation
through the selected profile or adapter emits common boundary events and a
normalized result. Neither owns high-level workflow composition, reusable goal
pursuit, persistent memory, or domain state.

“Recipe” remains a product- and package-facing label for an owner-qualified
composition such as a GoalRunProfile, WorkflowTemplate, AutomationSpec,
DataRecipe, development-environment recipe, or session-launch recipe. IOI introduces no generic
`RecipeEnvelope` or `run-recipe:` identity.

MCP remains a replaceable transport and compatibility projection. Pursuit,
workflow, and skill definitions declare transport-neutral semantic capability
requirements. Packages, application releases, adapters, and System manifests
may carry immutable MCP gateway requirements. Daemon admission may resolve one
to native capabilities, service modules, connectors, or a concrete gateway
profile; only when MCP exposure is selected does it issue a separately admitted,
subject-scoped gateway profile. MCP tools normalize to RuntimeToolContract,
resources to leased policy-bound projections, prompts to untrusted imports,
elicitation to typed input, tasks to external HarnessInvocation handles, and
Apps to sandboxed extension surfaces. MCP protocol state never becomes GoalRun
identity, IOI authority, or canonical domain truth.

Editable domain state remains with its domain owner. Materialization records an
immutable source snapshot, and each derived export binds that exact snapshot,
the responsible tool or WorkflowTemplate revision, run, and receipt. Export is
artifact lineage, not another harness family.

## Invariants

- Reusable definitions declare requirements but never grant authority or own
  live state.
- Every admitted use of a reusable profile, template, or skill binds an exact
  immutable revision, content hash, permitted overrides, effective resolution,
  and receipt as required by its run owner.
- Patches create successor revisions; they never rewrite an active run.
- Concrete plan, topology, worker, model, harness, tool, context, authority, and
  runtime selections remain with their existing plan, run, invocation, lease,
  and receipt owners.
- HarnessInvocation binds an underlying typed work subject and never becomes a
  second work subject. Resolver-produced WorkResults freeze the exact
  producer-component snapshot/hash/receipt and resolver revision/hash.
- A DataRecipe and each ConnectorMapping revision commit exact semantic-
  component snapshots; TransformationRun reuses that exact tuple rather than
  following current ontology, mapping, object-model, schema, or view heads.
- A Package distributes typed components without collapsing their identities or
  lifecycles.
- `GoalMicroharness`, generic `MicroHarnessEnvelope`, and positive
  “meta-harness” product semantics are retired from current canon.

## Consequences

- GoalRunProfile patches enter the Improvement Proposal Plane as proposed
  successor revisions alongside WorkflowTemplate, SkillManifest,
  HarnessProfile, routing, verifier, and tool-contract improvements.
- Direct and adaptive pursuit, deterministic workflows, standing Automations,
  step resolution, and domain state remain composable without becoming aliases.
- Product packages may present coherent Recipes while APIs and receipts preserve
  exact owner-qualified object identities.
- Existing `GoalMicroharness`, `local_microharness`, `run-recipe:`, and bare
  Harness-as-workflow usages require migration to GoalKernel/GoalRun,
  HarnessInvocation, WorkflowTemplate, or another exact owner.

## Canonical References

- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/foundations/governed-autonomous-systems.md`
- `docs/architecture/components/daemon-runtime/default-harness-profile.md`
- `docs/architecture/components/daemon-runtime/api.md`
- `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`
- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/components/connectors-tools/contracts.md`
- `docs/architecture/_meta/vocabulary.md`
