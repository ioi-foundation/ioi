# Autopilot VS Code Workspace Substrate Plan

Last updated: 2026-03-27
Owner: Autopilot Studio / runtime / shell
Status: proposed implementation plan

## Why this exists

Autopilot Studio should keep its native operator shell while upgrading the
workspace experience for repo-heavy builder workflows.

Today the `explorer` surface is intentionally lightweight:

- a custom file tree with shallow directory loading
- basic git status badges
- a simple embedded editor
- no first-class project-wide search or source control workbench

That is good enough for light file access, but it is not where we should keep
spending product and engineering effort.

The recommendation in this plan is:

- keep the Autopilot shell native
- replace the custom workspace utilities behind the existing `explorer` surface
- use a Monaco-based editor with VS Code-compatible workbench services and
  primitives where they materially improve workspace ergonomics

This is a workspace-subsystem plan, not a shell-replacement plan.

One important implication is that the workspace layer must be embeddable outside
the current Studio `explorer` surface. We expect to reuse it in other Autopilot
planes such as a Build plane where the operator may see:

- a left rail for task progress, chat, or build context
- an embedded explorer and file/navigation pane
- an editor and diff surface
- optional preview/code toggles

So the target is not "replace one Studio screen." The target is "build one
reusable workspace substrate that can be mounted in multiple Autopilot planes."

## Product doctrine

Autopilot remains the operator shell.

The native shell continues to own:

- top-level layout
- surface navigation
- operator pane and chat
- inbox
- runs and receipts
- capabilities
- policy and approvals
- promotion and mission control flows

The VS Code-backed workspace subsystem owns:

- explorer
- workspace-local search
- workspace-local source control
- file open/save/reveal behavior
- editor tabs and splits
- project-wide search
- diffing
- source control
- editor command semantics

Users should feel:

- "Autopilot has a world-class workspace"

Not:

- "Autopilot is a skinned IDE"

## Current baseline

The current Studio shell already has the right product boundary:

- `explorer` is only one primary view among workflows, runs, inbox,
  capabilities, policy, and settings
- Studio is explicitly positioned as builder-first without losing the operator
  shell
- the Tauri backend already has a path-bounded project shell contract

Relevant current files:

- `apps/autopilot/src/windows/StudioWindow/components/StudioWindowMainContent.tsx`
- `apps/autopilot/src/windows/StudioWindow/components/LocalActivityBar.tsx`
- `apps/autopilot/src/windows/StudioWindow/components/StudioIdeHeader.tsx`
- `apps/autopilot/src/windows/StudioWindow/components/StudioExplorerPane.tsx`
- `apps/autopilot/src/windows/StudioWindow/components/StudioExplorerView.tsx`
- `apps/autopilot/src/windows/StudioWindow/components/StudioCodeWorkbench.tsx`
- `apps/autopilot/src/windows/StudioWindow/useStudioWindowController.ts`
- `apps/autopilot/src-tauri/src/project.rs`

## Target architecture

### Layer 1: Native Autopilot shell

Keep the current Studio shell as the frame around the workspace:

- activity bar
- window header
- command palette entry point
- project selection
- operator utility panes
- inbox / runs / policy / capabilities

This layer continues to route between product surfaces and maintain Autopilot's
language, ontology, and policy model.

The global Studio activity bar should continue to represent product surfaces,
not every workspace utility. Source control should remain inside the workspace
layer rather than becoming a new top-level shell mode in the initial rollout.

### Layer 2: Embedded workspace subsystem

Mount a dedicated workspace host inside the existing `explorer` surface.

This subsystem should provide:

- Monaco editor
- VS Code-compatible workbench services where practical
- a file explorer
- a search pane
- source control pane
- diff editor support
- command routing for editor/workspace actions

The workspace host should be embedded and visually adapted to Studio. It should
not take over shell navigation or window framing.

The workspace layer may have its own local navigation or activity rail for:

- files
- search
- source control
- optional later utilities such as terminal

It must also support multiple embedding modes:

- full workbench mode for Studio `explorer`
- split-plane mode for Build or task-focused planes
- compact or read-only mode for contextual embeds elsewhere in Autopilot

## Implementation principles

- Keep the top-level `explorer` view id and navigation model unchanged.
- Replace internals behind the current explorer mode rather than adding a new
  primary product mode.
- Do not add Source Control as a new global Autopilot activity-bar item in the
  first rollout.
- Add Source Control as workspace-local navigation inside the embedded
  workspace subsystem.
- Prefer one dedicated workspace package over scattering Monaco and VS Code
  substrate logic through `apps/autopilot`.
- Keep a narrow adapter boundary between the workspace UI and Tauri commands.
- Preserve path-boundary enforcement and policy hooks for all write actions.
- Avoid introducing a generic public extension marketplace.
- Model worker backends, capabilities, and adapters as Autopilot-native objects,
  not editor plugins.

## Package and module shape

### New package

Create:

- `packages/workspace-substrate`

This package should contain:

- `WorkspaceHost` root component
- layout primitives for embedded use, not just one monolithic full-screen shell
- Monaco bootstrapping
- VS Code-compatible service initialization
- workspace-side explorer/search/scm/diff/editor panes
- adapter interfaces for filesystem, search, scm, terminal, and shell actions

Recommended exported primitives:

- `WorkspaceHost`
- `WorkspaceRail`
- `WorkspaceExplorerPane`
- `WorkspaceEditorPane`
- `WorkspaceSearchPane`
- `WorkspaceSourceControlPane`
- `WorkspaceDiffPane`
- shared workspace session/store hooks

It should be importable into `apps/autopilot` the same way shared surfaces are
already imported from `@ioi/agent-ide`.

### Autopilot app integration

`apps/autopilot` should remain responsible for:

- deciding when the workspace host is shown
- choosing the current project root
- passing operator-shell context into the workspace host
- choosing the embedding layout for the current plane
- handling Autopilot-native actions such as:
  - attach selection to operator
  - attach diff to run
  - open file from inbox or run artifact
  - route governed actions through policy

This is especially important for future planes that are not shaped like Studio's
current `explorer` mode. The Build plane may embed only part of the workspace
subsystem alongside other native panes.

## Backend plan

### Expand the current project shell into a workspace service

The current Tauri backend in `apps/autopilot/src-tauri/src/project.rs` exposes a
good starting point but is too small for a real workbench.

We should either:

- evolve `project.rs` into a broader workspace service

Or:

- split a new `workspace.rs` and keep `project.rs` for legacy compatibility

Recommended command families:

### Workspace lifecycle

- `workspace_inspect(root)`
- `workspace_watch_start(root)`
- `workspace_watch_stop(root)`
- `workspace_roots_list()`

### Filesystem

- `workspace_list_directory(root, path)`
- `workspace_read_file(root, path)`
- `workspace_write_file(root, path, content)`
- `workspace_create_file(root, path)`
- `workspace_create_directory(root, path)`
- `workspace_rename_path(root, from, to)`
- `workspace_delete_path(root, path)`
- `workspace_reveal_path(root, path)`

### Search

- `workspace_search_text(root, query, includes, excludes, case_sensitive,
  regex)`
- `workspace_search_symbols(root, query)`
- `workspace_replace_text(...)`

### Source control

- `workspace_git_status(root)`
- `workspace_git_diff(root, pathspec, staged)`
- `workspace_git_stage(root, pathspec)`
- `workspace_git_unstage(root, pathspec)`
- `workspace_git_discard(root, pathspec)`
- `workspace_git_commit_preview(root)`

### Diff and artifact bridges

- `workspace_open_diff(left, right, title)`
- `workspace_resolve_artifact_to_editor_input(artifact_ref)`

### Optional later terminal support

- `workspace_terminal_create(root, shell)`
- `workspace_terminal_write(session, input)`
- `workspace_terminal_resize(session, cols, rows)`
- `workspace_terminal_close(session)`

## Frontend integration plan

### Preserve the current Studio shell

Keep these Studio areas as native:

- `StudioWindowMainContent`
- `LocalActivityBar`
- `StudioIdeHeader`
- `StudioLeftUtilityPane`
- `StudioUtilityDrawer`

The key rule is that the workspace host mounts inside the current center area
for `activeView === "explorer"`.

### Design for multi-plane embedding

The workspace substrate should not assume:

- it always owns the full center column
- it always owns the entire left sidebar
- it is only ever mounted from Studio

Instead it should support:

- a full Studio workbench mount
- a Build plane mount with native panes on the left and workspace panes to the
  right
- selective mounting of only explorer/editor or only diff/editor combinations

The screenshot-driven target shape is a good example:

- native build/task context on the left
- embedded file tree and workspace-local nav in the middle
- code editor or preview surface on the right

That means composition matters more than one giant workspace screen.

### Navigation decision

Source Control should be part of the plan, but as workspace-local navigation,
not as a new top-level Studio primary view.

Reasoning:

- the current global activity bar represents Autopilot product surfaces
- source control is a builder utility, not a distinct operator-shell mode
- keeping it local preserves the operator-first hierarchy
- the embedded workspace can still mirror familiar editor ergonomics without
  making Studio globally IDE-shaped

Implementation shape:

- keep the global Studio activity bar unchanged in the first rollout
- add local workspace navigation inside the `explorer` surface for:
  - explorer
  - search
  - source control
- revisit a dedicated global source-control item only if later user testing
  shows repo review deserves its own first-class shell surface

### Replace current explorer/editor components

The following current components become compatibility wrappers and can then be
retired after cutover:

- `StudioExplorerPane`
- `StudioExplorerView`
- `StudioCodeWorkbench`

Target state:

- one `StudioWorkspaceSurface` wrapper inside `apps/autopilot`
- one `WorkspaceHost` from `packages/workspace-substrate`
- optional plane-specific wrappers such as `BuildPlaneWorkspaceEmbed` that reuse
  the same substrate primitives

### Refactor controller ownership

`useStudioWindowController.ts` should stop owning low-level editor tab state and
file loading logic directly.

Instead it should own:

- current project id
- resolved project root
- current shell view
- Autopilot-to-workspace intents
  - open file
  - reveal file
  - open diff
  - attach selection
  - focus search

The workspace subsystem should own:

- editor tabs
- dirty state
- splits
- search UI state
- scm pane state
- editor-level command handling

## Rollout phases

### Phase 0: Spike and go/no-go

Build a hidden prototype behind a Studio feature flag.

Spike goals:

- Monaco boots correctly in Tauri dev and packaged builds
- worker-based editor services behave reliably
- one project root opens correctly
- open/save works through Tauri
- project search works on a medium repo
- git status and diff render correctly
- no shell-regression in chat, runs, or policy panes

Exit criteria:

- we can mount a real workspace host inside the current `explorer` surface
- startup and interaction are acceptable
- no packaging blocker remains

### Phase 1: Workspace host package

Implementation:

- create `packages/workspace-substrate`
- add Monaco bootstrapping
- add VS Code-compatible service initialization as needed
- define the adapter contract used by Autopilot
- add an embedded editor surface first
- make sure the package can render both as a full workbench and as composed
  subpanes

Exit criteria:

- package builds cleanly in the monorepo
- Autopilot can mount it in a development-only path
- basic composition works for both Studio `explorer` and a future Build-plane
  style embed

### Phase 2: Backend workspace service

Implementation:

- expand Tauri commands beyond inspect/list/read/write
- add typed search and git commands
- add file watch support
- add path-safe rename/create/delete operations
- add payload types for diff and source control results

Exit criteria:

- frontend no longer needs to fake explorer/scm/search behavior in React state

### Phase 3: Explorer parity

Implementation:

- mount workspace host under `activeView === "explorer"`
- add workspace-local navigation for files, search, and source control
- support project root selection
- support open file, reveal, rename, move, create, delete
- keep current Studio shell chrome and project chooser

Exit criteria:

- users can browse and edit files without falling back to the legacy explorer

### Phase 3.5: Build-plane embedding pass

Implementation:

- add one non-Studio embed that exercises the same workspace substrate
- prove explorer plus editor can live beside native plane-specific panes
- validate that local workspace navigation still behaves well in a narrower
  layout

Exit criteria:

- the substrate is proven reusable and not coupled to one Studio screen shape

### Phase 4: Search and diff parity

Implementation:

- add project-wide text search
- add search result navigation
- add diff editor support for:
  - git diffs
  - artifact diffs
  - run-generated patches

Exit criteria:

- search and diff become first-class builder workflows inside Studio

### Phase 5: Source control parity

Implementation:

- add source control pane
- display changed files, staged files, branch, and diff previews
- route write-risky actions through existing policy and evidence hooks when
  appropriate

Exit criteria:

- repo review and patch handling no longer depend on the custom explorer stack

### Phase 6: Autopilot-native bridges

Implementation:

- open a file from inbox, runs, or artifacts directly into the workspace
- attach a diff or selection into the operator pane
- convert workspace diffs into artifacts/receipts where useful
- support "open in workspace" actions from run detail surfaces

Exit criteria:

- the workspace is meaningfully integrated into Autopilot's operating loop

### Phase 7: Cutover and cleanup

Implementation:

- make the new workspace host the default `explorer` implementation
- keep a temporary legacy flag for rollback
- remove legacy custom explorer/editor components after one stable cycle

Exit criteria:

- `StudioExplorerPane`, `StudioExplorerView`, and `StudioCodeWorkbench` are no
  longer on the active path

## Acceptance criteria

The implementation is successful when:

- Autopilot still feels like an operator shell, not an IDE shell
- the explorer surface supports repo-scale browsing comfortably
- the workspace substrate is reusable in more than one Autopilot plane
- project-wide search is native and fast
- diff review is first-class
- source control workflows are materially better than today
- Studio shell surfaces outside `explorer` remain unchanged in ownership
- policy and evidence hooks still govern meaningful file and repo actions

## Risks and mitigations

### Risk: Tauri packaging and web workers

Monaco and VS Code-compatible services depend heavily on worker setup and asset
loading.

Mitigation:

- treat Phase 0 as a hard go/no-go checkpoint
- validate both `tauri dev` and bundled production builds
- keep worker bootstrapping isolated inside the workspace package

### Risk: shell identity drift

A rich IDE substrate can easily start pulling the whole app toward IDE-shaped
navigation and ontology.

Mitigation:

- keep all top-level navigation and surface labels in Studio
- do not adopt VS Code shell chrome outside the embedded workspace area
- keep Autopilot-native language for policy, runs, inbox, capabilities, and
  operators
- ensure Build and other future planes compose the workspace substrate rather
  than inherit a fixed IDE layout

### Risk: too many moving parts in one migration

Trying to swap editor, search, scm, terminal, and extensions at once is likely
to stall.

Mitigation:

- ship in phases
- require parity milestones before adding more capability
- keep terminal and installable capability packages as later work

### Risk: bypassing governance

A direct editor/SCM substrate can create paths that sidestep policy or evidence
capture.

Mitigation:

- route meaningful write and repo actions through typed Tauri commands
- preserve Autopilot as the policy authority
- add workspace-to-shell bridges intentionally, not ad hoc

## Non-goals

This plan does not include:

- replacing the top-level Studio shell with Code-OSS
- adopting a public extension marketplace as a product pillar
- making editor plugins the primary capability model
- rebranding Autopilot as an IDE-first product

## Open decisions

- whether the substrate should start with pure Monaco first or immediately use a
  VS Code-compatible service stack
- how much of the local workspace navigation should be provided by the substrate
  versus wrapped by each embedding plane
- whether git search/scm should be implemented directly over Tauri commands or
  partially delegated to a local helper service
- whether terminal support belongs in the first cut or should wait until search
  and scm parity land
- whether to place the new package alongside `@ioi/agent-ide` or fold it into
  that package later after it stabilizes

## Immediate next steps

1. Create the `packages/workspace-substrate` package.
2. Add a hidden feature-flagged `WorkspaceHost` mount under Studio's existing
   `explorer` view.
3. Prove Monaco plus worker bootstrapping in Tauri development and production
   packaging.
4. Define the typed adapter boundary between the workspace host and Tauri.
5. Start the backend expansion from the current `project.rs` contract.
