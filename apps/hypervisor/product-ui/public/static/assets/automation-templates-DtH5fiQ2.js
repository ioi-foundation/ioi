import{bn as e}from"./SegmentProvider-CXCNBY9U.js";import{B as t,Bs as n,Eu as r,F as i,H as a,I as o,L as s,M as c,N as l,P as u,R as d,U as f,V as p,Xu as m,bd as h,ef as g,g_ as _,pm as v,yu as y,z as b}from"./vendor-DAwbZtf0.js";import{Ls as x}from"./use-boot-in-app-chat-t-J_VjKS.js";import{C as S,E as C,M as w,N as T,O as E,S as D,T as O,b as k,d as A,f as j,j as M,k as N,v as P,x as F}from"./workflow_pb-DOR6D5WK.js";import{n as I}from"./automations-CN21BoUy.js";var L={"start-from-scratch":{id:`start-from-scratch`,title:`Start from scratch`,description:`Create a custom automation workflow from scratch.`,icon:b,iconColor:`text-content-brand`,iconBgColor:`bg-surface-brand-subtle`,enabled:!0,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`With prompts you can send messages to IOI Agent`}}}),_(k,{step:{case:`task`,value:{command:`echo 'with commands you can run shell commands'`}}})]},"automated-dev-environment-setup":{id:`automated-dev-environment-setup`,title:`Automated dev environment setup`,description:`Standardizes your development environment and opens a PR with the required updates.`,enabled:!0,icon:d,iconColor:`text-content-success`,iconBgColor:`bg-surface-success-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Create a high-quality, fully working “development environment as code” configuration for the current environment.

The setup must work for:
	•	IOI development environments, which use DevContainer configurations.
Do not confuse this with IOI Classic, which uses .ioi.yml.
	•	All Git repositories mounted under the DevContainer workspace.

Terminology
	•	apps: Source code intended to be built and shipped.
	•	dev tool: Any tool used for compiling, building, publishing, testing, profiling, debugging, or accessing an app's infrastructure.

Required Process
	1.	Read the documentation (see Allowed Sources) to fully understand:
	•	IOI automations, secrets, environment variables, CLI, and prebuilds.
	•	DevContainer fundamentals and how they integrate with IOI and VS Code.
	2.	Analyze the source code and identify:
	•	Documentation on dev setup or contribution guidelines.
	•	Configuration files for containers, IDEs, build tools, environment variables, etc.
	3.	Update all necessary files, including:
	•	devcontainer.json
	•	IOI automations (tasks and services)
	•	Any other files required to meet the Success Criteria.
	4.	Run the Acceptance Tests for all code you have created and iterate until the last run of every Acceptance Test has been successful.
	5.	Do not create any documentation files.

Success Criteria
	•	The DevContainer includes all tools needed to work with any file in any repo in this environment.
	•	IOI automation services exist for every service required or recommended to run any app in this environment.
	•	IOI automation services exist for every app, for the standard or documented configurations.
	•	IOI automation tasks exist for all standard or documented development workflows for this repo.
	•	If an app exposes a TCP port, the DevContainer must forward it.
	•	If an app exposes an HTTP/HTTPS port, the corresponding IOI automation service must expose it by running "ioi env port open" before starting the app.
	•	The DevContainer must install all VS Code extensions necessary to work effectively with the files and services in this environment.
	
Acceptance Tests:
	•	The command "ioi auto update <filename>" succeeds
	•	The command "ioi env devcontainer validate" succeeds
	•	The DevContainer rebuilds successfully.
	•	All installed tools launch successfully and are available in the correct version
	•	IOI automation tasks start and finish successfully. 	
	•	IOI automation services successfully reach the state "ready".
	•	Apps exposed via IOI port respond successfully when curl'ing the port. 	

Allowed Sources
	•	IOI documentation: automations, secrets, environment variables, CLI, prebuilds, DevContainers
https://ioi.com/docs/llms.txt
	•	DevContainer documentation: https://containers.dev/
	•	DevContainers in VS Code: https://code.visualstudio.com/docs/devcontainers/containers
	•	DevContainer base images: https://hub.docker.com/r/microsoft/devcontainers
	•	VS Code extensions:
	•	https://marketplace.visualstudio.com/vscode
	•	https://open-vsx.org/
	•	Any publicly available DevContainer features
	•	Anything installable within a Dockerfile
                                `}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`IOI: automated dev environment setup`,description:`The PR has been automatically created by IOI Agent to set up a consistent development environment for this repository. Please review the changes and merge if everything looks good.`,branch:`ioi/automated-dev-environment-setup`,draft:!0})}})]},"cve-mitigation-and-version-updates":{id:`cve-mitigation-and-version-updates`,title:`CVE mitigation & dependency updates`,description:`Fixes vulnerable or outdated dependencies, validates changes, and opens a PR.`,enabled:!0,icon:l,iconColor:`text-content-brand-accent-01`,iconBgColor:`bg-surface-brand-accent-01-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`First, scan this repository's dependency files (package.json, go.mod, requirements.txt, Gemfile, pom.xml, etc.) for outdated dependencies. Run the appropriate audit/outdated command for the package manager (npm audit, npm outdated, go list -m -u all, pip-audit, etc.). List dependencies that are more than one major or two minor versions behind, or have known vulnerabilities. If a specific {CVE_ID} was provided, also research that CVE: what is the vulnerability, which library/package, what versions are affected, what versions have the fix, and which specific functions or code patterns trigger it. Output: one sentence status only.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Check if this repository has the vulnerable library. Look at dependency files and analyze the full dependency tree including transitive dependencies. Report the version and whether it's direct or transitive. If not found or already patched, say so and skip remaining work. Do not analyze source code yet. Output: one sentence status only.`}}}),_(k,{step:{case:`agent`,value:{prompt:`If the vulnerable library was found: search source code to find if our code calls the vulnerable functions. Show the call chain. If the library was not found or not reachable, skip this work. Do not modify any files yet. Output: one sentence status only.`}}}),_(k,{step:{case:`agent`,value:{prompt:`If the vulnerability is reachable: update the dependency to the fixed version, adjust code if APIs changed, and run tests. Otherwise skip this work. Do not create a PR yet. Output: one sentence status only.`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`fix: CVE remediation`,description:`Automated CVE remediation by IOI Agent.`,branch:`ioi/cve-remediation`,draft:!0})}}),_(k,{step:{case:`agent`,value:{prompt:`Generate a security analysis report using all information from previous steps. Format:

**Result:** [Vulnerable/Not Vulnerable/Already Patched] - one line summary

**Impact:** CVSS score and worst-case scenario

**Evidence:** Call chain showing reachability (or why not reachable)

**Fix:** What was changed (if applicable)

**Verification:** Test results (if applicable)

Put the outcome first. Be concise.`}}})]},"add-and-maintain-readmes-and-backstage-yaml":{id:`add-and-maintain-readmes-and-backstage-yaml`,title:`Backstage catalog standardization`,description:`Updates catalog-info.yaml to match your Backstage standards and opens a PR.`,enabled:!0,icon:r,iconColor:`text-content-warning`,iconBgColor:`bg-surface-warning-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Fetch and analyze the Backstage catalog standardization RFC from this Gist: https://gist.github.com/loujaybee/7f8ed30f4dd2dee94a5db019b47cce62

Extract and summarize:

All required fields and their specifications
Acceptable values and formats for each field
Fields that can typically be inferred automatically vs. those requiring human input
Validation rules and compliance requirements

Output a structured summary of the RFC requirements that will guide the subsequent steps.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Examine this repository to understand its characteristics:

What type of component is this? (service, library, website, or documentation)
What is the primary programming language and technology stack?
What frameworks, databases, or notable dependencies are in use?
Does a catalog-info.yaml file already exist at the repository root? If so, what does it contain?
Based on the README, repository structure, and code, what is the purpose of this component?
Is this component actively maintained? (check recent commit history)
Are there any existing configuration files that provide context (package.json, requirements.txt, etc.)?

Provide a comprehensive analysis that will inform the catalog-info.yaml generation.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Based on the RFC requirements and repository analysis, generate or update the catalog-info.yaml file:

Create the file with proper Backstage catalog format (apiVersion: backstage.io/v1alpha1, kind: Component)
Populate all fields that can be confidently determined automatically:

metadata.name (derived from repository name)
metadata.description (based on repository purpose)
metadata.tags (technology stack and component category)
spec.type (service/library/website/documentation)
spec.lifecycle (production/experimental/deprecated based on activity and context)

For fields requiring human input (spec.owner, spec.system), add TODO comments with clear guidance on what needs to be provided
Include inline YAML comments explaining automated choices where helpful
Ensure valid YAML syntax

If catalog-info.yaml already exists, preserve any manually-added fields and only update missing or outdated automated fields.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Install the Backstage entity validator and validate the generated catalog-info.yaml file:

npm install --global @roadiehq/backstage-entity-validator

validate-entity catalog-info.yaml

Review the validation output. If there are any errors, fix them and re-validate until the file passes validation.

Report the validation results.`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`chore: add Backstage catalog metadata per RFC-2024-023`,description:`This PR implements the Backstage catalog standardization requirements defined in RFC-2024-023.

Changes Made:

[Created/Updated] catalog-info.yaml with automated fields
All automated fields populated based on repository analysis
File validated using @roadiehq/backstage-entity-validator

What Was Automated:

Component type, description, and technology tags
Lifecycle determination based on repository activity
Basic metadata derived from repository structure

Requires Manual Review:

spec.owner: Please specify the team responsible for this component
spec.system: Please specify which system/product this component belongs to
Review all automated fields for accuracy

Validation: ✅ Passed Backstage entity validation
Please review the automated fields and complete the manual items before merging.`,branch:`ioi/backstage-catalog-standardization`,draft:!0})}}),_(k,{step:{case:`agent`,value:{prompt:`Add a comment to the pull request highlighting what requires human attention:

⚠️ Manual Action Required
While most of the catalog metadata has been populated automatically, the following fields require your input:
Required Manual Fields:

spec.owner (Line XX)

Current: TODO: Specify team
Action needed: Replace with your team identifier (e.g., team:platform-engineering)
See team registry for valid team names

spec.system (Line XX)

Current: TODO: Specify system
Action needed: Specify which product/system this component belongs to
See system definitions or contact Platform Engineering to create a new system

Please Review:

Verify the component description accurately reflects the purpose
Confirm the technology tags are complete
Ensure the lifecycle state (production/experimental/deprecated) is correct

Once you've completed these items, this component will be fully compliant with RFC-2024-023.`}}})]},"code-review":{id:`code-review`,title:`Code review`,description:`Reviews PRs for quality, security, and test coverage, then leaves actionable feedback.`,enabled:!0,icon:t,iconColor:`text-content-brand`,iconBgColor:`bg-surface-brand-subtle`,trigger:_(O,{trigger:{case:`pullRequest`,value:_(w,{events:[M.OPENED,M.READY_FOR_REVIEW]})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`CODE REVIEW AGENT FOR IOI

1. PERSONA & ROLE

You are an expert software engineer performing code review for IOI. Your mission: provide high-value, actionable feedback on medium to high severity issues only.

Core Principles:
- Be helpful, not noisy. Only raise fair, actionable concerns that genuinely improve code.
- Focus exclusively on what changed in this PR (the diff).
- Work with available context. If tools fail, continue with what you have.
- Don't comment on style preferences. Only flag significant inconsistencies with existing codebase patterns.
- Treat generated code fairly if it's appropriate and contextually correct.

2. CONTEXT GATHERING

Gather context systematically, but continue even if some sources fail:

2.1 Identify & Verify PR
- Get current git branch and extract PR number
- Fetch PR state (open/closed/merged)
- EXIT IMMEDIATELY if closed or merged

2.2 Gather Available Context
Try to collect, but continue if any fail:
- PR description: problem, solution, requirements, breaking changes
- Commit messages: progression, decisions, iterations
- Linked issues: explore available tools to retrieve more context from linked issues
- Existing comments: what's already been raised, resolved status
- Code diff: full changes against default branch
- Existing codebase patterns: naming, error handling, testing conventions
- Repo coding guidelines, agent rules, and skills (available in system prompt context)

2.3 Repo-Specific Review Rules
- Check if a \`code-review\` skill exists using read_skill tool
- If found, apply those rules in addition to standard review dimensions
- Repo-specific rules take precedence for severity assessment
- If the diff changes access-control or authorization semantics, read the \`rbac-implementation\` skill if available and flag allow/disallow changes implemented outside RBAC layers

CRITICAL: Only review code in the diff. Never comment on:
- Pre-existing unchanged code
- Legacy issues outside PR scope
- General codebase patterns not touched by this PR

3. UNDERSTANDING & ANALYSIS

Synthesize context to build a mental model:
- What is this PR trying to achieve?
- What are the key technical changes and risks?
- What patterns exist in the codebase?
- What constraints or trade-offs are mentioned?

Focus areas based on context:
- Critical paths and core logic changes
- Security-sensitive code (auth, validation, data handling)
- Performance-critical sections
- Public APIs and interfaces
- Error handling and edge cases
- Test coverage and quality
- Consistency with existing patterns

4. SELF-REFLECTION & VALIDATION

Before flagging any issue, ask:
- Is this in the diff (code actually changed)?
- Is this intentional per PR description or linked issues?
- Does existing codebase use similar approaches?
- Has this been discussed by other reviewers?
- Could missing context make this look wrong when it's right?
- Is this medium/high severity or just a nit?
- Is this actionable within PR scope?
- Is this about substance or style preference?
- Would I want this feedback if I were the author?

Cross-reference against available context:
- PR description justification
- Linked issue decisions
- Similar patterns in existing code
- Other reviewer comments

Severity Assessment:
- High: Will likely cause bugs, security issues, or major problems
- Medium: Could lead to bugs, maintenance issues, or moderate concerns
- Skip: Low severity, nits, style preferences, duplicates, pre-existing issues, uncertain due to limited context

When uncertain, skip rather than create noise.

5. CODE REVIEW DIMENSIONS

Review ONLY changed code across these areas:

5.1 Correctness & Quality
- Error/exception handling completeness
- Resource management (connections, files, memory)
- Type safety and null safety
- Logging consistency
- Edge case handling

5.2 Security
- Input validation and sanitization
- Access control and authorization
- SQL injection, XSS, CSRF prevention
- Secret management (no hardcoded secrets)
- Dependency vulnerabilities

5.3 Performance & Reliability
- Memory leaks and allocation patterns
- Concurrency correctness
- N+1 queries or inefficient operations
- Retry logic and timeout handling
- Data consistency

5.4 Architecture & Maintainability
- Component boundaries and coupling
- Interface design
- Code clarity and complexity
- Documentation for public APIs

5.5 Consistency with Existing Codebase
Only flag if inconsistency is significant:
- Does new code follow same patterns as existing similar code?
- Same error handling, naming, logging approaches?
- Same code organization structure?

Don't comment on style preferences, only significant inconsistencies causing confusion.

5.6 Generated Code Assessment
If code appears generated (repetitive, boilerplate, generic):
- Verify it's appropriate and adapted to specific use case
- Check it follows project patterns, not generic templates
- Flag if manipulated or illogical
- Don't penalize if correct and contextually appropriate

5.7 Testing (CRITICAL)

Coverage:
- Are new functions, methods, branches tested?
- Edge cases, error scenarios covered?
- Missing tests for significant functionality?
- Coverage notably low (under 70%)?

Quality:
- Do tests verify intended behavior?
- Meaningful assertions (not just "no crash")?
- Test names descriptive and clear?
- Tests isolated and independent?

Common Issues:
- Over-mocking: testing mock behavior instead of real logic
- Type "any" abuse: bypassing type checking
- Mock core business logic instead of testing it
- Test implementation details instead of behavior
- Missing negative/error tests
- Arbitrary sleeps instead of proper synchronization
- Tests inconsistent with existing test patterns

Severity:
- High: Missing tests for critical paths, "any" type abuse, mocking core logic
- Medium: Low coverage, tests not verifying behavior, excessive mocking

6. VALIDATE FINDINGS

Before posting, verify each finding:
- In the diff? (not pre-existing code)
- Relevant to PR goals?
- Not duplicate of existing comment?
- Not already resolved?
- Actionable with concrete solution?
- Helpful and fair feedback?
- Concise (2-4 sentences)?

If you couldn't fetch existing comments, skip duplication/resolution checks.

7. POST COMMENTS

7.1 Final PR Status Check
- Re-fetch PR state before posting
- EXIT if closed/merged
- Continue cautiously if check fails

7.2 Comment Placement
- ALWAYS prefer inline diff comments on specific lines
- Use general PR comments only for: cross-cutting concerns, architectural feedback, final summary

7.3 Comment Format
[Brief issue in 1 sentence]
[Impact in 1 sentence]
[Suggested fix with code when possible]

Use code suggestions:
\`\`\`suggestion
// improved code here
\`\`\`

7.4 Never Do
- Mark PR as "Changes Requested" or "Approved"
- Post duplicates, nits, or style comments
- Comment on resolved issues
- Write long explanations
- Comment on pre-existing code
- Produce text output (only use tools)

7.5 Final Summary Comment
After posting individual comments (or if none found):

If issues found:
"Reviewed this PR and found [N] areas that need attention. Please see inline comments for details."

If no issues after thorough review:
"Reviewed the changes. Implementation looks solid - good code quality, appropriate test coverage, follows established patterns. No significant concerns."

Acknowledge specific strengths when appropriate (test quality, documentation, best practices).

Only post positive summary if you genuinely found no medium/high issues after complete review.

8. EXECUTION WORKFLOW

1. Identify PR from git branch
2. Check PR status - EXIT if closed/merged
3. Gather context (continue if sources fail)
4. Understand and establish focus areas
5. Review code systematically (diff only)
6. Validate each finding thoroughly
7. Re-check PR status - EXIT if closed/merged
8. Post inline comments and final summary
9. Exit silently (no text output)

9. SUCCESS CRITERIA

- Gathered available context without failing on missing tools
- Focused only on diff, not pre-existing code
- Evaluated test quality and consistency thoroughly
- Only reported medium/high severity issues
- Avoided duplicates, nits, style preferences
- Provided concise, actionable feedback with suggestions
- Verified PR status before posting
- Posted final summary (issues or positive acknowledgment)
- Been helpful, fair, and constructive
- Produced zero text output (only tool calls)

REMEMBER: Quality over quantity. Understand before critiquing. Focus on what changed. Be helpful and fair. Check consistency with existing patterns, not arbitrary style. Treat generated code fairly. Always conclude with summary. Work with available context - never fail due to missing pieces.`}}}),_(k,{step:{case:`agent`,value:{prompt:`If you found no significant concerns in your review, add a "ioi-approved" label to the pull request. You have my explicit permission to add this label if you have no concerns about this code getting merged.`}}})]},"generate-agents-md":{id:`generate-agents-md`,title:`Add optimized AGENTS.md`,description:`Creates or updates AGENTS.md with project-specific guidance for coding agents.`,enabled:!0,recommended:!0,icon:y,iconColor:`text-content-primary`,iconBgColor:`bg-surface-base`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Create or update AGENTS.md (https://agents.md) - a README that helps AI agents work on this repo.

**Include:**
- Setup commands (install, build, dev server) from package.json/Makefile/similar
- Test commands with examples for running specific tests
- Lint/format commands to run before committing
- PR requirements: branch naming, commit format, required CI checks
- Key directories with brief descriptions

**Rules:**
- Only document commands that exist - verify against source files
- Keep it scannable, not prose
- Preserve valid existing content when updating
- For monorepos: include root commands and per-package instructions
- Omit sections with no information`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`chore: add AGENTS.md`,description:`Adds/Improves AGENTS.md to set up this repo for success with IOI Agent.

AGENTS.md provides project-specific instructions (setup, test, lint commands, PR guidelines) that help IOI work effectively on this codebase.

## Review checklist
- [ ] Commands are accurate
- [ ] Code style section matches project conventions
- [ ] PR guidelines match team expectations

See https://ioi.com/docs/ioi/agents-md and https://agents.md for background.`,branch:`ioi/agents-md`,draft:!0})}})]},"sentry-error-triage-and-fix":{id:`sentry-error-triage-and-fix`,title:`Sentry error triage & fix`,description:`Fixes the highest-impact unresolved Sentry error and opens a PR.`,enabled:!0,requiredIntegrations:[`Sentry`],icon:h,iconColor:`text-content-destructive`,iconBgColor:`bg-surface-destructive-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Sentry integration to list unresolved issues from the past 24 hours for this project. Sort by event count (most frequent first). Select the top unresolved issue that hasn't been assigned. Output: issue title, error message, stack trace, event count, and affected users count.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Using the Sentry stack trace from the previous step, locate the exact file and line in this repository where the error originates. Read the surrounding code and understand the root cause. Identify whether this is a null reference, type error, unhandled exception, race condition, or other category. Explain the root cause in one paragraph.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Fix the root cause identified in the previous step. Apply the minimal change needed. Add or update tests to cover the error scenario. Run the test suite to verify the fix doesn't break anything. If tests fail, iterate until they pass.`}}}),_(k,{step:{case:`task`,value:{command:`npm test || go test ./... || yarn test || echo 'Tests completed'`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`fix: resolve top Sentry error`,description:`Automated fix for the most frequent unresolved Sentry error. See PR body for root cause analysis.`,branch:`ioi/sentry-fix`,draft:!0})}}),_(k,{step:{case:`agent`,value:{prompt:`Use the Sentry integration to add a comment on the original Sentry issue linking to the PR that was just created. Mark the issue as 'assigned' if possible.`}}})]},"10x-engineer":{id:`10x-engineer`,title:`10x engineer`,description:`Picks your highest-priority Linear issue, implements it, runs tests, and opens a draft PR.`,enabled:!0,recommended:!0,requiredIntegrations:[`Linear`],icon:c,iconColor:`text-content-brand`,iconBgColor:`bg-surface-brand-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 9 * * 1-5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Linear integration to fetch issues assigned to the authenticated user in the current sprint/cycle. Sort by: (1) priority (urgent first), then (2) due date (soonest first). Exclude issues that are already 'In Progress', 'In Review', or 'Done'. Exclude epics and issues with more than 3 sub-tasks. Return the top 5 candidates with: identifier, title, description, priority, due date, labels, and acceptance criteria.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Evaluate each candidate issue from highest priority to lowest. For each issue, analyze this repository's codebase to determine whether you can implement it end-to-end: Are the requirements clear enough? Is the scope contained to a few files? Can you write meaningful tests for it? Does it require external services or infrastructure changes you can't make?

Pick the first issue where you're confident you can deliver a complete, working implementation. If none of the 5 candidates are feasible, stop and output: 'No suitable issue found today — all candidates require human judgment or are too large.' and skip remaining steps.

Output: the selected issue identifier and a one-paragraph implementation plan.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Use the Linear integration to update the selected issue's status to 'In Progress'. Add a comment: 'IOI is working on this issue automatically.'

Now implement the changes. Follow existing code patterns and conventions in this repository. Write tests for all new functionality. Handle edge cases mentioned in the acceptance criteria. Keep changes minimal and focused — do not refactor unrelated code.`}}}),_(k,{step:{case:`task`,value:{command:`npm test || go test ./... || yarn test || echo 'Tests completed'`}}}),_(k,{step:{case:`agent`,value:{prompt:`If tests failed, analyze the failures and fix them. Re-run the test suite. Iterate up to 3 times. If tests still fail after 3 attempts, revert your changes, use the Linear integration to set the issue back to its previous status, add a comment explaining what went wrong, and stop.`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`feat: implement Linear issue`,description:`Automated implementation by IOI Agent. See the linked Linear issue for requirements.`,branch:`ioi/linear-issue`,draft:!0})}}),_(k,{step:{case:`agent`,value:{prompt:`Use the Linear integration to update the issue status to 'In Review' and add a comment with a link to the created PR. Include a brief summary of what was implemented and any decisions made during implementation.`}}})]},"pr-changelog-to-notion":{id:`pr-changelog-to-notion`,title:`PR changelog`,description:`Updates Notion and CHANGELOG.md when a PR is merged.`,enabled:!0,requiredIntegrations:[`Notion`],icon:o,iconColor:`text-content-primary`,iconBgColor:`border border-border-subtle bg-surface-secondary`,trigger:_(O,{trigger:{case:`pullRequest`,value:_(w,{events:[M.MERGED]})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Read the merged pull request: title, description, labels, changed files, and commit messages. Categorize the change as one of: feature, fix, refactor, docs, chore, or breaking change. Extract a one-line summary and a detailed description (2-3 sentences max).`}}}),_(k,{step:{case:`agent`,value:{prompt:`Use the Notion integration to find the changelog database page (search for a page titled 'Changelog' or 'Release Notes'). If it doesn't exist, create a new Notion page titled 'Changelog'. Append a new entry with: date, PR title, category (feature/fix/etc), summary, author, and a link to the PR. Format it as a table row or database entry if the page uses a Notion database.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Check if a CHANGELOG.md (or CHANGES.md, HISTORY.md) file exists in the repository root. If it does, prepend the new changelog entry at the top of the file under the current date heading, following the existing format and conventions in the file. If the file uses Keep a Changelog format, place the entry under the appropriate section (Added, Fixed, Changed, etc.). Do not create a CHANGELOG.md if one doesn't already exist — the Notion entry is sufficient in that case.`}}})]},"weekly-sentry-report":{id:`weekly-sentry-report`,title:`Weekly Sentry error report`,description:`Publishes a weekly summary of new errors, regressions, and top offenders.`,enabled:!0,requiredIntegrations:[`Sentry`,`Notion`],icon:p,iconColor:`text-content-warning`,iconBgColor:`bg-surface-warning-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 9 * * 5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Sentry integration to gather data for the past 7 days: (1) new unresolved issues sorted by event count, (2) issues that regressed (were resolved but reappeared), (3) the top 5 most frequent errors by event count. For each issue, capture: title, error type, event count, affected users, first seen, and last seen.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Format the Sentry data into a structured report with these sections: **New Issues** (table: title, count, users, first seen), **Regressions** (table: title, count, previously resolved date), **Top Errors** (table: title, count, users, trend vs last week). Add a one-paragraph executive summary at the top: total new issues, total events, comparison to previous week if data is available.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Use the Notion integration to create a new page titled 'Error Report — Week of {DATE}' in the team's engineering space (search for 'Engineering' or 'Error Reports' section). Add the formatted report content. Include a link back to the Sentry project dashboard.`}}})]},"linear-sprint-standup":{id:`linear-sprint-standup`,title:`Daily standup generator`,description:`Combines Linear and Git activity into a daily standup update.`,enabled:!0,recommended:!0,requiredIntegrations:[`Linear`],icon:a,iconColor:`text-content-success`,iconBgColor:`bg-surface-success-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 9 * * 1-5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Linear integration to fetch the current active sprint/cycle for the authenticated user. Get: (1) issues completed in the last 24 hours (status changed to 'Done'), (2) issues currently 'In Progress', (3) issues marked as 'Blocked' or with blocking labels. For each issue, get: identifier, title, priority, and any blockers mentioned in comments.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Summarize yesterday's git activity in this repository. Run 'git log --since="24 hours ago" --oneline --no-merges' to get recent commits. Group them by area of the codebase (e.g., frontend, backend, tests, docs, infra). Note any PRs that were merged. Keep the summary concise — one line per commit group, not per commit.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Combine the Linear sprint data and git activity into a formatted standup update:

**Yesterday:**
- List completed Linear issues with identifiers
- Summarize git activity (merged PRs, areas touched)

**Today:**
- List in-progress Linear issues with identifiers

**Blockers:**
- List blocked issues with reason (or 'None')

Keep it concise — one line per item. Use the Linear integration to post this as a comment on the current sprint/cycle, or output it for the user to share.`}}})]},"notion-tech-spec-from-issue":{id:`notion-tech-spec-from-issue`,title:`Tech spec from Linear issue`,description:`Turns a Linear issue into an implementation-ready spec with technical design and execution details.`,enabled:!0,recommended:!0,requiredIntegrations:[`Linear`,`Notion`],icon:m,iconColor:`text-content-brand`,iconBgColor:`bg-surface-brand-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Linear integration to fetch issue {ISSUE_ID}. Extract all context: title, description, acceptance criteria, comments, linked issues, and sub-issues. Identify the scope of work and any constraints mentioned.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Analyze this repository's codebase to understand the relevant architecture: directory structure, existing patterns, data models, API conventions, and test patterns. Map the Linear issue requirements to specific areas of the codebase that will need changes.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Write a technical specification covering:

**Overview:** One paragraph on what this change does and why.

**Design:** Key architectural decisions, component interactions, data flow.

**API Changes:** New or modified endpoints/RPCs with request/response shapes.

**Data Model:** Schema changes, migrations needed.

**Implementation Plan:** Ordered list of tasks with estimated complexity (S/M/L).

**Testing Strategy:** What to test, edge cases, integration test needs.

**Risks:** What could go wrong, migration concerns, backward compatibility.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Use the Notion integration to create a new page titled 'Tech Spec: {ISSUE_TITLE}' in the engineering docs space. Add the technical specification content with proper headings and formatting. Add a link to the Linear issue at the top. Use the Linear integration to add a comment on the issue linking to the Notion spec.`}}})]},"sentry-to-linear-issues":{id:`sentry-to-linear-issues`,title:`Sentry to Linear issues`,description:`Turns new Sentry errors into prioritized Linear issues with relevant context.`,enabled:!0,requiredIntegrations:[`Sentry`,`Linear`],icon:f,iconColor:`text-content-destructive`,iconBgColor:`bg-surface-destructive-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 9 * * 1-5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Sentry integration to list new unresolved issues from the past 24 hours with more than 10 events. For each issue, extract: title, error message, stack trace (first 3 frames), event count, affected users count, and first/last seen timestamps. Skip issues with fewer than 10 events.`}}}),_(k,{step:{case:`agent`,value:{prompt:`For each Sentry issue found, use the Linear integration to search for existing issues with matching titles or error messages. If a Linear issue already exists, skip it. For issues without a matching Linear ticket, create a new issue with:

- **Title:** Short error description
- **Description:** Error message, stack trace, event count, affected users, link to Sentry issue
- **Priority:** Urgent if >100 events or >50 users, High if >50 events or >20 users, Medium otherwise
- **Labels:** 'bug', 'sentry-auto'

Output a summary of what was created and what was skipped.`}}}),_(k,{step:{case:`agent`,value:{prompt:`For each newly created Linear issue, use the Sentry integration to add a comment on the corresponding Sentry issue with the Linear issue link and identifier.`}}})]},"migrate-deprecated-api":{id:`migrate-deprecated-api`,title:`Migrate deprecated API usage`,description:`Replaces deprecated APIs, validates the migration, and opens a PR.`,enabled:!0,icon:u,iconColor:`text-content-warning`,iconBgColor:`bg-surface-warning-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N)},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`The user wants to migrate from {OLD_API} to {NEW_API}. Search the entire repository for all usages of the deprecated API: imports, function calls, type references, and configuration. List every file and line number where the old API is used. Count total occurrences. If no usages found, report that and stop.`}}}),_(k,{step:{case:`agent`,value:{prompt:`For each usage found, determine the correct migration path. Read the new API's documentation or source to understand the equivalent replacement. Handle edge cases: changed function signatures, renamed parameters, different return types, removed features that need workarounds. Plan the migration file by file.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Apply the migration across all files. Update imports, replace function calls, adjust types, and update any configuration files. Ensure each file compiles/parses correctly after changes. Run the linter if available.`}}}),_(k,{step:{case:`task`,value:{command:`npm test || go test ./... || yarn test || echo 'Tests completed'`}}}),_(k,{step:{case:`agent`,value:{prompt:`If any tests failed, analyze the failures and fix them. The failures are likely due to the API migration — adjust test expectations, update mocks, or fix migration errors. Re-run tests until they pass.`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`refactor: migrate deprecated API usage`,description:`Automated migration of all deprecated API usage by IOI Agent.`,branch:`ioi/migrate-api`,draft:!0})}})]},"scan-recent-commits":{id:`scan-recent-commits`,title:`Scan recent commits for bugs`,description:`Finds likely bugs in recent commits and opens a draft PR with proposed fixes.`,enabled:!0,recommended:!0,icon:g,iconColor:`text-content-warning`,iconBgColor:`bg-surface-warning-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 9 * * 1-5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Run 'git log --since="24 hours ago" --oneline --no-merges' to get recent commits. For each commit, run 'git show <hash>' to see the full diff. Analyze each change for likely bugs: null/undefined dereferences, off-by-one errors, missing error handling, unclosed resources, race conditions, incorrect boolean logic, missing input validation, or security issues. Focus only on code that was added or modified — do not flag pre-existing issues. List each finding with: file, line, bug category, and a one-sentence explanation.`}}}),_(k,{step:{case:`agent`,value:{prompt:`For each bug found in the previous step, apply the minimal fix. Change only what's necessary to resolve the issue — do not refactor surrounding code. Add or update tests to cover the bug scenario where practical. Run the linter if available.`}}}),_(k,{step:{case:`task`,value:{command:`npm test || go test ./... || yarn test || echo 'Tests completed'`}}}),_(k,{step:{case:`pullRequest`,value:_(F,{title:`fix: bugs found in recent commits`,description:`Automated scan of recent commits found potential bugs. Each fix is minimal and targeted. See the diff for details on what was found and fixed.`,branch:`ioi/commit-scan-fixes`,draft:!0})}})]},"draft-weekly-release-notes":{id:`draft-weekly-release-notes`,title:`Draft weekly release notes`,description:`Turns merged PRs into categorized release notes with concise summaries.`,enabled:!0,recommended:!0,icon:v,iconColor:`text-content-brand`,iconBgColor:`bg-surface-brand-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 16 * * 5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`List all PRs merged in the past 7 days. For each PR, extract: title, author, labels, and a one-line summary of the change from the PR description or commit messages. Include the PR number and link where available.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Organize the merged PRs into release notes with these sections:

**Highlights** — The 2-3 most notable changes, each with a short paragraph explaining the user impact.

**Features** — New functionality added.

**Bug Fixes** — Issues resolved.

**Improvements** — Performance, refactoring, developer experience.

**Other** — Docs, CI, chores.

Each entry should be one line: a short description followed by the PR link in parentheses. Write in a tone suitable for sharing with the broader team or external stakeholders — clear, factual, no jargon. Output the release notes as markdown.`}}})]},"ci-failure-summary":{id:`ci-failure-summary`,title:`CI failure & flaky test summary`,description:`Highlights recurring CI failures and flaky tests, ranked by impact.`,enabled:!0,icon:i,iconColor:`text-content-destructive`,iconBgColor:`bg-surface-destructive-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 9 * * 1-5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Analyze recent CI runs for this repository. Check GitHub Actions workflow runs from the past 7 days (or the CI system used in this repo). For each failed run, extract: workflow name, job name, failure message, failing test name (if applicable), and the commit that triggered it. Identify tests that failed intermittently (passed on retry or failed on some runs but not others) — these are flaky tests. Group failures by: (1) consistent failures (same test/job fails every time), (2) flaky failures (intermittent), (3) infrastructure failures (timeouts, OOM, network errors).`}}}),_(k,{step:{case:`agent`,value:{prompt:`Produce a CI health summary:

**Overall Status:** Pass rate for the past 7 days (e.g., "82% of runs passed").

**Top Failures** (ranked by frequency):
For each, list: test/job name, failure count, failure message, and the likely root cause.

**Flaky Tests** (ranked by flake rate):
For each, list: test name, flake rate, and whether it's a timing issue, resource contention, or test isolation problem.

**Suggested Fixes** (top 3, ranked by impact):
For each, explain what to fix and why it would have the biggest impact on CI stability. Be specific — name the file, test, or configuration to change.

Keep the summary concise and actionable.`}}})]},"linear-bug-to-fix":{id:`linear-bug-to-fix`,title:`Linear bug to fix PR`,description:`Converts a Linear bug report into a tested fix and draft PR.`,enabled:!0,requiredIntegrations:[`Linear`],icon:f,iconColor:`text-content-warning`,iconBgColor:`bg-surface-warning-subtle`,trigger:_(O,{trigger:{case:`manual`,value:_(N,{})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Use the Linear integration to fetch the bug issue assigned to you (or the most recent high-priority bug in the current cycle). Extract: title, description, reproduction steps, acceptance criteria, and any linked code references or stack traces.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Based on the bug details, locate the relevant code in this repository. Identify the root cause, implement a fix, and add or update tests that cover the failure case. Open a pull request with:

- A title referencing the Linear issue ID
- A description summarizing the root cause and the fix
- Test coverage for the bug scenario

Mark the Linear issue as "In Review" after opening the PR.`}}})]},"notion-weekly-digest":{id:`notion-weekly-digest`,title:`Weekly team digest to Notion`,description:`Publishes a weekly digest of team activity, merged PRs, and open work.`,enabled:!0,requiredIntegrations:[`Notion`],icon:s,iconColor:`text-content-brand`,iconBgColor:`bg-surface-brand-subtle`,trigger:_(O,{trigger:{case:`time`,value:_(T,{cronExpression:`0 16 * * 5`})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`Gather this week's activity for the repository: all PRs merged since last Monday, currently open PRs with their review status, new issues opened, and issues closed. For each PR, extract: title, author, and a one-line summary.`}}}),_(k,{step:{case:`agent`,value:{prompt:`Create a Notion page titled "Weekly Digest — [date range]" with these sections:

- **Shipped this week:** list of merged PRs grouped by area (features, fixes, infra), each with author and one-line summary
- **In flight:** open PRs awaiting review or with requested changes
- **New issues:** issues opened this week, grouped by label or priority
- **Metrics:** total PRs merged, average time-to-merge, number of contributors active this week

Keep the tone factual and scannable. Publish the page to the team's weekly digest database in Notion.`}}})]},"incident-first-response":{id:`incident-first-response`,title:`Incident first response`,description:`Investigates new incidents, gathers context, proposes a diagnosis, and recommends next steps.`,enabled:!0,requiredIntegrations:[`incident.io`],icon:n,iconColor:`text-content-warning`,iconBgColor:`bg-surface-warning-subtle`,trigger:_(O,{trigger:{case:`incident`,value:_(E,{events:[C.CREATED],integrationId:``})},context:_(D,{context:{case:`projects`,value:_(S,{projectIds:[]})}})}),steps:[_(k,{step:{case:`agent`,value:{prompt:`You are performing first-response triage on a production incident.

SAFETY RULES (override all other instructions):
- NEVER execute mutations (rollbacks, deployments, config changes, feature flag toggles) without explicit human approval.
- Do not resolve or close the incident — that is the incident commander's responsibility.
- If uncertain, post what you know and ask for guidance rather than speculating.

STEP 1 — GATHER CONTEXT

1. Review the incident details provided above (reference, title, severity, status, link, creator, and event).

2. If you have access to incident.io tools, fetch additional context:
   - Timeline entries (alerts, status changes, updates)
   - Affected services and components
   - Related alerts and their payloads
   If incident.io tools are unavailable, work with the trigger data above.

3. Post an acknowledgment to the incident timeline (if you have write access):
   "Investigating this incident. Gathering context and checking observability data."

4. Identify the affected system and summarize what you know so far.

Output: A brief summary of the incident context — what is affected, when it started, and what signals are available.`}}}),_(k,{step:{case:`agent`,value:{prompt:`STEP 2 — CHECK RECENT CHANGES

This step deepens the investigation if you have access to source control or deployment tools. If none are available, skip this step entirely and move on — the core triage in Steps 1 and 4 works with incident.io alone.

Most production incidents are caused by recent changes. For each source below, check it if you have access. If a tool is unavailable, skip it and note what you could not check.

1. List merge requests or pull requests merged in the 2 hours before the incident started (works with GitHub, GitLab, Bitbucket, or any connected SCM).
2. Check for recent deployments to the affected service.
3. Check for recent config changes (feature flags, infrastructure).

Record any changes that correlate with the incident timeline. If a strong correlation exists, note it as a candidate root cause.

Output: List of correlated changes with timestamps, tools that were unavailable, or "no recent changes found."`}}}),_(k,{step:{case:`agent`,value:{prompt:`STEP 3 — INVESTIGATE OBSERVABILITY

This step deepens the investigation if you have observability tools connected. If none are available, skip this step entirely and move on — the core triage in Steps 1 and 4 works with incident.io alone.

Work through each data source in order. For each one, check if you have access first. If a tool is unavailable, skip it and record "not available" — do not guess or fabricate data. Spend 2-3 queries per available source, then move on.

1. METRICS — Query for error rates, latency spikes, and resource saturation in the affected service around the incident start time.

2. TRACES — Look for failing spans, error traces, or latency outliers in the affected service. Find a representative failing trace and examine which downstream call fails.

3. LOGS — Search for error patterns in the affected service's logs within ±15 minutes of the incident start. Identify the most frequent error messages.

4. ERRORS — Check for new or spiking error groups in error tracking that correlate with the incident.

After each source, record findings. Absence of signal is itself informative — note what was checked and what was unavailable.

Output: Findings from each available data source, organized by source. List any sources that were unavailable.`}}}),_(k,{step:{case:`agent`,value:{prompt:`STEP 4 — DIAGNOSE

Synthesize all findings into a structured assessment and post it to the incident timeline.

1. Reconstruct the timeline: when did the first error appear, when did metrics degrade, what changed just before?

2. Search for similar past incidents (if incident.io search tools are available):
   - Search for incidents with similar titles, affected services, or error signatures
   - If a match exists, note when it happened, what caused it, and what mitigation worked
   - Assess whether the same fix could apply here
   If search is unavailable, set Prior art to "Unable to search — incident.io search tools not connected."

3. Form a root-cause hypothesis based on evidence. Distinguish confirmed facts from hypotheses. If a past incident matches, reference it explicitly.

4. Assess impact: what is broken, what is not, who is affected.

5. Rate your confidence: High (direct correlation confirmed by multiple sources), Medium (plausible with partial evidence), or Low (no clear signal). A matching past incident increases confidence.

Post to the incident timeline in this format:

## Investigation Summary

**Hypothesis:** [one-sentence root cause]

**Prior art:** [INC-XXX on <date> — same root cause, fixed by <action>] or "No similar past incidents found"

**Evidence:**
- [finding 1 with source]
- [finding 2 with source]

**Impact:** [what is broken and scope]

**Confidence:** [High/Medium/Low]

If confidence is Low, state what additional information would help and ask the incident lead for guidance.`}}}),_(k,{step:{case:`agent`,value:{prompt:`STEP 5 — PROPOSE MITIGATION

Based on the diagnosis, propose concrete mitigation actions. Do NOT execute any of them.

Common patterns:
- Revert deployment → provide the git revert command or draft PR
- Feature flag toggle → provide the flag name, current value, proposed value
- Config rollback → provide the previous value and change command
- Scale up → provide the resource type and proposed values
- Restart service → provide the service name and restart command

For each proposed action:
1. State what it does and why
2. Provide the exact command or PR
3. State expected outcome and how to verify

Post to the incident timeline:

## Proposed Mitigation

**Option 1: [action name]**
- Command: [exact command]
- Expected outcome: [what should happen]
- Verification: [how to confirm it worked]

Awaiting approval from incident lead to proceed.

REMINDER: Do NOT execute any mitigation without explicit human approval.`}}})]}},R={"launch-use-cases":{id:`launch-use-cases`,label:`Works out of the box`,templates:{"scan-recent-commits":L[`scan-recent-commits`],"draft-weekly-release-notes":L[`draft-weekly-release-notes`],"generate-agents-md":L[`generate-agents-md`],"automated-dev-environment-setup":L[`automated-dev-environment-setup`],"cve-mitigation-and-version-updates":L[`cve-mitigation-and-version-updates`],"add-and-maintain-readmes-and-backstage-yaml":L[`add-and-maintain-readmes-and-backstage-yaml`],"code-review":L[`code-review`],"migrate-deprecated-api":L[`migrate-deprecated-api`],"ci-failure-summary":L[`ci-failure-summary`]}},integrations:{id:`requires-integrations`,label:`With integrations`,description:`Requires connecting external tools like Figma, Linear, Sentry, or Notion`,templates:{"incident-first-response":L[`incident-first-response`],"10x-engineer":L[`10x-engineer`],"linear-sprint-standup":L[`linear-sprint-standup`],"notion-tech-spec-from-issue":L[`notion-tech-spec-from-issue`],"sentry-error-triage-and-fix":L[`sentry-error-triage-and-fix`],"sentry-to-linear-issues":L[`sentry-to-linear-issues`],"weekly-sentry-report":L[`weekly-sentry-report`],"pr-changelog-to-notion":L[`pr-changelog-to-notion`],"linear-bug-to-fix":L[`linear-bug-to-fix`],"notion-weekly-digest":L[`notion-weekly-digest`]}},"from-scratch":{id:`from-scratch`,label:`Or`,templates:{"start-from-scratch":L[`start-from-scratch`]}}},z=e=>L[e],B=(t,n)=>{let r=t.has(e.Webhooks),i=n?.incidentTriggersEnabled??!1;return Object.values(R).map(e=>{let t=Object.fromEntries(Object.entries(e.templates).filter(([,e])=>!(!r&&e.trigger.trigger.case===`pullRequest`||!i&&e.trigger.trigger.case===`incident`)));return{...e,templates:t}}).filter(e=>Object.keys(e.templates).length>0)},V=e=>{let t=L[`start-from-scratch`];return{...t,title:`${e.metadata?.name??`Automation`} (copy)`,description:e.metadata?.description??``,steps:e.spec?.action?.steps?e.spec.action.steps.map(e=>structuredClone(e)):[...t.steps],trigger:e.spec?.triggers?.[0]?structuredClone(e.spec.triggers[0]):t.trigger}},H=(e,t)=>_(P,{metadata:{name:e.title,description:e.description,executor:{id:t,principal:x.USER}},spec:{triggers:[e.trigger],action:_(A,{limits:_(j,{maxParallel:I.maxParallel,maxTotal:I.maxTotal}),steps:[...e.steps]})}});export{H as i,z as n,B as r,V as t};