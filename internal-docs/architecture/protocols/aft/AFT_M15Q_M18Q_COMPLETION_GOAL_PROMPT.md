# Persistent goal prompt — complete AFT QUV M15Q–M18Q

Use the text below as the continuation goal. Do not assign a token budget
unless the owner explicitly requests one.

```text
Persistently execute the remaining AFT interactive-QUV completion program in:

- internal-docs/architecture/protocols/aft/MAXIMAL_CONSENSUS_ACTION_PLAN.md
- internal-docs/architecture/protocols/aft/AFT_MAXIMAL_E2E_GOAL_PROMPT.md
- internal-docs/architecture/protocols/aft/IMPLEMENTATION_LEDGER.md
- internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md
- internal-docs/architecture/protocols/aft/specs/query_unanimity_theorems.md
- internal-docs/architecture/protocols/aft/specs/query_unanimity_end_to_end_theorems.md

Begin from the repository's actual current state and preserve unrelated user
changes. Confirm that master contains commit e8ec2dc44, or a descendant with
equivalent evidence. Treat these dispositions as fixed unless new contrary
evidence requires reopening them: M9-M11 are complete; M12a remains the proved
and independently upheld lower bound for portable byte-only authorization;
M12b is PASS_CONSTRUCTION for interactive QUV under its exact known-synchrony
assumptions; M13Q and M14Q are locally proved/mechanized and await M17Q review.
Original M13-M18 remain blocked by M12a. M15Q is the sole critical path.

This is an implementation, qualification, review, and admission goal—not a
request for another plan. Continue autonomously through every safe executable
step. Inspect, design, edit, test, mechanize, commit coherent slices, preserve
reproducible evidence, and advance a gate only when its stated acceptance
criteria are genuinely met. Reopen any nominally complete gate contradicted by
process evidence.

Complete M15Q end to end:

1. Preserve and extend the proven Q-EA7 release-process handoff at e8ec2dc44:
   disjoint old/successor roots, old-root QC-certified exact boundary,
   non-authoritative owner ceremony draft, owner-signed source, successor-only
   state import, each successor's own live QUV operation, rollback-anchored
   install, strict-PQ activation, and post-handoff ordering progress. The
   boundary QC is replayable ordering evidence only; possession of it or of the
   handoff bytes must never enable successor authority.
2. Add process restart/recovery tests at every handoff durable boundary. A
   restart may recover an already installed local gate, but may never synthesize
   authorization retroactively, trust a cached transcript, or activate from
   source bytes alone. Cover overlapping and disjoint roots, failed/conflicting
   handoffs, expiry, rollback, and old-member retirement/observation semantics.
3. Replace test-only/manual source provisioning with explicit fail-closed
   operator ceremony tooling that emits, validates, signs, atomically installs,
   and audits the exact typed candidate without making the operator a hidden
   online finality oracle.
4. Complete the real irreversible-effect path. Every relying executor must run
   QUV itself immediately before T10's durable Claim transition and consume the
   process-local continuation directly. No transcript, receipt, RPC result,
   previous verifier, or cached "QUV passed" assertion may authorize execution.
   Preserve the stable conflict-domain idempotency key, claim-before-call,
   ambiguity/lookup reconciliation, crash recovery, and at-most-once modeled
   externalization. Audit evidence remains non-authorizing and
   portable_final_receipt=false.
5. Preserve bounded isolated QUV scheduling, strict hash/PQ profile separation,
   and the Hypervisor's dependency isolation and fast build/smoke path. Do not
   restore BLS, VDF, classic_bft, legacy, or fallback authority into the QUV
   theorem path.

Do not close M15Q until real multiprocess tests exercise both the complete
handoff/restart path and executor-to-members-to-durable-effect path through the
production implementation.

Then execute M16Q. Build reproducible adversarial and performance campaigns for
every correct-member placement at f=n-1; silence; valid conflicts; Byzantine
injection and opposite orderings; every delta_rt component and deadline edge;
missing correct replies; one-way-bound, write-before-durable, rollback,
split-atomicity, replay, cross-context, stale-session, and queue-flood
mutations; all member/verifier/successor/executor/resource crash boundaries;
overlapping/disjoint reconfiguration; stalled versus unrelated domains; mixed
profiles; and externalization ambiguity/reconciliation. Measure distributions
and worst cases, derive the deployment envelope with explicit margin, fail
closed outside it, retain raw artifacts, and bind every result to an exact
commit/toolchain/configuration. Do not weaken Q-A3 or Q-A9 to make a campaign
pass.

Only after M15Q and M16Q pass, execute M17Q. Freeze one clean immutable
candidate containing code, proofs, models, tests, raw evidence, claim matrices,
and reproduction commands. The owner expressly authorizes a fresh
gpt-daybreak-blue-latest agent as the independent automated security/theorem
reviewer at this gate. Give it only the immutable candidate and exact task,
assumptions, lower bounds, attack requirements, and commands. Require source
inspection, reproduction, process tests, an independent model/spec-only twin,
an independence disclosure, and attributable findings. This is automated
independent review, not human peer review or institutional certification.
Remediate every critical/high finding, rerun affected gates, freeze a new
candidate, and obtain fresh review. M17Q closes only on the exact final commit
with no unresolved critical/high finding.

Then execute M18Q on that same immutable candidate: clean-checkout reproduction,
affected workspace/formal/adversarial/restart/process/Hypervisor gates,
fault-property-profile matrix, coordinate-wise meet/no-laundering checks, exact
schema/spec/runtime/public wording, retained M12a lower bound, and explicit
timing/reachability/durability/PQ/portability/consequence costs. Prepare exact
release, tag, push, deployment, and publication artifacts. Do not perform a
public push, deployment, paid engagement, or publication without contemporaneous
owner authorization; when that is the only remaining action, provide the exact
immutable candidate and commands for approval without claiming it already
happened.

Treat every desired theorem and headline as a target, never a premise. Never
call QUV portable, offline, asynchronous, or a byte-verifiable certificate;
claim safety if the correct response can miss the rooted deadline; count Abort,
freeze, or veto as effect liveness; mint authority from timeout/silence; trust a
cached verifier; assume hidden publication/relay/oracle/TEE/honest-majority
custody; downgrade profiles on timeout; or relabel classic BFT, hash-async
ordering, terminal seals, or research code as QUV. Do not call the result
classical Byzantine consensus unless that exact task has separately been
proved, implemented, qualified, and independently reviewed.

Maintain exactly one critical-path milestone and keep the action plan, ledger,
assumptions, findings, and claim gates current after each material slice.
Distinguish bounded-model evidence, machine-checked proof, production process
evidence, and independent review. Slow or difficult work is not a blocker.
Ask the owner only for genuinely external authority or a premise change.

Continue until M15Q, M16Q, M17Q, and M18Q have honest terminal dispositions on
one immutable candidate. Mark completion only when the exact online QUV claim
is proved, implemented end to end, adversarially qualified, cleanly reproduced,
independently reviewed, accurately documented, and admitted for release while
M12a and portable_final_receipt=false remain intact. If a reproduced
counterexample or lower bound defeats the interactive target under its fixed
assumptions, preserve it, block the affected gate, and request an explicit owner
decision naming the premise that may change; never hide or weaken the result.
```
