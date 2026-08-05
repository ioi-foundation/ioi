# Engineering lessons from the M5-era work

The M5-era work exposed several recurring ways that an implementation can diverge from its intended boundary even when its labels and summaries look correct. These notes preserve the transferable engineering insights without recreating release criteria, required process, evidence retention, or a standing review program.

1. **Read the retained bytes.** Names, summaries, and prior reports are useful leads, but the bytes present at an exact revision describe what actually exists. For vendored code, enumerating the upstream Git tree is more reliable than inspecting a working copy whose contents may already have been shaped by ignore rules or copy behavior.

2. **Treat the resolver’s view as reachability.** A file can exist and still be absent from the running product because imports, package resolution, route registration, configuration, or generated maps never reach it. Conversely, a seemingly peripheral file can remain live through one indirect import. Following the resolver used by the product reveals the operative graph.

3. **Instrument before aiming.** Counts, traces, and call-site observations make hidden behavior visible before optimization or correction begins. Measuring traversal frequency, handle acquisition, or route use distinguishes a real hot path or ownership breach from an assumption based on an unchanged output.

4. **An absence claim covers the whole relevant tree.** Checking the expected directory alone can miss a duplicate, fallback, generated copy, fixture, or configuration alias elsewhere. Broad repository searches are most useful when paired with an understanding of imports and generation, because matching text and reachable behavior are related but different questions.

5. **Keep durable truth under one owner.** When multiple layers mint their own sequence, receipt, head, or lifecycle for the same event, they can drift while remaining individually plausible. A clearer design lets one substrate own the transition and lets consumers retain typed references and derived state. Backed reference constructors also avoid treating a well-formed string as proof that an object was admitted.

6. **Compare failure identity, not only pass or fail.** The same command can fail before and after a change for unrelated reasons. Comparing the test name, assertion, error, inputs, and baseline behavior distinguishes a newly introduced regression from an unchanged defect and makes the remaining work concrete.

7. **Derive projections from canonical inputs.** A registry or schema is easier to reason about when Rust and TypeScript projections are generated from it together. Editing projections independently creates several interpretations of one contract; generation from a shared source keeps representational limits and differences visible.

8. **Separate product regression signal from process artifacts.** Product tests exercise behavior that users and dependent components rely on. Transcripts, packets, and checker-specific fixtures describe how a particular review was conducted. When process artifacts consume iteration without adding product regression signal, removing them need not weaken the ordinary build and test suites.

9. **Use Git history for rollback.** Annotated tags before a broad deletion preserve an exact, inspectable recovery point without leaving archive copies in the active tree. This keeps a cleanup ordinary and reversible while allowing the current repository to describe only the current system.

10. **Keep investigative evidence scoped and disposable.** A small observation attached to the question being answered is easier to interpret than a permanently regenerated estate. A trace that is valuable during diagnosis does not automatically need permanent ownership, periodic refresh, or a review cadence; durable documentation is most useful when it records the resulting product or architectural insight.
