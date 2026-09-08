# Overlay scan propagation and registry bootstrap — scoped repair

The production state-overlay iterator now returns backing scan errors before
selecting a merge branch. An error cannot masquerade as an empty registry
namespace or be hidden behind pending overlay writes. The service regression
first failed against the original iterator (baseline-negative.log, exit 101),
then passed after repair. No third-party target or network reproduction is used.

Two iterator regressions preserve leading/repeated/middle/trailing errors while
checking sorted writes, overrides and deletions. The registry regression requires
the precise backend error and empty overlay write set, then verifies successful
bootstrap and explicit commit after the base becomes readable. This is an actual
service-to-overlay test, not process-boundary crash qualification.

The source-bound collector passes 364 API tests (one unrelated legacy chat test
is ignored), five registry tests, one transaction-write cleanup test, 15 runtime
finality tests, CLI compilation, formatting and syntax. The conditional bootstrap
proof discharges nine TLAPS obligations with nine model states and one expected
hidden-error counterexample. Existing locator checks also pass: ten obligations,
35/21 states and three expected countermodels. See results.json and completed.json.

Reproduce the scoped collector with `python3
internal-docs/architecture/protocols/aft/evidence/m17q-r1-overlay-scan-2026-09-06/run_checks.py`
from the repository root. Baseline source is retained in overlay-before.rs;
selected repaired sources/hashes, exact commands and timestamped toolchain
observation are retained. These are dirty-worktree source bindings, not immutable
qualification. No source changed during the collector.

A subsequent coverage audit found that M16Q's seven selected formal modes omitted
scheduled QUV repair proofs. The runner now invokes the complete default automated
corpus once, including trace replay and the timed QUV model. Syntax and census
pass; the full expensive qualification is deferred until integration is ready.
qualification-coverage-before/after.json and qualification-runner-after.sh bind
this later harness change separately. Existing manual debt for other profiles
remains labeled debt and supplies no QUV or classical-consensus authority.

Assumes: accurate underlying reads/scans, exclusive namespace custody during the
scan/commit interval, and transactional overlay commit/discard. Error propagation
discharges one read-barrier obligation, not physical resource/service bounds,
backing-store crash consistency, complete transition refinement, or migration.
All whole R1 findings remain OPEN; R2 unqualified; M17Q REPAIR_REQUIRED;
M18Q NOT_ADMITTED. No candidate, fresh reviewer or owner-only action exists.
