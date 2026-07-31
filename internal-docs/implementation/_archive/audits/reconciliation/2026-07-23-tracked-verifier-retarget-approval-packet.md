# Runtime-Kernel Verifier Retarget — Private-Only Completion Design

Date: 2026-07-23  
Checkout inspected: `feat/estate-camera-pipeline` at
`a894b25054cdb45f27deb3163793773d6449dd2b`  
Document class: dated reconciliation audit; this document schedules no work,
owns no implementation status, and amends no M0–M14 sequence.

## Decision

No tracked-change approval is required or justified.

The alleged tracked verifier,
`scripts/internal/verify-runtime-kernel-trust-audit.mjs`, is ignored by
`.gitignore:79`, is absent from this checkout's index and `HEAD`, is absent from
local `master` and `origin/master`, and has no path history in any inspected
local or remote-tracking ref. The implementation directory itself is ignored by
`.gitignore:109`. Consequently, force-adding or relocating the verifier into a
tracked path would create a new public/tracked implementation tool and would
contradict the private-only objective.

SA-4 already approves both root-body dispositions:

- preserve the dated trust audit under `audits/history/` and leave a stable
  pointer; and
- generate the residual census under `generated/` and leave a stable JSON
  pointer while preserving the exact former root body.

The compatibility holds arose from an incorrect tracked-file premise. They can
be retired entirely inside `internal-docs/implementation/`, with an optional
logic-free ignored wrapper at the old command path.

## Current evidence

| Fact | Evidence |
| --- | --- |
| Verifier is not indexed | `git ls-files --stage -- scripts/internal/verify-runtime-kernel-trust-audit.mjs` returns no entry. |
| Verifier is not in this commit | `git cat-file -e HEAD:scripts/internal/verify-runtime-kernel-trust-audit.mjs` fails with “does not exist in HEAD”. |
| Verifier is not in inspected master refs | The same object check fails for local `master` and `origin/master`; the path is absent from `git log --all --`. |
| Verifier is intentionally ignored | `git check-ignore -v` resolves it to `.gitignore:79:scripts/internal/`. |
| Private estate is intentionally ignored | `git check-ignore -v internal-docs/implementation/...` resolves to `.gitignore:109:/internal-docs/implementation/`. |
| Local verifier body | SHA-256 `b6d7f1da22d5efba2f18d0ca5c3a0ba3c9d2ea02b264186455fcb72af565ff70`; 783 lines. |
| Dated audit body | Root and `audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md` both have SHA-256 `75a51210750dca6022742a2c39e6289f9081f6451d3ef24828e4b6fdff51184b`. |
| Former residual body | Root SHA-256 `19500ed05d261a6fde6aa1879ae70de8111242d73b982fd39479ec62bc5273c5`. |
| Only executable call site | `tools/generate-runtime-kernel-residual.mjs` spawns the ignored verifier. No package script, tracked test, CI workflow, or tracked caller was found. |
| Current positive result | The verifier reports 198 baseline rows; callable counts 36/110/44/9; two retired methods; 52 residual modules; 134 kernel files; 863 scanned Rust files. |

The evidence proves that the proposed change is a private orchestration cleanup,
not a tracked runtime or canon change. It proves no stage, runtime behavior, or
namespace-extraction completion.

## Exact end-state path ownership

| Role | Exact path | Contract |
| --- | --- | --- |
| Reusable active method | `internal-docs/implementation/stage-guides/m0/runtime-trust-boundary.md` | Subordinate M0/M9 method; owns no sequence, status, architecture doctrine, or product authority. |
| Active verifier | `internal-docs/implementation/tools/verify-runtime-kernel-trust-audit.mjs` | Private fail-closed census checker over current Rust and immutable dated inputs. |
| Exact original verifier body | `internal-docs/implementation/_archive/pre-unification-baseline/scripts/internal/verify-runtime-kernel-trust-audit.mjs` | Byte-for-byte preservation of SHA-256 `b6d7f1...65ff70`; inert archive. |
| Dated 198-row audit | `internal-docs/implementation/audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md` | Immutable audit input and historical evidence; already exact. |
| Dated residual baseline | `internal-docs/implementation/_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json` | Byte-for-byte preservation of SHA-256 `19500e...73c5`; immutable verifier/generator input. |
| Current residual projection | `internal-docs/implementation/generated/runtime-kernel-namespace-residual.v1.json` | Deterministic, status-free projection written only by the private generator. |
| Stable audit root | `internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md` | One-screen Markdown compatibility pointer. |
| Stable residual root | `internal-docs/implementation/runtime-kernel-namespace-residual.v1.json` | Valid, status-free JSON compatibility pointer. |
| Optional old command | `scripts/internal/verify-runtime-kernel-trust-audit.mjs` | Ignored, logic-free wrapper importing the active private verifier. It is not an authority or estate owner. |

No implementation artifact moves into `docs/architecture/`, conformance,
runtime code, an application package, `package.json`, or another tracked path.

## Immutable input contracts

The active verifier must consume historical inputs, never its generated output.
That makes regeneration acyclic:

```text
current Rust owners
        +
dated 198-row audit -----------+
        +                      |
archived residual baseline     v
                       private verifier
                              |
                              v
                 private residual generator
                              |
                              v
               generated residual projection
```

The exact retained contracts are:

- audit count marker:
  `<!-- runtime-kernel-method-count: 198 -->`;
- exactly 198 nonempty table rows matching `^| RKS-NNN |`, with consecutive
  IDs `RKS-001` through `RKS-198`;
- dated residual schema:
  `ioi.runtime-kernel-namespace-residual.v1`;
- dated residual discriminator:
  `service_boundary_complete_namespace_extraction_residual`, retained only in
  the inert archived body and never copied into a current status surface;
- current generated schema:
  `ioi.runtime-kernel-namespace-residual-projection.v1`;
- generated projection class:
  `derived_private_runtime_residual`;
- generated authority disclaimers:
  `architecture_authority: false` and
  `implementation_status_authority: false`.

The generated projection must not be an input to either its own generator or
the verifier that the generator invokes. Reading the generated projection from
that verifier would create an unrecoverable self-dependency: a missing or stale
projection could not be regenerated from source.

## Exact private transaction

### 1. Preserve before editing

Create these byte-identical archive bodies before replacing any root:

```text
scripts/internal/verify-runtime-kernel-trust-audit.mjs
  -> internal-docs/implementation/_archive/pre-unification-baseline/scripts/internal/verify-runtime-kernel-trust-audit.mjs

internal-docs/implementation/runtime-kernel-namespace-residual.v1.json
  -> internal-docs/implementation/_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json
```

Require the exact SHA-256 values recorded above. The dated Markdown audit is
already preserved exactly at its history destination.

### 2. Install the private active verifier

Start from the exact preserved verifier body at
`tools/verify-runtime-kernel-trust-audit.mjs`. Preserve all parser self-tests,
recursive Rust scanning, alias and out-of-module-impl rejection, ordered
allowlists, retirement checks, residual-array checks, and inventory checks.
Apply only these path-semantic edits:

```diff
-const repoRoot = path.resolve(import.meta.dirname, "../..");
+const repoRoot = path.resolve(import.meta.dirname, "../../..");
 const auditPath = path.join(
   repoRoot,
-  "internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md",
+  "internal-docs/implementation/audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md",
 );
 const residualLedgerPath = path.join(
   repoRoot,
-  "internal-docs/implementation/runtime-kernel-namespace-residual.v1.json",
+  "internal-docs/implementation/_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json",
 );
```

The legacy schema/discriminator assertions at the current verifier's lines
704–709 remain valid because they now inspect dated archive evidence, not the
root pointer or current generated projection. The active verifier must not read
`generated/runtime-kernel-namespace-residual.v1.json`.

### 3. Retarget the private generator without a self-cycle

In `tools/generate-runtime-kernel-residual.mjs`:

1. Change the header from “tracked verifier” and “legacy roots unchanged” to a
   private-verifier/deterministic-history description.
2. Rename and retarget constants:

   ```text
   LEGACY_AUDIT_PATH
     -> BASELINE_AUDIT_PATH
     -> audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md

   LEGACY_RESIDUAL_PATH
     -> BASELINE_RESIDUAL_PATH
     -> _archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json

   TRACKED_VERIFIER_PATH
     -> PRIVATE_VERIFIER_PATH
     -> tools/verify-runtime-kernel-trust-audit.mjs
   ```

3. Replace `assertCompatibilityHoldBytes()` with
   `assertPreservedBaselineBytes()`. For each original source registry entry,
   require the preserved target's SHA-256 to equal its `baseline_sha256`; do not
   require a `compatibility_hold` field.
4. Rename `runTrackedVerifier()` to `runPrivateVerifier()` and retain its
   fail-closed subprocess behavior.
5. Read the archived baseline residual, not either root pointer and not the
   generated output.
6. Include the history audit, archived baseline residual, private verifier, and
   four current Rust owners in `source.inputs`.
7. Bump the generator version from `1` to `2` because the source graph changes.
8. Replace the generated `compatibility_hold` object with:

   ```json
   "baseline_provenance": {
     "audit_ref": "internal-docs/implementation/audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md",
     "audit_count_marker": "runtime-kernel-method-count: 198",
     "residual_ref": "internal-docs/implementation/_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json",
     "residual_schema": "ioi.runtime-kernel-namespace-residual.v1",
     "root_audit_pointer": "internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md",
     "root_residual_pointer": "internal-docs/implementation/runtime-kernel-namespace-residual.v1.json"
   }
   ```

9. Remove `legacy_compatibility_status` entirely. The archived original already
   preserves that dated field; a current projection must not repeat it as a
   status-like fact.
10. Change “compatibility-held ledger” in the generated nonclaim to “dated
    baseline ledger”, and change the CLI summary to say that historical inputs
    were preserved and stable roots are pointers.

The generator may report that its bounded verifier subprocess passed, but this
is census/check evidence only. It is not a literal proof exit, work-item status,
stage exit, runtime-capability claim, or product-authority artifact.

### 4. Replace the root Markdown body

The exact intended body is:

```markdown
# RuntimeKernelService Trust-Boundary Audit — Compatibility Pointer

Document class: pointer. This path owns no sequence, implementation status,
architecture doctrine, runtime capability, or product authority.

Use `stage-guides/m0/runtime-trust-boundary.md` for the current reusable method,
`generated/runtime-kernel-namespace-residual.v1.json` for the deterministic
current projection, and the exact dated 198-row body at
`audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md`.
```

This is below the 40-line tombstone limit, names its history destination, and
contains no Gate 0–5 execution order or live status prose.

### 5. Replace the root JSON body

The exact intended body is:

```json
{
  "schema_version": "ioi.program.compatibility-pointer.v1",
  "document_class": "pointer",
  "owner": "generated/runtime-kernel-namespace-residual.v1.json",
  "preserved_body": "_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json",
  "does_not_own": [
    "architecture doctrine",
    "implementation status",
    "sequence",
    "runtime capability",
    "product authority"
  ]
}
```

The pointer is valid JSON, carries no `status` key, names both the active
projection and exact preserved body, and remains at the stable legacy path.

### 6. Retain the old ignored command only as a wrapper

If old local scripts or dated instructions still need the historical command,
replace its body with exactly:

```javascript
#!/usr/bin/env node

import "../../internal-docs/implementation/tools/verify-runtime-kernel-trust-audit.mjs";
```

The wrapper contains no audit logic and creates no second implementation owner.
The generator and all active private documentation must use the private tool's
direct command:

```text
node internal-docs/implementation/tools/verify-runtime-kernel-trust-audit.mjs
```

Historical audit text may retain the old command as point-in-time evidence; the
wrapper keeps it operable without making that audit active.

### 7. Remove the false holds and classify the completed paths

Update `source-dispositions.v1.json`:

- for `runtime-kernel-service-trust-boundary-audit.md`, set
  `tombstone_required: true` and `compatibility_hold: null`; its destination
  remains the dated audit history path;
- for `runtime-kernel-namespace-residual.v1.json`, set
  `tombstone_required: true`, `compatibility_hold: null`, and
  `preserved_body_path` to
  `_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json`;
  its destination remains the generated projection;
- classify both root materializations as `pointer` /
  `COLLAPSE_TO_POINTER`, with no status ownership;
- classify the new active verifier as `tool` / `KEEP_PROJECTION`;
- classify the preserved verifier and residual bodies as `archive` /
  `KEEP_WORK_RECORD`; and
- classify this packet as `audit` / `KEEP_WORK_RECORD`.

Update `tools/bootstrap-source-registry.mjs` in the same transaction:

- delete both entries from its hard-coded `compatibilityHolds` map;
- add the residual archive path to `preservedBodyOverrides`; and
- let its existing `exactMoves` logic classify both roots as pointers.

Do not merely null the registry entries while leaving the bootstrap map intact;
that would recreate the wrong root classifications on the next bootstrap.

Update active README/execution-report wording from “tracked verifier” and
“approval-gated hold” to this corrected private provenance. Preserve the
independent delegated review as dated evidence; do not rewrite its historical
observation. Current generated files must contain no false tracked-verifier or
compatibility-hold claim.

## Required validation transaction

Run from the repository root after all private edits:

```bash
sha256sum \
  internal-docs/implementation/audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md \
  internal-docs/implementation/_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json \
  internal-docs/implementation/_archive/pre-unification-baseline/scripts/internal/verify-runtime-kernel-trust-audit.mjs

node internal-docs/implementation/tools/verify-runtime-kernel-trust-audit.mjs
node scripts/internal/verify-runtime-kernel-trust-audit.mjs

node internal-docs/implementation/tools/generate-runtime-kernel-residual.mjs --write
node internal-docs/implementation/tools/generate-runtime-kernel-residual.mjs --check
node internal-docs/implementation/tools/bootstrap-source-registry.mjs
node internal-docs/implementation/tools/freeze-source-manifest.mjs --write

node internal-docs/implementation/tools/check-source-dispositions.mjs
node internal-docs/implementation/tools/freeze-source-manifest.mjs --check
node internal-docs/implementation/tools/check-single-sequencer.mjs
node internal-docs/implementation/tools/check-status-truth.mjs
node internal-docs/implementation/tools/check-private-estate-boundary.mjs
node internal-docs/implementation/tools/check-module-headers.mjs
node internal-docs/implementation/tools/check-internal-links.mjs
node internal-docs/implementation/tools/check-generated.mjs
node internal-docs/implementation/tools/check-implementation-estate.mjs
```

Then prove the corrected topology explicitly:

```bash
test -z "$(git ls-files -- scripts/internal/verify-runtime-kernel-trust-audit.mjs)"
git check-ignore -q scripts/internal/verify-runtime-kernel-trust-audit.mjs
git check-ignore -q internal-docs/implementation/tools/verify-runtime-kernel-trust-audit.mjs

test "$(sha256sum internal-docs/implementation/audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md | cut -d' ' -f1)" = \
  75a51210750dca6022742a2c39e6289f9081f6451d3ef24828e4b6fdff51184b
test "$(sha256sum internal-docs/implementation/_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json | cut -d' ' -f1)" = \
  19500ed05d261a6fde6aa1879ae70de8111242d73b982fd39479ec62bc5273c5
test "$(sha256sum internal-docs/implementation/_archive/pre-unification-baseline/scripts/internal/verify-runtime-kernel-trust-audit.mjs | cut -d' ' -f1)" = \
  b6d7f1da22d5efba2f18d0ca5c3a0ba3c9d2ea02b264186455fcb72af565ff70

test -z "$(rg -l 'generated/runtime-kernel-namespace-residual\.v1\.json' \
  internal-docs/implementation/tools/verify-runtime-kernel-trust-audit.mjs || true)"
```

Acceptance requires:

- the direct private verifier and stable wrapper emit the same successful
  bounded census;
- the residual writer succeeds from historical inputs without reading its own
  output;
- source preservation remains complete;
- source-disposition and source-manifest compatibility-hold counts are zero;
- single-sequencer and status-truth checks emit zero compatibility-hold SKIPs;
- both root paths are pointers, the exact original bodies remain recoverable,
  and all local links resolve;
- the existing private-boundary checker proves all pre-existing tracked bytes
  unchanged; and
- no work-item status, literal exit, aggregate, stage, sequencer rule, canon
  meaning, runtime code, or application behavior changes.

## Nonclaims and rollback

This transaction proves only private source reconciliation and continued exact
runtime-kernel census checking. It does not prove namespace extraction,
authority convergence, runtime capability, M0 or M9 exit, or any later-stage
claim.

If the private verifier or generator fails after retargeting, restore the two
root bodies from their exact archives, restore the prior ignored verifier body,
and retain the compatibility holds. Do not weaken a parser, remove a census
check, change a work-item status, or emit a successful literal exit to make the
transaction pass.

## Approval disposition

No sequencer amendment and no tracked-change approval is requested. The
private-only transaction above is the faithful completion of the already
approved SA-4 dispositions after correcting the verifier's actual provenance.
