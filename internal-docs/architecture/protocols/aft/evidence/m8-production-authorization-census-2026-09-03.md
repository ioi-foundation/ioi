# M8 production authorization census — 2026-09-03

## Scope

This census answers release gate 4 for AFT-governed external consequences. It
does not reinterpret unrelated wallet, daemon HTTP, approval, or consensus
signing-fence uses of the generic word “authorization” as external effect
execution.

Repository-wide Rust searches establish that the only production
`ExternalResourceV1` trait and the only production call to `invoke_atomic` live
in `crates/agentgres/src/consequence.rs`. The operation is reachable only after
`ConsequenceStore::authorize` has persisted an authorization created from:

1. an `EffectManifestV1` whose complete policy and resource profile validate;
2. an opaque `VerifiedGuaranteeV1` (raw `GuaranteeVectorV1` is absent from the
   module and cannot be supplied to the method);
3. an `AcceptedEffectAuthorizationV1` bound to the same effect, manifest root,
   achieved-vector root, Agentgres record and authority snapshot;
4. re-verification of the committed runtime-v3 finality bundle; and
5. the modeled atomic idempotency-register contract for irreversible effects.

This is the pre-execution authorization path. `PortableAssuranceReceiptV1` is
produced only after consequence evidence exists and is independently verified
for relying parties; it is not fed back into this mutation owner. That
direction is intentional because a receipt containing execution, outcome, and
reconciliation roots cannot authorize the same execution without circularity.

The static gate fails if another production external-mutation owner appears,
if raw vector input reaches consequence authorization, or if the policy,
committed-evidence verification, authorization binding, or atomic-resource
fence disappears. Runtime tests separately exercise unsupported profiles,
raw-policy failures, fence mismatches, duplicate delivery, crashes and
ambiguous reconciliation.

## Reproduction

```text
bash .github/scripts/check_aft_production_authorization.sh
cargo test -p agentgres consequence::tests --lib
```

## Result

PASS on 2026-09-03. There is one production external mutation owner, and it
requires verifier-created `VerifiedGuaranteeV1` evidence before a consequence
can leave the authorized state.

## Boundary

This is an estate-wide source census plus executable enforcement test for the
AFT externalization boundary. It is not a claim that every unrelated local
side effect in the broader product has been converted into an AFT effect.
