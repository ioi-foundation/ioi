# Removed-rule control mutations (exact edits)

All three mutants were applied with the Edit tool to the owned consensus
files, the named test was run, and the exact original text was re-applied.
`sha256sum` before and after each control is recorded in the sibling `*.sha`
files; the test transcripts are in the sibling `*-output*.txt` files.

## Control A — re-add `predecessor` to `QuvConflictSlotV0`

File: `crates/consensus/src/aft/query_unanimity.rs`

```diff
 struct QuvConflictSlotV0 {
     ...
     slot: u64,
+    predecessor: QuvHash, // CONTROL-A MUTANT
     authority_mode: QuvAuthorityModeV0,
 }

 impl From<&QuvSlotV0> for QuvConflictSlotV0 {
     fn from(slot: &QuvSlotV0) -> Self {
         Self {
             ...
             slot: slot.slot,
+            predecessor: slot.predecessor, // CONTROL-A MUTANT
             authority_mode: slot.authority_mode,
         }
     }
 }
```

Named test: `predecessor_substitution_shares_one_conflict_slot`.

## Control B — remove `check_expected_slot` from `process_push_with_byte_limit`

File: `crates/consensus/src/aft/query_unanimity.rs`

```diff
         validator.validate_candidate(&request.candidate)?;
-        self.check_expected_slot(&request.candidate.slot)?;
+        // CONTROL-B MUTANT: check_expected_slot removed
         if request.verifier_nonce == [0; 32] {
```

Named tests: `predecessor_substitution_shares_one_conflict_slot`
(first attempt against the pre-existing test body, second attempt after the
test was extended); `accepted_history_refuses_conflicting_or_expired_grants_without_mutation`
(alternate, first attempt only).

## Control C — remove the predecessor comparison in `QuvAcceptedHistoryV0::check_slot`

File: `crates/consensus/src/aft/query_unanimity/head.rs`

```diff
             || slot.authority_mode != self.initial.authority_mode
-            || slot.predecessor != self.expected_predecessor(slot.slot)?
+        // CONTROL-C MUTANT: predecessor comparison removed
         {
             return Err(QuvError::UnexpectedHead);
         }
```

Named test: `accepted_history_derives_scope_and_preserves_historical_predecessors`.
