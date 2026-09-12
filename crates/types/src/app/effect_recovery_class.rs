//! THE external-effect recovery posture, owned once.
//!
//! CANON: `docs/architecture/foundations/canonical-enums.md` § External-Effect Recovery Classes
//! freezes the member set for the wire field `effect_recovery_class`. The registered ontology
//! action contract carries it, and its generated projection in this same crate —
//! [`crate::app::generated::architecture_contracts::OntologyActionContractV1EffectRecoveryClass`]
//! — is the contract's own Rust shape. This module is the ONE place the member set exists as a
//! list callers can check a string against, and `the_member_set_is_exactly_the_generated_contract`
//! below pins it to that projection so the two cannot drift.
//!
//! WHY IT LIVES HERE. The daemon's admission check and the work-lifecycle cancellation planner both
//! judge this field, and they live in different crates — one a `[[bin]]` target under `ioi-node`,
//! one the `ioi-services` library. A bin cannot be imported by a library, so before R-16 the two
//! carried their own vocabularies and only `compensatable` was common to both: a child declaring
//! the canonical `reconciliation_required` was refused by the planner as invalid, and one declaring
//! the planner's `irreversible` was refused by the action contract. `ioi-types` is the crate both
//! already depend on, so the set lives here and both READ it.
//!
//! R-16, ruled 2026-09-10: one field name carries one member set. A record written under the
//! retired vocabulary is MIGRATED through [`resolve`], which names the migration in its result, or
//! REFUSED with a typed reason. It is never silently reinterpreted, and the absence of a class is
//! never defaulted into one — an effect with no declared recovery is refused, exactly as the
//! daemon's claim gate already refuses it.

/// The frozen canonical member set, in canon's order.
pub const EFFECT_RECOVERY_CLASSES: [&str; 5] = [
    "replayable",
    "checkpointable",
    "compensatable",
    "reconciliation_required",
    "non_retryable",
];

/// The retired work-lifecycle vocabulary, paired with the canonical member each one becomes.
///
/// Each pairing is derived from what the RETIRED member actually did in the cancellation planner,
/// not from name similarity:
///
/// * `none` — a child with no external effect. The planner asked only to cancel and drain. An exact
///   replay of a child that changed nothing outside the boundary changes nothing, which is the
///   whole reason `replayable` is the one class an ambiguity does not block.
/// * `reversible` — cancel and drain, with no compensation policy required. `checkpointable`
///   resumes rather than restarts and likewise requires no compensating act, so the plan it
///   produces is unchanged. It is deliberately NOT `compensatable`: that member hard-refuses when
///   the cancel intent carries no `compensation_policy_ref`, so the mapping would newly refuse
///   work that is admitted today.
/// * `irreversible` — fence and reconcile what already landed, never retry. That is `non_retryable`:
///   one attempt, whatever its outcome.
/// * `ambiguous` — fence and reconcile against external truth. That is `reconciliation_required`,
///   the durable Unknown that only an external readback resolves.
///
/// `compensatable` is absent from this table because it is not retired: it is the one member the
/// two vocabularies already shared, and it keeps its exact meaning.
pub const RETIRED_EFFECT_RECOVERY_CLASSES: [(&str, &str); 4] = [
    ("none", "replayable"),
    ("reversible", "checkpointable"),
    ("irreversible", "non_retryable"),
    ("ambiguous", "reconciliation_required"),
];

/// What a declared `effect_recovery_class` string resolves to.
///
/// [`Self::Migrated`] is a distinct variant on purpose: a caller must handle the retired case
/// explicitly and can record that a migration happened. Collapsing it into [`Self::Canonical`]
/// would be the silent reinterpretation R-16 forbids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryClassResolution {
    /// The record already carries a canonical member.
    Canonical(&'static str),
    /// The record carries a retired member; `to` is the canonical member it means.
    Migrated {
        /// The retired member the record actually carries.
        from: &'static str,
        /// The canonical member it migrates to.
        to: &'static str,
    },
    /// The record carries a member of neither vocabulary. Refuse; never guess.
    Unknown,
    /// The record declares no class at all. Refuse; never default.
    Undeclared,
}

/// Whether a string is already a canonical member.
pub fn is_canonical(value: &str) -> bool {
    EFFECT_RECOVERY_CLASSES.contains(&value)
}

/// The canonical member a retired one becomes, or `None` when the string is not retired.
pub fn migrate_retired(value: &str) -> Option<&'static str> {
    RETIRED_EFFECT_RECOVERY_CLASSES
        .iter()
        .find(|(retired, _)| *retired == value)
        .map(|(_, canonical)| *canonical)
}

/// Resolve a declared class. `None` — the field is absent — is [`RecoveryClassResolution::Undeclared`]
/// rather than a default, because an effect with no declared recovery is refused, never defaulted.
pub fn resolve(value: Option<&str>) -> RecoveryClassResolution {
    let Some(raw) = value.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return RecoveryClassResolution::Undeclared;
    };
    if let Some(canonical) = EFFECT_RECOVERY_CLASSES
        .iter()
        .find(|member| **member == raw)
    {
        return RecoveryClassResolution::Canonical(canonical);
    }
    match RETIRED_EFFECT_RECOVERY_CLASSES
        .iter()
        .find(|(retired, _)| *retired == raw)
    {
        Some((from, to)) => RecoveryClassResolution::Migrated { from, to },
        None => RecoveryClassResolution::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::generated::architecture_contracts::OntologyActionContractV1EffectRecoveryClass as Generated;

    /// THE ANTI-DRIFT PIN. The list is the registered contract's own member set, proved by
    /// serialising every generated variant and requiring the two populations to be equal in both
    /// directions. A member added to the contract without being added here — or here without the
    /// contract — fails, which is what keeps ONE field name carrying ONE member set.
    #[test]
    fn the_member_set_is_exactly_the_generated_contract() {
        let generated = [
            Generated::Replayable,
            Generated::Checkpointable,
            Generated::Compensatable,
            Generated::ReconciliationRequired,
            Generated::NonRetryable,
        ];
        let wire: Vec<String> = generated
            .iter()
            .map(|variant| {
                serde_json::to_value(variant)
                    .expect("the generated projection serialises")
                    .as_str()
                    .expect("each variant is a string")
                    .to_string()
            })
            .collect();
        assert_eq!(wire.len(), EFFECT_RECOVERY_CLASSES.len());
        for member in EFFECT_RECOVERY_CLASSES {
            assert!(
                wire.iter().any(|w| w == member),
                "canonical member {member} is not in the generated contract"
            );
        }
        for w in &wire {
            assert!(
                EFFECT_RECOVERY_CLASSES.contains(&w.as_str()),
                "the generated contract carries {w}, which this list omits"
            );
        }
    }

    /// Every retired member migrates to a CANONICAL member, and no retired member is itself
    /// canonical — otherwise the table would silently shadow a live member.
    #[test]
    fn every_retired_member_migrates_into_the_canonical_set_and_shadows_nothing() {
        for (retired, canonical) in RETIRED_EFFECT_RECOVERY_CLASSES {
            assert!(
                is_canonical(canonical),
                "{retired} migrates to {canonical}, which is not canonical"
            );
            assert!(
                !is_canonical(retired),
                "{retired} is retired but is also a canonical member"
            );
        }
        // `compensatable` was common to both vocabularies and keeps its meaning, so it must NOT be
        // in the retired table.
        assert!(migrate_retired("compensatable").is_none());
        assert!(is_canonical("compensatable"));
    }

    #[test]
    fn resolution_separates_canonical_migrated_unknown_and_undeclared() {
        assert_eq!(
            resolve(Some("reconciliation_required")),
            RecoveryClassResolution::Canonical("reconciliation_required")
        );
        assert_eq!(
            resolve(Some("ambiguous")),
            RecoveryClassResolution::Migrated {
                from: "ambiguous",
                to: "reconciliation_required"
            }
        );
        assert_eq!(
            resolve(Some("best_effort")),
            RecoveryClassResolution::Unknown
        );
        // Absent, empty and whitespace are all UNDECLARED — never defaulted into a member.
        assert_eq!(resolve(None), RecoveryClassResolution::Undeclared);
        assert_eq!(resolve(Some("")), RecoveryClassResolution::Undeclared);
        assert_eq!(resolve(Some("   ")), RecoveryClassResolution::Undeclared);
    }
}
