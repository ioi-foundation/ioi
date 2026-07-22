//! Protected constitutional amendment execution (M1.5c).
//!
//! The declaration family (`ioi.autonomous-system-constitution-amendment.v1`)
//! states what changes; this module owns the machine floor that decides
//! whether an approved declaration may execute on the live chain: the
//! canonical predecessor→successor diff, the unamendable-path floor, the
//! semver lineage rule, and (in the plan compiler) the closed amendment
//! authority effect. Amendment never alters operational status and never
//! touches the fourteen operational ops in
//! [`super::system_lifecycle_transitions`].

use serde_json::Value;

/// Constitution fields excluded from the amendable body: lineage and
/// admission coordinates change only through their own rules, never as a
/// diff. `version` and `predecessor_constitution_ref` are verified by the
/// lineage checks instead; the rest may never differ at all.
pub const STRUCTURAL_CONSTITUTION_FIELDS: [&str; 8] = [
    "schema_version",
    "constitution_id",
    "system_id",
    "version",
    "predecessor_constitution_ref",
    "constitution_root",
    "activation_receipt_ref",
    "status",
];

/// The M1 machine-protected subtree: amending the amendment rules is a
/// distinct, not-yet-implemented path, so every `/governance/...` pointer is
/// refused outright. Clause-ref semantic mappings beyond this floor remain
/// declared governance evidence, not machine truth.
pub const MACHINE_PROTECTED_POINTER_PREFIX: &str = "/governance";

/// Canonical JSON-pointer diff between two constitution bodies.
///
/// Walks both values structurally and returns the sorted, deduplicated set
/// of RFC 6901 pointers at which they differ. Object differences recurse to
/// the deepest differing member (an added or removed key yields the pointer
/// of that key); arrays are compared as whole leaves (any inequality yields
/// the array's own pointer) so reordering cannot masquerade as an untouched
/// path. Structural fields are excluded at the top level only.
pub fn canonical_constitution_diff(predecessor: &Value, successor: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    diff_into(predecessor, successor, "", true, &mut paths);
    paths.sort();
    paths.dedup();
    paths
}

fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn diff_into(a: &Value, b: &Value, pointer: &str, top: bool, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(map_a), Value::Object(map_b)) => {
            let mut keys: Vec<&String> = map_a.keys().chain(map_b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                if top && STRUCTURAL_CONSTITUTION_FIELDS.contains(&key.as_str()) {
                    continue;
                }
                let child = format!("{pointer}/{}", escape_token(key));
                match (map_a.get(key), map_b.get(key)) {
                    (Some(va), Some(vb)) => diff_into(va, vb, &child, false, out),
                    _ => out.push(child),
                }
            }
        }
        _ => {
            if a != b {
                out.push(if pointer.is_empty() {
                    "/".to_owned()
                } else {
                    pointer.to_owned()
                });
            }
        }
    }
}

/// Strict semver ordering for the constitution `version` lineage rule.
///
/// Accepts exactly `MAJOR.MINOR.PATCH` with plain non-negative integers (no
/// pre-release or build tags: constitution versions are governance lineage,
/// not software releases). Returns an error for any malformed input rather
/// than guessing.
pub fn semver_strictly_greater(successor: &str, predecessor: &str) -> Result<bool, String> {
    Ok(parse_semver(successor)? > parse_semver(predecessor)?)
}

fn parse_semver(text: &str) -> Result<(u64, u64, u64), String> {
    let mut parts = text.split('.');
    let mut next = |name: &str| -> Result<u64, String> {
        let piece = parts
            .next()
            .ok_or_else(|| format!("constitution version lacks a {name} component: {text}"))?;
        if piece.is_empty() || piece.len() > 9 || !piece.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "constitution version {name} component is not a plain integer: {text}"
            ));
        }
        if piece.len() > 1 && piece.starts_with('0') {
            return Err(format!(
                "constitution version {name} component has a leading zero: {text}"
            ));
        }
        piece
            .parse::<u64>()
            .map_err(|_| format!("constitution version {name} component overflows: {text}"))
    };
    let triple = (next("major")?, next("minor")?, next("patch")?);
    if parts.next().is_some() {
        return Err(format!(
            "constitution version has more than three components: {text}"
        ));
    }
    Ok(triple)
}

/// True when `pointer` falls under the machine-protected floor: any
/// `/governance` path (subtree self-protection) — structural fields never
/// appear in a diff at all because [`canonical_constitution_diff`] excludes
/// them before comparison.
pub fn pointer_is_machine_protected(pointer: &str) -> bool {
    pointer == MACHINE_PROTECTED_POINTER_PREFIX
        || pointer.starts_with("/governance/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diff_is_canonical_sorted_and_structural_blind() {
        let predecessor = json!({
            "schema_version": "ioi.autonomous-system-constitution.v1",
            "version": "1.0.0",
            "declared_purpose": "serve",
            "normative_constraints": {"spend_ceiling": 5, "region": "us"},
            "shutdown": {"grace_seconds": 30},
        });
        let successor = json!({
            "schema_version": "ioi.autonomous-system-constitution.v2-tampered",
            "version": "1.1.0",
            "declared_purpose": "serve",
            "normative_constraints": {"spend_ceiling": 9, "region": "us", "added": true},
            "shutdown": {"grace_seconds": 30},
        });
        // schema_version and version differences are structurally excluded.
        assert_eq!(
            canonical_constitution_diff(&predecessor, &successor),
            vec![
                "/normative_constraints/added".to_owned(),
                "/normative_constraints/spend_ceiling".to_owned(),
            ],
        );
    }

    #[test]
    fn removed_and_added_keys_yield_their_own_pointers() {
        let a = json!({"body": {"kept": 1, "removed": 2}});
        let b = json!({"body": {"kept": 1, "added": 3}});
        assert_eq!(
            canonical_constitution_diff(&a, &b),
            vec!["/body/added".to_owned(), "/body/removed".to_owned()],
        );
    }

    #[test]
    fn arrays_are_whole_leaves_so_reorder_is_a_difference() {
        let a = json!({"invariants": ["x", "y"]});
        let b = json!({"invariants": ["y", "x"]});
        assert_eq!(
            canonical_constitution_diff(&a, &b),
            vec!["/invariants".to_owned()],
        );
    }

    #[test]
    fn escaped_pointer_tokens_round_trip() {
        let a = json!({"odd/key~name": 1});
        let b = json!({"odd/key~name": 2});
        assert_eq!(
            canonical_constitution_diff(&a, &b),
            vec!["/odd~1key~0name".to_owned()],
        );
    }

    #[test]
    fn semver_lineage_is_strict_and_rejects_malformed() {
        assert!(semver_strictly_greater("1.1.0", "1.0.9").unwrap());
        assert!(semver_strictly_greater("2.0.0", "1.999999999.999999999").unwrap());
        assert!(!semver_strictly_greater("1.0.0", "1.0.0").unwrap());
        assert!(!semver_strictly_greater("1.0.0", "1.0.1").unwrap());
        for bad in ["1.0", "1.0.0.0", "1.0.-1", "v1.0.0", "1.0.01", "1..0", "1.0.0-rc1"] {
            assert!(semver_strictly_greater(bad, "1.0.0").is_err(), "{bad}");
        }
    }

    #[test]
    fn governance_subtree_is_machine_protected() {
        assert!(pointer_is_machine_protected("/governance"));
        assert!(pointer_is_machine_protected("/governance/amendment_mode"));
        assert!(pointer_is_machine_protected("/governance/protected_clause_refs"));
        assert!(!pointer_is_machine_protected("/governance_adjacent"));
        assert!(!pointer_is_machine_protected("/declared_purpose"));
        assert!(!pointer_is_machine_protected("/normative_constraints/spend_ceiling"));
    }
}
