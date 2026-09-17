//! RECORD MATERIAL — neutral helpers over a record's own bytes.
//!
//! Content-addressing a record's material and refusing plaintext secrets anywhere inside it are
//! properties of A RECORD, not of any application that happens to hold one. Both lived in
//! `outcome_room_routes` until 2026-09-17 (R-172 slice S4c), where four platform modules —
//! System genesis, System activation, System sequence-zero and governed authority — had to reach
//! into an ioi.ai application module to hash their own material, and a System-genesis request
//! carrying a secret was refused with a ROOM-NAMED error code. Neither is a room fact. They live
//! here so the room module can be deleted without taking the platform's own hygiene with it.
//!
//! Nothing here reads a room, a participant, a claim or an orchestration. It reads a `Value`.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// A validation refusal: `(code, message)`. The code is the wire contract; the message explains it.
pub(crate) type VErr = (String, String);

pub(crate) fn verr(code: &str, msg: impl Into<String>) -> VErr {
    (code.into(), msg.into())
}

/// Key fragments that never carry a plaintext value in an admitted record. Compared against a
/// normalized key (lowercased, with `_`, `-`, ` ` and `.` removed), so `API_KEY`, `api-key` and
/// `apiKey` are the same fragment and none of them can slip through on spelling.
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "secret",
    "credential",
    "authorization",
    "privatekey",
    "apikey",
    "token",
];

/// The content address of a record's material, with `excludes` removed first — used to hash a
/// record without the field that will carry the hash.
pub(crate) fn record_output_hash(record: &Value, excludes: &[&str]) -> String {
    let mut clone = record.clone();
    if let Some(obj) = clone.as_object_mut() {
        for k in excludes {
            obj.remove(*k);
        }
    }
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&clone).unwrap_or_default())
    )
}

/// Refuses a plaintext secret ANYWHERE in the record, at any depth, in an object key or inside an
/// array. A null is not a secret: a declared-but-empty field is a shape, not a disclosure.
///
/// Renamed from `outcome_room_plaintext_secret_rejected` to `plaintext_secret_rejected` on
/// 2026-09-17 (R-172 slice S4c). The old code was asserted in exactly two places, both inside the
/// module that defined it, and no verifier, client or canon document pinned it — so the rename
/// carries no wire contract with it. What it does carry is the correction: System genesis called
/// this helper, so a platform request with a secret in it used to be refused in an application's
/// vocabulary.
pub(crate) fn reject_sensitive_keys(v: &Value, path: &str) -> Result<(), VErr> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let normalized: String = k
                    .to_lowercase()
                    .chars()
                    .filter(|c| !matches!(c, '_' | '-' | ' ' | '.'))
                    .collect();
                if SENSITIVE_KEY_FRAGMENTS
                    .iter()
                    .any(|f| normalized.contains(f))
                    && !child.is_null()
                {
                    return Err(verr(
                        "plaintext_secret_rejected",
                        format!(
                            "sensitive key `{path}{k}` is never accepted anywhere in the record \
                             — records carry canonical refs; secrets stay in the daemon \
                             credential planes"
                        ),
                    ));
                }
                reject_sensitive_keys(child, &format!("{path}{k}."))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_sensitive_keys(child, &format!("{path}{index}."))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
