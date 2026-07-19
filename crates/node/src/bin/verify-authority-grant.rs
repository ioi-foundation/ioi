//! Offline verifier for portable `AuthorityGrantEnvelope` v2 artifacts.
//!
//! The command performs no network access. The caller supplies a locally trusted issuer
//! key set and a signed, bounded-freshness revocation snapshot.

use anyhow::{anyhow, Context, Result};
use ioi_types::app::generated::architecture_contracts::{
    AuthorityGrantEnvelopeV2, AuthorityKeySetV1, AuthorityRevocationSnapshotV1,
};
use ioi_validator::portable_authority::{
    verify_portable_authority_grant_v2, PortableAuthorityParentProof,
    PortableAuthorityVerificationContext,
};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{env, fs, path::Path};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn required(args: &[String], name: &str) -> Result<String> {
    flag(args, name).ok_or_else(|| anyhow!("missing required {name}"))
}

fn read_json<T: DeserializeOwned>(path: &str) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", Path::new(path).display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse {} as closed portable-authority JSON",
            Path::new(path).display()
        )
    })
}

fn optional_parent<'a>(
    grant: &'a Option<AuthorityGrantEnvelopeV2>,
    key_set: &'a Option<AuthorityKeySetV1>,
    snapshot: &'a Option<AuthorityRevocationSnapshotV1>,
) -> Result<Option<PortableAuthorityParentProof<'a>>> {
    match (grant.as_ref(), key_set.as_ref(), snapshot.as_ref()) {
        (None, None, None) => Ok(None),
        (Some(grant), Some(key_set), Some(revocation_snapshot)) => {
            Ok(Some(PortableAuthorityParentProof {
                grant,
                key_set,
                revocation_snapshot,
                parent: None,
            }))
        }
        _ => Err(anyhow!(
            "--parent-grant, --parent-key-set, and --parent-revocation-snapshot must be supplied together"
        )),
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let grant: AuthorityGrantEnvelopeV2 = read_json(&required(&args, "--grant")?)?;
    let key_set: AuthorityKeySetV1 = read_json(&required(&args, "--key-set")?)?;
    let snapshot: AuthorityRevocationSnapshotV1 =
        read_json(&required(&args, "--revocation-snapshot")?)?;
    let audience = required(&args, "--audience")?;
    let holder_id = required(&args, "--holder-id")?;
    let holder_key_id = required(&args, "--holder-key-id")?;
    let now = required(&args, "--now")?
        .parse::<u64>()
        .context("--now must be Unix seconds")?;
    let max_staleness = flag(&args, "--max-snapshot-staleness-seconds")
        .unwrap_or_else(|| "300".to_string())
        .parse::<u64>()
        .context("--max-snapshot-staleness-seconds must be an integer")?;

    let parent_grant = flag(&args, "--parent-grant")
        .map(|path| read_json(&path))
        .transpose()?;
    let parent_key_set = flag(&args, "--parent-key-set")
        .map(|path| read_json(&path))
        .transpose()?;
    let parent_snapshot = flag(&args, "--parent-revocation-snapshot")
        .map(|path| read_json(&path))
        .transpose()?;
    let parent = optional_parent(&parent_grant, &parent_key_set, &parent_snapshot)?;

    let context = PortableAuthorityVerificationContext {
        expected_audience: &audience,
        expected_holder_id: &holder_id,
        expected_holder_key_id: &holder_key_id,
        now,
        max_snapshot_staleness_seconds: max_staleness,
        key_set: &key_set,
        revocation_snapshot: &snapshot,
        parent: parent.as_ref(),
    };
    match verify_portable_authority_grant_v2(&grant, &context) {
        Ok(()) => {
            println!(
                "{}",
                json!({
                    "ok": true,
                    "authority_grant_id": grant.authority_grant_id,
                    "body_hash": grant.body_hash,
                    "signature_key_id": grant.signature_key_id,
                    "revocation_epoch": snapshot.epoch,
                    "verification_mode": "offline_local_key_set"
                })
            );
            Ok(())
        }
        Err(error) => {
            println!(
                "{}",
                json!({
                    "ok": false,
                    "error": { "code": error.code.as_str(), "detail": error.detail }
                })
            );
            Err(anyhow!("portable authority verification failed"))
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
