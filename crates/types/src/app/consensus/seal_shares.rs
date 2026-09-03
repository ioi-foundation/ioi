/// Protocol version bound into every AFT terminal share.
pub const AFT_SEAL_PROTOCOL_VERSION_V2: u16 = 2;
/// Wire-schema version for [`SealShareV2`].
pub const AFT_SEAL_SHARE_SCHEMA_V2: u16 = 2;
/// Wire-schema version for [`SealKeyManifestV1`].
pub const AFT_SEAL_KEY_MANIFEST_SCHEMA_V1: u16 = 1;
/// FIPS 205 SLH-DSA-SHA2-128s public-key length.
pub const SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES: usize = 32;
/// FIPS 205 SLH-DSA-SHA2-128s signature length.
pub const SLH_DSA_SHA2_128S_SIGNATURE_BYTES: usize = 7_856;

const KEY_COMMITMENT_DOMAIN: &[u8] = b"ioi.aft.seal-key-commitment.v1\0";
const MANIFEST_COMMITMENT_DOMAIN: &[u8] = b"ioi.aft.seal-key-manifest.v1\0";
const SHARE_SIGNING_DOMAIN: &[u8] = b"ioi.aft.seal-share.v2\0";
const KEY_EXHAUSTION_DOMAIN: &[u8] = b"ioi.aft.seal-key-exhaustion.v1\0";

fn sha256_domain_separated(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(domain.len() + payload.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(payload);
    let digest = DcryptSha256::digest(&material).map_err(|error| format!("{error:?}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

/// Commitment used as the signed successor of the final provisioned key.
/// The signer then has no current key and every later signing attempt refuses.
pub fn seal_key_exhaustion_commitment(
    scope: &SealKeyScopeV1,
    exhausted_after_key_index: u64,
) -> Result<[u8; 32], String> {
    sha256_domain_separated(
        KEY_EXHAUSTION_DOMAIN,
        &(scope, exhausted_after_key_index).encode(),
    )
}

/// Exact scope authenticated by a terminal-seal key.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Encode, Decode,
)]
pub struct SealKeyScopeV1 {
    /// Network or chain identity commitment.
    pub network_id: [u8; 32],
    /// Exact validator/seal configuration commitment.
    pub configuration_id: [u8; 32],
    /// Configuration epoch.
    pub epoch: u64,
    /// Independent conflict-domain commitment.
    pub conflict_domain_id: [u8; 32],
    /// Stable member identity.
    pub member_id: AccountId,
    /// Member position in the committed configuration.
    pub member_index: u32,
}

/// One scheduled public key, authenticated by its configuration manifest or
/// by the preceding accepted terminal share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SealKeyBindingV1 {
    /// Scope that this key is permitted to sign within.
    pub scope: SealKeyScopeV1,
    /// Terminal key-use index. The v2 profile requires this to equal the seal
    /// slot so every scheduled key is consumed at most once.
    pub key_index: u64,
    /// Signature suite. The normative v2 profile accepts only
    /// `SLH_DSA_SHA2_128S`.
    pub signature_suite: SignatureSuite,
    /// Exact FIPS 205 public-key encoding.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Commitment that authenticated the preceding key state. The first key
    /// uses the manifest's declared chain anchor.
    pub predecessor_key_commitment: [u8; 32],
}

impl SealKeyBindingV1 {
    /// Validates the normative v2 terminal-key representation.
    pub fn validate(&self) -> Result<(), String> {
        if self.signature_suite != SignatureSuite::SLH_DSA_SHA2_128S {
            return Err("unsupported terminal seal signature suite".into());
        }
        if self.public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES {
            return Err(format!(
                "SLH-DSA-SHA2-128s public key must be {} bytes, got {}",
                SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES,
                self.public_key.len()
            ));
        }
        Ok(())
    }

    /// Canonical domain-separated commitment to this scheduled key and its
    /// complete authorization scope.
    pub fn commitment(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        sha256_domain_separated(KEY_COMMITMENT_DOMAIN, &self.encode())
    }
}

/// Initial enrolled terminal key for one configuration member/domain pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SealKeyManifestEntryV1 {
    /// First key binding accepted for this member and conflict domain.
    pub initial_key: SealKeyBindingV1,
    /// Redundant fail-closed commitment pinned by configuration state.
    pub initial_key_commitment: [u8; 32],
}

/// Configuration-owned enrollment manifest. Verification begins here rather
/// than at a public key supplied by a share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SealKeyManifestV1 {
    /// Must equal [`AFT_SEAL_KEY_MANIFEST_SCHEMA_V1`].
    pub schema_version: u16,
    /// Entries sorted by the full [`SealKeyScopeV1`] order.
    pub entries: Vec<SealKeyManifestEntryV1>,
}

impl SealKeyManifestV1 {
    /// Validates versioning, canonical order, uniqueness, and every enrolled
    /// key commitment.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != AFT_SEAL_KEY_MANIFEST_SCHEMA_V1 {
            return Err(format!(
                "unsupported seal key manifest version {}",
                self.schema_version
            ));
        }
        let mut previous_scope: Option<&SealKeyScopeV1> = None;
        for entry in &self.entries {
            entry.initial_key.validate()?;
            if entry.initial_key.commitment()? != entry.initial_key_commitment {
                return Err("seal manifest entry commitment mismatch".into());
            }
            if let Some(previous) = previous_scope {
                if previous >= &entry.initial_key.scope {
                    return Err("seal manifest entries must be strictly scope-sorted".into());
                }
            }
            previous_scope = Some(&entry.initial_key.scope);
        }
        Ok(())
    }

    /// Canonical manifest commitment used as configuration/key-root evidence.
    pub fn commitment(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        sha256_domain_separated(MANIFEST_COMMITMENT_DOMAIN, &self.encode())
    }

    /// Resolves the exactly enrolled initial key for a scope. Absence or an
    /// ambiguous duplicate is a refusal, never a self-authenticated fallback.
    pub fn initial_key_for_scope(
        &self,
        scope: &SealKeyScopeV1,
    ) -> Result<&SealKeyManifestEntryV1, String> {
        self.validate()?;
        self.entries
            .binary_search_by(|entry| entry.initial_key.scope.cmp(scope))
            .map(|index| &self.entries[index])
            .map_err(|_| "seal key scope is not enrolled in the configuration manifest".into())
    }
}

/// Attribution-preserving, identity- and state-bound terminal signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SealShareV2 {
    /// Must equal [`AFT_SEAL_PROTOCOL_VERSION_V2`].
    pub protocol_version: u16,
    /// Must equal [`AFT_SEAL_SHARE_SCHEMA_V2`].
    pub schema_version: u16,
    /// Current scheduled public key and complete authorization scope.
    pub current_key: SealKeyBindingV1,
    /// Terminal seal slot. The normative profile requires this to equal
    /// `current_key.key_index`.
    pub seal_slot: u64,
    /// Root being terminally sealed.
    pub seal_root: [u8; 32],
    /// Commitment to the next scheduled key. This is authenticated by the
    /// current signature and becomes the next verifier anchor.
    pub next_key_commitment: [u8; 32],
    /// FIPS 205 signature over [`SealShareV2::signing_bytes`].
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SealShareV2 {
    /// Validates version, suite, sizes, and key/slot agreement without
    /// performing the cryptographic signature check.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_SEAL_PROTOCOL_VERSION_V2 {
            return Err(format!(
                "unsupported seal protocol version {}",
                self.protocol_version
            ));
        }
        if self.schema_version != AFT_SEAL_SHARE_SCHEMA_V2 {
            return Err(format!(
                "unsupported seal share schema version {}",
                self.schema_version
            ));
        }
        self.current_key.validate()?;
        if self.seal_slot != self.current_key.key_index {
            return Err("seal slot does not equal scheduled key index".into());
        }
        if self.signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_BYTES {
            return Err(format!(
                "SLH-DSA-SHA2-128s signature must be {} bytes, got {}",
                SLH_DSA_SHA2_128S_SIGNATURE_BYTES,
                self.signature.len()
            ));
        }
        if self.next_key_commitment == [0u8; 32] {
            return Err("next key commitment must not be zero".into());
        }
        Ok(())
    }

    /// Current scheduled-key commitment authenticated by the enrollment chain.
    pub fn current_key_commitment(&self) -> Result<[u8; 32], String> {
        self.current_key.commitment()
    }

    /// Canonical bytes signed by the terminal key. The signature field is
    /// excluded; every authorization, state, and successor field is included.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        if self.protocol_version != AFT_SEAL_PROTOCOL_VERSION_V2
            || self.schema_version != AFT_SEAL_SHARE_SCHEMA_V2
        {
            return Err("unsupported seal share version".into());
        }
        self.current_key.validate()?;
        if self.seal_slot != self.current_key.key_index {
            return Err("seal slot does not equal scheduled key index".into());
        }
        if self.next_key_commitment == [0u8; 32] {
            return Err("next key commitment must not be zero".into());
        }

        let payload = (
            self.protocol_version,
            self.schema_version,
            &self.current_key,
            self.seal_slot,
            self.seal_root,
            self.next_key_commitment,
        )
            .encode();
        let mut bytes = Vec::with_capacity(SHARE_SIGNING_DOMAIN.len() + payload.len());
        bytes.extend_from_slice(SHARE_SIGNING_DOMAIN);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Checks the share's current key against an exact verifier anchor.
    pub fn verify_anchor(&self, expected_key_commitment: [u8; 32]) -> Result<(), String> {
        self.validate_shape()?;
        if self.current_key_commitment()? != expected_key_commitment {
            return Err("seal share current key is not authenticated by the expected anchor".into());
        }
        Ok(())
    }
}
