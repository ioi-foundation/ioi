use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_crypto::key_store::load_api_key;
use ioi_types::app::{GuardianProductionMode, KeyAuthorityDescriptor, KeyAuthorityKind};
use std::path::Path;

/// Backend abstraction for signing / secret material resolution.
#[async_trait]
pub trait KeyAuthority: Send + Sync {
    /// Returns the backend descriptor.
    fn descriptor(&self) -> &KeyAuthorityDescriptor;

    /// Whether this authority satisfies production requirements.
    fn is_production_capable(&self) -> bool;

    /// Resolves a secret value for guarded egress.
    async fn resolve_secret_string(&self, path: &Path, passphrase: Option<&str>) -> Result<String>;
}

/// Development-only authority that resolves secrets from local encrypted files.
#[derive(Debug, Clone)]
pub struct DevMemoryKeyAuthority {
    descriptor: KeyAuthorityDescriptor,
}

impl DevMemoryKeyAuthority {
    /// Builds a development-only local authority descriptor wrapper.
    pub fn new(descriptor: KeyAuthorityDescriptor) -> Self {
        Self { descriptor }
    }
}

#[async_trait]
impl KeyAuthority for DevMemoryKeyAuthority {
    fn descriptor(&self) -> &KeyAuthorityDescriptor {
        &self.descriptor
    }

    fn is_production_capable(&self) -> bool {
        false
    }

    async fn resolve_secret_string(&self, path: &Path, passphrase: Option<&str>) -> Result<String> {
        let pass =
            passphrase.ok_or_else(|| anyhow!("passphrase required for dev-memory secret"))?;
        load_api_key(path, pass).map_err(|e| anyhow!(e.to_string()))
    }
}

fn unsupported_key_authority(kind: KeyAuthorityKind) -> anyhow::Error {
    anyhow!(
        "{kind:?} key authority is not available in this build; configure a supported backend or enable a real authority feature"
    )
}

/// Builds the configured key authority for a guardian profile.
pub fn build_key_authority(
    descriptor: Option<KeyAuthorityDescriptor>,
    production_mode: GuardianProductionMode,
) -> Result<Box<dyn KeyAuthority>> {
    let descriptor = descriptor.unwrap_or_default();
    let authority: Box<dyn KeyAuthority> = match descriptor.kind {
        KeyAuthorityKind::DevMemory => Box::new(DevMemoryKeyAuthority::new(descriptor)),
        KeyAuthorityKind::Tpm2 | KeyAuthorityKind::Pkcs11 | KeyAuthorityKind::CloudKms => {
            return Err(unsupported_key_authority(descriptor.kind));
        }
    };

    if matches!(production_mode, GuardianProductionMode::Production)
        && !authority.is_production_capable()
    {
        return Err(anyhow!(
            "production guardian profile refuses {:?} key authority",
            authority.descriptor().kind
        ));
    }

    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(kind: KeyAuthorityKind) -> KeyAuthorityDescriptor {
        KeyAuthorityDescriptor {
            kind,
            key_id: "test-key".to_string(),
            ..KeyAuthorityDescriptor::default()
        }
    }

    #[test]
    fn production_refuses_dev_memory_authority() {
        let err = match build_key_authority(
            Some(descriptor(KeyAuthorityKind::DevMemory)),
            GuardianProductionMode::Production,
        ) {
            Ok(_) => panic!("dev-memory must not satisfy production authority"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("production guardian profile refuses"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unsupported_authority_kinds_fail_before_runtime_resolution() {
        for kind in [
            KeyAuthorityKind::Tpm2,
            KeyAuthorityKind::Pkcs11,
            KeyAuthorityKind::CloudKms,
        ] {
            let err = match build_key_authority(
                Some(descriptor(kind)),
                GuardianProductionMode::Production,
            ) {
                Ok(_) => panic!("unsupported authority should fail at configuration time"),
                Err(err) => err,
            };
            assert!(
                err.to_string().contains("not available in this build"),
                "unexpected error for {kind:?}: {err}"
            );
        }
    }
}
