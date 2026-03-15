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

macro_rules! stub_authority {
    ($name:ident, $kind:expr) => {
        #[doc = "Production-capable key authority backend descriptor wrapper."]
        #[derive(Debug, Clone)]
        pub struct $name {
            descriptor: KeyAuthorityDescriptor,
        }

        impl $name {
            #[doc = "Builds a backend handle for this authority family."]
            pub fn new(mut descriptor: KeyAuthorityDescriptor) -> Self {
                descriptor.kind = $kind;
                Self { descriptor }
            }
        }

        #[async_trait]
        impl KeyAuthority for $name {
            fn descriptor(&self) -> &KeyAuthorityDescriptor {
                &self.descriptor
            }

            fn is_production_capable(&self) -> bool {
                true
            }

            async fn resolve_secret_string(
                &self,
                _path: &Path,
                _passphrase: Option<&str>,
            ) -> Result<String> {
                Err(anyhow!(
                    "{} secret resolution is not implemented in this build",
                    stringify!($name)
                ))
            }
        }
    };
}

stub_authority!(Tpm2KeyAuthority, KeyAuthorityKind::Tpm2);
stub_authority!(Pkcs11KeyAuthority, KeyAuthorityKind::Pkcs11);
stub_authority!(CloudKmsKeyAuthority, KeyAuthorityKind::CloudKms);

/// Builds the configured key authority for a guardian profile.
pub fn build_key_authority(
    descriptor: Option<KeyAuthorityDescriptor>,
    production_mode: GuardianProductionMode,
) -> Result<Box<dyn KeyAuthority>> {
    let descriptor = descriptor.unwrap_or_default();
    let authority: Box<dyn KeyAuthority> = match descriptor.kind {
        KeyAuthorityKind::DevMemory => Box::new(DevMemoryKeyAuthority::new(descriptor)),
        KeyAuthorityKind::Tpm2 => Box::new(Tpm2KeyAuthority::new(descriptor)),
        KeyAuthorityKind::Pkcs11 => Box::new(Pkcs11KeyAuthority::new(descriptor)),
        KeyAuthorityKind::CloudKms => Box::new(CloudKmsKeyAuthority::new(descriptor)),
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
