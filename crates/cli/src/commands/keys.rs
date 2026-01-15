// Path: crates/cli/src/commands/keys.rs

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_crypto::sign::{dilithium::MldsaScheme, eddsa::Ed25519KeyPair};
use ioi_types::app::{account_id_from_key_material, SignatureSuite};
use libp2p::identity;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct KeysArgs {
    #[clap(subcommand)]
    pub command: KeysCommands,
}

#[derive(Subcommand, Debug)]
pub enum KeysCommands {
    /// Generate a new keypair.
    Generate {
        #[clap(long, value_enum, default_value = "ed25519")]
        suite: KeySuite,
    },
    /// Inspect a public key (hex) to derive its Account ID.
    Inspect {
        #[clap(long, value_enum, default_value = "ed25519")]
        suite: KeySuite,
        hex_key: String,
    },
    /// Provision a new API key for external connectors.
    Provision {
        /// The identifier for this key (e.g., "openai").
        #[clap(long)]
        name: String,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum KeySuite {
    Ed25519,
    Dilithium2,
}

pub fn run(args: KeysArgs) -> Result<()> {
    match args.command {
        KeysCommands::Generate { suite } => {
            match suite {
                KeySuite::Ed25519 => {
                    let kp =
                        Ed25519KeyPair::generate().map_err(|e| anyhow!("Gen failed: {}", e))?;
                    let pub_bytes = kp.public_key().to_bytes();
                    let pk_hex = hex::encode(&pub_bytes);
                    let libp2p_pk =
                        identity::ed25519::PublicKey::try_from_bytes(&pub_bytes).unwrap();
                    let proto_pk = identity::PublicKey::from(libp2p_pk).encode_protobuf();

                    let acct =
                        account_id_from_key_material(SignatureSuite::ED25519, &proto_pk).unwrap();

                    println!("--- New Ed25519 Identity ---");
                    println!(
                        "Private Key (Seed): {}",
                        hex::encode(kp.private_key().as_bytes())
                    );
                    println!("Public Key:         {}", pk_hex);
                    println!("Account ID:         0x{}", hex::encode(acct));
                }
                KeySuite::Dilithium2 => {
                    let kp = MldsaScheme::new(ioi_crypto::security::SecurityLevel::Level2)
                        .generate_keypair()
                        .map_err(|e| anyhow!("PQC Gen failed: {}", e))?;
                    let pk_bytes = kp.public_key().to_bytes();
                    let acct =
                        account_id_from_key_material(SignatureSuite::ML_DSA_44, &pk_bytes).unwrap();

                    println!("--- New ML-DSA-44 (formerly Dilithium2) Identity ---");
                    println!(
                        "Public Key ({} bytes): {}",
                        pk_bytes.len(),
                        hex::encode(&pk_bytes)
                    );
                    println!("Account ID:            0x{}", hex::encode(acct));
                }
            }
        }
        KeysCommands::Inspect { suite, hex_key } => {
            let bytes = hex::decode(&hex_key).context("Invalid hex")?;
            match suite {
                KeySuite::Ed25519 => {
                    let libp2p_pk = identity::ed25519::PublicKey::try_from_bytes(&bytes)
                        .context("Invalid Ed25519 key bytes")?;
                    let proto_pk = identity::PublicKey::from(libp2p_pk).encode_protobuf();
                    let acct = account_id_from_key_material(SignatureSuite::ED25519, &proto_pk)?;
                    println!("Account ID: 0x{}", hex::encode(acct));
                }
                KeySuite::Dilithium2 => {
                    let acct = account_id_from_key_material(SignatureSuite::ML_DSA_44, &bytes)?;
                    println!("Account ID: 0x{}", hex::encode(acct));
                }
            }
        }
        KeysCommands::Provision { name } => {
            let certs_dir = std::env::var("CERTS_DIR")
                .map(PathBuf::from)
                .or_else(|_| std::env::current_dir().map(|p| p.join("certs")))
                .map_err(|_| anyhow!("Could not determine CERTS_DIR"))?;

            if !certs_dir.exists() {
                fs::create_dir_all(&certs_dir)?;
            }

            let key_path = certs_dir.join(format!("{}.key", name));

            println!("Enter API Key for '{}': ", name);
            let secret = rpassword::read_password()?;

            if secret.trim().is_empty() {
                return Err(anyhow!("API Key cannot be empty"));
            }

            ioi_validator::common::GuardianContainer::save_encrypted_file(
                &key_path,
                secret.as_bytes(),
            )?;
            println!("✅ Key encrypted and saved to {}", key_path.display());
            println!(
                "Use key_ref = \"{}\" in your workload.toml connectors config.",
                name
            );
        }
    }
    Ok(())
}