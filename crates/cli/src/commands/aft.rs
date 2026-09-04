use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use ioi_cli::aft_quv_ceremony::{
    inspect_handoff, install_signed_handoff, sign_handoff_draft, verify_signed_handoff,
};

#[derive(Parser, Debug)]
pub struct AftArgs {
    #[clap(subcommand)]
    pub command: AftCommands,
}

#[derive(Subcommand, Debug)]
pub enum AftCommands {
    /// Prepare or audit a Q-EA7 handoff candidate input. This never runs QUV.
    QuvHandoff {
        #[clap(subcommand)]
        command: QuvHandoffCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum QuvHandoffCommands {
    /// Inspect and structurally validate an exact canonical draft or source.
    Inspect { input: PathBuf },
    /// Sign an unsigned process-emitted draft with its rooted ML-DSA owner.
    Sign {
        #[clap(long)]
        draft: PathBuf,
        #[clap(long)]
        owner_key_file: PathBuf,
        #[clap(long)]
        output: PathBuf,
        /// Replace an existing output only after full validation.
        #[clap(long)]
        replace: bool,
    },
    /// Verify the exact typed payload, owner identity, and ML-DSA signature.
    Verify {
        input: PathBuf,
        #[clap(long)]
        owner_public_key_file: PathBuf,
    },
    /// Atomically publish a verified source candidate for node consumption.
    /// Publishing these bytes grants no successor or finality authority.
    Install {
        #[clap(long)]
        input: PathBuf,
        #[clap(long)]
        owner_public_key_file: PathBuf,
        #[clap(long)]
        destination: PathBuf,
        /// Replace a different existing source only after full validation.
        #[clap(long)]
        replace: bool,
    },
}

pub fn run(args: AftArgs) -> Result<()> {
    let audit = match args.command {
        AftCommands::QuvHandoff { command } => match command {
            QuvHandoffCommands::Inspect { input } => inspect_handoff(&input)?,
            QuvHandoffCommands::Sign {
                draft,
                owner_key_file,
                output,
                replace,
            } => sign_handoff_draft(&draft, &owner_key_file, &output, replace)?,
            QuvHandoffCommands::Verify {
                input,
                owner_public_key_file,
            } => verify_signed_handoff(&input, &owner_public_key_file)?,
            QuvHandoffCommands::Install {
                input,
                owner_public_key_file,
                destination,
                replace,
            } => install_signed_handoff(&input, &owner_public_key_file, &destination, replace)?,
        },
    };
    println!("{}", serde_json::to_string_pretty(&audit)?);
    Ok(())
}
