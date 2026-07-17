use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use codex_auditbase_benchmark::PackageOptions;
use codex_auditbase_benchmark::load_catalog;
use codex_auditbase_benchmark::package_case;
use codex_auditbase_benchmark::verify_package;

#[derive(Debug, Parser)]
#[command(name = "auditbase-benchmark")]
#[command(about = "Package and verify offline AuditBase benchmark inputs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Copy an exact catalog allowlist into a deterministic agent input package.
    Package {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Evaluator-issued `run-` plus 32 lowercase hex characters.
        #[arg(long)]
        opaque_run_case_id: String,
        #[arg(long)]
        allow_internal_evaluation_only: bool,
    },
    /// Re-verify a previously built package without executing its contents.
    Verify {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        package: PathBuf,
        /// Must match the opaque ID used when the package was created.
        #[arg(long)]
        opaque_run_case_id: String,
        #[arg(long)]
        allow_internal_evaluation_only: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let receipt = match cli.command {
        Command::Package {
            catalog,
            source,
            output,
            opaque_run_case_id,
            allow_internal_evaluation_only,
        } => {
            let catalog = load_catalog(catalog)?;
            package_case(
                &catalog,
                source,
                output,
                PackageOptions {
                    allow_internal_evaluation_only,
                    opaque_run_case_id,
                },
            )?
        }
        Command::Verify {
            catalog,
            package,
            opaque_run_case_id,
            allow_internal_evaluation_only,
        } => {
            let catalog = load_catalog(catalog)?;
            verify_package(
                &catalog,
                package,
                PackageOptions {
                    allow_internal_evaluation_only,
                    opaque_run_case_id,
                },
            )?
        }
    };
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
