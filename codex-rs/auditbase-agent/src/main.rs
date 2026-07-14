//! AuditBase V3 headless agent entry point.
//!
//! This binary intentionally delegates to the upstream `codex-exec` runtime so
//! the initial AuditBase product baseline preserves Codex behavior without
//! depending on its terminal UI.

use clap::Parser;
use codex_arg0::Arg0DispatchPaths;
use codex_arg0::arg0_dispatch_or_else;
use codex_exec::Cli;
use codex_exec::run_main;
use codex_utils_cli::CliConfigOverrides;

#[derive(Parser, Debug)]
#[command(
    name = "auditbase-agent",
    about = "AuditBase V3 headless agent",
    override_usage = "auditbase-agent [OPTIONS] [PROMPT]\n       auditbase-agent [OPTIONS] <COMMAND> [ARGS]"
)]
struct TopCli {
    #[clap(flatten)]
    config_overrides: CliConfigOverrides,

    #[clap(flatten)]
    inner: Cli,
}

fn main() -> anyhow::Result<()> {
    arg0_dispatch_or_else(|arg0_paths: Arg0DispatchPaths| async move {
        let top_cli = TopCli::parse();
        let mut inner = top_cli.inner;
        inner
            .config_overrides
            .prepend_root_overrides(top_cli.config_overrides);

        run_main(inner, arg0_paths).await?;
        Ok(())
    })
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
