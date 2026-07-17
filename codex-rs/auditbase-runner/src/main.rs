use std::io::Read;
use std::io::Write;
use std::process::ExitCode;

use codex_auditbase_runner::child_protocol::MAX_REQUEST_BYTES;
use codex_auditbase_runner::child_protocol::RunnerOutput;
use codex_auditbase_runner::child_protocol::parse_runner_request;
use codex_auditbase_runner::child_protocol::production_rejection;
use codex_auditbase_runner::child_protocol::trusted_real_completed_outputs;
use codex_auditbase_runner::child_protocol::trusted_real_failed_output;
use codex_auditbase_runner::child_protocol::trusted_real_failed_output_with_partial;
use codex_auditbase_runner::child_protocol::trusted_real_progress_output;
use codex_auditbase_runner::child_protocol::trusted_real_start_outputs;
use codex_auditbase_runner::trusted_local::LOCAL_REAL_MODE;
use codex_auditbase_runner::trusted_local::TrustedLocalSettings;
use codex_auditbase_runner::trusted_local::execute_trusted_local_with_progress;
use codex_auditbase_runner::trusted_local::install_cancellation_handlers;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("auditbase-v3-runner: {message}");
            ExitCode::from(65)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    if std::env::args().len() != 1 {
        return Err("production runner accepts no command-line arguments".to_owned());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read request: {error}"))?;
    let request = parse_runner_request(&bytes).map_err(|error| error.to_string())?;

    if std::env::var("AUDITBASE_V3_EXECUTION_MODE").unwrap_or_default() != LOCAL_REAL_MODE {
        emit(&production_rejection(&request))?;
        eprintln!(
            "production execution is disabled until isolation and gateway attestations are supplied"
        );
        // The protocol terminal is the authoritative rejection. Exit zero once it has
        // been flushed so supervisors do not replace its specific failure code with a
        // generic child-process failure.
        return Ok(ExitCode::SUCCESS);
    }
    install_cancellation_handlers().map_err(|error| error.to_string())?;

    for output in trusted_real_start_outputs(&request) {
        emit(&output)?;
    }
    let settings = match TrustedLocalSettings::from_environment() {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            eprintln!("trusted-local real mode was not selected consistently");
            emit(&trusted_real_failed_output("internal", 3))?;
            return Ok(ExitCode::SUCCESS);
        }
        Err(error) => {
            eprintln!("trusted-local real runner configuration failed: {error}");
            emit(&trusted_real_failed_output(error.code().as_str(), 3))?;
            return Ok(ExitCode::SUCCESS);
        }
    };
    let mut next_sequence = 3_u64;
    let result = execute_trusted_local_with_progress(&request, &settings, || {
        let following = next_sequence
            .checked_add(1)
            .ok_or_else(|| "runner progress sequence overflowed".to_owned())?;
        emit(&trusted_real_progress_output(&request, next_sequence))?;
        next_sequence = following;
        Ok(())
    });
    match result {
        Ok(success) => {
            for output in
                trusted_real_completed_outputs(&request, &success.result_sha256, next_sequence)
            {
                emit(&output)?;
            }
        }
        Err(error) => {
            eprintln!("trusted-local real audit failed: {error}");
            let terminal = match error.partial() {
                Some(partial) => trusted_real_failed_output_with_partial(
                    error.code().as_str(),
                    next_sequence,
                    &partial.result_ref,
                    &partial.result_sha256,
                ),
                None => trusted_real_failed_output(error.code().as_str(), next_sequence),
            };
            emit(&terminal)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn emit(output: &RunnerOutput) -> Result<(), String> {
    let line = serde_json::to_string(output)
        .map_err(|error| format!("failed to serialize runner output: {error}"))?;
    println!("{line}");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush runner output: {error}"))?;
    Ok(())
}
