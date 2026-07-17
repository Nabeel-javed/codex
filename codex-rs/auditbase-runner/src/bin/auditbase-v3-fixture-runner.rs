use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use codex_auditbase_runner::child_protocol::MAX_REQUEST_BYTES;
use codex_auditbase_runner::child_protocol::TrustedFixtureScenario;
use codex_auditbase_runner::child_protocol::parse_runner_request;
use codex_auditbase_runner::child_protocol::trusted_fixture_outputs;
use codex_auditbase_runner::child_protocol::validate_trusted_fixture_artifact;

const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("auditbase-v3-fixture-runner: {message}");
            ExitCode::from(65)
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [scenario, artifact_path] = args.as_slice() else {
        return Err(
            "usage: auditbase-v3-fixture-runner completed|failed /absolute/staged-result.json"
                .to_owned(),
        );
    };
    let scenario = match scenario.as_str() {
        "completed" => TrustedFixtureScenario::Completed,
        "failed" => TrustedFixtureScenario::Failed,
        _ => return Err("scenario must be `completed` or `failed`".to_owned()),
    };

    let path = Path::new(artifact_path);
    if !path.is_absolute() {
        return Err("fixture artifact path must be absolute".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect fixture artifact: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("fixture artifact must be a regular non-symlink file".to_owned());
    }
    let mut artifact = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| format!("could not open fixture artifact: {error}"))?
        .take((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut artifact)
        .map_err(|error| format!("could not read fixture artifact: {error}"))?;

    let mut request_bytes = Vec::new();
    std::io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut request_bytes)
        .map_err(|error| format!("failed to read request: {error}"))?;
    let request = parse_runner_request(&request_bytes).map_err(|error| error.to_string())?;
    let artifact_sha256 =
        validate_trusted_fixture_artifact(&artifact, MAX_ARTIFACT_BYTES, &request, scenario)
            .map_err(|error| error.to_string())?;
    for output in trusted_fixture_outputs(&request, scenario, &artifact_sha256) {
        let line = serde_json::to_string(&output)
            .map_err(|error| format!("failed to serialize fixture output: {error}"))?;
        println!("{line}");
    }
    Ok(())
}
