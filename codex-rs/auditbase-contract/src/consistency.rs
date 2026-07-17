use std::collections::HashSet;

use crate::AuditRequest;
use crate::AuditResult;
use crate::AuditSnapshot;
use crate::AuditStatus;
use crate::ContractLimits;
use crate::TerminalAuditStatus;
use crate::Validate;
use crate::ValidateWithLimits;
use crate::ValidationError;
use crate::validation::require_token;

/// Validates the request/result invariants that cannot be expressed by either
/// top-level object in isolation.
pub fn validate_result_for_job(
    expected_audit_id: &str,
    request: &AuditRequest,
    result: &AuditResult,
    limits: &ContractLimits,
) -> Result<(), ValidationError> {
    require_token(expected_audit_id, "expectedAuditId")?;
    request.validate_with_limits(limits)?;
    result.validate_with_limits(limits)?;
    if result.audit_id != expected_audit_id {
        return Err(ValidationError::new(
            "auditId",
            "must match the expected audit ID",
        ));
    }

    let manifest_paths = request
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();
    let coverage_paths = result
        .coverage
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();

    for (index, file) in result.coverage.files.iter().enumerate() {
        require_manifest_path(
            &manifest_paths,
            &file.path,
            &format!("coverage.files[{index}].path"),
        )?;
    }
    if coverage_paths.len() != manifest_paths.len() {
        return Err(ValidationError::new(
            "coverage.files",
            "must contain every submitted manifest path exactly once",
        ));
    }

    for (finding_index, finding) in result.findings.iter().enumerate() {
        for (location_index, location) in finding.locations.iter().enumerate() {
            require_manifest_path(
                &manifest_paths,
                &location.path,
                &format!("findings[{finding_index}].locations[{location_index}].path"),
            )?;
        }
        for (evidence_index, evidence) in finding.evidence.iter().enumerate() {
            if let Some(location) = &evidence.location {
                require_manifest_path(
                    &manifest_paths,
                    &location.path,
                    &format!("findings[{finding_index}].evidence[{evidence_index}].location.path"),
                )?;
            }
        }
    }
    for (limitation_index, limitation) in result.limitations.iter().enumerate() {
        for (path_index, path) in limitation.affected_paths.iter().enumerate() {
            require_manifest_path(
                &manifest_paths,
                path,
                &format!("limitations[{limitation_index}].affectedPaths[{path_index}]"),
            )?;
        }
    }
    Ok(())
}

/// Validates that a public snapshot truthfully describes the result currently
/// available for that audit.
pub fn validate_snapshot_against_result(
    snapshot: &AuditSnapshot,
    result: Option<&AuditResult>,
) -> Result<(), ValidationError> {
    snapshot.validate()?;
    if let Some(result) = result {
        result.validate()?;
        if result.audit_id != snapshot.audit_id {
            return Err(ValidationError::new(
                "auditId",
                "snapshot and result audit IDs must match",
            ));
        }
    }

    match snapshot.status {
        AuditStatus::Completed => match result {
            Some(result) if result.status == TerminalAuditStatus::Completed => Ok(()),
            Some(_) => Err(ValidationError::new(
                "status",
                "completed snapshot requires a completed result",
            )),
            None => Err(ValidationError::new(
                "resultAvailable",
                "completed snapshot requires an available result",
            )),
        },
        AuditStatus::Failed => match (snapshot.result_available, result) {
            (true, Some(result)) => {
                if result.status != TerminalAuditStatus::Failed || !result.partial {
                    return Err(ValidationError::new(
                        "status",
                        "failed snapshot requires a failed partial result",
                    ));
                }
                if result.failure.as_ref() != snapshot.failure.as_ref() {
                    return Err(ValidationError::new(
                        "failure",
                        "snapshot and result failure details must match",
                    ));
                }
                Ok(())
            }
            (false, None) => Ok(()),
            (true, None) => Err(ValidationError::new(
                "resultAvailable",
                "snapshot declares a result but none was provided",
            )),
            (false, Some(_)) => Err(ValidationError::new(
                "resultAvailable",
                "snapshot hides an available result",
            )),
        },
        AuditStatus::Queued
        | AuditStatus::Preparing
        | AuditStatus::Auditing
        | AuditStatus::Finalizing => {
            if result.is_some() {
                return Err(ValidationError::new(
                    "resultAvailable",
                    "non-terminal snapshot must not expose a terminal result",
                ));
            }
            Ok(())
        }
    }
}

fn require_manifest_path(
    manifest_paths: &HashSet<&str>,
    path: &str,
    field: &str,
) -> Result<(), ValidationError> {
    if !manifest_paths.contains(path) {
        return Err(ValidationError::new(
            field,
            "must reference a submitted manifest path",
        ));
    }
    Ok(())
}
