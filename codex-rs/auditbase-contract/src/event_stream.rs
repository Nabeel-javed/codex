use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::AuditEvent;
use crate::AuditEventPayload;
use crate::AuditResult;
use crate::AuditSnapshot;
use crate::AuditStatus;
use crate::AuditUsage;
use crate::ContractLimits;
use crate::Finding;
use crate::FindingEventAction;
use crate::JS_MAX_SAFE_INTEGER;
use crate::Limitation;
use crate::TerminalAuditStatus;
use crate::ValidateWithLimits;
use crate::ValidationError;
use crate::validate_snapshot_against_result;
use crate::validation::require_rfc3339;

/// Validates an entire persisted event stream. `queued` is considered to have
/// been established by `AuditAccepted`, so the first status event may be the
/// canonical `queued -> preparing` transition.
pub fn validate_event_stream(
    events: &[AuditEvent],
    result: Option<&AuditResult>,
    snapshot: Option<&AuditSnapshot>,
    limits: &ContractLimits,
) -> Result<(), ValidationError> {
    let first = events
        .first()
        .ok_or_else(|| ValidationError::new("events", "must not be empty"))?;
    if let Some(result) = result {
        result.validate_with_limits(limits)?;
    }
    let audit_id = first.audit_id.as_str();
    let mut event_ids = HashSet::new();
    let mut last_timestamp = None;
    let mut current_status = AuditStatus::Queued;
    let mut saw_status = false;
    let mut terminal_status_count = 0_u8;
    let mut terminal_payload_count = 0_u8;
    let mut findings = HashMap::<String, Finding>::new();
    let mut finding_order = Vec::<String>::new();
    let mut limitations = Vec::<Limitation>::new();
    let mut usage = AuditUsage::default();
    let mut usage_event_count = 0_u32;

    for (index, event) in events.iter().enumerate() {
        event.validate_with_limits(limits)?;
        if event.audit_id != audit_id {
            return Err(ValidationError::new(
                format!("events[{index}].auditId"),
                "all events in a stream must use the same audit ID",
            ));
        }
        if !event_ids.insert(event.event_id.as_str()) {
            return Err(ValidationError::new(
                format!("events[{index}].eventId"),
                "must be unique within the audit stream",
            ));
        }
        let expected_sequence = index as u64 + 1;
        if event.sequence != expected_sequence {
            return Err(ValidationError::new(
                format!("events[{index}].sequence"),
                format!("must be the contiguous sequence value {expected_sequence}"),
            ));
        }

        let timestamp =
            require_rfc3339(&event.occurred_at, &format!("events[{index}].occurredAt"))?;
        if let Some(previous) = &last_timestamp
            && timestamp.compare(previous) == Ordering::Less
        {
            return Err(ValidationError::new(
                format!("events[{index}].occurredAt"),
                "must not precede the previous event timestamp",
            ));
        }
        last_timestamp = Some(timestamp);

        if current_status.is_terminal()
            && !matches!(
                (&current_status, &event.payload),
                (AuditStatus::Completed, AuditEventPayload::Completed(_))
                    | (AuditStatus::Failed, AuditEventPayload::Failed(_))
            )
        {
            return Err(ValidationError::new(
                format!("events[{index}]"),
                "only the matching terminal payload may follow a terminal status",
            ));
        }

        match &event.payload {
            AuditEventPayload::Status(status) => {
                match status.previous {
                    None if !saw_status && status.status == AuditStatus::Queued => {}
                    Some(previous) if previous == current_status => {
                        if !previous.can_transition_to(status.status) {
                            return Err(ValidationError::new(
                                format!("events[{index}].data.status"),
                                "is not a permitted canonical status transition",
                            ));
                        }
                    }
                    None => {
                        return Err(ValidationError::new(
                            format!("events[{index}].data.previous"),
                            "may be absent only on the initial queued status event",
                        ));
                    }
                    Some(_) => {
                        return Err(ValidationError::new(
                            format!("events[{index}].data.previous"),
                            "must equal the current stream status",
                        ));
                    }
                }
                current_status = status.status;
                saw_status = true;
                if current_status.is_terminal() {
                    terminal_status_count = terminal_status_count.saturating_add(1);
                }
            }
            AuditEventPayload::Finding(finding_event) => {
                let finding_id = finding_event.finding.id.clone();
                match finding_event.action {
                    FindingEventAction::Discovered => {
                        if findings
                            .insert(finding_id, finding_event.finding.clone())
                            .is_some()
                        {
                            return Err(ValidationError::new(
                                format!("events[{index}].data.finding.id"),
                                "a finding may be discovered only once",
                            ));
                        }
                        finding_order.push(finding_event.finding.id.clone());
                    }
                    FindingEventAction::Updated => {
                        let Some(existing) = findings.get_mut(&finding_id) else {
                            return Err(ValidationError::new(
                                format!("events[{index}].data.finding.id"),
                                "updated finding must have been discovered first",
                            ));
                        };
                        *existing = finding_event.finding.clone();
                    }
                }
            }
            AuditEventPayload::Completed(completed) => {
                terminal_payload_count = terminal_payload_count.saturating_add(1);
                require_last_event(index, events.len())?;
                if current_status != AuditStatus::Completed {
                    return Err(ValidationError::new(
                        format!("events[{index}].type"),
                        "completion payload requires completed stream status",
                    ));
                }
                let result = result.ok_or_else(|| {
                    ValidationError::new(
                        format!("events[{index}].data.resultAvailable"),
                        "completion payload requires an available result",
                    )
                })?;
                if !completed.result_available || result.status != TerminalAuditStatus::Completed {
                    return Err(ValidationError::new(
                        format!("events[{index}].data.resultAvailable"),
                        "must reference a completed result",
                    ));
                }
            }
            AuditEventPayload::Failed(failed) => {
                terminal_payload_count = terminal_payload_count.saturating_add(1);
                require_last_event(index, events.len())?;
                if current_status != AuditStatus::Failed {
                    return Err(ValidationError::new(
                        format!("events[{index}].type"),
                        "failure payload requires failed stream status",
                    ));
                }
                match (failed.partial_results_available, result) {
                    (true, Some(result)) => {
                        if result.status != TerminalAuditStatus::Failed
                            || result.failure.as_ref() != Some(&failed.failure)
                        {
                            return Err(ValidationError::new(
                                format!("events[{index}].data.failure"),
                                "must match the failed partial result",
                            ));
                        }
                    }
                    (false, None) => {}
                    (true, None) => {
                        return Err(ValidationError::new(
                            format!("events[{index}].data.partialResultsAvailable"),
                            "declares a partial result but none was provided",
                        ));
                    }
                    (false, Some(_)) => {
                        return Err(ValidationError::new(
                            format!("events[{index}].data.partialResultsAvailable"),
                            "must be true when a partial result is available",
                        ));
                    }
                }
            }
            AuditEventPayload::Limitation(limitation) => limitations.push(limitation.clone()),
            AuditEventPayload::Usage(delta) => {
                add_usage(&mut usage, delta, index)?;
                usage_event_count = usage_event_count.checked_add(1).ok_or_else(|| {
                    ValidationError::new(
                        format!("events[{index}].data"),
                        "usage event count overflowed",
                    )
                })?;
            }
            AuditEventPayload::Progress(_) | AuditEventPayload::Log(_) => {}
        }
    }

    if terminal_status_count != 1 || terminal_payload_count != 1 {
        return Err(ValidationError::new(
            "events",
            "must contain exactly one terminal status and one matching terminal payload",
        ));
    }

    if let Some(result) = result {
        if result.audit_id != audit_id {
            return Err(ValidationError::new(
                "result.auditId",
                "must match the event stream audit ID",
            ));
        }
        if findings.len() != result.findings.len()
            || finding_order.len() != result.findings.len()
            || result
                .findings
                .iter()
                .zip(&finding_order)
                .any(|(finding, event_id)| {
                    finding.id != *event_id || findings.get(&finding.id) != Some(finding)
                })
        {
            return Err(ValidationError::new(
                "result.findings",
                "must exactly match the latest finding state in the event stream",
            ));
        }
        if limitations != result.limitations {
            return Err(ValidationError::new(
                "result.limitations",
                "must exactly match limitation events in stream order",
            ));
        }
        if usage_event_count == 0 || usage != result.usage {
            return Err(ValidationError::new(
                "result.usage",
                "must exactly match the sum of usage events",
            ));
        }
    } else if !findings.is_empty() {
        return Err(ValidationError::new(
            "events.findings",
            "retained findings require an available partial result",
        ));
    } else if !limitations.is_empty() {
        return Err(ValidationError::new(
            "events.limitations",
            "retained limitations require an available partial result",
        ));
    }

    if let Some(snapshot) = snapshot {
        if snapshot.audit_id != audit_id {
            return Err(ValidationError::new(
                "snapshot.auditId",
                "must match the event stream audit ID",
            ));
        }
        if snapshot.status != current_status {
            return Err(ValidationError::new(
                "snapshot.status",
                "must match the terminal stream status",
            ));
        }
        validate_snapshot_against_result(snapshot, result)?;
    }
    Ok(())
}

fn add_usage(
    total: &mut AuditUsage,
    delta: &AuditUsage,
    event_index: usize,
) -> Result<(), ValidationError> {
    let field = |name: &str| format!("events[{event_index}].data.{name}");
    total.input_tokens = checked_usage_add(
        total.input_tokens,
        delta.input_tokens,
        &field("inputTokens"),
    )?;
    total.cached_input_tokens = checked_usage_add(
        total.cached_input_tokens,
        delta.cached_input_tokens,
        &field("cachedInputTokens"),
    )?;
    total.cache_write_input_tokens = checked_usage_add(
        total.cache_write_input_tokens,
        delta.cache_write_input_tokens,
        &field("cacheWriteInputTokens"),
    )?;
    total.output_tokens = checked_usage_add(
        total.output_tokens,
        delta.output_tokens,
        &field("outputTokens"),
    )?;
    total.reasoning_output_tokens = checked_usage_add(
        total.reasoning_output_tokens,
        delta.reasoning_output_tokens,
        &field("reasoningOutputTokens"),
    )?;
    total.duration_ms =
        checked_usage_add(total.duration_ms, delta.duration_ms, &field("durationMs"))?;
    total.model_requests = total
        .model_requests
        .checked_add(delta.model_requests)
        .ok_or_else(|| ValidationError::new(field("modelRequests"), "usage total overflowed"))?;
    Ok(())
}

fn checked_usage_add(left: u64, right: u64, field: &str) -> Result<u64, ValidationError> {
    let total = left
        .checked_add(right)
        .ok_or_else(|| ValidationError::new(field, "usage total overflowed"))?;
    if total > JS_MAX_SAFE_INTEGER {
        return Err(ValidationError::new(
            field,
            format!("usage total must not exceed {JS_MAX_SAFE_INTEGER}"),
        ));
    }
    Ok(total)
}

fn require_last_event(index: usize, event_count: usize) -> Result<(), ValidationError> {
    if index + 1 != event_count {
        return Err(ValidationError::new(
            format!("events[{index}]"),
            "terminal payload must be the final event",
        ));
    }
    Ok(())
}
