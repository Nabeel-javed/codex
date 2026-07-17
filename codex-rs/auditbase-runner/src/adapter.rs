use codex_auditbase_contract::AuditEvent;
use codex_auditbase_contract::AuditEventPayload;
use codex_auditbase_contract::AuditEventSchemaVersion;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::AuditResultSchemaVersion;
use codex_auditbase_contract::AuditStatus;
use codex_auditbase_contract::AuditUsage;
use codex_auditbase_contract::CompletedEvent;
use codex_auditbase_contract::FailedEvent;
use codex_auditbase_contract::FindingEvent;
use codex_auditbase_contract::FindingEventAction;
use codex_auditbase_contract::LogEvent;
use codex_auditbase_contract::LogLevel;
use codex_auditbase_contract::LogSource;
use codex_auditbase_contract::StatusEvent;
use codex_auditbase_contract::Validate;
use codex_exec::ExecThreadItem;
use codex_exec::ThreadEvent;
use codex_exec::ThreadItemDetails;

use crate::RunnerError;
use crate::supervisor::RunResolution;

const RESERVED_COMPLETION_EVENTS: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterContext {
    pub audit_id: String,
    /// Trusted runner timestamp. Raw model/event timestamps are never used.
    pub occurred_at: String,
    pub max_events: usize,
    pub max_message_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawTerminalKind {
    Completed,
    Failed,
    Error,
}

/// Converts private Codex events into a small public vocabulary. Reasoning,
/// prompts, command output, tool arguments, queries, and model-authored final
/// JSON are deliberately never copied into public events.
pub struct AuditEventAdapter {
    context: AdapterContext,
    events: Vec<AuditEvent>,
    next_sequence: u64,
    status: AuditStatus,
    saw_thread: bool,
    saw_turn: bool,
    saw_unrecoverable_stream_error: bool,
    raw_terminal: Option<RawTerminalKind>,
    raw_usage: Option<AuditUsage>,
    finished: bool,
}

impl AuditEventAdapter {
    pub fn new(context: AdapterContext) -> Result<Self, RunnerError> {
        if context.max_events < 6 {
            return Err(RunnerError::Adapter {
                message: "max_events must be at least 6".to_owned(),
            });
        }
        if context.max_message_bytes < 32 {
            return Err(RunnerError::Adapter {
                message: "max_message_bytes must be at least 32".to_owned(),
            });
        }
        if context.audit_id.trim().is_empty() || context.occurred_at.trim().is_empty() {
            return Err(RunnerError::Adapter {
                message: "audit_id and occurred_at must not be empty".to_owned(),
            });
        }
        Ok(Self {
            context,
            events: Vec::new(),
            next_sequence: 1,
            status: AuditStatus::Queued,
            saw_thread: false,
            saw_turn: false,
            saw_unrecoverable_stream_error: false,
            raw_terminal: None,
            raw_usage: None,
            finished: false,
        })
    }

    pub fn adapt_all(&mut self, events: &[ThreadEvent]) -> Result<(), RunnerError> {
        for event in events {
            self.adapt(event)?;
        }
        Ok(())
    }

    pub fn adapt(&mut self, event: &ThreadEvent) -> Result<(), RunnerError> {
        if self.finished {
            return Err(RunnerError::Adapter {
                message: "cannot adapt events after the public terminal event".to_owned(),
            });
        }
        if self.raw_terminal.is_some() {
            return Err(RunnerError::Adapter {
                message: "Codex emitted an event after its terminal event".to_owned(),
            });
        }

        match event {
            ThreadEvent::ThreadStarted(_) => {
                if self.saw_thread {
                    return Err(RunnerError::Adapter {
                        message: "Codex emitted thread.started more than once".to_owned(),
                    });
                }
                self.saw_thread = true;
                self.transition(
                    AuditStatus::Preparing,
                    "Preparing the isolated audit workspace.",
                )?;
            }
            ThreadEvent::TurnStarted(_) => {
                if !self.saw_thread || self.saw_turn {
                    return Err(RunnerError::Adapter {
                        message: "turn.started violated the pinned lifecycle".to_owned(),
                    });
                }
                self.saw_turn = true;
                self.transition(AuditStatus::Auditing, "Analyzing the submitted source.")?;
            }
            ThreadEvent::ItemStarted(event) => self.adapt_item(&event.item, "started")?,
            ThreadEvent::ItemUpdated(event) => self.adapt_item(&event.item, "updated")?,
            ThreadEvent::ItemCompleted(event) => self.adapt_item(&event.item, "completed")?,
            ThreadEvent::TurnCompleted(event) => {
                self.raw_terminal = Some(if self.saw_unrecoverable_stream_error {
                    RawTerminalKind::Error
                } else {
                    RawTerminalKind::Completed
                });
                self.transition(AuditStatus::Finalizing, "Validating the audit output.")?;
                let usage = AuditUsage {
                    input_tokens: nonnegative(event.usage.input_tokens, "input_tokens")?,
                    cached_input_tokens: nonnegative(
                        event.usage.cached_input_tokens,
                        "cached_input_tokens",
                    )?,
                    cache_write_input_tokens: nonnegative(
                        event.usage.cache_write_input_tokens,
                        "cache_write_input_tokens",
                    )?,
                    output_tokens: nonnegative(event.usage.output_tokens, "output_tokens")?,
                    reasoning_output_tokens: nonnegative(
                        event.usage.reasoning_output_tokens,
                        "reasoning_output_tokens",
                    )?,
                    model_requests: 1,
                    duration_ms: 0,
                };
                self.raw_usage = Some(usage);
            }
            ThreadEvent::TurnFailed(_) => {
                self.raw_terminal = Some(RawTerminalKind::Failed);
            }
            ThreadEvent::Error(error) => {
                // Codex may recover from transient stream failures internally.
                // Do not expose the private upstream message or mark the run
                // terminal while that retry is in progress. A non-retryable
                // error is also pending because exec emits turn.failed next.
                if !error.will_retry {
                    self.saw_unrecoverable_stream_error = true;
                }
            }
        }
        Ok(())
    }

    pub fn finish(
        &mut self,
        resolution: &RunResolution,
        result: Option<&AuditResult>,
    ) -> Result<&[AuditEvent], RunnerError> {
        if self.finished {
            return Err(RunnerError::Adapter {
                message: "public terminal event was already emitted".to_owned(),
            });
        }

        self.validate_terminal_result(resolution, result)?;
        self.ensure_final_event_capacity(resolution, result)?;
        if let Some(result) = result {
            self.emit_result_state(result)?;
        }

        match resolution {
            RunResolution::Completed => {
                if self.raw_terminal != Some(RawTerminalKind::Completed) {
                    return Err(RunnerError::Adapter {
                        message: "completion requires a raw turn.completed event".to_owned(),
                    });
                }
                if self.status != AuditStatus::Finalizing {
                    self.transition(AuditStatus::Finalizing, "Validating the audit output.")?;
                }
                self.transition(AuditStatus::Completed, "The audit completed successfully.")?;
                self.push_required(AuditEventPayload::Completed(CompletedEvent {
                    result_available: true,
                    result_schema_version: AuditResultSchemaVersion::V1,
                }))?;
            }
            RunResolution::Failed(failure) => {
                self.transition(AuditStatus::Failed, "The audit did not complete.")?;
                self.push_required(AuditEventPayload::Failed(FailedEvent {
                    partial_results_available: result.is_some(),
                    failure: failure.clone(),
                }))?;
            }
        }
        self.finished = true;
        Ok(&self.events)
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<AuditEvent> {
        self.events
    }

    fn validate_terminal_result(
        &self,
        resolution: &RunResolution,
        result: Option<&AuditResult>,
    ) -> Result<(), RunnerError> {
        if let Some(result) = result {
            result.validate().map_err(|error| RunnerError::Adapter {
                message: format!("terminal result is invalid: {error}"),
            })?;
            if result.audit_id != self.context.audit_id {
                return Err(RunnerError::Adapter {
                    message: "terminal result audit_id does not match the adapter context"
                        .to_owned(),
                });
            }
        }
        match (resolution, result) {
            (RunResolution::Completed, Some(result)) => {
                if self.raw_terminal != Some(RawTerminalKind::Completed) {
                    return Err(RunnerError::Adapter {
                        message: "completion requires a raw turn.completed event".to_owned(),
                    });
                }
                if self.status != AuditStatus::Finalizing
                    && !self.status.can_transition_to(AuditStatus::Finalizing)
                {
                    return Err(RunnerError::Adapter {
                        message: "completion cannot enter the finalizing state".to_owned(),
                    });
                }
                if result.status != codex_auditbase_contract::TerminalAuditStatus::Completed {
                    return Err(RunnerError::Adapter {
                        message: "completed resolution requires a completed result".to_owned(),
                    });
                }
                let raw_usage = self
                    .raw_usage
                    .as_ref()
                    .ok_or_else(|| RunnerError::Adapter {
                        message: "completed resolution is missing raw Codex usage".to_owned(),
                    })?;
                if !same_token_usage(raw_usage, &result.usage) {
                    return Err(RunnerError::Adapter {
                        message: "trusted result token usage differs from turn.completed"
                            .to_owned(),
                    });
                }
            }
            (RunResolution::Completed, None) => {
                return Err(RunnerError::Adapter {
                    message: "completed resolution requires a canonical result".to_owned(),
                });
            }
            (RunResolution::Failed(failure), Some(result)) => {
                if !self.status.can_transition_to(AuditStatus::Failed) {
                    return Err(RunnerError::Adapter {
                        message: "failure cannot transition from the current public status"
                            .to_owned(),
                    });
                }
                if result.status != codex_auditbase_contract::TerminalAuditStatus::Failed
                    || result.failure.as_ref() != Some(failure)
                {
                    return Err(RunnerError::Adapter {
                        message: "failed resolution must match the retained partial result"
                            .to_owned(),
                    });
                }
            }
            (RunResolution::Failed(_), None) => {
                if !self.status.can_transition_to(AuditStatus::Failed) {
                    return Err(RunnerError::Adapter {
                        message: "failure cannot transition from the current public status"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn ensure_final_event_capacity(
        &self,
        resolution: &RunResolution,
        result: Option<&AuditResult>,
    ) -> Result<(), RunnerError> {
        let result_events = result.map_or(0, |result| {
            result.findings.len() + result.limitations.len() + 1
        });
        let status_events = match resolution {
            RunResolution::Completed => usize::from(self.status != AuditStatus::Finalizing) + 1,
            RunResolution::Failed(_) => 1,
        };
        let required = result_events
            .checked_add(status_events)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| RunnerError::Adapter {
                message: "normalized final event count overflowed".to_owned(),
            })?;
        if self.events.len().saturating_add(required) > self.context.max_events {
            return Err(RunnerError::Adapter {
                message: "normalized event limit cannot retain the canonical final result state"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn emit_result_state(&mut self, result: &AuditResult) -> Result<(), RunnerError> {
        for finding in &result.findings {
            self.push_required(AuditEventPayload::Finding(Box::new(FindingEvent {
                action: FindingEventAction::Discovered,
                finding: finding.clone(),
            })))?;
        }
        for limitation in &result.limitations {
            self.push_required(AuditEventPayload::Limitation(limitation.clone()))?;
        }
        self.push_required(AuditEventPayload::Usage(result.usage.clone()))
    }

    fn adapt_item(&mut self, item: &ExecThreadItem, phase: &str) -> Result<(), RunnerError> {
        if !self.saw_turn {
            return Err(RunnerError::Adapter {
                message: "item event arrived before turn.started".to_owned(),
            });
        }
        let message = match &item.details {
            ThreadItemDetails::Reasoning(_) | ThreadItemDetails::AgentMessage(_) => return Ok(()),
            ThreadItemDetails::CommandExecution(_) => {
                format!("Repository command {phase}.")
            }
            ThreadItemDetails::FileChange(_) => format!("Workspace change {phase}."),
            ThreadItemDetails::McpToolCall(_) => format!("External tool call {phase}."),
            ThreadItemDetails::CollabToolCall(_) => format!("Audit worker task {phase}."),
            ThreadItemDetails::WebSearch(_) => format!("Public research request {phase}."),
            ThreadItemDetails::TodoList(_) => format!("Audit plan {phase}."),
            ThreadItemDetails::Error(_) => {
                "A recoverable agent item error was recorded.".to_owned()
            }
        };
        let level = if matches!(&item.details, ThreadItemDetails::Error(_)) {
            LogLevel::Warning
        } else {
            LogLevel::Info
        };
        self.push_optional(AuditEventPayload::Log(LogEvent {
            level,
            source: LogSource::Agent,
            message: self.bound_message(&message),
        }))
    }

    fn transition(&mut self, status: AuditStatus, message: &str) -> Result<(), RunnerError> {
        if self.status == status {
            return Ok(());
        }
        if !self.status.can_transition_to(status) {
            return Err(RunnerError::Adapter {
                message: format!(
                    "invalid public status transition {:?} -> {:?}",
                    self.status, status
                ),
            });
        }
        let previous = self.status;
        self.push_required(AuditEventPayload::Status(StatusEvent {
            previous: Some(previous),
            status,
            message: self.bound_message(message),
        }))?;
        self.status = status;
        Ok(())
    }

    fn push_optional(&mut self, payload: AuditEventPayload) -> Result<(), RunnerError> {
        if self.events.len() + RESERVED_COMPLETION_EVENTS >= self.context.max_events {
            return Ok(());
        }
        self.push(payload)
    }

    fn push_required(&mut self, payload: AuditEventPayload) -> Result<(), RunnerError> {
        if self.events.len() == self.context.max_events {
            return Err(RunnerError::Adapter {
                message: "normalized event limit leaves no room for a required event".to_owned(),
            });
        }
        self.push(payload)
    }

    fn push(&mut self, payload: AuditEventPayload) -> Result<(), RunnerError> {
        let sequence = self.next_sequence;
        let event = AuditEvent {
            schema_version: AuditEventSchemaVersion::V1,
            event_id: format!("{}-event-{sequence:020}", self.context.audit_id),
            sequence,
            audit_id: self.context.audit_id.clone(),
            occurred_at: self.context.occurred_at.clone(),
            payload,
        };
        event.validate().map_err(|error| RunnerError::Adapter {
            message: error.to_string(),
        })?;
        self.events.push(event);
        self.next_sequence =
            self.next_sequence
                .checked_add(1)
                .ok_or_else(|| RunnerError::Adapter {
                    message: "normalized event sequence overflowed".to_owned(),
                })?;
        Ok(())
    }

    fn bound_message(&self, message: &str) -> String {
        truncate_utf8(message, self.context.max_message_bytes)
    }
}

fn nonnegative(value: i64, field: &str) -> Result<u64, RunnerError> {
    u64::try_from(value).map_err(|_| RunnerError::Adapter {
        message: format!("Codex reported a negative {field} value"),
    })
}

fn same_token_usage(raw: &AuditUsage, trusted: &AuditUsage) -> bool {
    raw.input_tokens == trusted.input_tokens
        && raw.cached_input_tokens == trusted.cached_input_tokens
        && raw.cache_write_input_tokens == trusted.cache_write_input_tokens
        && raw.output_tokens == trusted.output_tokens
        && raw.reasoning_output_tokens == trusted.reasoning_output_tokens
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    const SUFFIX: &str = "...";
    let target = max_bytes.saturating_sub(SUFFIX.len());
    let mut end = target.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = value[..end].to_owned();
    output.push_str(SUFFIX);
    output
}
