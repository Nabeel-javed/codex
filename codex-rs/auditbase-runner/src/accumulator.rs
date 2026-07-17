use std::collections::BTreeMap;

use codex_auditbase_contract::AuditEvent;
use codex_auditbase_contract::AuditEventPayload;
use codex_auditbase_contract::AuditStatus;
use codex_auditbase_contract::FindingEventAction;
use codex_auditbase_contract::Validate;

use crate::RunnerError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestResult {
    Added,
    Duplicate,
}

/// Deterministic replay guard for at-least-once event delivery.
pub struct AuditAccumulator {
    audit_id: String,
    next_sequence: u64,
    status: AuditStatus,
    pending_terminal_status: Option<AuditStatus>,
    terminal: bool,
    events: BTreeMap<u64, AuditEvent>,
    event_ids: BTreeMap<String, u64>,
    finding_ids: BTreeMap<String, bool>,
}

impl AuditAccumulator {
    pub fn new(audit_id: impl Into<String>) -> Self {
        Self {
            audit_id: audit_id.into(),
            next_sequence: 1,
            status: AuditStatus::Queued,
            pending_terminal_status: None,
            terminal: false,
            events: BTreeMap::new(),
            event_ids: BTreeMap::new(),
            finding_ids: BTreeMap::new(),
        }
    }

    pub fn ingest(&mut self, event: AuditEvent) -> Result<IngestResult, RunnerError> {
        event
            .validate()
            .map_err(|error| RunnerError::ReplayConflict {
                message: format!("invalid event: {error}"),
            })?;
        if event.audit_id != self.audit_id {
            return conflict(format!(
                "event audit_id `{}` does not match `{}`",
                event.audit_id, self.audit_id
            ));
        }

        if let Some(sequence) = self.event_ids.get(&event.event_id) {
            let Some(existing) = self.events.get(sequence) else {
                return conflict("internal event replay indexes are inconsistent".to_owned());
            };
            return if existing == &event {
                Ok(IngestResult::Duplicate)
            } else {
                conflict(format!(
                    "event_id `{}` was replayed with a different payload",
                    event.event_id
                ))
            };
        }
        if let Some(existing) = self.events.get(&event.sequence) {
            return if existing == &event {
                Ok(IngestResult::Duplicate)
            } else {
                conflict(format!(
                    "sequence {} was replayed with a different identity or payload",
                    event.sequence
                ))
            };
        }
        if self.terminal {
            return conflict("new event arrived after the terminal event".to_owned());
        }
        if event.sequence != self.next_sequence {
            return conflict(format!(
                "expected sequence {}, received {}",
                self.next_sequence, event.sequence
            ));
        }
        if let Some(pending) = self.pending_terminal_status {
            let matching_payload = matches!(
                (&event.payload, pending),
                (AuditEventPayload::Completed(_), AuditStatus::Completed)
                    | (AuditEventPayload::Failed(_), AuditStatus::Failed)
            );
            if !matching_payload {
                return conflict(
                    "terminal status must be followed immediately by its terminal payload"
                        .to_owned(),
                );
            }
        }

        self.apply_payload(&event.payload)?;
        self.event_ids
            .insert(event.event_id.clone(), event.sequence);
        self.events.insert(event.sequence, event);
        self.next_sequence =
            self.next_sequence
                .checked_add(1)
                .ok_or_else(|| RunnerError::ReplayConflict {
                    message: "event sequence overflowed".to_owned(),
                })?;
        Ok(IngestResult::Added)
    }

    pub fn replay(
        &mut self,
        events: impl IntoIterator<Item = AuditEvent>,
    ) -> Result<(), RunnerError> {
        for event in events {
            self.ingest(event)?;
        }
        Ok(())
    }

    pub fn events(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.values()
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn apply_payload(&mut self, payload: &AuditEventPayload) -> Result<(), RunnerError> {
        match payload {
            AuditEventPayload::Status(status) => {
                if status.previous != Some(self.status) {
                    return conflict(format!(
                        "status previous {:?} does not match accumulated {:?}",
                        status.previous, self.status
                    ));
                }
                self.status = status.status;
                if status.status.is_terminal() {
                    self.pending_terminal_status = Some(status.status);
                }
            }
            AuditEventPayload::Finding(event) => {
                let known = self.finding_ids.contains_key(&event.finding.id);
                match (event.action, known) {
                    (FindingEventAction::Discovered, true) => {
                        return conflict(format!(
                            "finding `{}` was discovered more than once",
                            event.finding.id
                        ));
                    }
                    (FindingEventAction::Updated, false) => {
                        return conflict(format!(
                            "finding `{}` was updated before discovery",
                            event.finding.id
                        ));
                    }
                    _ => {
                        self.finding_ids.insert(event.finding.id.clone(), true);
                    }
                }
            }
            AuditEventPayload::Completed(_) => {
                if self.pending_terminal_status != Some(AuditStatus::Completed) {
                    return conflict(
                        "completed payload requires an immediately preceding completed status"
                            .to_owned(),
                    );
                }
                self.pending_terminal_status = None;
                self.terminal = true;
            }
            AuditEventPayload::Failed(_) => {
                if self.pending_terminal_status != Some(AuditStatus::Failed) {
                    return conflict(
                        "failed payload requires an immediately preceding failed status".to_owned(),
                    );
                }
                self.pending_terminal_status = None;
                self.terminal = true;
            }
            AuditEventPayload::Progress(_)
            | AuditEventPayload::Log(_)
            | AuditEventPayload::Limitation(_)
            | AuditEventPayload::Usage(_) => {}
        }
        Ok(())
    }
}

fn conflict<T>(message: String) -> Result<T, RunnerError> {
    Err(RunnerError::ReplayConflict { message })
}
